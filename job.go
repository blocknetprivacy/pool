package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Job represents a mining job derived from a block template.
type Job struct {
	ID         string          `json:"id"`
	Height     uint64          `json:"height"`
	HeaderBase string          `json:"header_base"` // hex-encoded 92-byte header (no nonce)
	Target     string          `json:"target"`       // hex-encoded 32-byte network target
	Difficulty uint64          `json:"difficulty"`    // network difficulty
	Block      json.RawMessage `json:"block"`        // full block JSON for submission
	CreatedAt  time.Time       `json:"created_at"`
}

// JobManager polls the node for block templates and manages current jobs.
type JobManager struct {
	node   *NodeClient
	config *Config

	mu         sync.RWMutex
	currentJob *Job
	jobs       map[string]*Job // jobID -> Job, recent jobs for late share validation
	jobCount   atomic.Uint64

	// nonceCounter is used to assign non-overlapping nonce ranges to miners.
	nonceCounter atomic.Uint64

	// subscribers receive new jobs
	subMu       sync.RWMutex
	subscribers []chan *Job

	cancel context.CancelFunc
	
	// Rate limiting for job refreshes
	lastRefresh time.Time
	refreshMu   sync.Mutex

	// Cached daemon wallet address used when pool_wallet_address is not configured.
	rewardAddrMu            sync.Mutex
	daemonRewardAddress     string
	daemonRewardCheckedAt   time.Time
}

func NewJobManager(node *NodeClient, config *Config) *JobManager {
	return &JobManager{
		node:   node,
		config: config,
		jobs:   make(map[string]*Job),
	}
}

// Start begins polling for new block templates and listening for SSE events.
func (jm *JobManager) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	jm.cancel = cancel

	// SSE listener for instant new-block notification
	sseCh := make(chan SSEEvent, 16)
	go jm.node.SubscribeBlocks(ctx, sseCh)

	// Initial template fetch
	jm.refreshTemplate()

	// Poll loop + SSE
	go func() {
		ticker := time.NewTicker(jm.config.BlockPollDuration())
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jm.refreshTemplate()
			case event := <-sseCh:
				if event.Event == "new_block" || event.Event == "mined_block" {
					log.Printf("[jobs] new block event, refreshing template")
					jm.refreshTemplate()
				}
			}
		}
	}()
}

func (jm *JobManager) Stop() {
	if jm.cancel != nil {
		jm.cancel()
	}
}

func (jm *JobManager) refreshTemplate() {
	// Rate limit: max 1 refresh per second to prevent flooding
	jm.refreshMu.Lock()
	if time.Since(jm.lastRefresh) < 1*time.Second {
		jm.refreshMu.Unlock()
		return
	}
	jm.lastRefresh = time.Now()
	jm.refreshMu.Unlock()
	
	rewardAddress := jm.resolveRewardAddress()
	tmpl, err := jm.node.GetBlockTemplate(rewardAddress)
	if err != nil {
		log.Printf("[jobs] failed to get block template: %v", err)
		return
	}
	if rewardAddress == "" {
		// If no explicit address is configured, use the daemon-selected reward address
		// so coinbase validation still verifies the template payout destination.
		rewardAddress = strings.TrimSpace(tmpl.RewardAddressUsed)
	}
	if rewardAddress != "" && tmpl.RewardAddressUsed != "" && tmpl.RewardAddressUsed != rewardAddress {
		log.Printf("[jobs] SECURITY: daemon returned template for unexpected reward address (expected=%s got=%s), rejecting",
			rewardAddress, tmpl.RewardAddressUsed)
		return
	}

	// Extract height from the block JSON
	var blockInfo struct {
		Header struct {
			Height     uint64 `json:"height"`
			Difficulty uint64 `json:"difficulty"`
		} `json:"header"`
		Transactions []struct {
			Type       string            `json:"type"`
			IsCoinbase bool              `json:"is_coinbase"`
			Inputs     []json.RawMessage `json:"inputs"`
			Outputs []struct {
				Address string `json:"address"`
				Amount  uint64 `json:"amount"`
			} `json:"outputs"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal(tmpl.Block, &blockInfo); err != nil {
		log.Printf("[jobs] failed to parse block template header: %v", err)
		return
	}
	
	// Validate coinbase transaction pays to pool wallet
	if rewardAddress != "" {
		if !jm.validateCoinbase(&blockInfo, rewardAddress) {
			log.Printf("[jobs] SECURITY: block template coinbase does not pay to expected wallet, rejecting")
			return
		}
	}

	// Check if this is actually a new job (different height or difficulty)
	jm.mu.RLock()
	if jm.currentJob != nil &&
		jm.currentJob.Height == blockInfo.Header.Height &&
		jm.currentJob.Difficulty == blockInfo.Header.Difficulty {
		jm.mu.RUnlock()
		return
	}
	jm.mu.RUnlock()

	job := &Job{
		ID:         generateJobID(),
		Height:     blockInfo.Header.Height,
		HeaderBase: tmpl.HeaderBase,
		Target:     tmpl.Target,
		Difficulty: blockInfo.Header.Difficulty,
		Block:      tmpl.Block,
		CreatedAt:  time.Now(),
	}

	jm.mu.Lock()
	jm.currentJob = job
	jm.jobs[job.ID] = job
	jm.jobCount.Add(1)

	// Prune old jobs (keep last 10)
	if len(jm.jobs) > 10 {
		var oldest string
		var oldestTime time.Time
		for id, j := range jm.jobs {
			if oldest == "" || j.CreatedAt.Before(oldestTime) {
				oldest = id
				oldestTime = j.CreatedAt
			}
		}
		delete(jm.jobs, oldest)
	}

	// Reset nonce counter for new job
	jm.nonceCounter.Store(0)
	jm.mu.Unlock()

	log.Printf("[jobs] new job %s height=%d difficulty=%d", job.ID, job.Height, job.Difficulty)

	// Notify subscribers
	jm.notifySubscribers(job)
}

func (jm *JobManager) validateCoinbase(blockInfo *struct {
	Header struct {
		Height     uint64 `json:"height"`
		Difficulty uint64 `json:"difficulty"`
	} `json:"header"`
	Transactions []struct {
		Type       string            `json:"type"`
		IsCoinbase bool              `json:"is_coinbase"`
		Inputs     []json.RawMessage `json:"inputs"`
		Outputs []struct {
			Address string `json:"address"`
			Amount  uint64 `json:"amount"`
		} `json:"outputs"`
	} `json:"transactions"`
}, expectedAddress string) bool {
	// Daemon v0.5.2 templates can use confidential outputs, where output address
	// is not present inside block.transactions[*].outputs. In that case we rely
	// on reward_address_used (already verified by refreshTemplate()).
	for _, tx := range blockInfo.Transactions {
		isCoinbase := tx.IsCoinbase || tx.Type == "coinbase" || tx.Type == "miner_reward" || len(tx.Inputs) == 0
		if !isCoinbase {
			continue
		}

		// If explicit output addresses are present, enforce strict match.
		hasExplicitAddress := false
		for _, out := range tx.Outputs {
			if out.Address == "" {
				continue
			}
			hasExplicitAddress = true
			if out.Address == expectedAddress && out.Amount > 0 {
				return true
			}
		}
		if hasExplicitAddress {
			log.Printf("[jobs] coinbase transaction does not pay to expected wallet %s", expectedAddress)
			return false
		}

		// No address field available in this template format.
		return true
	}

	log.Printf("[jobs] no coinbase transaction found in block template")
	return false
}

func (jm *JobManager) resolveRewardAddress() string {
	// Always source the reward address from the daemon's loaded wallet.
	// This avoids stale/duplicated config and keeps templates bound to the live node wallet.
	const cacheTTL = 30 * time.Second
	jm.rewardAddrMu.Lock()
	cachedAddr := jm.daemonRewardAddress
	checkedAt := jm.daemonRewardCheckedAt
	jm.rewardAddrMu.Unlock()

	if cachedAddr != "" && time.Since(checkedAt) < cacheTTL {
		return cachedAddr
	}

	addrResp, err := jm.node.GetWalletAddress()
	jm.rewardAddrMu.Lock()
	defer jm.rewardAddrMu.Unlock()
	jm.daemonRewardCheckedAt = time.Now()

	if err != nil {
		if jm.daemonRewardAddress == "" {
			log.Printf("[jobs] daemon wallet address unavailable: %v", err)
		}
		return jm.daemonRewardAddress
	}

	resolved := strings.TrimSpace(addrResp.Address)
	if resolved == "" {
		return jm.daemonRewardAddress
	}
	if jm.daemonRewardAddress != resolved {
		jm.daemonRewardAddress = resolved
		log.Printf("[jobs] using daemon wallet address for templates: %s", resolved)
	}
	return jm.daemonRewardAddress
}

// CurrentJob returns the current job.
func (jm *JobManager) CurrentJob() *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.currentJob
}

// GetJob returns a job by ID (for validating late shares).
func (jm *JobManager) GetJob(id string) *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.jobs[id]
}

// AssignNonceRange returns a starting nonce for a miner.
// Each call advances the counter by rangeSize to avoid overlap.
func (jm *JobManager) AssignNonceRange(rangeSize uint64) uint64 {
	return jm.nonceCounter.Add(rangeSize) - rangeSize
}

// Subscribe returns a channel that receives new jobs.
func (jm *JobManager) Subscribe() chan *Job {
	ch := make(chan *Job, 4)
	jm.subMu.Lock()
	jm.subscribers = append(jm.subscribers, ch)
	jm.subMu.Unlock()
	return ch
}

// Unsubscribe removes a job channel.
func (jm *JobManager) Unsubscribe(ch chan *Job) {
	jm.subMu.Lock()
	defer jm.subMu.Unlock()
	for i, sub := range jm.subscribers {
		if sub == ch {
			jm.subscribers = append(jm.subscribers[:i], jm.subscribers[i+1:]...)
			close(ch)
			return
		}
	}
}

func (jm *JobManager) notifySubscribers(job *Job) {
	jm.subMu.RLock()
	defer jm.subMu.RUnlock()
	for _, ch := range jm.subscribers {
		select {
		case ch <- job:
		default:
			// Slow subscriber, skip
		}
	}
}

// SubmitBlock submits a solved block to the node.
func (jm *JobManager) SubmitBlock(job *Job, nonce uint64) (*SubmitBlockResponse, error) {
	// Inject the nonce into the block JSON
	var block map[string]json.RawMessage
	if err := json.Unmarshal(job.Block, &block); err != nil {
		return nil, fmt.Errorf("unmarshal block: %w", err)
	}

	var header map[string]json.RawMessage
	if err := json.Unmarshal(block["header"], &header); err != nil {
		return nil, fmt.Errorf("unmarshal header: %w", err)
	}

	nonceJSON, _ := json.Marshal(nonce)
	header["nonce"] = nonceJSON

	headerJSON, _ := json.Marshal(header)
	block["header"] = headerJSON

	blockJSON, _ := json.Marshal(block)

	return jm.node.SubmitBlock(blockJSON)
}

func generateJobID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// BuildMinerJob creates the data sent to a miner over stratum.
type MinerJob struct {
	JobID      string `json:"job_id"`
	HeaderBase string `json:"header_base"` // hex 92 bytes
	Target     string `json:"target"`      // hex share target (not network target)
	Height     uint64 `json:"height"`
	NonceStart uint64 `json:"nonce_start"`
	NonceEnd   uint64 `json:"nonce_end"`
}

// BuildMinerJob creates a job tailored for a specific miner's share difficulty.
func (jm *JobManager) BuildMinerJob(shareDifficulty uint64) *MinerJob {
	job := jm.CurrentJob()
	if job == nil {
		return nil
	}

	// Nonce range per assignment: 1M nonces
	// At ~0.5 H/s per thread (Argon2id 2GB), this is ~23 days of work
	// so effectively unlimited per job lifetime
	const nonceRange = 1_000_000
	start := jm.AssignNonceRange(nonceRange)

	shareTarget := difficultyToTarget(shareDifficulty)

	return &MinerJob{
		JobID:      job.ID,
		HeaderBase: job.HeaderBase,
		Target:     hex.EncodeToString(shareTarget[:]),
		Height:     job.Height,
		NonceStart: start,
		NonceEnd:   start + nonceRange - 1,
	}
}
