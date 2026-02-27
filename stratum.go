package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Security limits
// ============================================================================

const (
	maxConnsPerIP    = 16                   // max stratum connections from one IP
	maxConnsTotal    = 4096                 // max total stratum connections
	loginTimeout     = 30 * time.Second     // must login within this or get kicked
	maxSeenMapSize   = 500_000              // cap on duplicate-share tracker entries
	banDuration      = 10 * time.Minute     // initial ban duration
	maxBanDuration   = 24 * time.Hour       // maximum ban duration with exponential backoff
	banThreshold     = 50                   // consecutive rejects before ban
	maxWorkerNameLen = 64
	maxAddressLen    = 128
)

// AddressBanRecord tracks repeat offenders at the address level
type AddressBanRecord struct {
	Address      string
	BanCount     int       // number of times banned
	LastBanTime  time.Time
	BanExpiresAt time.Time
}

// ============================================================================
// Difficulty adjustment
// ============================================================================

const (
	targetShareInterval    = 10                 // target seconds between shares
	minShareDifficulty     = uint64(1)
	maxShareDifficulty     = uint64(1 << 30)
	diffAdjustShares       = 5                  // re-evaluate every N accepted shares
	minDiffAdjustInterval  = 60 * time.Second   // minimum time between difficulty adjustments
	maxDifficultyIncrease  = 2.0                // max 2x increase per adjustment
	maxDifficultyDecrease  = 1.5                // max 33% decrease per adjustment (1/1.5)
)

// ============================================================================
// Protocol types
// ============================================================================

const (
	MethodLogin  = "login"
	MethodSubmit = "submit"
)

type StratumRequest struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type StratumResponse struct {
	ID     uint64 `json:"id"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
	Result any    `json:"result,omitempty"`
}

type StratumNotify struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

type LoginParams struct {
	Address string `json:"address"`
	Worker  string `json:"worker"`
}

type SubmitParams struct {
	JobID string `json:"job_id"`
	Nonce uint64 `json:"nonce"`
}

// ============================================================================
// Miner
// ============================================================================

type Miner struct {
	ID          string
	Conn        net.Conn
	Address     string
	Worker      string
	Difficulty  uint64
	JobCh       chan *Job
	ConnectedAt time.Time
	writeMu     sync.Mutex

	SharesAccepted atomic.Uint64
	SharesRejected atomic.Uint64
	LastShareAt    atomic.Int64
	lastAdjustAt   atomic.Int64

	// Security: consecutive rejects counter (reset on accept)
	consecutiveRejects atomic.Uint64
}

type MinerSnapshot struct {
	Address        string    `json:"address"`
	Worker         string    `json:"worker"`
	Difficulty     uint64    `json:"difficulty"`
	SharesAccepted uint64    `json:"shares_accepted"`
	SharesRejected uint64    `json:"shares_rejected"`
	LastShareAt    int64     `json:"last_share_at"`
	ConnectedAt    time.Time `json:"connected_at"`
}

// ============================================================================
// Server
// ============================================================================

type StratumServer struct {
	config *Config
	jobs   *JobManager
	store  *Store
	stats  *PoolStats

	mu     sync.RWMutex
	miners map[string]*Miner // connID -> Miner
	ln     net.Listener
	cancel context.CancelFunc

	// Per-IP connection tracking
	ipMu    sync.Mutex
	ipConns map[string]int

	// Duplicate share tracking: key = "jobID:nonce"
	seenMu sync.Mutex
	seen   map[string]struct{}

	// IP ban list
	banMu   sync.RWMutex
	banned  map[string]time.Time // IP -> ban expiry
	
	// Address-level ban tracking for repeat offenders
	addressBanMu sync.RWMutex
	addressBans  map[string]*AddressBanRecord
}

func NewStratumServer(config *Config, jobs *JobManager, store *Store, stats *PoolStats) *StratumServer {
	return &StratumServer{
		config:      config,
		jobs:        jobs,
		store:       store,
		stats:       stats,
		miners:      make(map[string]*Miner),
		ipConns:     make(map[string]int),
		seen:        make(map[string]struct{}),
		banned:      make(map[string]time.Time),
		addressBans: make(map[string]*AddressBanRecord),
	}
}

func (s *StratumServer) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	addr := fmt.Sprintf("0.0.0.0:%d", s.config.StratumPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		cancel()
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	s.ln = ln
	log.Printf("[stratum] listening on %s", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Flush seen-map on new jobs
	jobCh := s.jobs.Subscribe()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-jobCh:
				if !ok {
					return
				}
				s.flushSeen()
			}
		}
	}()

	// Accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[stratum] accept error: %v", err)
				continue
			}

			ip := connIP(conn)

			// Check ban
			if s.isBanned(ip) {
				conn.Close()
				continue
			}

			// Check total connection limit
			s.mu.RLock()
			total := len(s.miners)
			s.mu.RUnlock()
			if total >= maxConnsTotal {
				conn.Close()
				continue
			}

			// Check per-IP limit
			if !s.trackIP(ip) {
				conn.Close()
				continue
			}

			go s.handleConn(ctx, conn, ip)
		}
	}()

	return nil
}

func (s *StratumServer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// ============================================================================
// IP tracking and banning
// ============================================================================

func connIP(conn net.Conn) string {
	addr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func (s *StratumServer) trackIP(ip string) bool {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if s.ipConns[ip] >= maxConnsPerIP {
		return false
	}
	s.ipConns[ip]++
	return true
}

func (s *StratumServer) untrackIP(ip string) {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	s.ipConns[ip]--
	if s.ipConns[ip] <= 0 {
		delete(s.ipConns, ip)
	}
}

func (s *StratumServer) banIP(ip string) {
	s.banMu.Lock()
	s.banned[ip] = time.Now().Add(banDuration)
	s.banMu.Unlock()
	log.Printf("[stratum] BANNED IP %s for %v", ip, banDuration)
}

func (s *StratumServer) banAddress(address string, reason string) {
	s.addressBanMu.Lock()
	defer s.addressBanMu.Unlock()
	
	record, exists := s.addressBans[address]
	if !exists {
		record = &AddressBanRecord{
			Address:  address,
			BanCount: 0,
		}
		s.addressBans[address] = record
	}
	
	// Exponential backoff: 10min, 1hr, 6hr, 24hr (capped)
	record.BanCount++
	duration := time.Duration(banDuration.Nanoseconds() * int64(1<<uint(record.BanCount-1)))
	if duration > maxBanDuration {
		duration = maxBanDuration
	}
	
	record.LastBanTime = time.Now()
	record.BanExpiresAt = time.Now().Add(duration)
	
	log.Printf("[stratum] BANNED ADDRESS %s for %v (ban #%d, reason: %s)", 
		address, duration, record.BanCount, reason)
}

func (s *StratumServer) isAddressBanned(address string) bool {
	s.addressBanMu.RLock()
	record, exists := s.addressBans[address]
	s.addressBanMu.RUnlock()
	
	if !exists {
		return false
	}
	
	if time.Now().After(record.BanExpiresAt) {
		// Ban expired - clean up
		s.addressBanMu.Lock()
		delete(s.addressBans, address)
		s.addressBanMu.Unlock()
		return false
	}
	
	return true
}

func (s *StratumServer) isBanned(ip string) bool {
	s.banMu.RLock()
	expiry, ok := s.banned[ip]
	s.banMu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		s.banMu.Lock()
		delete(s.banned, ip)
		s.banMu.Unlock()
		return false
	}
	return true
}

// ============================================================================
// Duplicate share tracking
// ============================================================================

func (s *StratumServer) flushSeen() {
	s.seenMu.Lock()
	s.seen = make(map[string]struct{})
	s.seenMu.Unlock()
}

func (s *StratumServer) isDuplicate(jobID string, nonce uint64) bool {
	key := fmt.Sprintf("%s:%d", jobID, nonce)
	s.seenMu.Lock()
	defer s.seenMu.Unlock()

	if _, ok := s.seen[key]; ok {
		return true
	}

	// Cap the map to prevent unbounded growth if jobs aren't refreshing
	if len(s.seen) >= maxSeenMapSize {
		s.seen = make(map[string]struct{})
	}

	s.seen[key] = struct{}{}
	return false
}

// ============================================================================
// Connection handler
// ============================================================================

func (s *StratumServer) handleConn(ctx context.Context, conn net.Conn, ip string) {
	connID := conn.RemoteAddr().String()

	miner := &Miner{
		ID:          connID,
		Conn:        conn,
		Difficulty:  s.config.InitialShareDifficulty,
		ConnectedAt: time.Now(),
		JobCh:       s.jobs.Subscribe(),
	}
	miner.lastAdjustAt.Store(time.Now().Unix())

	s.mu.Lock()
	s.miners[connID] = miner
	s.mu.Unlock()

	defer func() {
		conn.Close()
		s.jobs.Unsubscribe(miner.JobCh)
		s.mu.Lock()
		delete(s.miners, connID)
		s.mu.Unlock()
		s.untrackIP(ip)
		s.stats.RemoveMiner(connID)
	}()

	// Login timeout: if the miner doesn't authenticate within loginTimeout, kick them.
	// This prevents idle connections from eating resources.
	loginTimer := time.AfterFunc(loginTimeout, func() {
		if miner.Address == "" {
			log.Printf("[stratum] login timeout, kicking %s", connID)
			conn.Close()
		}
	})
	defer loginTimer.Stop()

	// Job push goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case job, ok := <-miner.JobCh:
				if !ok {
					return
				}
				if miner.Address != "" { // only push jobs to logged-in miners
					s.sendJob(miner, job)
				}
			}
		}
	}()

	// Read loop
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req StratumRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.sendError(miner, 0, "invalid JSON")
			continue
		}

		switch req.Method {
		case MethodLogin:
			s.handleLogin(miner, &req, loginTimer)
		case MethodSubmit:
			s.handleSubmit(miner, &req, ip)
		default:
			s.sendError(miner, req.ID, "unknown method")
		}
	}
}

func (s *StratumServer) handleLogin(miner *Miner, req *StratumRequest, loginTimer *time.Timer) {
	var params LoginParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(miner, req.ID, "invalid login params")
		return
	}

	if params.Address == "" || len(params.Address) > maxAddressLen {
		s.sendError(miner, req.ID, "invalid address")
		return
	}
	
	// Check if address is banned
	if s.isAddressBanned(params.Address) {
		s.sendError(miner, req.ID, "address banned")
		miner.Conn.Close()
		return
	}

	worker := params.Worker
	if worker == "" {
		worker = "default"
	}
	if len(worker) > maxWorkerNameLen {
		worker = worker[:maxWorkerNameLen]
	}

	miner.Address = params.Address
	miner.Worker = worker

	// Cancel the login timeout
	loginTimer.Stop()

	log.Printf("[stratum] login %s/%s from %s", miner.Address, miner.Worker, miner.ID)

	s.stats.AddMiner(miner)
	s.sendJSON(miner, StratumResponse{ID: req.ID, Status: "ok"})

	if job := s.jobs.CurrentJob(); job != nil {
		s.sendJob(miner, job)
	}
}

func (s *StratumServer) handleSubmit(miner *Miner, req *StratumRequest, ip string) {
	var params SubmitParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(miner, req.ID, "invalid submit params")
		return
	}

	if miner.Address == "" {
		s.sendError(miner, req.ID, "not logged in")
		return
	}

	reject := func(reason string) {
		s.sendError(miner, req.ID, reason)
		miner.SharesRejected.Add(1)
		s.stats.RecordRejectedShare(miner)

		// Ban after too many consecutive rejects
		n := miner.consecutiveRejects.Add(1)
		if n >= banThreshold {
			s.banIP(ip)
			s.banAddress(miner.Address, fmt.Sprintf("excessive rejects (%d consecutive)", n))
			miner.Conn.Close()
		}
	}

	// Stale job
	job := s.jobs.GetJob(params.JobID)
	if job == nil {
		reject("stale job")
		return
	}

	// Duplicate share - CHECK BEFORE EXPENSIVE PoW VERIFICATION
	// This prevents CPU exhaustion attacks
	// Check memory cache first for speed
	if s.isDuplicate(params.JobID, params.Nonce) {
		reject("duplicate share")
		return
	}
	
	// Check persistent storage for shares within 24h window
	seen, err := s.store.IsShareSeen(params.JobID, params.Nonce)
	if err != nil {
		log.Printf("[stratum] error checking persistent share dedup: %v", err)
	} else if seen {
		reject("duplicate share")
		return
	}

	// Decode header
	headerBase, err := hex.DecodeString(job.HeaderBase)
	if err != nil {
		s.sendError(miner, req.ID, "internal error")
		return
	}

	// Compute Argon2id hash (~2-3 seconds, 2GB RAM)
	hash := PowHash(headerBase, params.Nonce)

	// Check share target
	shareTarget := difficultyToTarget(miner.Difficulty)
	if !CheckTarget(hash, shareTarget) {
		reject("low difficulty share")
		return
	}

	// --- Valid share ---
	miner.SharesAccepted.Add(1)
	miner.LastShareAt.Store(time.Now().Unix())
	miner.consecutiveRejects.Store(0) // reset on valid share
	
	// Mark share as seen in persistent storage
	if err := s.store.MarkShareSeen(params.JobID, params.Nonce); err != nil {
		log.Printf("[stratum] error marking share as seen: %v", err)
	}

	share := &Share{
		JobID:      params.JobID,
		Miner:      miner.Address,
		Worker:     miner.Worker,
		Difficulty: miner.Difficulty,
		Timestamp:  time.Now(),
		Nonce:      params.Nonce,
	}

	// Check network target
	networkTarget, err := hex.DecodeString(job.Target)
	if err == nil && len(networkTarget) == 32 {
		var nt [32]byte
		copy(nt[:], networkTarget)
		if CheckTarget(hash, nt) {
			log.Printf("[stratum] BLOCK FOUND by %s/%s at height %d!", miner.Address, miner.Worker, job.Height)
			share.BlockHash = fmt.Sprintf("%x", hash)

			result, err := s.jobs.SubmitBlock(job, params.Nonce)
			if err != nil {
				log.Printf("[stratum] block submit failed: %v", err)
			} else if result.Accepted {
				log.Printf("[stratum] block accepted! hash=%s height=%d", result.Hash, result.Height)
				s.recordBlock(job, miner, result)
			}
			
			// Block-finding shares are critical - write immediately
			if err := s.store.AddShareImmediate(share); err != nil {
				log.Printf("[stratum] failed to store block share: %v", err)
			}
		} else {
			// Regular share - use batch writer
			if err := s.store.AddShare(share); err != nil {
				log.Printf("[stratum] failed to store share: %v", err)
			}
		}
	} else {
		// Regular share - use batch writer
		if err := s.store.AddShare(share); err != nil {
			log.Printf("[stratum] failed to store share: %v", err)
		}
	}

	s.stats.RecordAcceptedShare(miner)

	s.sendJSON(miner, StratumResponse{
		ID:     req.ID,
		Status: "ok",
		Result: map[string]any{"accepted": true},
	})

	if miner.SharesAccepted.Load()%diffAdjustShares == 0 {
		s.adjustDifficulty(miner)
	}
}

// ============================================================================
// Difficulty adjustment
// ============================================================================

func (s *StratumServer) adjustDifficulty(miner *Miner) {
	now := time.Now().Unix()
	lastAdj := miner.lastAdjustAt.Load()
	elapsed := now - lastAdj
	
	// Enforce minimum adjustment interval to prevent manipulation
	if elapsed < int64(minDiffAdjustInterval.Seconds()) {
		return
	}
	
	if elapsed < 1 {
		return
	}

	actualInterval := float64(elapsed) / float64(diffAdjustShares)
	ratio := actualInterval / float64(targetShareInterval)

	newDiff := miner.Difficulty
	
	// Apply capped adjustments to prevent manipulation
	if ratio < 0.5 {
		// Miner is too fast - increase difficulty
		increase := maxDifficultyIncrease
		if ratio > 0 {
			increase = 1.0 / ratio
			if increase > maxDifficultyIncrease {
				increase = maxDifficultyIncrease
			}
		}
		newDiff = uint64(float64(miner.Difficulty) * increase)
	} else if ratio > 2.0 {
		// Miner is too slow - decrease difficulty (but limit reduction)
		decrease := maxDifficultyDecrease
		if ratio < 10.0 { // reasonable upper bound
			decrease = ratio
			if decrease > maxDifficultyDecrease {
				decrease = maxDifficultyDecrease
			}
		}
		newDiff = uint64(float64(miner.Difficulty) / decrease)
	} else {
		// Fine-tune within normal range
		newDiff = uint64(float64(miner.Difficulty) / ratio)
	}

	if newDiff < minShareDifficulty {
		newDiff = minShareDifficulty
	}
	if newDiff > maxShareDifficulty {
		newDiff = maxShareDifficulty
	}

	if newDiff != miner.Difficulty {
		log.Printf("[stratum] difficulty %s/%s: %d -> %d (interval=%.1fs, ratio=%.2f)",
			miner.Address, miner.Worker, miner.Difficulty, newDiff, actualInterval, ratio)
		miner.Difficulty = newDiff
		if job := s.jobs.CurrentJob(); job != nil {
			s.sendJob(miner, job)
		}
	}

	miner.lastAdjustAt.Store(now)
}

// ============================================================================
// Helpers
// ============================================================================

func (s *StratumServer) recordBlock(job *Job, miner *Miner, result *SubmitBlockResponse) {
	poolBlock := &PoolBlock{
		Height:       result.Height,
		Hash:         result.Hash,
		Difficulty:   job.Difficulty,
		Finder:       miner.Address,
		FinderWorker: miner.Worker,
		Reward:       0,
		Timestamp:    time.Now(),
	}
	if err := s.store.AddBlock(poolBlock); err != nil {
		log.Printf("[stratum] failed to store block: %v", err)
	}
	s.stats.RecordBlock(poolBlock)
}

func (s *StratumServer) sendJob(miner *Miner, job *Job) {
	minerJob := s.jobs.BuildMinerJob(miner.Difficulty)
	if minerJob == nil {
		return
	}
	s.sendJSON(miner, StratumNotify{Method: "job", Params: minerJob})
}

func (s *StratumServer) sendError(miner *Miner, id uint64, msg string) {
	s.sendJSON(miner, StratumResponse{ID: id, Error: msg})
}

func (s *StratumServer) sendJSON(miner *Miner, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	data = append(data, '\n')

	miner.writeMu.Lock()
	defer miner.writeMu.Unlock()

	miner.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := miner.Conn.Write(data); err != nil {
		log.Printf("[stratum] write error to %s: %v", miner.ID, err)
	}
}

// MinerCount returns the number of connected miners.
func (s *StratumServer) MinerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.miners)
}

// GetMiners returns a snapshot of all connected miners.
func (s *StratumServer) GetMiners() []*MinerSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	miners := make([]*MinerSnapshot, 0, len(s.miners))
	for _, m := range s.miners {
		miners = append(miners, &MinerSnapshot{
			Address:        m.Address,
			Worker:         m.Worker,
			Difficulty:     m.Difficulty,
			SharesAccepted: m.SharesAccepted.Load(),
			SharesRejected: m.SharesRejected.Load(),
			LastShareAt:    m.LastShareAt.Load(),
			ConnectedAt:    m.ConnectedAt,
		})
	}
	return miners
}
