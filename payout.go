package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// PayoutProcessor handles the full block lifecycle:
// 1. Confirm blocks — verify on chain, fetch reward, detect orphans
// 2. Distribute rewards — credit miner balances per PPLNS or proportional
// 3. Send payouts — wallet send to miners who meet min payout threshold
type PayoutProcessor struct {
	config *Config
	store  *Store
	node   *NodeClient

	cancel context.CancelFunc
}

const (
	walletPasswordEnv = "BLOCKNET_WALLET_PASSWORD"
	autoLoadWalletEnv = "BLOCKNET_POOL_AUTO_LOAD_WALLET"
)

func NewPayoutProcessor(config *Config, store *Store, node *NodeClient) *PayoutProcessor {
	return &PayoutProcessor{
		config: config,
		store:  store,
		node:   node,
	}
}

func (pp *PayoutProcessor) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	pp.cancel = cancel

	go func() {
		// Check for stuck pending payouts on startup
		pp.recoverPendingPayouts()

		// Run on startup
		pp.tick()

		ticker := time.NewTicker(pp.config.PayoutIntervalDuration())
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pp.tick()
			}
		}
	}()
}

func (pp *PayoutProcessor) Stop() {
	if pp.cancel != nil {
		pp.cancel()
	}
}

func (pp *PayoutProcessor) tick() {
	// Refresh node state so ChainHeight is current
	if _, err := pp.node.GetStatus(); err != nil {
		log.Printf("[payout] cannot reach node: %v", err)
		return
	}

	pp.confirmBlocks()
	pp.distributeRewards()
	pp.sendPayouts()
}

// ============================================================================
// Phase 1: Confirm or orphan unconfirmed blocks
// ============================================================================

func (pp *PayoutProcessor) confirmBlocks() {
	blocks, err := pp.store.GetUnconfirmedBlocks()
	if err != nil {
		log.Printf("[payout] failed to get unconfirmed blocks: %v", err)
		return
	}

	currentHeight := pp.node.ChainHeight()

	for _, block := range blocks {
		// Not enough confirmations yet
		if currentHeight < block.Height || currentHeight-block.Height < uint64(pp.config.BlocksBeforePayout) {
			continue
		}

		// Verify this block is still on chain at the expected height
		nodeBlock, err := pp.node.GetBlock(fmt.Sprintf("%d", block.Height))
		if err != nil {
			log.Printf("[payout] cannot verify block %d: %v", block.Height, err)
			continue
		}

		if nodeBlock.Hash != block.Hash {
			// Hash mismatch - but wait for grace period before marking orphaned
			// This handles temporary chain reorgs
			const orphanGracePeriod = 6 // additional confirmations before finalizing orphan status

			if currentHeight-block.Height < uint64(pp.config.BlocksBeforePayout+orphanGracePeriod) {
				// Still in grace period - don't make a decision yet
				log.Printf("[payout] block %d hash mismatch (chain has %s, we have %s), waiting for grace period",
					block.Height, nodeBlock.Hash, block.Hash)
				continue
			}

			// Grace period expired - finalize as orphaned
			log.Printf("[payout] block %d ORPHANED after grace period (chain has %s, we have %s)",
				block.Height, nodeBlock.Hash, block.Hash)
			block.Orphaned = true
			if err := pp.store.UpdateBlock(&block); err != nil {
				log.Printf("[payout] failed to update orphaned block %d: %v", block.Height, err)
			}
			continue
		}

		// Block confirmed on chain — record the reward
		block.Confirmed = true
		block.Reward = nodeBlock.Reward
		if err := pp.store.UpdateBlock(&block); err != nil {
			log.Printf("[payout] failed to confirm block %d: %v", block.Height, err)
			continue
		}

		log.Printf("[payout] block %d CONFIRMED (reward=%d)", block.Height, block.Reward)
	}
}

// ============================================================================
// Phase 2: Distribute rewards for confirmed, unpaid blocks
// ============================================================================

func (pp *PayoutProcessor) distributeRewards() {
	blocks, err := pp.store.GetUnpaidBlocks()
	if err != nil {
		log.Printf("[payout] failed to get unpaid blocks: %v", err)
		return
	}

	for _, block := range blocks {
		if block.Reward == 0 {
			log.Printf("[payout] block %d confirmed but reward=0, skipping", block.Height)
			continue
		}

		// Deduct pool fee
		fee := pp.config.PoolFee(block.Reward)
		distributable := block.Reward - fee
		if fee > 0 {
			log.Printf("[payout] block %d: reward=%d fee=%d distributable=%d",
				block.Height, block.Reward, fee, distributable)
		}

		var err error
		switch pp.config.PayoutScheme {
		case "pplns":
			err = pp.distributePPLNS(&block, distributable)
		default:
			err = pp.distributeProportional(&block, distributable)
		}

		if err != nil {
			log.Printf("[payout] failed to distribute block %d: %v", block.Height, err)
			continue
		}

		block.PaidOut = true
		if err := pp.store.UpdateBlock(&block); err != nil {
			log.Printf("[payout] failed to mark block %d as paid: %v", block.Height, err)
		}
	}
}

func (pp *PayoutProcessor) distributePPLNS(block *PoolBlock, reward uint64) error {
	// Use time-based window if configured, otherwise fall back to share count
	windowDuration := pp.config.PPLNSWindowDur()

	var shares []Share
	var err error

	if windowDuration > 0 {
		// Time-based PPLNS - more resistant to manipulation
		since := time.Now().Add(-windowDuration)
		shares, err = pp.store.GetSharesSince(since)
		if err != nil {
			return err
		}
		log.Printf("[payout] PPLNS using %d shares from last %v", len(shares), windowDuration)
	} else {
		// Legacy share-count based PPLNS
		shares, err = pp.store.GetLastNShares(pp.config.PPLNSWindow)
		if err != nil {
			return err
		}
		log.Printf("[payout] PPLNS using last %d shares", len(shares))
	}

	if len(shares) == 0 {
		return pp.store.CreditBalance(block.Finder, reward)
	}

	minerWeights, totalWeight := weightShares(shares)
	if totalWeight == 0 {
		return pp.store.CreditBalance(block.Finder, reward)
	}

	distributable := reward

	// Block finder bonus
	if pp.config.BlockFinderBonus && pp.config.BlockFinderBonusPct > 0 {
		bonus := uint64(float64(reward) * pp.config.BlockFinderBonusPct / 100.0)
		if err := pp.store.CreditBalance(block.Finder, bonus); err != nil {
			log.Printf("[payout] failed to credit finder bonus: %v", err)
		}
		distributable -= bonus
	}

	credited := pp.creditMiners(minerWeights, totalWeight, distributable)
	log.Printf("[payout] PPLNS block %d: %d distributed across %d miners", block.Height, credited, len(minerWeights))
	return nil
}

func (pp *PayoutProcessor) distributeProportional(block *PoolBlock, reward uint64) error {
	// Shares between this block and the previous paid block.
	// Use block timestamp as the boundary.
	shares, err := pp.store.GetSharesSince(block.Timestamp.Add(-1 * time.Hour))
	if err != nil {
		return err
	}
	if len(shares) == 0 {
		return pp.store.CreditBalance(block.Finder, reward)
	}

	minerWeights, totalWeight := weightShares(shares)
	if totalWeight == 0 {
		return pp.store.CreditBalance(block.Finder, reward)
	}

	distributable := reward

	if pp.config.BlockFinderBonus && pp.config.BlockFinderBonusPct > 0 {
		bonus := uint64(float64(reward) * pp.config.BlockFinderBonusPct / 100.0)
		if err := pp.store.CreditBalance(block.Finder, bonus); err != nil {
			log.Printf("[payout] failed to credit finder bonus: %v", err)
		}
		distributable -= bonus
	}

	credited := pp.creditMiners(minerWeights, totalWeight, distributable)
	log.Printf("[payout] proportional block %d: %d distributed across %d miners", block.Height, credited, len(minerWeights))
	return nil
}

// weightShares sums difficulty weights per miner address.
func weightShares(shares []Share) (map[string]uint64, uint64) {
	weights := make(map[string]uint64)
	var total uint64
	for _, s := range shares {
		weights[s.Miner] += s.Difficulty
		total += s.Difficulty
	}
	return weights, total
}

// creditMiners distributes amount proportional to weights. Returns total credited.
func (pp *PayoutProcessor) creditMiners(weights map[string]uint64, totalWeight, amount uint64) uint64 {
	var credited uint64
	for addr, weight := range weights {
		share := uint64(float64(amount) * float64(weight) / float64(totalWeight))
		if share == 0 {
			continue
		}
		if err := pp.store.CreditBalance(addr, share); err != nil {
			log.Printf("[payout] credit %s: %v", addr, err)
			continue
		}
		credited += share
	}
	return credited
}

// ============================================================================
// Phase 3: Send actual payouts to miners via the node wallet
// ============================================================================

// recoverPendingPayouts checks for payouts that were interrupted during send
func (pp *PayoutProcessor) recoverPendingPayouts() {
	pending, err := pp.store.GetPendingPayouts()
	if err != nil {
		log.Printf("[payout] failed to get pending payouts: %v", err)
		return
	}

	if len(pending) == 0 {
		return
	}

	log.Printf("[payout] found %d pending payouts from previous session", len(pending))

	for _, p := range pending {
		age := time.Since(p.InitiatedAt)
		if age > 1*time.Hour {
			// Pending too long - likely failed, cancel it
			log.Printf("[payout] canceling stale pending payout for %s (age: %v)", p.Address, age)
			if err := pp.store.CancelPendingPayout(p.Address); err != nil {
				log.Printf("[payout] failed to cancel pending payout: %v", err)
			}
		} else {
			// Recent pending - log for manual review
			log.Printf("[payout] WARNING: pending payout for %s amount=%d initiated %v ago - may need manual reconciliation",
				p.Address, p.Amount, age)
		}
	}
}

func (pp *PayoutProcessor) sendPayouts() {
	if !pp.ensureWalletReady() {
		return
	}

	minAmount := uint64(pp.config.MinPayoutAmount * 100_000_000)

	balances, err := pp.store.GetAllBalances()
	if err != nil {
		log.Printf("[payout] failed to get balances: %v", err)
		return
	}

	for _, bal := range balances {
		if bal.Pending < minAmount {
			continue
		}

		// Check wallet has enough funds before attempting
		walletBal, err := pp.node.GetWalletBalance()
		if err != nil {
			log.Printf("[payout] cannot check wallet balance: %v", err)
			return // stop all payouts if wallet unreachable
		}

		if walletBal.Spendable < bal.Pending {
			log.Printf("[payout] insufficient wallet balance for %s: need %d, have %d",
				bal.Address, bal.Pending, walletBal.Spendable)
			continue
		}

		// PHASE 1: Ensure we have exactly one pending payout intent.
		pending, err := pp.store.GetPendingPayout(bal.Address)
		if err != nil {
			log.Printf("[payout] failed to read pending payout for %s: %v", bal.Address, err)
			continue
		}
		if pending == nil {
			if err := pp.store.CreatePendingPayout(bal.Address, bal.Pending); err != nil {
				log.Printf("[payout] failed to create pending payout for %s: %v", bal.Address, err)
				continue
			}
			pending, err = pp.store.GetPendingPayout(bal.Address)
			if err != nil || pending == nil {
				log.Printf("[payout] failed to re-read pending payout for %s: %v", bal.Address, err)
				continue
			}
		}
		if pending.Amount != bal.Pending {
			// Defensive check: never send when pending intent and balance disagree.
			log.Printf("[payout] pending amount mismatch for %s: pending=%d balance=%d; skipping for safety",
				bal.Address, pending.Amount, bal.Pending)
			continue
		}

		// PHASE 2: Send wallet transaction
		idempotencyKey := payoutIdempotencyKey(*pending)
		result, err := pp.node.WalletSend(bal.Address, bal.Pending, idempotencyKey)
		if err != nil {
			log.Printf("[payout] send to %s failed (idempotency_key=%s): %v", bal.Address, idempotencyKey[:12], err)
			// Keep pending entry; next run retries the same payout intent with same key.
			continue
		}

		// PHASE 3: Complete the payout (debit balance + record + remove pending) atomically
		if err := pp.store.CompletePendingPayout(bal.Address, bal.Pending, result.TxID); err != nil {
			// CRITICAL: Funds were sent but database update failed
			// The pending entry remains so we can reconcile on next startup
			log.Printf("[payout] CRITICAL: sent %d to %s (tx=%s) but failed to complete payout: %v",
				bal.Pending, bal.Address, result.TxID, err)
			log.Printf("[payout] MANUAL ACTION REQUIRED: Verify transaction and manually reconcile address %s", bal.Address)
			continue
		}

		log.Printf("[payout] sent %d to %s tx=%s fee=%d", bal.Pending, bal.Address, result.TxID, result.Fee)
	}
}

func (pp *PayoutProcessor) ensureWalletReady() bool {
	if _, err := pp.node.GetWalletBalance(); err == nil {
		return pp.validateDaemonWalletAddress()
	} else {
		password := strings.TrimSpace(os.Getenv(walletPasswordEnv))
		if password == "" {
			log.Printf("[payout] wallet not ready and %s is not set; skipping payouts", walletPasswordEnv)
			return false
		}

		switch {
		case IsHTTPStatus(err, 403):
			if _, unlockErr := pp.node.WalletUnlock(password); unlockErr != nil {
				log.Printf("[payout] wallet locked and unlock failed: %v", unlockErr)
				return false
			}
			log.Printf("[payout] wallet unlocked for payout processing")
		case IsHTTPStatus(err, 503):
			if !envEnabled(autoLoadWalletEnv) {
				log.Printf("[payout] no wallet loaded; set %s=true to allow auto-load, skipping payouts", autoLoadWalletEnv)
				return false
			}
			if _, loadErr := pp.node.WalletLoad(password); loadErr != nil && !IsHTTPStatus(loadErr, 409) {
				log.Printf("[payout] wallet load failed: %v", loadErr)
				return false
			}
			if _, unlockErr := pp.node.WalletUnlock(password); unlockErr != nil {
				log.Printf("[payout] wallet unlock after load failed: %v", unlockErr)
				return false
			}
			log.Printf("[payout] wallet loaded and unlocked for payout processing")
		default:
			log.Printf("[payout] wallet readiness check failed: %v", err)
			return false
		}

		if _, verifyErr := pp.node.GetWalletBalance(); verifyErr != nil {
			log.Printf("[payout] wallet readiness verification failed: %v", verifyErr)
			return false
		}
		return pp.validateDaemonWalletAddress()
	}
}

func (pp *PayoutProcessor) validateDaemonWalletAddress() bool {
	addrResp, err := pp.node.GetWalletAddress()
	if err != nil {
		log.Printf("[payout] wallet address check failed: %v", err)
		return false
	}

	daemonAddress := strings.TrimSpace(addrResp.Address)
	if daemonAddress == "" {
		log.Printf("[payout] wallet address check failed: daemon returned empty address")
		return false
	}
	if addrResp.ViewOnly {
		log.Printf("[payout] wallet address check failed: daemon wallet is view-only, payouts are disabled")
		return false
	}

	log.Printf("[payout] using daemon wallet address for payouts: %s", daemonAddress)
	return true
}

func envEnabled(name string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func payoutIdempotencyKey(p PendingPayout) string {
	input := fmt.Sprintf("blocknet-pool:payout:%s:%d:%s", p.Address, p.Amount, p.InitiatedAt.UTC().Format(time.RFC3339Nano))
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}
