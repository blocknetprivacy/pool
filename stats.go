package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// PoolStats tracks live pool statistics.
type PoolStats struct {
	mu sync.RWMutex

	// Global counters
	TotalSharesAccepted atomic.Uint64
	TotalSharesRejected atomic.Uint64
	TotalBlocksFound    atomic.Uint64

	// Per-miner stats (address -> stats)
	minerStats map[string]*MinerStats

	// Connected miners (connID -> address)
	connectedMiners map[string]string

	// Recent shares for hashrate estimation
	recentShares []shareRecord
}

type MinerStats struct {
	Address        string
	Workers        map[string]bool
	SharesAccepted uint64
	SharesRejected uint64
	BlocksFound    uint64
	LastShareAt    time.Time
}

type shareRecord struct {
	Miner      string
	Difficulty uint64
	Timestamp  time.Time
}

func NewPoolStats() *PoolStats {
	return &PoolStats{
		minerStats:      make(map[string]*MinerStats),
		connectedMiners: make(map[string]string),
	}
}

func (ps *PoolStats) AddMiner(miner *Miner) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.connectedMiners[miner.ID] = miner.Address

	ms, ok := ps.minerStats[miner.Address]
	if !ok {
		ms = &MinerStats{
			Address: miner.Address,
			Workers: make(map[string]bool),
		}
		ps.minerStats[miner.Address] = ms
	}
	ms.Workers[miner.Worker] = true
}

func (ps *PoolStats) RemoveMiner(connID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.connectedMiners, connID)
}

func (ps *PoolStats) RecordAcceptedShare(miner *Miner) {
	ps.TotalSharesAccepted.Add(1)

	ps.mu.Lock()
	defer ps.mu.Unlock()

	ms, ok := ps.minerStats[miner.Address]
	if !ok {
		ms = &MinerStats{
			Address: miner.Address,
			Workers: make(map[string]bool),
		}
		ps.minerStats[miner.Address] = ms
	}
	ms.SharesAccepted++
	ms.LastShareAt = time.Now()

	ps.recentShares = append(ps.recentShares, shareRecord{
		Miner:      miner.Address,
		Difficulty: miner.Difficulty,
		Timestamp:  time.Now(),
	})

	// Keep only last hour of shares for hashrate calculation
	cutoff := time.Now().Add(-1 * time.Hour)
	trimIdx := 0
	for i, s := range ps.recentShares {
		if s.Timestamp.After(cutoff) {
			trimIdx = i
			break
		}
	}
	if trimIdx > 0 {
		ps.recentShares = ps.recentShares[trimIdx:]
	}
}

func (ps *PoolStats) RecordRejectedShare(miner *Miner) {
	ps.TotalSharesRejected.Add(1)

	ps.mu.Lock()
	defer ps.mu.Unlock()

	ms, ok := ps.minerStats[miner.Address]
	if !ok {
		return
	}
	ms.SharesRejected++
}

func (ps *PoolStats) RecordBlock(block *PoolBlock) {
	ps.TotalBlocksFound.Add(1)

	ps.mu.Lock()
	defer ps.mu.Unlock()

	ms, ok := ps.minerStats[block.Finder]
	if !ok {
		return
	}
	ms.BlocksFound++
}

// EstimateHashrate estimates the pool hashrate based on recent shares.
// For Argon2id at 2GB, each hash takes ~2-3s, so hashrate is very low (< 1 H/s per thread).
// We estimate: hashrate = (sum of share difficulties) / time_window_seconds
func (ps *PoolStats) EstimateHashrate() float64 {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if len(ps.recentShares) < 2 {
		return 0
	}

	oldest := ps.recentShares[0].Timestamp
	newest := ps.recentShares[len(ps.recentShares)-1].Timestamp
	window := newest.Sub(oldest).Seconds()
	if window < 1 {
		return 0
	}

	var totalDiff uint64
	for _, s := range ps.recentShares {
		totalDiff += s.Difficulty
	}

	return float64(totalDiff) / window
}

// EstimateMinerHashrate estimates a specific miner's hashrate.
func (ps *PoolStats) EstimateMinerHashrate(address string) float64 {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var minerShares []shareRecord
	for _, s := range ps.recentShares {
		if s.Miner == address {
			minerShares = append(minerShares, s)
		}
	}

	if len(minerShares) < 2 {
		return 0
	}

	oldest := minerShares[0].Timestamp
	newest := minerShares[len(minerShares)-1].Timestamp
	window := newest.Sub(oldest).Seconds()
	if window < 1 {
		return 0
	}

	var totalDiff uint64
	for _, s := range minerShares {
		totalDiff += s.Difficulty
	}

	return float64(totalDiff) / window
}

// ConnectedMinerCount returns the number of unique connected miners.
func (ps *PoolStats) ConnectedMinerCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.connectedMiners)
}

// ConnectedWorkerCount returns the total number of connected workers.
func (ps *PoolStats) ConnectedWorkerCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	count := 0
	for _, ms := range ps.minerStats {
		count += len(ms.Workers)
	}
	return count
}

// GetMinerStats returns stats for a specific address.
func (ps *PoolStats) GetMinerStats(address string) *MinerStats {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	ms, ok := ps.minerStats[address]
	if !ok {
		return nil
	}

	// Return a copy
	cpy := *ms
	cpy.Workers = make(map[string]bool)
	for k, v := range ms.Workers {
		cpy.Workers[k] = v
	}
	return &cpy
}

// GetAllMinerStats returns stats for all miners.
func (ps *PoolStats) GetAllMinerStats() map[string]*MinerStats {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	result := make(map[string]*MinerStats)
	for addr, ms := range ps.minerStats {
		cpy := *ms
		cpy.Workers = make(map[string]bool)
		for k, v := range ms.Workers {
			cpy.Workers[k] = v
		}
		result[addr] = &cpy
	}
	return result
}
