package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketShares         = []byte("shares")
	bucketBlocks         = []byte("blocks")
	bucketBalances       = []byte("balances")
	bucketPayouts        = []byte("payouts")
	bucketMeta           = []byte("meta")
	bucketSeenShares     = []byte("seen_shares")     // persistent share deduplication
	bucketPendingPayouts = []byte("pending_payouts") // atomicity for payouts
)

// BatchWriter handles buffered writes to reduce BoltDB lock contention
type BatchWriter struct {
	store       *Store
	shareBuf    []Share
	bufMu       sync.Mutex
	flushTicker *time.Ticker
	cancel      context.CancelFunc

	// Configuration
	maxBufferSize int
	flushInterval time.Duration

	// Metrics
	totalFlushed  uint64
	flushCount    uint64
	lastFlushTime time.Time
	metricsMu     sync.RWMutex
}

type Store struct {
	db          *bolt.DB
	batchWriter *BatchWriter
}

// Share represents a valid share submitted by a miner.
type Share struct {
	ID         uint64    `json:"id"`
	JobID      string    `json:"job_id"`
	Miner      string    `json:"miner"`      // wallet address
	Worker     string    `json:"worker"`     // worker name
	Difficulty uint64    `json:"difficulty"` // share difficulty
	Timestamp  time.Time `json:"timestamp"`
	Nonce      uint64    `json:"nonce"`
	BlockHash  string    `json:"block_hash,omitempty"` // set if this share found a block
}

// PoolBlock represents a block found by the pool.
type PoolBlock struct {
	Height       uint64    `json:"height"`
	Hash         string    `json:"hash"`
	Difficulty   uint64    `json:"difficulty"`
	Finder       string    `json:"finder"` // miner address
	FinderWorker string    `json:"finder_worker"`
	Reward       uint64    `json:"reward"`
	Timestamp    time.Time `json:"timestamp"`
	Confirmed    bool      `json:"confirmed"`
	Orphaned     bool      `json:"orphaned"`
	PaidOut      bool      `json:"paid_out"`
}

// Balance tracks pending and paid amounts per miner address.
type Balance struct {
	Address string `json:"address"`
	Pending uint64 `json:"pending"` // atomic units
	Paid    uint64 `json:"paid"`    // total paid out
}

// Payout records a payout transaction.
type Payout struct {
	ID        uint64    `json:"id"`
	Address   string    `json:"address"`
	Amount    uint64    `json:"amount"`
	TxHash    string    `json:"tx_hash"`
	Timestamp time.Time `json:"timestamp"`
	BlockIDs  []uint64  `json:"block_ids"` // blocks this payout covers
}

// PendingPayout tracks payouts that have been initiated but not yet confirmed
type PendingPayout struct {
	Address     string    `json:"address"`
	Amount      uint64    `json:"amount"`
	InitiatedAt time.Time `json:"initiated_at"`
}

func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Create buckets
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketShares, bucketBlocks, bucketBalances, bucketPayouts, bucketMeta, bucketSeenShares, bucketPendingPayouts} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create buckets: %w", err)
	}

	store := &Store{db: db}

	// Initialize batch writer with sensible defaults
	ctx := context.Background()
	store.batchWriter = NewBatchWriter(store, 100, 2*time.Second)
	store.batchWriter.Start(ctx)

	return store, nil
}

func (s *Store) Close() error {
	if s.batchWriter != nil {
		s.batchWriter.Stop()
	}
	return s.db.Close()
}

// ============================================================================
// Batch Writer Implementation
// ============================================================================

func NewBatchWriter(store *Store, maxBufferSize int, flushInterval time.Duration) *BatchWriter {
	return &BatchWriter{
		store:         store,
		shareBuf:      make([]Share, 0, maxBufferSize),
		maxBufferSize: maxBufferSize,
		flushInterval: flushInterval,
		lastFlushTime: time.Now(),
	}
}

func (bw *BatchWriter) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	bw.cancel = cancel
	bw.flushTicker = time.NewTicker(bw.flushInterval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				// Final flush on shutdown
				if err := bw.flushShares(); err != nil {
					log.Printf("[batch] shutdown flush error: %v", err)
				}
				return
			case <-bw.flushTicker.C:
				if err := bw.flushShares(); err != nil {
					log.Printf("[batch] periodic flush error: %v", err)
				}
			}
		}
	}()
}

func (bw *BatchWriter) Stop() {
	if bw.cancel != nil {
		bw.cancel()
	}
	if bw.flushTicker != nil {
		bw.flushTicker.Stop()
	}
}

func (bw *BatchWriter) AddShare(share *Share) error {
	bw.bufMu.Lock()
	defer bw.bufMu.Unlock()

	bw.shareBuf = append(bw.shareBuf, *share)

	// Trigger immediate flush if buffer is full
	if len(bw.shareBuf) >= bw.maxBufferSize {
		bw.bufMu.Unlock()
		err := bw.flushShares()
		bw.bufMu.Lock()
		return err
	}

	return nil
}

func (bw *BatchWriter) flushShares() error {
	bw.bufMu.Lock()
	if len(bw.shareBuf) == 0 {
		bw.bufMu.Unlock()
		return nil
	}

	// Take ownership of current buffer and create new one
	toFlush := bw.shareBuf
	bw.shareBuf = make([]Share, 0, bw.maxBufferSize)
	bw.bufMu.Unlock()

	// Batch write all shares in a single transaction
	err := bw.store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketShares)
		if b == nil {
			return fmt.Errorf("shares bucket not found")
		}

		for i := range toFlush {
			id, _ := b.NextSequence()
			toFlush[i].ID = id

			data, err := json.Marshal(&toFlush[i])
			if err != nil {
				log.Printf("[batch] marshal share %d error: %v", id, err)
				continue
			}

			if err := b.Put(itob(id), data); err != nil {
				log.Printf("[batch] put share %d error: %v", id, err)
				continue
			}
		}
		return nil
	})

	if err == nil {
		bw.metricsMu.Lock()
		bw.totalFlushed += uint64(len(toFlush))
		bw.flushCount++
		bw.lastFlushTime = time.Now()
		bw.metricsMu.Unlock()
	}

	return err
}

func (bw *BatchWriter) GetMetrics() (totalFlushed, flushCount uint64, lastFlush time.Time) {
	bw.metricsMu.RLock()
	defer bw.metricsMu.RUnlock()
	return bw.totalFlushed, bw.flushCount, bw.lastFlushTime
}

// ============================================================================
// Shares
// ============================================================================

func (s *Store) AddShare(share *Share) error {
	// Use batch writer for non-blocking buffered writes
	return s.batchWriter.AddShare(share)
}

// AddShareImmediate writes a share directly without buffering (for critical shares like block finds)
func (s *Store) AddShareImmediate(share *Share) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketShares)
		id, _ := b.NextSequence()
		share.ID = id
		data, err := json.Marshal(share)
		if err != nil {
			return err
		}
		return b.Put(itob(id), data)
	})
}

// GetRecentShares returns the last N shares.
func (s *Store) GetRecentShares(limit int) ([]Share, error) {
	var shares []Share
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketShares)
		c := b.Cursor()
		count := 0
		for k, v := c.Last(); k != nil && count < limit; k, v = c.Prev() {
			var sh Share
			if err := json.Unmarshal(v, &sh); err != nil {
				continue
			}
			shares = append(shares, sh)
			count++
		}
		return nil
	})
	return shares, err
}

// GetSharesForMiner returns shares for a specific address, most recent first.
func (s *Store) GetSharesForMiner(address string, limit int) ([]Share, error) {
	var shares []Share
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketShares)
		c := b.Cursor()
		count := 0
		for k, v := c.Last(); k != nil && count < limit; k, v = c.Prev() {
			var sh Share
			if err := json.Unmarshal(v, &sh); err != nil {
				continue
			}
			if sh.Miner == address {
				shares = append(shares, sh)
				count++
			}
		}
		return nil
	})
	return shares, err
}

// GetSharesSince returns all shares after a given timestamp.
func (s *Store) GetSharesSince(since time.Time) ([]Share, error) {
	var shares []Share
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketShares)
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var sh Share
			if err := json.Unmarshal(v, &sh); err != nil {
				continue
			}
			if sh.Timestamp.Before(since) {
				break
			}
			shares = append(shares, sh)
		}
		return nil
	})
	return shares, err
}

// GetLastNShares returns the most recent N shares (for PPLNS).
func (s *Store) GetLastNShares(n int) ([]Share, error) {
	return s.GetRecentShares(n)
}

// GetTotalShareCount returns the total number of shares.
func (s *Store) GetTotalShareCount() (uint64, error) {
	var count uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketShares)
		count = uint64(b.Stats().KeyN)
		return nil
	})
	return count, err
}

// ============================================================================
// Blocks
// ============================================================================

func (s *Store) AddBlock(block *PoolBlock) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		data, err := json.Marshal(block)
		if err != nil {
			return err
		}
		return b.Put(itob(block.Height), data)
	})
}

func (s *Store) GetBlock(height uint64) (*PoolBlock, error) {
	var block PoolBlock
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		data := b.Get(itob(height))
		if data == nil {
			return fmt.Errorf("block %d not found", height)
		}
		return json.Unmarshal(data, &block)
	})
	if err != nil {
		return nil, err
	}
	return &block, nil
}

func (s *Store) UpdateBlock(block *PoolBlock) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		data, err := json.Marshal(block)
		if err != nil {
			return err
		}
		return b.Put(itob(block.Height), data)
	})
}

// GetRecentBlocks returns the most recent blocks found by the pool.
func (s *Store) GetRecentBlocks(limit int) ([]PoolBlock, error) {
	var blocks []PoolBlock
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		c := b.Cursor()
		count := 0
		for k, v := c.Last(); k != nil && count < limit; k, v = c.Prev() {
			var pb PoolBlock
			if err := json.Unmarshal(v, &pb); err != nil {
				continue
			}
			blocks = append(blocks, pb)
			count++
		}
		return nil
	})
	return blocks, err
}

// GetUnconfirmedBlocks returns blocks that are not yet confirmed and not orphaned.
func (s *Store) GetUnconfirmedBlocks() ([]PoolBlock, error) {
	var blocks []PoolBlock
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var pb PoolBlock
			if err := json.Unmarshal(v, &pb); err != nil {
				continue
			}
			if !pb.Confirmed && !pb.Orphaned {
				blocks = append(blocks, pb)
			}
		}
		return nil
	})
	return blocks, err
}

// GetUnpaidBlocks returns confirmed, non-orphaned blocks that haven't been paid out yet.
func (s *Store) GetUnpaidBlocks() ([]PoolBlock, error) {
	var blocks []PoolBlock
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var pb PoolBlock
			if err := json.Unmarshal(v, &pb); err != nil {
				continue
			}
			if pb.Confirmed && !pb.Orphaned && !pb.PaidOut {
				blocks = append(blocks, pb)
			}
		}
		return nil
	})
	return blocks, err
}

// GetBlockCount returns total blocks found.
func (s *Store) GetBlockCount() (int, error) {
	var count int
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		count = b.Stats().KeyN
		return nil
	})
	return count, err
}

// ============================================================================
// Balances
// ============================================================================

func (s *Store) GetBalance(address string) (*Balance, error) {
	var bal Balance
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBalances)
		data := b.Get([]byte(address))
		if data == nil {
			bal = Balance{Address: address}
			return nil
		}
		return json.Unmarshal(data, &bal)
	})
	return &bal, err
}

func (s *Store) UpdateBalance(bal *Balance) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBalances)
		data, err := json.Marshal(bal)
		if err != nil {
			return err
		}
		return b.Put([]byte(bal.Address), data)
	})
}

func (s *Store) CreditBalance(address string, amount uint64) error {
	if amount == 0 {
		return nil
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBalances)
		var bal Balance
		data := b.Get([]byte(address))
		if data != nil {
			if err := json.Unmarshal(data, &bal); err != nil {
				return err
			}
		}

		bal.Address = address

		// Overflow check
		if amount > math.MaxUint64-bal.Pending {
			return fmt.Errorf("balance overflow: current=%d, credit=%d", bal.Pending, amount)
		}

		bal.Pending += amount
		out, err := json.Marshal(&bal)
		if err != nil {
			return err
		}
		return b.Put([]byte(address), out)
	})
}

func (s *Store) DebitBalance(address string, amount uint64) error {
	if amount == 0 {
		return nil
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBalances)
		var bal Balance
		data := b.Get([]byte(address))
		if data != nil {
			if err := json.Unmarshal(data, &bal); err != nil {
				return err
			}
		}

		// Underflow check
		if bal.Pending < amount {
			return fmt.Errorf("insufficient balance: have=%d, need=%d", bal.Pending, amount)
		}

		bal.Address = address
		bal.Pending -= amount

		// Overflow check on paid amount
		if amount > math.MaxUint64-bal.Paid {
			return fmt.Errorf("paid balance overflow: current=%d, credit=%d", bal.Paid, amount)
		}

		bal.Paid += amount
		out, err := json.Marshal(&bal)
		if err != nil {
			return err
		}
		return b.Put([]byte(address), out)
	})
}

// GetAllBalances returns all miner balances.
func (s *Store) GetAllBalances() ([]Balance, error) {
	var balances []Balance
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBalances)
		return b.ForEach(func(k, v []byte) error {
			var bal Balance
			if err := json.Unmarshal(v, &bal); err != nil {
				return nil
			}
			balances = append(balances, bal)
			return nil
		})
	})
	return balances, err
}

// ============================================================================
// Payouts
// ============================================================================

func (s *Store) AddPayout(payout *Payout) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPayouts)
		id, _ := b.NextSequence()
		payout.ID = id
		data, err := json.Marshal(payout)
		if err != nil {
			return err
		}
		return b.Put(itob(id), data)
	})
}

func (s *Store) GetRecentPayouts(limit int) ([]Payout, error) {
	var payouts []Payout
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPayouts)
		c := b.Cursor()
		count := 0
		for k, v := c.Last(); k != nil && count < limit; k, v = c.Prev() {
			var p Payout
			if err := json.Unmarshal(v, &p); err != nil {
				continue
			}
			payouts = append(payouts, p)
			count++
		}
		return nil
	})
	return payouts, err
}

// ============================================================================
// Meta (pool stats, etc.)
// ============================================================================

func (s *Store) SetMeta(key string, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		return b.Put([]byte(key), value)
	})
}

func (s *Store) GetMeta(key string) ([]byte, error) {
	var val []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		data := b.Get([]byte(key))
		if data != nil {
			val = make([]byte, len(data))
			copy(val, data)
		}
		return nil
	})
	return val, err
}

// ============================================================================
// Persistent Share Deduplication (24-hour window)
// ============================================================================

const shareSeenExpiry = 24 * time.Hour

// MarkShareSeen records a share as seen with expiry timestamp
// Key format: "jobID:nonce" -> timestamp
func (s *Store) MarkShareSeen(jobID string, nonce uint64) error {
	key := fmt.Sprintf("%s:%d", jobID, nonce)
	expiry := time.Now().Add(shareSeenExpiry).Unix()

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSeenShares)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(expiry))
		return b.Put([]byte(key), buf[:])
	})
}

// IsShareSeen checks if a share has been seen (within 24h window)
func (s *Store) IsShareSeen(jobID string, nonce uint64) (bool, error) {
	key := fmt.Sprintf("%s:%d", jobID, nonce)

	var seen bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSeenShares)
		data := b.Get([]byte(key))
		if data == nil {
			return nil
		}

		if len(data) != 8 {
			return nil
		}

		expiry := int64(binary.BigEndian.Uint64(data))
		if time.Now().Unix() < expiry {
			seen = true
		}
		return nil
	})

	return seen, err
}

// CleanExpiredSeenShares removes expired entries from the seen shares bucket
// Should be called periodically (e.g., daily)
func (s *Store) CleanExpiredSeenShares() error {
	now := time.Now().Unix()

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSeenShares)
		c := b.Cursor()

		var toDelete [][]byte
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(v) != 8 {
				toDelete = append(toDelete, append([]byte(nil), k...))
				continue
			}

			expiry := int64(binary.BigEndian.Uint64(v))
			if now >= expiry {
				toDelete = append(toDelete, append([]byte(nil), k...))
			}
		}

		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				log.Printf("[storage] failed to delete expired seen share: %v", err)
			}
		}

		if len(toDelete) > 0 {
			log.Printf("[storage] cleaned %d expired seen shares", len(toDelete))
		}

		return nil
	})
}

// ============================================================================
// Atomic Payout Operations
// ============================================================================

// CreatePendingPayout marks a payout as pending before wallet send
func (s *Store) CreatePendingPayout(address string, amount uint64) error {
	pending := PendingPayout{
		Address:     address,
		Amount:      amount,
		InitiatedAt: time.Now(),
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPendingPayouts)
		data, err := json.Marshal(&pending)
		if err != nil {
			return err
		}
		return b.Put([]byte(address), data)
	})
}

// CompletePendingPayout finalizes a pending payout after successful wallet send
// This deducts the balance and removes the pending entry atomically
func (s *Store) CompletePendingPayout(address string, amount uint64, txHash string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		// Debit balance
		balBucket := tx.Bucket(bucketBalances)
		var bal Balance
		data := balBucket.Get([]byte(address))
		if data != nil {
			if err := json.Unmarshal(data, &bal); err != nil {
				return fmt.Errorf("unmarshal balance: %w", err)
			}
		}

		if bal.Pending < amount {
			return fmt.Errorf("insufficient balance: have=%d, need=%d", bal.Pending, amount)
		}

		bal.Address = address
		bal.Pending -= amount

		if amount > math.MaxUint64-bal.Paid {
			return fmt.Errorf("paid balance overflow: current=%d, credit=%d", bal.Paid, amount)
		}

		bal.Paid += amount
		balData, err := json.Marshal(&bal)
		if err != nil {
			return fmt.Errorf("marshal balance: %w", err)
		}
		if err := balBucket.Put([]byte(address), balData); err != nil {
			return fmt.Errorf("put balance: %w", err)
		}

		// Record payout
		payoutBucket := tx.Bucket(bucketPayouts)
		id, _ := payoutBucket.NextSequence()
		payout := Payout{
			ID:        id,
			Address:   address,
			Amount:    amount,
			TxHash:    txHash,
			Timestamp: time.Now(),
		}
		payoutData, err := json.Marshal(&payout)
		if err != nil {
			return fmt.Errorf("marshal payout: %w", err)
		}
		if err := payoutBucket.Put(itob(id), payoutData); err != nil {
			return fmt.Errorf("put payout: %w", err)
		}

		// Remove pending entry
		pendingBucket := tx.Bucket(bucketPendingPayouts)
		if err := pendingBucket.Delete([]byte(address)); err != nil {
			return fmt.Errorf("delete pending: %w", err)
		}

		return nil
	})
}

// CancelPendingPayout removes a pending payout entry without completing it
func (s *Store) CancelPendingPayout(address string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPendingPayouts)
		return b.Delete([]byte(address))
	})
}

// GetPendingPayouts returns all pending payouts (for crash recovery)
func (s *Store) GetPendingPayouts() ([]PendingPayout, error) {
	var pending []PendingPayout
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPendingPayouts)
		return b.ForEach(func(k, v []byte) error {
			var p PendingPayout
			if err := json.Unmarshal(v, &p); err != nil {
				return nil
			}
			pending = append(pending, p)
			return nil
		})
	})
	return pending, err
}

// GetPendingPayout returns the pending payout for an address, or nil if none exists.
func (s *Store) GetPendingPayout(address string) (*PendingPayout, error) {
	var pending *PendingPayout
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPendingPayouts)
		data := b.Get([]byte(address))
		if data == nil {
			return nil
		}
		var p PendingPayout
		if err := json.Unmarshal(data, &p); err != nil {
			return err
		}
		pending = &p
		return nil
	})
	return pending, err
}

// ============================================================================
// Helpers
// ============================================================================

func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
