package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	// Pool identity
	PoolName string `json:"pool_name"`
	PoolURL  string `json:"pool_url"`

	// Network
	StratumPort int    `json:"stratum_port"`
	APIPort     int    `json:"api_port"`
	APIHost     string `json:"api_host"`

	// Blocknet daemon
	DaemonBinary  string `json:"daemon_binary"`
	DaemonDataDir string `json:"daemon_data_dir"` // node data dir containing api.cookie
	DaemonAPI     string `json:"daemon_api"`
	DaemonToken   string `json:"daemon_token"`
	PoolWalletAddress string `json:"pool_wallet_address"` // deprecated: runtime wallet address is sourced from daemon API

	// Mining
	InitialShareDifficulty uint64 `json:"initial_share_difficulty"`
	BlockPollInterval      string `json:"block_poll_interval"`
	JobTimeout             string `json:"job_timeout"`

	// Pool fee
	PoolFeeFlat float64 `json:"pool_fee_flat"` // flat fee in BNT per block (e.g. 20.0 = 20 BNT)
	PoolFeePct  float64 `json:"pool_fee_pct"`  // percentage fee per block (e.g. 5.0 = 5%)

	// Payouts
	PayoutScheme         string  `json:"payout_scheme"` // "pplns" or "proportional"
	PPLNSWindow          int     `json:"pplns_window"`  // number of shares to look back (deprecated - use PPLNSWindowDuration)
	PPLNSWindowDuration  string  `json:"pplns_window_duration"` // time window for PPLNS (e.g. "24h")
	BlocksBeforePayout   int     `json:"blocks_before_payout"`
	MinPayoutAmount      float64 `json:"min_payout_amount"`
	BlockFinderBonus     bool    `json:"block_finder_bonus"`
	BlockFinderBonusPct  float64 `json:"block_finder_bonus_pct"`
	PayoutInterval       string  `json:"payout_interval"`

	// Storage
	DatabasePath string `json:"database_path"`

	// Frontend
	TemplatePath string `json:"template_path"`
	StaticPath   string `json:"static_path"`
	
	// API Security
	APIKey string `json:"api_key"` // optional API key for protected endpoints (leave empty to disable)

	// Runtime-only fields (not loaded from JSON).
	LogPath string `json:"-"`
}

func DefaultConfig() *Config {
	return &Config{
		PoolName:               "blocknet pool",
		PoolURL:                "http://localhost:8080",
		StratumPort:            3333,
		APIPort:                8080,
		APIHost:                "0.0.0.0",
		DaemonBinary:           "./blocknet",
		DaemonDataDir:          "data",
		DaemonAPI:              "http://127.0.0.1:8332",
		DaemonToken:            "",
		PoolWalletAddress:      "", // deprecated; kept for backward compatibility
		InitialShareDifficulty: 1,
		BlockPollInterval:      "2s",
		JobTimeout:             "5m",
		PoolFeeFlat:            0,
		PoolFeePct:             0,
		PayoutScheme:           "pplns",
		PPLNSWindow:            1000,
		PPLNSWindowDuration:    "24h",
		BlocksBeforePayout:     120,
		MinPayoutAmount:        0.1,
		BlockFinderBonus:       false,
		BlockFinderBonusPct:    5.0,
		PayoutInterval:         "1h",
		DatabasePath:           "pool.db",
		TemplatePath:           "templates",
		StaticPath:             "static",
		APIKey:                 "", // optional - generate with: openssl rand -hex 32
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func (c *Config) BlockPollDuration() time.Duration {
	d, err := time.ParseDuration(c.BlockPollInterval)
	if err != nil {
		return 2 * time.Second
	}
	return d
}

func (c *Config) JobTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(c.JobTimeout)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

func (c *Config) PayoutIntervalDuration() time.Duration {
	d, err := time.ParseDuration(c.PayoutInterval)
	if err != nil {
		return 1 * time.Hour
	}
	return d
}

func (c *Config) PPLNSWindowDur() time.Duration {
	if c.PPLNSWindowDuration == "" {
		// Fallback to old share-count based system if duration not set
		return 0
	}
	d, err := time.ParseDuration(c.PPLNSWindowDuration)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

// PoolFee returns the total pool fee in atomic units for a given block reward.
// Flat fee is applied first, then percentage on the remainder.
func (c *Config) PoolFee(reward uint64) uint64 {
	var fee uint64

	// Flat fee (BNT -> atomic: multiply by 1e8)
	if c.PoolFeeFlat > 0 {
		flat := uint64(c.PoolFeeFlat * 100_000_000)
		if flat > reward {
			return reward
		}
		fee += flat
	}

	// Percentage fee on the remainder
	if c.PoolFeePct > 0 {
		remainder := reward - fee
		pct := uint64(float64(remainder) * c.PoolFeePct / 100.0)
		fee += pct
	}

	if fee > reward {
		return reward
	}
	return fee
}

func GenerateDefaultConfig(path string) error {
	cfg := DefaultConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
