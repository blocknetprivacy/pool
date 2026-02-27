package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NodeClient communicates with the blocknet daemon HTTP API.
type NodeClient struct {
	baseURL string
	token   string
	client  *http.Client

	mu          sync.RWMutex
	chainHeight uint64
	syncing     bool

	// SSE reconnection management
	sseReconnectAttempts int
	sseLastReconnect     time.Time
}

// BlockTemplate is the response from GET /api/mining/blocktemplate.
type BlockTemplate struct {
	Block             json.RawMessage `json:"block"`
	Target            string          `json:"target"`
	HeaderBase        string          `json:"header_base"`
	RewardAddressUsed string          `json:"reward_address_used"`
}

// NodeStatus is the response from GET /api/status.
type NodeStatus struct {
	PeerID       string `json:"peer_id"`
	Peers        int    `json:"peers"`
	ChainHeight  uint64 `json:"chain_height"`
	BestHash     string `json:"best_hash"`
	TotalWork    uint64 `json:"total_work"`
	MempoolSize  int    `json:"mempool_size"`
	MempoolBytes int    `json:"mempool_bytes"`
	Syncing      bool   `json:"syncing"`
	IdentityAge  string `json:"identity_age"`
}

// NodeBlock is the response from GET /api/block/{id}.
type NodeBlock struct {
	Height     uint64 `json:"height"`
	Hash       string `json:"hash"`
	Reward     uint64 `json:"reward"`
	Difficulty uint64 `json:"difficulty"`
	TxCount    int    `json:"tx_count"`
}

// SubmitBlockResponse is the response from POST /api/mining/submitblock.
type SubmitBlockResponse struct {
	Accepted bool   `json:"accepted"`
	Hash     string `json:"hash"`
	Height   uint64 `json:"height"`
}

// WalletSendRequest is the body for POST /api/wallet/send.
type WalletSendRequest struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"`
}

// WalletSendResponse is the response from POST /api/wallet/send.
type WalletSendResponse struct {
	TxID   string `json:"txid"`
	Fee    uint64 `json:"fee"`
	Change uint64 `json:"change"`
}

type WalletLoadResponse struct {
	Loaded  bool   `json:"loaded"`
	Address string `json:"address"`
}

type WalletUnlockResponse struct {
	Locked bool `json:"locked"`
}

type WalletAddressResponse struct {
	Address  string `json:"address"`
	ViewOnly bool   `json:"view_only"`
}

// WalletBalance is the response from GET /api/wallet/balance.
type WalletBalance struct {
	Spendable uint64 `json:"spendable"`
	Pending   uint64 `json:"pending"`
	Total     uint64 `json:"total"`
}

// SSEEvent represents a parsed server-sent event.
type SSEEvent struct {
	Event string
	Data  string
}

// HTTPError represents a non-200 daemon API response.
type HTTPError struct {
	Path       string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %d: %s", e.Path, e.StatusCode, e.Body)
}

// IsHTTPStatus reports whether err (possibly wrapped) is an HTTPError with the given status.
func IsHTTPStatus(err error, status int) bool {
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	return httpErr.StatusCode == status
}

func NewNodeClient(baseURL, token string) *NodeClient {
	return &NodeClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (n *NodeClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, n.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	req.Header.Set("Content-Type", "application/json")
	return n.client.Do(req)
}

func (n *NodeClient) doRequestWithHeaders(method, path string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, n.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		if k == "" || v == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	return n.client.Do(req)
}

func (n *NodeClient) doGet(path string, out any) error {
	resp, err := n.doRequest("GET", path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &HTTPError{Path: path, StatusCode: resp.StatusCode, Body: string(body)}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (n *NodeClient) doPost(path string, reqBody, out any) error {
	return n.doPostWithHeaders(path, reqBody, out, nil)
}

func (n *NodeClient) doPostWithHeaders(path string, reqBody, out any, headers map[string]string) error {
	data, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := n.doRequestWithHeaders("POST", path, bytes.NewReader(data), headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{Path: path, StatusCode: resp.StatusCode, Body: string(body)}
	}
	return json.Unmarshal(body, out)
}

// GetStatus fetches the node status and caches key fields.
func (n *NodeClient) GetStatus() (*NodeStatus, error) {
	var status NodeStatus
	if err := n.doGet("/api/status", &status); err != nil {
		return nil, fmt.Errorf("node status: %w", err)
	}

	n.mu.Lock()
	n.chainHeight = status.ChainHeight
	n.syncing = status.Syncing
	n.mu.Unlock()

	return &status, nil
}

// GetBlockTemplate fetches a fresh block template for mining.
// If rewardAddress is set, it is passed to the daemon so coinbase pays that address.
func (n *NodeClient) GetBlockTemplate(rewardAddress string) (*BlockTemplate, error) {
	var tmpl BlockTemplate
	path := "/api/mining/blocktemplate"
	if rewardAddress != "" {
		path = fmt.Sprintf("%s?address=%s", path, url.QueryEscape(rewardAddress))
	}
	if err := n.doGet(path, &tmpl); err != nil {
		return nil, fmt.Errorf("blocktemplate: %w", err)
	}
	return &tmpl, nil
}

// GetBlock fetches a block by height or hash from the node.
func (n *NodeClient) GetBlock(id string) (*NodeBlock, error) {
	var block NodeBlock
	if err := n.doGet("/api/block/"+id, &block); err != nil {
		return nil, err
	}
	return &block, nil
}

// SubmitBlock submits a solved block to the node.
func (n *NodeClient) SubmitBlock(blockJSON json.RawMessage) (*SubmitBlockResponse, error) {
	resp, err := n.doRequest("POST", "/api/mining/submitblock", bytes.NewReader(blockJSON))
	if err != nil {
		return nil, fmt.Errorf("submitblock: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{Path: "/api/mining/submitblock", StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result SubmitBlockResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode submitblock: %w", err)
	}
	return &result, nil
}

// WalletSend sends BNT to an address via POST /api/wallet/send.
func (n *NodeClient) WalletSend(address string, amount uint64, idempotencyKey string) (*WalletSendResponse, error) {
	var result WalletSendResponse
	headers := map[string]string{}
	if idempotencyKey != "" {
		headers["Idempotency-Key"] = idempotencyKey
	}
	err := n.doPostWithHeaders("/api/wallet/send", &WalletSendRequest{
		Address: address,
		Amount:  amount,
	}, &result, headers)
	if err != nil {
		return nil, fmt.Errorf("wallet send: %w", err)
	}
	return &result, nil
}

// WalletLoad loads (or creates) a wallet in daemon mode.
func (n *NodeClient) WalletLoad(password string) (*WalletLoadResponse, error) {
	var result WalletLoadResponse
	err := n.doPost("/api/wallet/load", map[string]string{
		"password": password,
	}, &result)
	if err != nil {
		return nil, fmt.Errorf("wallet load: %w", err)
	}
	return &result, nil
}

// WalletUnlock unlocks the currently loaded wallet.
func (n *NodeClient) WalletUnlock(password string) (*WalletUnlockResponse, error) {
	var result WalletUnlockResponse
	err := n.doPost("/api/wallet/unlock", map[string]string{
		"password": password,
	}, &result)
	if err != nil {
		return nil, fmt.Errorf("wallet unlock: %w", err)
	}
	return &result, nil
}

// GetWalletAddress fetches the currently loaded wallet address.
func (n *NodeClient) GetWalletAddress() (*WalletAddressResponse, error) {
	var addr WalletAddressResponse
	if err := n.doGet("/api/wallet/address", &addr); err != nil {
		return nil, fmt.Errorf("wallet address: %w", err)
	}
	return &addr, nil
}

// GetWalletBalance fetches the wallet balance.
func (n *NodeClient) GetWalletBalance() (*WalletBalance, error) {
	var bal WalletBalance
	if err := n.doGet("/api/wallet/balance", &bal); err != nil {
		return nil, fmt.Errorf("wallet balance: %w", err)
	}
	return &bal, nil
}

// SubscribeBlocks opens an SSE connection to /api/events and sends events to the channel.
// Reconnects on failure with exponential backoff. Runs until ctx is cancelled.
func (n *NodeClient) SubscribeBlocks(ctx context.Context, ch chan<- SSEEvent) {
	const (
		maxReconnectAttempts = 10
		baseBackoff          = 5 * time.Second
		maxBackoff           = 5 * time.Minute
	)

	for {
		if ctx.Err() != nil {
			return
		}

		// Calculate backoff with exponential increase
		var backoff time.Duration
		if n.sseReconnectAttempts == 0 {
			backoff = 0 // first attempt is immediate
		} else if n.sseReconnectAttempts >= maxReconnectAttempts {
			log.Printf("[node] SSE max reconnection attempts reached, waiting %v", maxBackoff)
			backoff = maxBackoff
		} else {
			// Exponential backoff: 5s, 10s, 20s, 40s, 80s, ...
			backoff = baseBackoff * time.Duration(1<<uint(n.sseReconnectAttempts-1))
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}

		if backoff > 0 {
			log.Printf("[node] SSE reconnecting in %v (attempt %d)", backoff, n.sseReconnectAttempts+1)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}

		n.sseReconnectAttempts++
		n.sseLastReconnect = time.Now()

		if err := n.streamSSE(ctx, ch); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[node] SSE connection lost: %v", err)
		}
	}
}

func (n *NodeClient) streamSSE(ctx context.Context, ch chan<- SSEEvent) error {
	req, err := http.NewRequestWithContext(ctx, "GET", n.baseURL+"/api/events", nil)
	if err != nil {
		return err
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	req.Header.Set("Accept", "text/event-stream")

	sseClient := &http.Client{}
	resp, err := sseClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &HTTPError{Path: "/api/events", StatusCode: resp.StatusCode, Body: string(body)}
	}

	// Reset reconnect counter on successful connection
	n.sseReconnectAttempts = 0

	scanner := bufio.NewScanner(resp.Body)
	var event SSEEvent

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event.Event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			event.Data = strings.TrimPrefix(line, "data: ")
		case line == "":
			if event.Event != "" {
				select {
				case ch <- event:
				case <-ctx.Done():
					return ctx.Err()
				}
				event = SSEEvent{}
			}
		}
	}

	return scanner.Err()
}

// ChainHeight returns the last known chain height.
func (n *NodeClient) ChainHeight() uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.chainHeight
}

// Syncing returns whether the node is syncing.
func (n *NodeClient) Syncing() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.syncing
}
