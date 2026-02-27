package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WebServer serves the pool frontend and JSON API.
type WebServer struct {
	config  *Config
	store   *Store
	stats   *PoolStats
	node    *NodeClient
	stratum *StratumServer
	jobs    *JobManager

	templates *template.Template
	mux       *http.ServeMux
}

func NewWebServer(config *Config, store *Store, stats *PoolStats, node *NodeClient, stratum *StratumServer, jobs *JobManager) *WebServer {
	ws := &WebServer{
		config:  config,
		store:   store,
		stats:   stats,
		node:    node,
		stratum: stratum,
		jobs:    jobs,
		mux:     http.NewServeMux(),
	}

	ws.loadTemplates()
	ws.setupRoutes()
	return ws
}

func (ws *WebServer) loadTemplates() {
	pattern := filepath.Join(ws.config.TemplatePath, "*.html")
	tmpl, err := template.New("").Funcs(ws.templateFuncMap()).ParseGlob(pattern)
	if err != nil {
		log.Printf("[web] failed to parse templates: %v (will use embedded fallback)", err)
		tmpl = template.Must(template.New("").Funcs(ws.templateFuncMap()).Parse(""))
	}
	ws.templates = tmpl
}

func (ws *WebServer) templateFuncMap() template.FuncMap {
	return template.FuncMap{
		"formatHashrate": formatHashrate,
		"formatDuration": formatDuration,
		"formatCoins":    formatCoins,
		"timeAgo":        timeAgo,
		"truncHash":      truncHash,
	}
}

func (ws *WebServer) newPageData(path, title, description string) map[string]any {
	baseURL := strings.TrimRight(ws.config.PoolURL, "/")
	stratumHost := ws.stratumHost()
	metaURL := baseURL
	if path != "" && path != "/" {
		metaURL = baseURL + path
	}
	metaImage := baseURL + "/static/og.png"
	if title == "" {
		title = fmt.Sprintf("%s | Blocknet Mining Pool", ws.config.PoolName)
	}
	if description == "" {
		description = fmt.Sprintf("%s — Blocknet mining pool with live stats, block history, and payout tracking.", ws.config.PoolName)
	}

	return map[string]any{
		"PoolName":         ws.config.PoolName,
		"PoolURL":          ws.config.PoolURL,
		"StratumHost":      stratumHost,
		"StratumEndpoint":  fmt.Sprintf("%s:%d", stratumHost, ws.config.StratumPort),
		"CurrentPage":      "pool",
		"MetaTitle":        title,
		"MetaDescription":  description,
		"MetaURL":          metaURL,
		"MetaImage":        metaImage,
		"MetaImageAlt":     fmt.Sprintf("%s preview banner", ws.config.PoolName),
		"MetaSiteName":     ws.config.PoolName,
	}
}

func (ws *WebServer) stratumHost() string {
	raw := strings.TrimSpace(ws.config.PoolURL)
	if raw == "" {
		return "localhost"
	}

	u, err := url.Parse(raw)
	if err == nil && u.Host != "" {
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	// Handle values without explicit scheme, like "bntpool.com".
	u2, err := url.Parse("//" + raw)
	if err == nil && u2.Host != "" {
		if h := u2.Hostname(); h != "" {
			return h
		}
	}
	return strings.Trim(raw, "/")
}

// validAddress matches base58 blocknet addresses (alphanumeric, no 0OIl).
var validAddress = regexp.MustCompile(`^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{1,128}$`)

func (ws *WebServer) setupRoutes() {
	rl := newRateLimiter(30, time.Minute) // 30 requests per IP per minute for API

	// Pages (server-rendered HTML)
	ws.mux.HandleFunc("GET /", ws.handleIndex)
	ws.mux.HandleFunc("GET /miners/{address}", ws.handleMiner)
	ws.mux.HandleFunc("GET /blocks", ws.handleBlocks)
	ws.mux.HandleFunc("GET /payouts", ws.handlePayouts)

	// JSON API (rate-limited + optionally authenticated)
	ws.mux.Handle("GET /api/pool/stats", rl.wrap(ws.requireAuth(http.HandlerFunc(ws.handleAPIStats))))
	ws.mux.Handle("GET /api/pool/miners", rl.wrap(ws.requireAuth(http.HandlerFunc(ws.handleAPIMiners))))
	ws.mux.Handle("GET /api/pool/blocks", rl.wrap(ws.requireAuth(http.HandlerFunc(ws.handleAPIBlocks))))
	ws.mux.Handle("GET /api/pool/payouts", rl.wrap(ws.requireAuth(http.HandlerFunc(ws.handleAPIPayouts))))
	ws.mux.Handle("GET /api/pool/miner/{address}", rl.wrap(ws.requireAuth(http.HandlerFunc(ws.handleAPIMiner))))
	ws.mux.Handle("GET /api/pool/logs", rl.wrap(ws.requireAuth(http.HandlerFunc(ws.handleAPILogs))))

	// Static files
	ws.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir(ws.config.StaticPath))))
}

// requireAuth wraps a handler with API key authentication if configured
func (ws *WebServer) requireAuth(next http.Handler) http.Handler {
	// If no API key is configured, allow all requests
	if ws.config.APIKey == "" {
		return next
	}
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check API key in Authorization header: "Bearer <key>"
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Also check X-API-Key header for convenience
			authHeader = r.Header.Get("X-API-Key")
			if authHeader != "" {
				authHeader = "Bearer " + authHeader
			}
		}
		
		expectedAuth := "Bearer " + ws.config.APIKey
		if authHeader != expectedAuth {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "unauthorized - API key required",
			})
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (ws *WebServer) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", ws.config.APIHost, ws.config.APIPort)
	log.Printf("[web] listening on %s", addr)
	return http.ListenAndServe(addr, ws.mux)
}

// ============================================================================
// Rate limiter (token bucket per IP)
// ============================================================================

type rateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*rlEntry
	max      int
	interval time.Duration
}

type rlEntry struct {
	tokens int
	last   time.Time
}

func newRateLimiter(max int, interval time.Duration) *rateLimiter {
	return &rateLimiter{
		clients:  make(map[string]*rlEntry),
		max:      max,
		interval: interval,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.clients[ip]
	if !ok {
		rl.clients[ip] = &rlEntry{tokens: rl.max - 1, last: time.Now()}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := time.Since(e.last)
	refill := int(elapsed / (rl.interval / time.Duration(rl.max)))
	if refill > 0 {
		e.tokens += refill
		if e.tokens > rl.max {
			e.tokens = rl.max
		}
		e.last = time.Now()
	}

	if e.tokens <= 0 {
		return false
	}
	e.tokens--
	return true
}

func (rl *rateLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !rl.allow(ip) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Page handlers
// ============================================================================

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	blocks, _ := ws.store.GetRecentBlocks(10)
	payouts, _ := ws.store.GetRecentPayouts(8)
	job := ws.jobs.CurrentJob()

	var networkHeight uint64
	var networkDifficulty uint64
	if job != nil {
		networkHeight = job.Height
		networkDifficulty = job.Difficulty
	}

	data := ws.newPageData(
		"/",
		fmt.Sprintf("%s | Blocknet Mining Pool", ws.config.PoolName),
		fmt.Sprintf("Mine Blocknet on %s. Argon2id proof of work, transparent pool stats, block history, and payout tracking.", ws.config.PoolName),
	)
	data["PoolHashrate"] = ws.stats.EstimateHashrate()
	data["ConnectedMiners"] = ws.stats.ConnectedMinerCount()
	data["ConnectedWorkers"] = ws.stats.ConnectedWorkerCount()
	totalAccepted := ws.stats.TotalSharesAccepted.Load()
	totalRejected := ws.stats.TotalSharesRejected.Load()
	data["TotalSharesAccepted"] = totalAccepted
	data["TotalSharesRejected"] = totalRejected
	totalShares := totalAccepted + totalRejected
	data["RejectRate"] = "0.0000%"
	if totalShares > 0 {
		rejectPct := (float64(totalRejected) / float64(totalShares)) * 100
		data["RejectRate"] = fmt.Sprintf("%.4f%%", rejectPct)
	}
	data["TotalBlocksFound"] = ws.stats.TotalBlocksFound.Load()
	data["NetworkHeight"] = networkHeight
	data["NetworkDifficulty"] = networkDifficulty
	data["RecentBlocks"] = blocks
	data["RecentPayouts"] = payouts
	data["PayoutScheme"] = ws.config.PayoutScheme
	data["MinPayout"] = ws.config.MinPayoutAmount
	data["PoolFeeFlat"] = ws.config.PoolFeeFlat
	data["PoolFeePct"] = ws.config.PoolFeePct
	data["StratumPort"] = ws.config.StratumPort
	data["PoolURL"] = ws.config.PoolURL
	data["CurrentPage"] = "pool"
	data["LastShareAgo"] = "n/a"
	lastShareAt := int64(0)
	for _, miner := range ws.stratum.GetMiners() {
		if miner.LastShareAt > lastShareAt {
			lastShareAt = miner.LastShareAt
		}
	}
	if lastShareAt > 0 {
		data["LastShareAgo"] = timeAgo(time.Unix(lastShareAt, 0))
	}

	ws.render(w, "index.html", data)
}

func (ws *WebServer) handleMiner(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" || !validAddress.MatchString(address) {
		http.NotFound(w, r)
		return
	}

	minerStats := ws.stats.GetMinerStats(address)
	balance, _ := ws.store.GetBalance(address)
	shares, _ := ws.store.GetSharesForMiner(address, 50)

	data := ws.newPageData(
		"/miners/"+address,
		fmt.Sprintf("Miner %s | %s", truncHash(address), ws.config.PoolName),
		fmt.Sprintf("Miner stats for %s on %s, including hashrate, shares, and payout balance.", truncHash(address), ws.config.PoolName),
	)
	data["Address"] = address
	data["MinerStats"] = minerStats
	data["Balance"] = balance
	data["RecentShares"] = shares
	data["MinerHashrate"] = ws.stats.EstimateMinerHashrate(address)
	data["CurrentPage"] = "miner"

	ws.render(w, "miner.html", data)
}

func (ws *WebServer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	blocks, _ := ws.store.GetRecentBlocks(100)

	data := ws.newPageData(
		"/blocks",
		fmt.Sprintf("Blocks | %s", ws.config.PoolName),
		fmt.Sprintf("Recent blocks found by %s, including confirmation and payout status.", ws.config.PoolName),
	)
	data["Blocks"] = blocks
	data["CurrentPage"] = "blocks"

	ws.render(w, "blocks.html", data)
}

func (ws *WebServer) handlePayouts(w http.ResponseWriter, r *http.Request) {
	payouts, _ := ws.store.GetRecentPayouts(100)

	data := ws.newPageData(
		"/payouts",
		fmt.Sprintf("Payouts | %s", ws.config.PoolName),
		fmt.Sprintf("Recent payouts from %s with miner address, amount, and transaction hash.", ws.config.PoolName),
	)
	data["Payouts"] = payouts
	data["CurrentPage"] = "payouts"

	ws.render(w, "payouts.html", data)
}

// ============================================================================
// API handlers
// ============================================================================

func (ws *WebServer) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	job := ws.jobs.CurrentJob()

	var networkHeight uint64
	var networkDifficulty uint64
	if job != nil {
		networkHeight = job.Height
		networkDifficulty = job.Difficulty
	}

	blockCount, _ := ws.store.GetBlockCount()

	writeJSON(w, http.StatusOK, map[string]any{
		"pool_hashrate":     ws.stats.EstimateHashrate(),
		"connected_miners":  ws.stats.ConnectedMinerCount(),
		"connected_workers": ws.stats.ConnectedWorkerCount(),
		"shares_accepted":   ws.stats.TotalSharesAccepted.Load(),
		"shares_rejected":   ws.stats.TotalSharesRejected.Load(),
		"blocks_found":      blockCount,
		"network_height":    networkHeight,
		"network_difficulty": networkDifficulty,
		"payout_scheme":     ws.config.PayoutScheme,
		"pool_fee_flat":     ws.config.PoolFeeFlat,
		"pool_fee_pct":      ws.config.PoolFeePct,
	})
}

func (ws *WebServer) handleAPIMiners(w http.ResponseWriter, r *http.Request) {
	miners := ws.stratum.GetMiners()
	writeJSON(w, http.StatusOK, miners)
}

func (ws *WebServer) handleAPIBlocks(w http.ResponseWriter, r *http.Request) {
	blocks, _ := ws.store.GetRecentBlocks(100)
	writeJSON(w, http.StatusOK, blocks)
}

func (ws *WebServer) handleAPIPayouts(w http.ResponseWriter, r *http.Request) {
	payouts, _ := ws.store.GetRecentPayouts(100)
	writeJSON(w, http.StatusOK, payouts)
}

func (ws *WebServer) handleAPIMiner(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" || !validAddress.MatchString(address) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid address"})
		return
	}

	minerStats := ws.stats.GetMinerStats(address)
	balance, _ := ws.store.GetBalance(address)

	writeJSON(w, http.StatusOK, map[string]any{
		"address":   address,
		"stats":     minerStats,
		"balance":   balance,
		"hashrate":  ws.stats.EstimateMinerHashrate(address),
	})
}

func (ws *WebServer) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	lines := 200
	if q := strings.TrimSpace(r.URL.Query().Get("lines")); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 {
			if v > 2000 {
				v = 2000
			}
			lines = v
		}
	}

	logPath := strings.TrimSpace(ws.config.LogPath)
	if logPath == "" {
		logPath = "pool.log"
	}

	text, err := tailFileLines(logPath, lines)
	if err != nil {
		http.Error(w, fmt.Sprintf("read log failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(text))
}

// ============================================================================
// Helpers
// ============================================================================

func (ws *WebServer) render(w http.ResponseWriter, name string, data any) {
	layoutPath := filepath.Join(ws.config.TemplatePath, "layout.html")
	pagePath := filepath.Join(ws.config.TemplatePath, name)
	tmpl, err := template.New("").Funcs(ws.templateFuncMap()).ParseFiles(layoutPath, pagePath)
	if err != nil {
		log.Printf("[web] parse %s: %v", name, err)
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("[web] render %s: %v", name, err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func tailFileLines(path string, maxLines int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	buf := make([]string, 0, maxLines)
	for scanner.Scan() {
		line := scanner.Text()
		if len(buf) < maxLines {
			buf = append(buf, line)
		} else {
			copy(buf, buf[1:])
			buf[len(buf)-1] = line
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return strings.Join(buf, "\n") + "\n", nil
}

// Template helper functions

func formatHashrate(h float64) string {
	if h < 0.001 {
		return "0 H/s"
	}
	if h < 1 {
		return fmt.Sprintf("%.3f H/s", h)
	}
	if h < 1000 {
		return fmt.Sprintf("%.1f H/s", h)
	}
	if h < 1_000_000 {
		return fmt.Sprintf("%.1f KH/s", h/1000)
	}
	return fmt.Sprintf("%.1f MH/s", h/1_000_000)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

func formatCoins(amount uint64) string {
	whole := amount / 100_000_000
	frac := amount % 100_000_000
	if frac == 0 {
		return fmt.Sprintf("%d", whole)
	}
	return fmt.Sprintf("%d.%08d", whole, frac)
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		m := int(d.Minutes())
		if m == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d min ago", m)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	}
	days := int(d.Hours()) / 24
	if days == 1 {
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

func truncHash(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	return hash[:8] + "..." + hash[len(hash)-8:]
}
