package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type ProxyConfig struct {
	ListenAddr       string   `json:"listen_addr"`
	C2Addr           string   `json:"c2_addr"`
	PeerProxies      []string `json:"peer_proxies"`
	DashboardPort    string   `json:"dashboard_port"`
	AdminUsername    string   `json:"admin_username"`
	AdminPassword    string   `json:"admin_password"`
	CertFile         string   `json:"cert_file"`
	KeyFile          string   `json:"key_file"`
	CACertFile       string   `json:"ca_cert_file"`
	StatsInterval    int      `json:"stats_interval"`
	PeerSyncInterval int      `json:"peer_sync_interval"`
}

type TrafficStats struct {
	TotalBytesIn      uint64 `json:"total_bytes_in"`
	TotalBytesOut     uint64 `json:"total_bytes_out"`
	ActiveConnections int    `json:"active_connections"`
	PeersConnected    int    `json:"peers_connected"`
}

type ProxyServer struct {
	config    *ProxyConfig
	stats     *TrafficStats
	statsLock sync.Mutex
	peers     map[string]*PeerConnection
	peersLock sync.Mutex
	upgrader  websocket.Upgrader
	tlsConfig *tls.Config
}

type PeerConnection struct {
	conn       *websocket.Conn
	lastActive time.Time
}

func main() {
	configFile, err := os.Open("LoadBal.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	defer configFile.Close()

	var config ProxyConfig
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	caCert, err := os.ReadFile(config.CACertFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse CA certificate")
	}

	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load key pair: %v", err)
	}

	proxy := &ProxyServer{
		config: &config,
		stats:  &TrafficStats{},
		peers:  make(map[string]*PeerConnection),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS13,
		},
	}

	go proxy.syncWithPeers()
	go proxy.startProxyServer()
	proxy.startDashboard()
}

func (p *ProxyServer) startProxyServer() {
	listener, err := tls.Listen("tcp", p.config.ListenAddr, p.tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
	defer listener.Close()

	log.Printf("Proxy server listening on %s", p.config.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go p.handleConnection(conn)
	}
}

func (p *ProxyServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	p.statsLock.Lock()
	p.stats.ActiveConnections++
	p.statsLock.Unlock()

	defer func() {
		p.statsLock.Lock()
		p.stats.ActiveConnections--
		p.statsLock.Unlock()
	}()

	c2Conn, err := tls.Dial("tcp", p.config.C2Addr, p.tlsConfig)
	if err != nil {
		log.Printf("Failed to connect to C2: %v", err)
		return
	}
	defer c2Conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(c2Conn, clientConn)
		if err != nil && err != io.EOF {
			log.Printf("Client->C2 copy error: %v", err)
		}
		p.statsLock.Lock()
		p.stats.TotalBytesIn += uint64(n)
		p.statsLock.Unlock()
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, c2Conn)
		if err != nil && err != io.EOF {
			log.Printf("C2->Client copy error: %v", err)
		}
		p.statsLock.Lock()
		p.stats.TotalBytesOut += uint64(n)
		p.statsLock.Unlock()
	}()

	wg.Wait()
}

func (p *ProxyServer) syncWithPeers() {
	ticker := time.NewTicker(time.Duration(p.config.PeerSyncInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var wg sync.WaitGroup
		connectedPeers := 0

		for _, peerAddr := range p.config.PeerProxies {
			if peerAddr == p.config.ListenAddr {
				continue
			}

			wg.Add(1)
			go func(addr string) {
				defer wg.Done()
				conn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("wss://%s/peer", addr), nil)
				if err != nil {
					log.Printf("Failed to connect to peer %s: %v", addr, err)
					return
				}
				defer conn.Close()

				p.peersLock.Lock()
				p.peers[addr] = &PeerConnection{conn: conn, lastActive: time.Now()}
				p.peersLock.Unlock()

				connectedPeers++

				for {
					var stats TrafficStats
					if err := conn.ReadJSON(&stats); err != nil {
						log.Printf("Error reading from peer %s: %v", addr, err)
						break
					}
				}
			}(peerAddr)
		}

		wg.Wait()

		p.statsLock.Lock()
		p.stats.PeersConnected = connectedPeers
		p.statsLock.Unlock()
	}
}

func (p *ProxyServer) startDashboard() {
	http.HandleFunc("/", p.handleDashboard)
	http.HandleFunc("/stats", p.handleStats)
	http.HandleFunc("/peer", p.handlePeerConnection)
	http.HandleFunc("/api/stats", p.handleAPIStats)
	http.HandleFunc("/api/auth", p.handleAuth)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("views/static/"))))

	log.Printf("Dashboard listening on port %s", p.config.DashboardPort)
	if err := http.ListenAndServeTLS(":"+p.config.DashboardPort, p.config.CertFile, p.config.KeyFile, nil); err != nil {
		log.Fatalf("Failed to start dashboard: %v", err)
	}
}

func (p *ProxyServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == p.config.AdminUsername && password == p.config.AdminPassword {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  p.config,
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid credentials",
		})
	}
}

func (p *ProxyServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	http.ServeFile(w, r, filepath.Join("views", "dashboard.html"))
}

func (p *ProxyServer) handleStats(w http.ResponseWriter, r *http.Request) {
	conn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(time.Duration(p.config.StatsInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.statsLock.Lock()
		stats := *p.stats
		p.statsLock.Unlock()

		if err := conn.WriteJSON(stats); err != nil {
			log.Printf("Error sending stats: %v", err)
			return
		}
	}
}

func (p *ProxyServer) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	p.statsLock.Lock()
	stats := *p.stats
	p.statsLock.Unlock()
	json.NewEncoder(w).Encode(stats)
}

func (p *ProxyServer) handlePeerConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade peer connection: %v", err)
		return
	}
	defer conn.Close()

	peerAddr := r.RemoteAddr
	log.Printf("Peer connected from %s", peerAddr)

	p.peersLock.Lock()
	p.peers[peerAddr] = &PeerConnection{conn: conn, lastActive: time.Now()}
	p.peersLock.Unlock()

	defer func() {
		p.peersLock.Lock()
		delete(p.peers, peerAddr)
		p.peersLock.Unlock()
	}()

	p.statsLock.Lock()
	if err := conn.WriteJSON(p.stats); err != nil {
		log.Printf("Error sending initial stats to peer: %v", err)
		p.statsLock.Unlock()
		return
	}
	p.statsLock.Unlock()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Error sending ping to peer %s: %v", peerAddr, err)
				return
			}
		default:
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			_, _, err := conn.ReadMessage()
			if err != nil {
				if !websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("Peer %s disconnected: %v", peerAddr, err)
				}
				return
			}
		}
	}
}
