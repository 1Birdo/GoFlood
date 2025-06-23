package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
)

type ProxyConfig struct {
	ListenAddr      string `json:"listen_addr"`
	BackendAddr     string `json:"backend_addr"`
	DashboardPort   string `json:"dashboard_port"`
	AdminUsername   string `json:"admin_username"`
	AdminPassword   string `json:"admin_password"`
	CertFile        string `json:"cert_file"`
	KeyFile         string `json:"key_file"`
	CACertFile      string `json:"ca_cert_file"`
	StatsInterval   int    `json:"stats_interval"`
	MaxConnections  int    `json:"max_connections"`
	MaxBufferSize   int64  `json:"max_buffer_size"`
	JWTSecret       string `json:"jwt_secret"`
	EnableDebugLogs bool   `json:"enable_debug_logs"`
}

type TrafficStats struct {
	TotalBytesIn       uint64 `json:"total_bytes_in"`
	TotalBytesOut      uint64 `json:"total_bytes_out"`
	ActiveConnections  int    `json:"active_connections"`
	HealthyConnections int    `json:"healthy_connections"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type ProxyServer struct {
	config       *ProxyConfig
	stats        *TrafficStats
	statsLock    sync.Mutex
	upgrader     websocket.Upgrader
	tlsConfig    *tls.Config
	loginLimiter *rate.Limiter
	logger       zerolog.Logger
	activeConns  chan struct{}
}

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	config, err := loadConfig("proxy_config.json")
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load config")
	}

	if config.EnableDebugLogs {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if err := validateConfig(config); err != nil {
		logger.Fatal().Err(err).Msg("Invalid configuration")
	}

	caCert, err := os.ReadFile(config.CACertFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to read CA certificate")
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		logger.Fatal().Msg("Failed to parse CA certificate")
	}

	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load key pair")
	}

	if config.MaxConnections == 0 {
		config.MaxConnections = 100
	}
	if config.MaxBufferSize == 0 {
		config.MaxBufferSize = 10 * 1024 * 1024
	}
	if config.JWTSecret == "" {
		config.JWTSecret = generateRandomSecret()
		logger.Warn().Msg("Using auto-generated JWT secret - recommend setting a fixed value in config")
	}

	proxy := &ProxyServer{
		config: config,
		stats:  &TrafficStats{},
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
		loginLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1), // 1 request per 5 seconds
		logger:       logger,
		activeConns:  make(chan struct{}, config.MaxConnections),
	}

	go proxy.startProxyServer()
	proxy.startDashboard()
}

func loadConfig(filename string) (*ProxyConfig, error) {
	configFile, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer configFile.Close()

	var config ProxyConfig
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &config, nil
}

func validateConfig(config *ProxyConfig) error {
	if config.ListenAddr == "" {
		return fmt.Errorf("listen address must be configured")
	}
	if config.BackendAddr == "" {
		return fmt.Errorf("backend address must be configured")
	}
	if config.CertFile == "" || config.KeyFile == "" {
		return fmt.Errorf("TLS certificate and key files must be specified")
	}
	if _, err := os.Stat(config.CertFile); os.IsNotExist(err) {
		return fmt.Errorf("certificate file does not exist")
	}
	if _, err := os.Stat(config.KeyFile); os.IsNotExist(err) {
		return fmt.Errorf("key file does not exist")
	}
	if config.AdminUsername == "" || config.AdminPassword == "" {
		return fmt.Errorf("admin credentials must be configured")
	}
	if config.StatsInterval <= 0 {
		config.StatsInterval = 5
	}
	return nil
}

func generateRandomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random secret")
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (p *ProxyServer) startProxyServer() {
	listener, err := tls.Listen("tcp", p.config.ListenAddr, p.tlsConfig)
	if err != nil {
		p.logger.Fatal().Err(err).Msg("Failed to start proxy server")
	}
	defer listener.Close()

	p.logger.Info().Str("address", p.config.ListenAddr).Msg("Proxy server listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			p.logger.Error().Err(err).Msg("Error accepting connection")
			continue
		}

		select {
		case p.activeConns <- struct{}{}:
			go p.handleConnection(conn)
		default:
			p.logger.Warn().Msg("Max connections reached, rejecting new connection")
			conn.Close()
		}
	}
}

func (p *ProxyServer) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		<-p.activeConns
	}()

	clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	p.statsLock.Lock()
	p.stats.ActiveConnections++
	p.statsLock.Unlock()

	defer func() {
		p.statsLock.Lock()
		p.stats.ActiveConnections--
		p.statsLock.Unlock()
	}()

	backendConn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: 10 * time.Second,
	}, "tcp", p.config.BackendAddr, p.tlsConfig)
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed to connect to backend")
		return
	}
	defer backendConn.Close()

	if err := backendConn.VerifyHostname(p.config.BackendAddr); err != nil {
		p.logger.Error().Err(err).Msg("Backend certificate verification failed")
		return
	}

	p.statsLock.Lock()
	p.stats.HealthyConnections++
	p.statsLock.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)

	clientLimited := io.LimitReader(clientConn, p.config.MaxBufferSize)
	backendLimited := io.LimitReader(backendConn, p.config.MaxBufferSize)

	go func() {
		defer wg.Done()
		n, err := io.Copy(backendConn, clientLimited)
		if err != nil && err != io.EOF {
			p.logger.Error().Err(err).Msg("Client->Backend copy error")
		}
		p.statsLock.Lock()
		p.stats.TotalBytesIn += uint64(n)
		p.statsLock.Unlock()
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, backendLimited)
		if err != nil && err != io.EOF {
			p.logger.Error().Err(err).Msg("Backend->Client copy error")
		}
		p.statsLock.Lock()
		p.stats.TotalBytesOut += uint64(n)
		p.statsLock.Unlock()
	}()

	wg.Wait()
}

func (p *ProxyServer) startDashboard() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.authMiddleware(p.handleDashboard))
	mux.HandleFunc("/stats", p.authMiddleware(p.handleStats))
	mux.HandleFunc("/api/stats", p.authMiddleware(p.handleAPIStats))
	mux.HandleFunc("/api/auth", p.handleAuth)
	mux.Handle("/static/", http.StripPrefix("/static/",
		p.securityHeaders(http.FileServer(http.Dir("views/static/")))))

	server := &http.Server{
		Addr:         ":" + p.config.DashboardPort,
		Handler:      p.securityHeaders(mux),
		TLSConfig:    p.tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	p.logger.Info().Str("port", p.config.DashboardPort).Msg("Dashboard listening")
	if err := server.ListenAndServeTLS(p.config.CertFile, p.config.KeyFile); err != nil {
		p.logger.Fatal().Err(err).Msg("Failed to start dashboard")
	}
}

func (p *ProxyServer) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net 'unsafe-inline'; "+
				"style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self' ws://* wss://*; "+
				"frame-ancestors 'none'; "+
				"form-action 'self'; "+
				"base-uri 'self'")

		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		if r.Method == http.MethodGet {
			token := generateCSRFToken()
			w.Header().Set("X-CSRF-Token", token)
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    token,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}

		next.ServeHTTP(w, r)
	})
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (p *ProxyServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		tokenString := ""
		if cookie, err := r.Cookie("auth_token"); err == nil {
			tokenString = cookie.Value
		} else if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		}

		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(p.config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodGet {
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = r.FormValue("csrf_token")
			}

			cookie, err := r.Cookie("csrf_token")
			if err != nil || cookie.Value != csrfToken {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	}
}

func (p *ProxyServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !p.loginLimiter.Allow() {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == p.config.AdminUsername && password == p.config.AdminPassword {
		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			Username: username,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
				Issuer:    "secure-proxy",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(p.config.JWTSecret))
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed to generate token")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    tokenString,
			Expires:  expirationTime,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"token":   tokenString,
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
	tokenString := ""
	if cookie, err := r.Cookie("auth_token"); err == nil {
		tokenString = cookie.Value
	} else if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	}

	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed to upgrade to WebSocket")
		return
	}
	defer conn.Close()

	// Send initial auth verification
	if err := conn.WriteJSON(map[string]interface{}{
		"type":    "auth",
		"success": true,
	}); err != nil {
		p.logger.Error().Err(err).Msg("Failed to send auth verification")
		return
	}

	ticker := time.NewTicker(time.Duration(p.config.StatsInterval) * time.Second)
	defer ticker.Stop()

	// Improved version using range over ticker channel
	for range ticker.C {
		p.statsLock.Lock()
		stats := *p.stats
		p.statsLock.Unlock()

		if err := conn.WriteJSON(stats); err != nil {
			p.logger.Error().Err(err).Msg("Error sending stats")
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
