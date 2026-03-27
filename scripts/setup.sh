#!/bin/bash
set -e

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
BLU='\033[0;34m'
RST='\033[0m'

BASE_DIR=$(pwd)
AGENT_DIR="$BASE_DIR/agent"
RELAY_DIR="$BASE_DIR/relay"
SERVER_DIR="$BASE_DIR/server"
CERTS_DIR="$BASE_DIR/certs"
BUILD_DIR="$BASE_DIR/build"

log()  { echo -e "${BLU}[+] $1${RST}"; }
warn() { echo -e "${YLW}[!] $1${RST}"; }
ok()   { echo -e "${GRN}[+] $1${RST}"; }
err()  { echo -e "${RED}[-] $1${RST}"; }

check_deps() {
    log "Checking dependencies..."
    local missing=()
    for cmd in openssl go; do
        command -v $cmd &>/dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -ne 0 ]; then
        err "Missing: ${missing[*]}"
        exit 1
    fi
    ok "All deps found"
}

gen_certs() {
    log "Generating TLS certificates..."
    mkdir -p "$CERTS_DIR"/{ca,server,relay,agent}

    # CA
    openssl genrsa -out "$CERTS_DIR/ca/ca.key" 4096
    openssl req -new -x509 -days 3650 -key "$CERTS_DIR/ca/ca.key" \
        -out "$CERTS_DIR/ca/ca.crt" -subj "/CN=Root CA" \
        -addext "basicConstraints=critical,CA:TRUE"

    # server cert
    openssl genrsa -out "$CERTS_DIR/server/server.key" 4096
    openssl req -new -key "$CERTS_DIR/server/server.key" \
        -out "$CERTS_DIR/server/server.csr" -subj "/CN=Server" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
    openssl x509 -req -days 3650 -in "$CERTS_DIR/server/server.csr" \
        -CA "$CERTS_DIR/ca/ca.crt" -CAkey "$CERTS_DIR/ca/ca.key" \
        -CAcreateserial -out "$CERTS_DIR/server/server.crt" \
        -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost")

    # relay cert
    openssl genrsa -out "$CERTS_DIR/relay/server.key" 4096
    openssl req -new -key "$CERTS_DIR/relay/server.key" \
        -out "$CERTS_DIR/relay/server.csr" -subj "/CN=Relay" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
    openssl x509 -req -days 3650 -in "$CERTS_DIR/relay/server.csr" \
        -CA "$CERTS_DIR/ca/ca.crt" -CAkey "$CERTS_DIR/ca/ca.key" \
        -CAcreateserial -out "$CERTS_DIR/relay/server.crt" \
        -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost")

    # agent cert
    openssl genrsa -out "$CERTS_DIR/agent/client.key" 4096
    openssl req -new -key "$CERTS_DIR/agent/client.key" \
        -out "$CERTS_DIR/agent/client.csr" -subj "/CN=Agent"
    openssl x509 -req -days 3650 -in "$CERTS_DIR/agent/client.csr" \
        -CA "$CERTS_DIR/ca/ca.crt" -CAkey "$CERTS_DIR/ca/ca.key" \
        -CAcreateserial -out "$CERTS_DIR/agent/client.crt"

    # pem bundles
    cat "$CERTS_DIR/server/server.crt" "$CERTS_DIR/server/server.key" > "$CERTS_DIR/server/server.pem"
    cat "$CERTS_DIR/relay/server.crt" "$CERTS_DIR/relay/server.key" > "$CERTS_DIR/relay/server.pem"
    cat "$CERTS_DIR/agent/client.crt" "$CERTS_DIR/agent/client.key" > "$CERTS_DIR/agent/client.pem"

    rm -f "$CERTS_DIR"/*/*.{csr,srl}
    find "$CERTS_DIR" -type f -exec chmod 600 {} \;
    ok "Certs generated"
}

dist_certs() {
    log "Distributing certs..."
    mkdir -p "$AGENT_DIR/certs" "$RELAY_DIR/certs" "$SERVER_DIR/certs"
    cp "$CERTS_DIR/ca/ca.crt" "$AGENT_DIR/certs/"
    cp "$CERTS_DIR/agent/client.pem" "$AGENT_DIR/certs/"
    cp "$CERTS_DIR/agent/client.key" "$AGENT_DIR/certs/"
    cp "$CERTS_DIR/ca/ca.crt" "$RELAY_DIR/certs/"
    cp "$CERTS_DIR/relay/server.pem" "$RELAY_DIR/certs/"
    cp "$CERTS_DIR/relay/server.key" "$RELAY_DIR/certs/"
    cp "$CERTS_DIR/ca/ca.crt" "$SERVER_DIR/certs/"
    cp "$CERTS_DIR/server/server.crt" "$SERVER_DIR/certs/"
    cp "$CERTS_DIR/server/server.key" "$SERVER_DIR/certs/"
    ok "Certs distributed"
}

build_all() {
    log "Building components..."
    mkdir -p "$BUILD_DIR"

    cd "$SERVER_DIR"
    go build -ldflags="-s -w" -o "$BUILD_DIR/goflood-srv" .
    ok "Server built"

    cd "$AGENT_DIR"
    go build -ldflags="-s -w" -o "$BUILD_DIR/goflood-agent" .
    ok "Agent built"

    cd "$RELAY_DIR"
    go build -ldflags="-s -w" -o "$BUILD_DIR/goflood-relay" .
    ok "Relay built"

    cd "$BASE_DIR"
}

main() {
    clear
    echo -e "${BLU}"
    echo "  ╔══════════════════════════════╗"
    echo "  ║      GoFlood Setup           ║"
    echo "  ╚══════════════════════════════╝"
    echo -e "${RST}"

    echo ""
    echo "  1) Full setup (certs + build)"
    echo "  2) Generate certs only"
    echo "  3) Build only"
    echo "  4) Distribute certs"
    echo "  5) Exit"
    echo ""
    read -p "  Select: " choice

    case $choice in
        1) check_deps; gen_certs; dist_certs; build_all ;;
        2) check_deps; gen_certs; dist_certs ;;
        3) check_deps; build_all ;;
        4) dist_certs ;;
        5) exit 0 ;;
        *) err "Invalid option"; exit 1 ;;
    esac

    ok "Done!"
}

main
