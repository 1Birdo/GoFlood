# ☾☼☽ GolangV4 C2 Framework ☾☼☽


## 🚧 STILL PRODUCING / Finishing off for github repo
# Please Make a new branch or Favourite it to keep update-to-date with the Release 

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A high-performance command and control (C2) server written in Go, featuring TLS encryption, rate limiting, attack queuing, and multi-user management with privilege levels.

To connect to the C2 server, you must use OpenSSL with the generated TLS certificates - standard SSH clients like PuTTY are not supported.
The recommended connection method is:

```bash
openssl s_client -connect [SERVER_IP]:[PORT] -cert client.crt -key client.key -CAfile ca.crt
```
This ensures proper certificate authentication and encrypted communication with the command-and-control interface. Make sure all certificate files (.crt, .key, and CA bundle) are in your working directory before attempting to connect.

# This is the old Demo video for it, Visuals have change for the better since then.
https://github.com/user-attachments/assets/d7e4b3d9-75b6-4a4f-95db-f88b376c020f
# Visuals / Colouring Theme has changed / customizable 

## ✨ Features

- **Secure Communications**: TLS 1.3 with mutual authentication and certificate pinning
- **Multi-User System**: Role-based access control (Owner/Admin/Pro/Basic)
- **Attack Management**: 
  - 8+ attack methods (!udpflood, !synflood, etc.)
  - Attack queuing with priority system
  - Daily attack limits per user
- **Bot Network**: 
  - Real-time bot tracking
  - Automatic reconnection
- **Audit System**: 
  - Comprehensive logging
  - Log rotation
- **User-Friendly Interface**:
  - Animated text effects
  - Color-coded prompts
  - Interactive help system

## 📦 Installation

### Prerequisites
- Go 1.21+
- OpenSSL (for certificate generation)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/golang-c2.git
cd golang-c2

# Generate certificates (requires OpenSSL)
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
openssl req -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.csr -nodes
openssl x509 -req -in certs/ca.csr -signkey certs/ca.key -out certs/ca.crt

# Build and run
go build -o c2server main.go
./c2server
```

Security Fundamentals

TLS with certificate pinning (verifyCert)
Rate limiting (IP and user-based)
Secure password handling (bcrypt)
Input sanitization (sanitizeInput)
IP/port validation against reserved ranges
Session management with timeouts

Operational Features

Attack queuing with priority system
Audit logging with rotation

Bot connection management
User role hierarchy (Owner/Admin/Pro/Basic)
Interactive terminal UI with colorized output

Maintainability

Configuration via JSON
Structured logging
Clear separation of concerns (auth, attacks, bots, etc.)
