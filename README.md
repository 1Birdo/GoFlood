# ☾☼☽ Advanced Golang C2 Framework ☾☼☽

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A high-performance command and control (C2) server written in Go, featuring TLS encryption, rate limiting, attack queuing, and multi-user management with privilege levels.

##STILL PRODUCING / Finishing off for github repo

https://github.com/user-attachments/assets/d7e4b3d9-75b6-4a4f-95db-f88b376c020f


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
