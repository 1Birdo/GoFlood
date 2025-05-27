# ☾☼☽ Advanced Botnet C2 Framework

![Go](https://img.shields.io/badge/Go-1.20+-00ADD8?logo=go)
![License](https://img.shields.io/badge/License-MIT-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows-lightgrey)

A high-performance, encrypted Command and Control (C2) server with advanced features for botnet management, written in Go with military-grade security.

## 🔥 Features

### ⚡ Core Capabilities
- **TLS 1.3 Encrypted Communications** (AES-256-GCM, CHACHA20-POLY1305)
- **Multi-Architecture Bot Support** (x86, x64, ARM, MIPS)
- **Session-Based Authentication** with configurable timeout
- **Rate-Limited Command Execution** to prevent abuse
- **Priority-Based Attack Queueing** system

### 🛡️ Security Features
- **Certificate Pinning** with SHA-256 fingerprint verification
- **Brute Force Protection** with account lockout
- **IP/User Rate Limiting**
- **Session Management** with concurrent session limits
- **Reserved IP Blocking** (RFC 1918, localhost, etc.)

### ⚙️ Attack Methods
| Method       | Description                          | Required Level |
|--------------|--------------------------------------|----------------|
| `!udpflood`  | Standard UDP flood                   |             |
| `!udpsmart`  | Smart UDP flood with optimized payload |             |
| `!tcpflood`  | TCP connection flood                 |             |
| `!synflood`  | SYN packet flood                     |             |
| `!ackflood`  | ACK packet flood                     |             |
| `!greflood`  | GRE IP encapsulation flood           |             |
| `!dns`       | DNS amplification attack             |             |
| `!http`      | HTTP/S flood attack                  |             |

### 👑 User Management
- **Multi-Level Access Control**:
  - Owner (Full access)
  - Admin (User management + attacks)
  - Pro (Attacks only)
  - Basic (Limited features)
- **Password Policies** with bcrypt hashing
- **Account Expiration** system
- **Audit Logging** of all actions

## 🚀 Installation

### Prerequisites
- Go 1.20+ installed
- Linux/Windows server
- Valid domain name (for TLS)
- Basic firewall configuration (open ports)

### Quick Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/botnet-c2.git
   cd botnet-c2
