 # GoStress - C2 DDos Framework
### Client is uploaded cnc needs to be done

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Security](https://img.shields.io/badge/Security-Level_5-green)
![Multi-User](https://img.shields.io/badge/Multi--User-Yes-blue)
![Bot Support](https://img.shields.io/badge/Bots-Cross--platform-orange)

A sophisticated Command and Control (C2) server with enterprise-grade features for managing distributed botnets securely and efficiently.


> ⚠️ **Note**: In the wake of coordinated efforts such as Operation EndGame, PowerOFF, and Cronos, this project serves only as an educational and analytical reference for understanding botnet infrastructure. Real-world deployment of such tools carries significant legal risk.

## 📁 File Status Overview

### Core Components
| File          | Status       | Improvements Made                                                                 |
|---------------|-------------|-----------------------------------------------------------------------------------|
| `main.go`  cnc   | ❌ Needs Work  | - Enhanced TLS 1.3 configuration<br>- Added TOTP authentication<br>- Improved attack queue system |
| `bot.go`   bot   | ⚠️ Partial   | - Added anti-debugging checks<br>- Improved persistence mechanism<br>- Enhanced stats reporting |
| `README.md`   | ⚠️ Partial  | - Restructured documentation<br>- Added demo video placeholders<br>- Needs final polish |

### Support Scripts
| File                     | Status       | Key Features                                                                      |
|--------------------------|-------------|-----------------------------------------------------------------------------------|
| `generate_certs.sh`  Certificates    | ✅ Complete  | - 4096-bit key generation<br>- SAN support for IP/DNS<br>- Proper file permissions |
| `generate_32byte_key.sh` Cert Pinning | ✅ Complete  | - Hex/Base64 output<br>- Cryptographically secure RNG<br>- Clean output formatting |
| `build.sh`   Might not need          | ❌ Needs Work | - Missing ARM64 support<br>- No Windows cross-compile<br>- Needs output directory |

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

## ✨ Key Features

- **Military-Grade Encryption**: TLS 1.3 with mutual authentication
- **Advanced Authentication**: TOTP 2FA, bcrypt password hashing
- **Real-time Monitoring**: Live bot statistics and attack analytics
- **Attack Management**: Queue system with priority scheduling
- **Multi-Architecture Support**: Cross-platform bot clients
- **Comprehensive Auditing**: Detailed activity logging
- **Resource Management**: Rate limiting and quotas

## 📦 Quick Start

### Prerequisites
- Go 1.20+
- OpenSSL for certificate generation
- Linux server (recommended)

### Installation
```bash
# Generate certificates
chmod +x generate_certs.sh
./generate_certs.sh

# Build server
go build -o cnc main.go

# Build bots (multiple architectures)
chmod +x build.sh
./build.sh

# Start server
./cnc
```


## 🎥 Video Demonstrations

### All Video Demonstrations are also embedded at the bottom of this Readme.md

| Feature Demo                                                   | Description                                     | Preview |
|----------------------------------------------------------------|-------------------------------------------------|---------|
| [🚀 Starter Setup](https://github.com/user-attachments/assets/00b6ddb0-0c9e-47aa-9e91-08e689a1d272)  | Initial setup and certificate generation       | ✅ |
| [💻 CLI Interface](https://github.com/user-attachments/assets/b7349373-e985-4d10-ba7b-87edb3844247)  | Beautiful terminal interface and login flow    | ✅ |
| [🧨 Attack Management](https://github.com/user-attachments/assets/531f09ef-ae28-4bcc-aae4-aaa564162acd) | Launching and managing attacks                 | ✅ |
| [🛡️ Admin Controls](https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118) | User management, audit logs, system controls   | ✅ |


## 🛠️ Configuration

Edit `config.json` to customize settings:

```json
{
  "users_file": "users.json",
  "audit_log_file": "audit.log",
  "bot_server_ip": "0.0.0.0",
  "user_server_ip": "0.0.0.0",
  "bot_server_port": "7002",
  "user_server_port": "7001",
  "cert_file": "certs/server.pem",
  "key_file": "certs/server.key",
  "session_timeout": "30m",
  "max_conns": 1000,
  "max_read_size": 4096,
  "max_log_size": 104857600,
  "max_queued_attacks": 50,
  "max_daily_attacks": 100,
  "max_attack_duration": 3600,
  "max_sessions_per_user": 3,
  "min_password_length": 8,
  "password_complexity": true,
  "max_connections_per_ip": 5,
  "totp_enabled": true
}
```

## 🔐 Security Features

- **Certificate Pinning**: Hardcoded CA verification
- **Rate Limiting**: IP and user-based request throttling
- **Session Management**: Automatic timeout and cleanup
- **Input Sanitization**: Protection against injection attacks
- **TOTP Support**: Time-based one-time passwords
- **Password Policies**: Complexity requirements and lockout

## 🤖 Bot Client Features

```go
// From bot.go
type BotStats struct {
  StartTime    time.Time
  AttackCount  int
  SuccessCount int
  LastCommand  time.Time
}
```

- Multi-architecture support (x86, ARM, MIPS)
- Anti-debugging techniques
- Process hiding
- Automated persistence
- Resource-efficient operation
- Encrypted communications

## ⚙️ Attack Methods

| Command     | Description           | Example                         |
|------------|-----------------------|----------------------------------|
| !udpflood   | Standard UDP flood    | !udpflood 1.1.1.1 80 60         |
| !udpsmart   | Adaptive UDP flood    | !udpsmart 1.1.1.1 80 120        |
| !tcpflood   | TCP connection flood  | !tcpflood 1.1.1.1 80 300        |
| !synflood   | SYN packet flood      | !synflood 1.1.1.1 80 60         |
| !ackflood   | ACK packet flood      | !ackflood 1.1.1.1 80 60         |
| !greflood   | GRE protocol flood    | !greflood 1.1.1.1 80 60         |
| !dns        | DNS amplification     | !dns 1.1.1.1 53 120             |
| !http       | HTTP request flood    | !http 1.1.1.1 80 300            |

## 👨‍💻 Admin Commands

```go
// From main.go
type User struct {
  Username       string    `json:"username"`
  PasswordHash   string    `json:"passwordHash"`
  Expire         time.Time `json:"expire"`
  Level          string    `json:"level"`
  // ... other fields
}
```

| Command     | Description         | Required Level |
|-------------|---------------------|----------------|
| adduser     | Create new user     | Admin+         |
| deluser     | Delete user         | Admin+         |
| resetpw     | Reset password      | Admin+         |
| db          | View user database  | Admin+         |
| logs        | View audit logs     | Admin+         |
| reinstall   | Reinstall bots      | Admin+         |

## 📊 Statistics Tracking

```go
// From main.go
type AggregatedStats struct {
  AvgLatency    time.Duration
  AvgThroughput float64
  TotalRAM      float64
  TotalCores    int
  HealthyBots   int
  UnhealthyBots int
}
```

- Real-time bot performance metrics
- Attack success rates
- Resource utilization
- Network latency monitoring
- Health status tracking

## 📜 License

MIT License - See LICENSE for details.

## ⚠️ Disclaimer

This project is for educational and research purposes only. The authors are not responsible for any misuse of this software.

## Easy Videos

## Cli Output - Basically shows what the CLI outputs on your terminal 
https://github.com/user-attachments/assets/b7349373-e985-4d10-ba7b-87edb3844247

## Starter – Walkthrough of the login process and essential commands.

https://github.com/user-attachments/assets/00b6ddb0-0c9e-47aa-9e91-08e689a1d272

## Admin – Demonstrates Admin commands + usage.

https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118

## Attack -- All outgoing traffic was filtered / Disabled for this Example.
https://github.com/user-attachments/assets/531f09ef-ae28-4bcc-aae4-aaa564162acd

