# GoFlood - DDos Framework

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Security](https://img.shields.io/badge/Security-Level_5-green)
![Security](https://img.shields.io/badge/Security-MTLS_Encrypted-brightgreen)
![Multi-User](https://img.shields.io/badge/Multi--User-Yes-blue)
![Bot Support](https://img.shields.io/badge/Bots-Cross--platform-orange)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-blueviolet)
![Architecture](https://img.shields.io/badge/Architecture-Distributed-orange)

All Files mainly uploaded just need fixes and to be stable and to make it just work on first run.

*A sophisticated Command and Control (C2) server with standard features, with secure and efficient distributed botnet management. Includes both Terminal and Web UI interfaces to accommodate different user preferences.*
###  Mostly Linux Based / WSL Supported (Testing for MacOS + Windows)
📶 This framework merges the functionality of **Gostress-V2 / Gostress-Enhanced** and **BotnetGo**, offering a complete **C2 solution** featuring:
-  **Encrypted C2 Channels**:
    - TLS 1.3 secured terminal interface (TCP/1337)
    - WebSocket dashboard (TCP/8443) 
    - Mutual TLS authentication for all connections

 - **C2 Channel Description (Bot Connection Protocol)**:
   - Protocol: TCP with TLS 1.3 encryption (TCP/7002).
   - Bots and the C2 server authenticate each other using client and server certificates (X.509).
   - The server validates bot certificates against a pinned CA certificate to prevent impersonation.
   - Bots verify the server's certificate to avoid MITM attacks.
    

 *⚠️ **Note**: In the wake of coordinated efforts such as Operation EndGame, PowerOFF, and Cronos, this project serves only as an educational and analytical reference for understanding botnet infrastructure. Real-world deployment of such tools carries significant legal risk*.
## 📁 File Status Overview
###  🏗️  Proxy Client is Optional
### Project Status
| Component       | Status        | Current Progress | Improvements to be Added / Implemented                                                                             |
|-----------------|--------------|------------------|---------------------------------------------------------------------------------------------------------------------|
| **C2 Server**    | Testing Phase   | 84% Complete  🟠     | - Implement Gosstress-V2 Web Dashboard<br>- Develop REST API endpoints<br>- Enhance command queuing system|
| **Stress Client**| Needs Development | 80% Complete 🔴     | - Expand L7/L4 attack methods<br>- Improve stability and fix features                                     |
| **Proxy Client** | Testing Phase | 98% Finishing Up 🟢 | - Just needs testing to make sure it secure<br>- Synchronization Verification                             |


### Core Files
| File          | File desc   | Status       | Improvements Made                                                                    |
|---------------|-------------|--------------|--------------------------------------------------------------------------------------|
| **main.go**   | C2 Server File  | 🟡 Medium Improvements  | - Enhanced TLS 1.3 configuration<br>- Improved attack queue system    |
| **bot.go**    | Client File   | 🔴 Partial Changes  | - Improved persistence mechanism<br>- Enhanced stats reporting              |
| **proxy.go**  | Proxy File| 🟢 Minor Improvements   | - JWT Authentication<br>- Traffic monitoring improvements                   |
| **README.md** |  Readme.md File| 🟡 Major Changes   | - Restructured documentation<br>- Added demo video <br>- small final polish |

### Support Scripts 
| File                       | Status        | Key Features                                                                                |
|----------------------------|---------------|---------------------------------------------------------------------------------------------|
| **generate_certs.sh**      | ✅ Complete   | - 4096-bit key generation<br>- SAN support for IP/DNS<br>- Proper file permissions          |
| **generate_32byte_key.sh** | ✅ Complete   | - Hex/Base64 output<br>- Cryptographically secure RNG<br>- Clean output formatting          |
| **build.sh**               | 🟠 Needs Work | - Missing ARM64 support<br>- No Windows cross-compile / Support<br>- Needs output directory |

## 🛠️ Technical Architecture

```mermaid
%%{init: {"flowchart": {"useMaxWidth": false, "htmlLabels": true}} }%%
flowchart TD
    subgraph C2_Server["C2 Server"]
        A1[User Auth]
        A2[Stress Attacks]
    end
    ...
```

```mermaid
flowchart TD
    subgraph C2_Server["C2 Server"]
        A1[User Auth]
        A2[Stress Attacks]
        A3[Audit Logging]
    end

    subgraph Proxy_Client["Proxy Client (Optional)"]
        B1[Traffic Obfuscation]
        B2[TLS 1.3]
        B3[Web Dashboard]
    end

    subgraph Bot_Clients["Bot Clients"]
        C1[Auto-Connect]
        C2[Attack Execution]
        C3[Stats Reporting]
    end

    subgraph Target["Target"]
        D1[Target Host]
        D2[Stress Attack]
    end

    subgraph Admin_Dashboard["Admin Dashboard"]
        E1[Authentication]
        E2[Real-time Stats]
        E3[Monitoring]
        E4[Config Edits]
        E5[Attack Queue]
        E6[Attack Scheduling]
    end

    subgraph Proxy_Dashboard["Proxy Dashboard"]
        F1[Traffic Stats]
        F2[Health Check]
        F3[Authentication]
    end

    C2_Server -->|Commands| Proxy_Client
    Proxy_Client -->|Control| Bot_Clients
    Bot_Clients -->|Attack| Target
    Bot_Clients -->|Stats| Proxy_Client
    Proxy_Client -->|Logs| C2_Server
    C2_Server --> Admin_Dashboard
    Proxy_Client --> Proxy_Dashboard
```


## 🎥 Video Demonstrations

### All Video Demonstrations are also embedded at the bottom of this Readme.md

| Feature Demo                                                   | Description                                     | Preview |
|----------------------------------------------------------------|-------------------------------------------------|---------|
| [🚀 Starter Setup](https://github.com/user-attachments/assets/00b6ddb0-0c9e-47aa-9e91-08e689a1d272)  | Initial setup and certificate generation       | ✅ |
| [💻 CLI Interface](https://github.com/user-attachments/assets/b7349373-e985-4d10-ba7b-87edb3844247)  | Beautiful terminal interface and login flow    | ✅ |
| [🧨 Attack Management](https://github.com/user-attachments/assets/531f09ef-ae28-4bcc-aae4-aaa564162acd) | Launching and managing attacks                 | ✅ |
| [🛡️ Admin Controls](https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118) | User management, audit logs, system controls   | ✅ |

### Server / C2
```
# Generate certificates
chmod +x generate_certs.sh setup_C2.sh 
./generate_certs.sh
./setup_C2.sh 

# Build server
go build -o cnc main.go

# Start server
./cnc
```

### Install needed packages / Tools
```bash
# UPX (compression) - Openssl (Certs) - 
sudo apt install upx-ucl

# Binary packer (optional)
go install github.com/upx/upx@lates

# JSON Parser - JWT Token - WS support - Logging library 
go get github.com/json-iterator/go
go get github.com/golang-jwt/jwt/v5
go get github.com/gorilla/websocket
go get github.com/rs/zerolog
```

## 🔐 Security Features

- **Certificate Pinning**: CA verification
- **Rate Limiting**: IP and user-based request throttling
- **Session Management**: Automatic timeout and cleanup
- **Input Sanitization**: Protection against injection attacks
- **TOTP For Passwd reset**: Time-based one-time passwords reset codes
- **Password Policies**: Complexity requirements and lockout
- **Encryption**: TLS 1.3 with mutual authentication
- **Authentication**: Bcrypt password hashing
- **Real-time Monitoring**: Live bot statistics and attack analytics
- **Attack Management**: Queue system with priority scheduling
- **Multi-Architecture Support**: Cross-platform bot clients
- **Comprehensive Auditing**: Detailed activity logging

## 🤖 Bot Client Features

- Multi-architecture support (x86, ARM, MIPS)
- Anti-debugging techniques
- Automated persistence
- Resource efficient
## 🛠️ Configuration
Edit `config.json` to customize settings:

```json
{
  "users_file": "users.json",
  "audit_log_file": "audit.log",
  "bot_server_ip": "172.17.126.64",
  "user_server_ip": "0.0.0.0",
  "bot_server_port": "7002",
  "user_server_port": "5555",
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
  "min_password_length": 8,
  "password_complexity": true,
  "max_connections_per_ip": 5,
  "ddos_protection": true,
  "max_conn_rate": 10,
  "syn_flood_threshold": 50,
  "reset_token_validity": 3600,
  "pinned_cert_file": "certs/pinned.crt",
  "command_signing_key": "your_very_secure"
}
```

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

| Command     | Description         | Required Level |
|-------------|---------------------|----------------|
| adduser     | Create new user     | Admin+         |
| deluser     | Delete user         | Admin+         |
| resetpw     | Reset password      | Admin+         |
| db          | View user database  | Admin+         |
| logs        | View audit logs     | Admin+         |
| reinstall   | Reinstall bots      | Admin+         |

## Easy Videos (21/06/25) - All the videos are old and need updating
## *Finishing (05/06/25)* Proxy  - Showing off Proxy POC
https://github.com/user-attachments/assets/fbe96e3a-ed11-4ea2-b8f1-cb567129cba6

## Cli Output - CLI outputs on your terminal 
https://github.com/user-attachments/assets/b7349373-e985-4d10-ba7b-87edb3844247

## Starter – Walkthrough of the login process + essential commands.
https://github.com/user-attachments/assets/00b6ddb0-0c9e-47aa-9e91-08e689a1d272

## Admin – Admin commands + usage.
https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118

## Attack Example -- All outgoing traffic was filtered / Disabled for this Example.
https://github.com/user-attachments/assets/531f09ef-ae28-4bcc-aae4-aaa564162acd

## 📜 License
MIT License - See LICENSE for details.

## ⚠️ Disclaimer
This project is for educational and research purposes only. The authors are not responsible for any misuse of this software.
