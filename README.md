# GoFlood - DDoS Framework

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Multi-User](https://img.shields.io/badge/Multi--User-Yes-blue)
![Bot Support](https://img.shields.io/badge/Bots-Cross--platform-orange)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL%20%7C%20Windows%20%7C%20macOS-blueviolet)
![Architecture](https://img.shields.io/badge/Architecture-Distributed-orange)

> ### 📶 This project merges **Gostress-V2 + Gostress-Enhanced** and **BotnetGo**, offering a complete **C2 Framework solution**:
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

### 🌐 Multi-Platform Support (Windows/Linux/macOS)

*A Command and Control (C2) Framework with secure and efficient distributed botnet management. Includes both Terminal and Web UI interfaces to accommodate different user preferences.*

#### 🔒 Encrypted C2 Channels
| **Component**             | **Protocol**       | **Port** | **Security Features**                     |
|---------------------------|--------------------|----------|-------------------------------------------|
| Terminal Interface         | TLS 1.3            | 1337     | AES-256-GCM, P-384 ECDH                   |
| Web Dashboard             | WebSocket + TLS    | 8443     | Mutual TLS, OCSP Stapling                 |
| Bot Communication         | mTLS 1.3           | 7002     | X.509 Cert Pinning, CA Verification       | 

 *⚠️ **Note**: In the wake of coordinated efforts such as Operation EndGame, PowerOFF, and Cronos, this project serves only as an educational and analytical reference for understanding botnet infrastructure. Real-world deployment of such tools carries significant legal risk*.

 ## 📁 Project Status

### 🏗️ Core Components
| Component          | Status               | Improvements Needed                          |
|--------------------|----------------------|----------------------------------------------|
| **C2 Server**      | 🟢 100% Complete     | None                                         |
| **Stress Client**  | 🟡 97% Complete      | Expand L7/L4 methods + AMP research         |
| **Proxy Client**   | 🟢 100% Complete     | None                                         |
| **Support Scripts**| 🟢 100% Complete     | None                                         |

### 📜 Key Files
| File            | Description          | Status               | Recent Improvements                          |
|-----------------|----------------------|----------------------|----------------------------------------------|
| **main.go**     | C2 Core              | 🟢 Stable            | REST API + Dashboard                         |
| **client.go**   | Client Handler       | 🟡 Finalizing        | IPv4/IPv6 support                            |
| **proxy.go**    | Proxy System         | 🟢 Stable            | Enhanced traffic monitoring                  |
| **README.md**   | Documentation        | 🟡 Polishing         | Video updates needed                         |

### 🛠️ Support Scripts
| Script               | Status       | Features                                      |
|----------------------|--------------|-----------------------------------------------|
| **SetupC2_V2.sh**    | ✅ Complete   | Simplified deployment                         |
| **build.sh**         | ✅ Complete   | Cross-platform (Win/Linux/Mac)               |
| **obf_build.sh**     | ✅ Complete   | Obfuscation + compression                    |

## 🛠️ Technical Topology

```text
                    ┌──────────────────────┐
                    │      Proxy Layer     │
                    │  ┌─────────────────┐ │
┌─────────────┐     │  │  Proxy Client   │ │     ┌─────────────┐
│  C2 Server  │─────┼─►│ • Traffic Obf   │ │◄────┤  Bot Fleet  │
│ • Auth      │◄────┼──│ • TLS 1.3       │ ├────►│ • Auto-Exec │───┐
│ • Attack Q  │     │  │ • Dashboard     │ │     │ • Reporting │   │
└──────┬──────┘     │  └─────────────────┘ │     └─────────────┘   │
       │            └──────────┬───────────┘                       ▼
       ▼                       ▼                         ┌─────────────────┐
┌──────────────┐      ┌─────────────────┐                │   Target Host   │
│ Admin Portal │      │ Proxy Dashboard │                │ • Under Attack  │
│ • Live Stats │      │ • Traffic Stats │                └─────────────────┘
│ • Config     │      │ • Health Checks │
│ • Monitoring │      └─────────────────┘
└──────────────┘
```

### 🖥️ Server/C2 Setup

```bash
# 1. Generate Certificates & Setup
chmod +x generate_certs.sh setup_C2.sh
./generate_certs.sh && ./setup_C2.sh

# 2. Build Server
go build -ldflags="-s -w" -o cnc main.go

# 3. Run C2
./cnc
```

### Install needed packages / Tools
```bash
# Essential Tools
sudo apt install -y upx-ucl openssl

# Go Packages
go get github.com/json-iterator/go \
       github.com/golang-jwt/jwt/v5 \
       github.com/gorilla/websocket \
       github.com/rs/zerolog

# Optional Binary Packer
go install github.com/upx/upx@latest
```
  
<div align="center">
  
## 🛠️ Configuration
Remember to to customize settings via `config.json` 

## 👨‍💻 Commands

### 🚀 Attack
`key is optional and doesn't need to be sent`
`![Method] IP PORT TIME KEY`  
Example: `![Method] 0.0.0.0 80 22 0656d970cef...`

### 👥 User Management
| `adduser` | `deluser` | `resetpw` | `db`    | `logs`  |
|-----------|-----------|-----------|---------|---------|
| Add user  | Delete    | Reset PW  | Database| Audit   |

### ⚙️ System
| `ongoing` | `queue` | `cancel` | `reinstall` | `bots` |
|-----------|---------|----------|-------------|--------|
| Attacks   | Schedule| Cancel   | Reinstall   | Count  |

### 🛠️ Utilities
| `logout`/`exit` | `clear`/`cls` | `help` | `stats` | `status` |
|-----------------|---------------|--------|---------|----------|
| Exit session    | Clear screen  | Help   | Bot stats| C2 status|

## 🎬 Feature Previews

## 🔐 Security

| `📌 Pinning` | `⏱️ Rate Limit` | `🕒 Sessions` | `🛡️ Sanitize` | `🔑 TOTP` |
|-------------|----------------|--------------|---------------|----------|
| CA Verify  | IP/User Throttle| Auto Timeout | Injection Proof| 2FA Codes|

| `🔒 TLS 1.3` | `🔐 Bcrypt` | `📊 Live Stats` | `⚔️ Attack Q` | `📜 Audit` |
|-------------|------------|----------------|--------------|-----------|
| Mutual Auth | PW Hashing | Real-time      | Priority     | Full Logs |

  
## 🤖 Bot Features

| `🖥️ Multi-Arch` | `👾 Anti-Debug` | `♻️ Persist` | `💾 Lightweight` |
|----------------|----------------|-------------|------------------|
|  x86/ARM/MIPS  | Debug Detection| Auto-Run    | Low Resources    |


| Feature Demo                                                   | Description                                     | Preview |
|----------------------------------------------------------------|-------------------------------------------------|---------|
| [🚀 Starter Setup](https://github.com/user-attachments/assets/00b6ddb0-0c9e-47aa-9e91-08e689a1d272)  | Initial setup and certificate generation | ✅ |
| [💻 CLI Interface](https://github.com/user-attachments/assets/b7349373-e985-4d10-ba7b-87edb3844247)  | Terminal interface and login showcase    | ✅ |
| [🧨 Attack Management](https://github.com/user-attachments/assets/531f09ef-ae28-4bcc-aae4-aaa564162acd) | Launching and managing attacks        | ✅ |
| [🛡️ Admin Controls](https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118)    | User management, audit logs, system controls | ✅|
| [🛡️ Support Scripts](https://github.com/user-attachments/assets/e2b9535f-5ede-401c-bb2d-da97b601a118)   | Full C2 setup  | ❎ |

## YT video (Still debaiting)
Might make a video just for setup as well as to properly show it off as a whole.

## Easy Videos (21/06/25) - All videos need updating

| | | |
|-|-|-|
| **Proxy Dashboard**<br>*Showing off Web-ui (05/06/25)*<br><video src="https://github.com/user-attachments/assets/raw/fbe96e3a-ed11-4ea2-b8f1-cb567129cba6" controls width="100%"></video> | **Terminal Output**<br>CLI outputs<br><video src="https://github.com/user-attachments/assets/raw/b7349373-e985-4d10-ba7b-87edb3844247" controls width="100%"></video> | **Starter Guide**<br>Login + commands<br><video src="https://github.com/user-attachments/assets/raw/00b6ddb0-0c9e-47aa-9e91-08e689a1d272" controls width="100%"></video> |
| **Admin Commands**<br>Usage examples<br><video src="https://github.com/user-attachments/assets/raw/e2b9535f-5ede-401c-bb2d-da97b601a118" controls width="100%"></video> | **Attack / stress Example**<br>Filtered traffic demo<br><video src="https://github.com/user-attachments/assets/raw/531f09ef-ae28-4bcc-aae4-aaa564162acd" controls width="100%"></video> | |
