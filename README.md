# GolangV4 C2 Framework

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Development Status](https://img.shields.io/badge/status-in%20development-yellow.svg)

A high-performance command and control (C2) framework written in Go, featuring enterprise-grade security with TLS 1.3 encryption, multi-user management, attack orchestration, and comprehensive audit logging.

> **⚠️ Development Status**: This project is currently in active development. Please star or watch the repository to stay updated with releases.

## 🎯 Overview

This C2 framework provides a secure, scalable solution for network operations with robust authentication, role-based access control, and real-time bot management. Built with modern Go practices and enterprise security standards.

### Key Highlights
- **Enterprise Security**: TLS 1.3 with mutual authentication and certificate pinning
- **Scalable Architecture**: Multi-user system with role-based permissions
- **Attack Orchestration**: 8+ attack vectors with intelligent queuing
- **Real-time Monitoring**: Live bot tracking and connection management
- **Comprehensive Auditing**: Full activity logging with automatic rotation

## ✨ Features

### 🔒 Security
- **TLS 1.3 Encryption** with mutual authentication
- **Certificate Pinning** for enhanced security
- **Rate Limiting** (IP and user-based)
- **Secure Password Handling** using bcrypt
- **Input Sanitization** and validation
- **Session Management** with automatic timeouts

### 👥 Multi-User Management
- **Role-Based Access Control**: Owner, Admin, Pro, Basic
- **Daily Attack Limits** per user tier
- **User Authentication** with secure session handling
- **Privilege Escalation Protection**

### ⚔️ Attack Management
- **8+ Attack Methods**: UDP flood, SYN flood, and more
- **Priority Queue System** for attack orchestration
- **Real-time Attack Monitoring**
- **Automatic Failure Handling**

### 🤖 Bot Network
- **Real-time Bot Tracking**
- **Automatic Reconnection**
- **Connection Health Monitoring**
- **Distributed Command Execution**

### 📊 Monitoring & Logging
- **Comprehensive Audit System**
- **Automatic Log Rotation**
- **Real-time Activity Monitoring**
- **Structured Logging**

### 🎨 User Experience
- **Interactive Terminal UI**
- **Color-coded Interface**
- **Animated Text Effects**
- **Contextual Help System**
- **Customizable Themes**

## 🚀 Quick Start

### Prerequisites
- **Go 1.21+**
- **OpenSSL** (for certificate generation)
- **Linux/Unix Environment** (recommended)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/golang-c2.git
   cd golang-c2
   ```

2. **Generate TLS Certificates**
   ```bash
   # Create certificates directory
   mkdir -p certs
   
   # Generate server certificate
   openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
   
   # Generate CA certificate
   openssl req -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.csr -nodes
   openssl x509 -req -in certs/ca.csr -signkey certs/ca.key -out certs/ca.crt
   
   # Generate client certificates
   openssl req -newkey rsa:2048 -keyout certs/client.key -out certs/client.csr -nodes
   openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -out certs/client.crt -days 365
   ```

3. **Build and Run**
   ```bash
   # Build the server
   go build -o c2server main.go
   
   # Run the server
   ./c2server
   ```

### Connecting to the Server

**Important**: This C2 server requires OpenSSL for connection - standard SSH clients are not supported.

```bash
openssl s_client -connect [SERVER_IP]:[PORT] -cert client.crt -key client.key -CAfile ca.crt
```

Ensure all certificate files (.crt, .key, and CA bundle) are in your working directory before connecting.

## 📋 Usage

### Available Commands
- `!help` - Display available commands
- `!users` - List connected users
- `!bots` - Show bot network status
- `!attack` - Launch attack vectors
- `!logs` - View audit logs
- `!config` - Server configuration

### User Roles & Permissions
- **Owner**: Full system access, user management
- **Admin**: Attack management, bot control
- **Pro**: Limited attack capabilities
- **Basic**: View-only access

## 🔧 Configuration

The server uses JSON configuration files for customization:

```json
{
  "server": {
    "port": 8443,
    "max_connections": 100,
    "timeout": 300
  },
  "security": {
    "rate_limit": 10,
    "max_failed_attempts": 5
  },
  "logging": {
    "level": "info",
    "rotate_days": 7
  }
}
```

## 🛡️ Security Features

- **Certificate Pinning**: Prevents man-in-the-middle attacks
- **Input Validation**: All user inputs are sanitized
- **IP Range Validation**: Blocks connections from reserved ranges
- **Session Timeouts**: Automatic disconnection of idle sessions
- **Audit Trail**: Complete logging of all activities

## 📖 Documentation

### Demo Video
[View the demonstration video](https://github.com/user-attachments/assets/d7e4b3d9-75b6-4a4f-95db-f88b376c020f)

*Note: This is from an earlier version - current visuals and theming have been significantly improved.*

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is intended for educational and authorized testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The developers assume no liability for misuse of this software.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/golang-c2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/golang-c2/discussions)

---

**Star ⭐ this repository if you find it useful!**
