# GoFlood
(Deprecated Project)
Network stress testing tool written in go. distributed architecture with a controller, lightweight agents, and an optional relay proxy.

been working on this for a lil bit, figured i'd clean it up and release it properly.

## whats in here

```
server/     controller - web dashboard, cli, manages all the agents
agent/      connects back to the server, runs the actual tasks
relay/      tls proxy that sits in front (optional, has its own dashboard)
scripts/    cert generation + build scripts
```

## setup

easiest way:
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

or manually:

1. gen your TLS certs (the setup script does this for you)
2. `cp server/config.example.json server/config.json` and edit it
3. build + run:

```bash
cd server && go build -o goflood . && ./goflood
cd agent && go build -o agent . && ./agent
cd relay && go build -o relay . && ./relay   # optional
```

## server

- web ui on 443 (https), cli on 7001, agents connect on 7002
- role system: Owner > Admin > Pro > Basic
- rate limiting per-ip and per-user
- session management, audit log, the usual
## agent

- auto-reconnect with backoff
- challenge-response auth (hmac)
- reports system info (cpu, ram, arch)
- cross-compiled to linux/windows/darwin (arm, mips, x86, x64)

## relay

- tls 1.3 proxy, sits between agents and server
- has its own web dashboard with live traffic graphs
- jwt auth, csrf, websocket stats

## building agents for multiple platforms

```bash
cd agent
chmod +x ../scripts/build_agent.sh
../scripts/build_agent.sh
```

builds for linux (x86, arm, mips), windows, and macos. uses upx if available.

## requirements

- go 1.21+
- openssl (cert gen)
- linux/macos recommended, works on windows too

## license

MIT
