# 🛰️ Destiny: Advanced Network Monitoring & EDR Tool

Destiny is a high-performance network analysis engine written in Go. It combines passive packet sniffing, active device discovery, and Layer 7 proxy interception with real-time process-to-packet correlation.

## 🚀 Key Features

- **Multi-Interface Sniffing:** Monitor multiple network cards simultaneously using `libpcap`.
- **EDR Correlation:** Automatically maps network traffic to local PID, application names, and thread counts using `gopsutil`.
- **Active Discovery (Phase 4):** ARP-based network mapping and SSH service fingerprinting.
- **L7 Transparent Proxy:** Intercept HTTP/HTTPS traffic metadata via a dedicated proxy server.
- **Live Dashboard:** Real-time WebSocket-based Web UI for visual traffic monitoring.
- **.dbg Storage:** Custom binary-style logging format for long-term traffic analysis.

## 🛠️ Installation

### Prerequisites
- Go 1.21+
- `libpcap` headers (e.g., `sudo apt install libpcap-dev` on Ubuntu)

```bash
git clone [https://github.com/12sub/Destiny.git](https://github.com/12sub/Destiny.git)
cd Destiny
go mod tidy
go build -o destiny cmd/destiny/main.go
```
📖 Usage
- **Monitor Mode**

Run the sniffer on specific interfaces with process tracking enabled:

```bash
sudo ./destiny monitor -i eth0 -i wlan0 --proxy
```
- **Network Scanning**

Scan a CIDR range to identify live hosts and their SSH versions:


```Bash
sudo ./destiny scan 192.168.1.0/24
```
- **System Diagnostics**

View local hardware specs and a map of network-active processes:

```bash
./destiny info
./destiny netstat
```

🏗️ Project Structure

    /cmd: CLI entry points and Cobra command definitions.

    /internal/capture: Core logic for gopacket and raw socket handling.

    /internal/proxy: HTTP/HTTPS transparent proxy implementation.

    /internal/sysinfo: OS-level process, thread, and hardware telemetry.

    /internal/web: Fiber-based web server and WebSocket hub.

    /pkg/models: Shared data structures across the engine.


---

