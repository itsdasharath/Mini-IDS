# 🛡️ Mini IDS (Intrusion Detection System)

A beginner-friendly Python-based **Intrusion Detection System (IDS)** built using [Scapy](https://scapy.net/).  
It monitors network traffic in real-time and detects suspicious activities like SYN floods, port scans, brute-force attempts, and high traffic anomalies.

---

## 🚀 Features
- Detects **SYN Flood attacks**
- Detects **Port Scanning attempts**
- Detects **High Traffic anomalies**
- Detects **Brute-force login attempts** on common ports (SSH, RDP, HTTP, HTTPS)
- Logs alerts with timestamps in `alerts.log`
- Lightweight and easy to customize thresholds

---

## 🛠️ Requirements
- Python 3.x
- [Scapy](https://pypi.org/project/scapy/)

Install dependencies:
```bash
pip install scapy
```

---

## ▶️ Usage
1. Clone this repo:
   ```bash
   git clone https://github.com/itsdasharath/mini-ids.git
   cd mini-ids
   ```

2. Run the IDS (may require admin/root privileges):
   ```bash
   python mini_ids.py
   ```

3. By default, it monitors the interface set in the script (`INTERFACE = "Ethernet"`).  
   Change it if needed (e.g., `eth0`, `wlan0`).

4. Stop anytime with `Ctrl + C`.

---

## 📂 Logs
All alerts are saved in:
```
alerts.log
```

Example:
```
[2025-09-05 10:32:15] ALERT: Port Scan from 192.168.1.10 - 12 ports in 10s
```

---

## ⚠️ Disclaimer
This tool is for **educational and research purposes only**.  
Use it responsibly on your own networks.
