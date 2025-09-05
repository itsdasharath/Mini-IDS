from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timedelta
from collections import defaultdict
import os

# Log file name
LOG_FILE = "alerts.log"

# Change this to your network interface (like Wi-Fi, Ethernet, eth0)
INTERFACE = "Ethernet"

# Threshold settings
SYN_LIMIT = 50           # max SYN packets in short time
SYN_WINDOW = 5           # seconds

PORTSCAN_LIMIT = 10      # number of different ports
PORTSCAN_WINDOW = 10     # seconds

TRAFFIC_LIMIT = 1000     # number of packets
TRAFFIC_WINDOW = 10      # seconds

BRUTE_FORCE_LIMIT = 15   # number of tries
BRUTE_FORCE_WINDOW = 60  # seconds
LOGIN_PORTS = [22, 23, 3389, 80, 443]  # ssh, telnet, rdp, http, https

# Trackers
syn_data = defaultdict(list)
portscan_data = defaultdict(list)
traffic_data = defaultdict(list)
brute_data = defaultdict(list)

# Save alert to file and print
def alert(alert_type, ip, msg):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] ALERT: {alert_type} from {ip} - {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

# Clean old timestamps
def clean_old(data, time_window):
    now = datetime.now()
    for ip in list(data.keys()):
        data[ip] = [item for item in data[ip] if now - item[0] < timedelta(seconds=time_window)]
        if not data[ip]:
            del data[ip]

# Detect SYN flood
def detect_syn(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        flags = packet[TCP].flags

        if flags == "S":  # only SYN
            syn_data[ip].append((datetime.now(), "S"))
            clean_old(syn_data, SYN_WINDOW)

            count = len([f for t, f in syn_data[ip] if f == "S"])
            if count >= SYN_LIMIT:
                alert("SYN Flood", ip, f"{count} SYN packets in {SYN_WINDOW}s")
                syn_data[ip].clear()

# Detect port scanning
def detect_portscan(packet):
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        ip = packet[IP].src
        port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport

        portscan_data[ip].append((datetime.now(), port))
        clean_old(portscan_data, PORTSCAN_WINDOW)

        ports = set(p for t, p in portscan_data[ip])
        if len(ports) >= PORTSCAN_LIMIT:
            alert("Port Scan", ip, f"{len(ports)} ports in {PORTSCAN_WINDOW}s")
            portscan_data[ip].clear()

# Detect high traffic
def detect_traffic(packet):
    if packet.haslayer(IP):
        ip = packet[IP].src
        traffic_data[ip].append((datetime.now(), 1))
        clean_old(traffic_data, TRAFFIC_WINDOW)

        count = len(traffic_data[ip])
        if count >= TRAFFIC_LIMIT:
            alert("High Traffic", ip, f"{count} packets in {TRAFFIC_WINDOW}s")
            traffic_data[ip].clear()

# Detect brute-force login attempts
def detect_brute(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        port = packet[TCP].dport
        flags = packet[TCP].flags

        if port in LOGIN_PORTS and flags == "S":
            brute_data[ip].append((datetime.now(), port))
            clean_old(brute_data, BRUTE_FORCE_WINDOW)

            count = len(brute_data[ip])
            if count >= BRUTE_FORCE_LIMIT:
                alert("Brute Force Try", ip, f"{count} tries to login ports in {BRUTE_FORCE_WINDOW}s")
                brute_data[ip].clear()

# Handle each packet
def check_packet(pkt):
    try:
        detect_syn(pkt)
        detect_portscan(pkt)
        detect_traffic(pkt)
        detect_brute(pkt)
    except Exception as e:
        print("Error handling packet:", e)

# Start IDS
def start_ids():
    print("Starting Mini IDS...")
    print(f"Monitoring interface: {INTERFACE}")
    print(f"Logging alerts to: {LOG_FILE}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(iface=INTERFACE, prn=check_packet, store=0)
    except KeyboardInterrupt:
        print("\nIDS stopped.")
    except Exception as e:
        print("Error starting IDS:", e)
        print("Check permissions or correct interface name.")

if __name__ == "__main__":
    start_ids()
