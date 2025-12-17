from scapy.all import *
import socket

# 1. Get the local IP address accurately
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

local_ip = get_local_ip()
print(f"Monitoring traffic for Local IP: {local_ip}")

# 2. Counters
stats = {
    "received": 0,
    "by_router": 0,    # ICMP Unreachable
    "by_receiver": 0   # TCP RST
}

# 3. Processing Logic
def process_packet(packet):
    # Count general incoming TCP traffic
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[IP].dst == local_ip:
            stats["received"] += 1
            
            # Check if a remote host is Rejecting the connection (RST flag)
            if packet[TCP].flags & 0x04:
                stats["by_receiver"] += 1

    # Check for Router/Network issues (ICMP Type 3)
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 3:
            stats["by_router"] += 1

# 4. Start Capture
print("Capturing 1000 packets... (Run a browser or curl to generate traffic)")
# Filter captures TCP and ICMP (router errors)
sniff(filter="tcp or icmp", prn=process_packet, count=1000)

# 5. Final Report
print("\n--- Capture Results ---")
print(f"Total TCP Packets Received: {stats['received']}")
print(f"Packets Rejected by Receiver (RST): {stats['by_receiver']}")
print(f"Packets Blocked by Router (ICMP Unreachable): {stats['by_router']}")

if stats['by_router'] > stats['by_receiver']:
    print("\nConclusion: Network/Router issues are more prevalent.")
elif stats['by_receiver'] > 0:
    print("\nConclusion: Target hosts are actively rejecting connections.")
else:
    print("\nConclusion: No significant drops detected.")
