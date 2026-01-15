from scapy.all import sniff, IP, TCP, ICMP
import socket
import time
from collections import defaultdict

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

# Track outbound SYNs we send: (dst_ip, dst_port, src_port) -> timestamp
pending = {}
results = {
    "syn_sent": 0,
    "synack_received": 0,
    "rst_received": 0,
    "icmp_unreachable": 0,
    "icmp_by_code": defaultdict(int),
    "timeouts": 0
}

TIMEOUT_SEC = 3.0  # consider "dropped/filtered" if no reply seen in this window

def is_syn(pkt):
    return pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].src == local_ip and (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10)

def is_synack(pkt):
    return pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].dst == local_ip and (pkt[TCP].flags & 0x12) == 0x12

def is_rst(pkt):
    return pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].dst == local_ip and (pkt[TCP].flags & 0x04)

def is_icmp_unreach(pkt):
    return pkt.haslayer(ICMP) and pkt[ICMP].type == 3

def process_packet(pkt):
    now = time.time()

    # Record outbound SYN attempts
    if is_syn(pkt):
        key = (pkt[IP].dst, int(pkt[TCP].dport), int(pkt[TCP].sport))
        pending[key] = now
        results["syn_sent"] += 1
        return

    # Classify inbound TCP responses to our pending SYNs
    if is_synack(pkt) or is_rst(pkt):
        # Response from remote src -> our local dst
        remote_ip = pkt[IP].src
        src_port = int(pkt[TCP].sport)   # remote port
        dst_port = int(pkt[TCP].dport)   # our ephemeral port

        # Match against pending SYN key (dst_ip=remote_ip, dst_port=src_port, src_port=dst_port)
        key = (remote_ip, src_port, dst_port)
        if key in pending:
            if is_synack(pkt):
                results["synack_received"] += 1
            elif is_rst(pkt):
                results["rst_received"] += 1
            pending.pop(key, None)
        return

    # ICMP unreachable often contains the original IP header + 8 bytes (enough for TCP ports)
    if is_icmp_unreach(pkt):
        results["icmp_unreachable"] += 1
        code = int(pkt[ICMP].code)
        results["icmp_by_code"][code] += 1

        # Try to correlate to the original SYN attempt
        inner = pkt.getlayer(IP, 2)  # inner IP (embedded)
        if inner and inner.haslayer(TCP) and inner.src == local_ip:
            key = (inner.dst, int(inner[TCP].dport), int(inner[TCP].sport))
            pending.pop(key, None)
        return

def reap_timeouts():
    now = time.time()
    expired = [k for k, t in pending.items() if (now - t) > TIMEOUT_SEC]
    for k in expired:
        pending.pop(k, None)
        results["timeouts"] += 1

print("Sniffing... generate traffic (curl/browser). Ctrl+C to stop.")
try:
    # tcp/icmp only is fine; include "ip" explicitly for clarity
    sniff(filter="ip and (tcp or icmp)", prn=process_packet, store=False)
except KeyboardInterrupt:
    pass

# One last timeout sweep
reap_timeouts()

print("\n--- Results (SYN-based) ---")
print(f"SYNs sent: {results['syn_sent']}")
print(f"SYN/ACK received (allowed/open): {results['synack_received']}")
print(f"RST received (rejected/closed): {results['rst_received']}")
print(f"ICMP Unreachable: {results['icmp_unreachable']}")
if results["icmp_unreachable"]:
    print("  ICMP codes:")
    for code, n in sorted(results["icmp_by_code"].items()):
        print(f"    code {code}: {n}")
print(f"Timeouts (no reply within {TIMEOUT_SEC}s): {results['timeouts']}")

# Simple “dominant” conclusion
if results["timeouts"] > max(results["rst_received"], results["icmp_unreachable"]):
    print("\nConclusion: Most attempts got no response (possible filtering/drops or silent loss).")
elif results["icmp_unreachable"] > results["rst_received"]:
    print("\nConclusion: ICMP Unreachable dominates (path/policy/network signaling).")
elif results["rst_received"] > 0:
    print("\nConclusion: RST dominates (targets/edge actively rejecting or ports closed).")
else:
    print("\nConclusion: No strong rejection/drop signal detected from observed attempts.")
