from scapy.all import *
import socket

# Get the local IP address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
local_ip_address = s.getsockname()[0]
s.close()

# Set up the filter to capture incoming traffic
filter = "tcp and inbound"

# Start capturing traffic on the network interface
packets = sniff(filter=filter, count=1000)

# Count the number of packets received and dropped
received = 0
dropped = 0
by_router = 0
by_receiver = 0

for packet in packets:
    if IP in packet and TCP in packet:
        if packet[IP].src == local_ip_address:
            # Count only packets received from your IP address
            received += 1
            if packet[TCP].flags & 0x04:
                if packet[TCP].dport == 80:
                    # Packets dropped by receiver
                    by_receiver += 1
                else:
                    # Packets dropped by router
                    by_router += 1
                    dropped += 1
        else:
            # Packets not sent to your IP address
            dropped += 1

# Print the results
print("Packets received: ", received)
print("Packets dropped: ", dropped)

if by_router > by_receiver:
    print("Packets dropped by router")
else:
    print("Packets dropped by receiver")
