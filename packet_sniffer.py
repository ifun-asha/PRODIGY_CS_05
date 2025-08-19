from scapy.all import sniff, IP, TCP, UDP, conf

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {proto}", end="")

        # Extra details if TCP or UDP
        if packet.haslayer(TCP):
            print(f" | TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f" | UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")
        else:
            print()
        print("-" * 50)

print("🔍 Packet Sniffer Started... (Press CTRL+C to stop)")

try:
    # Try Layer 2 sniffing (requires Npcap/WinPcap)
    sniff(prn=packet_callback, store=0)
except RuntimeError as e:
    print("⚠️ Layer 2 sniffing not available. Falling back to Layer 3 (IP only).")
    conf.L3socket  # Ensure scapy uses L3
    sniff(prn=packet_callback, store=0, filter="ip")
