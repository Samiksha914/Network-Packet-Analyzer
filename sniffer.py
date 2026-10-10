from scapy.all import sniff, IP, TCP, UDP

def analyze_packet(packet):
    # Check if packet has a Network (IP) Layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for TCP Transport Layer
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            # Highlight insecure protocols
            if dst_port == 80:
                print("   ⚠️  WARNING: Insecure HTTP web traffic!")
            elif dst_port == 21:
                print("   ⚠️  WARNING: Insecure FTP file transfer!")

        # Check for UDP Transport Layer
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

print("🚀 Starting Security Packet Sniffer... Press Ctrl+C to stop.")
# This line starts looking at your Wi-Fi/Ethernet data card
sniff(prn=analyze_packet, store=False)
