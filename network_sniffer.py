rom scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Function to process each packet
def process_packet(packet):
    print("\n--- Packet Captured at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "---")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")

        if packet.haslayer(TCP):
            print("Protocol Name  : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("Protocol Name  : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("Protocol Name  : ICMP")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload        : {payload[:100]}")
        else:
            print("Payload        : None")
    else:
        print("Non-IP Packet")

if __name__ == "__main__":
    print("Starting packet sniffing... Press CTRL+C to stop.\n")
    sniff(prn=process_packet, store=False)
