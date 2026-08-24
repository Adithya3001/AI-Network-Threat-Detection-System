from scapy.all import IP, IPv6, TCP, UDP

def extract_features(packet):

    protocol = 0
    src_port = 0
    dst_port = 0

    if IP in packet:
        protocol = packet[IP].proto

    elif IPv6 in packet:
        protocol = packet[IPv6].nh

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    packet_length = len(packet)

    return {
        "Protocol": protocol,
        "Source Port": src_port,
        "Destination Port": dst_port,
        "Packet Length": packet_length
    }