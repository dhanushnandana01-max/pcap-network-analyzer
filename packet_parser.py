
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


def is_icmpv6(packet):
    """Return True if the packet contains an ICMPv6 layer."""
    return any(
        layer.__name__.startswith("ICMPv6")
        for layer in packet.layers()
    )


def analyze_pcap(file_path):
    """
    Parse a PCAP/PCAPNG file into packet metadata.

    Returns:
        packet_details: list of packet dictionaries
        protocol_counts: counts for TCP, UDP, ICMP, and Other
    """
    packets = rdpcap(file_path)

    packet_details = []
    protocol_counts = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "Other": 0,
    }

    for packet_number, packet in enumerate(packets, start=1):
        source_ip = None
        destination_ip = None

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
        else:
            protocol_counts["Other"] += 1
            continue

        timestamp = float(packet.time)

        source_port = None
        destination_port = None
        tcp_flags = None
        tcp_seq = None
        tcp_ack = None

        if TCP in packet:
            protocol = "TCP"
            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)
            tcp_seq = int(packet[TCP].seq)
            tcp_ack = int(packet[TCP].ack)

        elif UDP in packet:
            protocol = "UDP"
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)

        elif ICMP in packet or is_icmpv6(packet):
            protocol = "ICMP"

        else:
            protocol = "Other"

        protocol_counts[protocol] += 1

        packet_details.append({
            "packet_number": packet_number,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "tcp_flags": tcp_flags,
            "tcp_seq": tcp_seq,
            "tcp_ack": tcp_ack,
        })

    return packet_details, protocol_counts
