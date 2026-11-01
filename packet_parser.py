"""Parse PCAP/PCAPNG traffic into metadata used by the diagnosis engine."""

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS


def _find_icmpv6_layer(packet):
    """Return the first ICMPv6 layer instance, or None."""
    for layer_class in packet.layers():
        if layer_class.__name__.startswith("ICMPv6"):
            return packet[layer_class]
    return None


def _dns_qname(packet):
    """Return the DNS question name as a normalized string when present."""
    if DNS not in packet:
        return None
    question = packet[DNS].qd
    if question is None:
        return None
    name = getattr(question, "qname", None)
    if name is None:
        return None
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")
    return str(name).rstrip(".").lower() or None


def analyze_pcap(file_path):
    """Parse a PCAP/PCAPNG file.

    Returns ``(packet_details, protocol_counts)``. The protocol-count keys are
    kept compatible with the original app: TCP, UDP, ICMP, and Other. ARP
    packets are retained in packet_details with protocol="ARP" and included
    in the Other count.
    """
    packets = rdpcap(file_path)
    packet_details = []
    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

    for packet_number, packet in enumerate(packets, start=1):
        source_ip = None
        destination_ip = None
        ip_version = None

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            ip_version = 4
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
            ip_version = 6

        # ARP has no IP layer, but it is essential for duplicate-IP analysis.
        is_arp = ARP in packet
        if source_ip is None and not is_arp:
            protocol_counts["Other"] += 1
            continue

        timestamp = float(packet.time)
        source_port = destination_port = None
        tcp_flags = tcp_seq = tcp_ack = None
        tcp_payload_length = 0
        dns_qr = dns_rcode = dns_id = dns_qname = None
        icmp_type = icmp_code = icmp_mtu = None
        arp_operation = arp_sender_ip = arp_target_ip = None
        arp_sender_mac = arp_target_mac = None

        if is_arp:
            protocol = "ARP"
            arp = packet[ARP]
            arp_operation = int(arp.op)
            arp_sender_ip = str(arp.psrc) if arp.psrc else None
            arp_target_ip = str(arp.pdst) if arp.pdst else None
            arp_sender_mac = str(arp.hwsrc).lower() if arp.hwsrc else None
            arp_target_mac = str(arp.hwdst).lower() if arp.hwdst else None
        elif TCP in packet:
            protocol = "TCP"
            tcp = packet[TCP]
            source_port = int(tcp.sport)
            destination_port = int(tcp.dport)
            tcp_flags = str(tcp.flags)
            tcp_seq = int(tcp.seq)
            tcp_ack = int(tcp.ack)
            tcp_payload_length = len(bytes(tcp.payload))
        elif UDP in packet:
            protocol = "UDP"
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)
        elif ICMP in packet or _find_icmpv6_layer(packet) is not None:
            protocol = "ICMP"
            if ICMP in packet:
                icmp = packet[ICMP]
                icmp_type = int(icmp.type)
                icmp_code = int(icmp.code)
                if icmp_type == 3 and icmp_code == 4:
                    value = getattr(icmp, "nexthopmtu", None)
                    icmp_mtu = int(value) if value is not None else None
            else:
                icmp6 = _find_icmpv6_layer(packet)
                icmp_type = int(getattr(icmp6, "type", -1))
                icmp_code = int(getattr(icmp6, "code", 0))
                # ICMPv6 Packet Too Big (type 2) carries an MTU value.
                if icmp_type == 2:
                    value = getattr(icmp6, "mtu", None)
                    icmp_mtu = int(value) if value is not None else None
        else:
            protocol = "Other"

        if protocol == "ARP":
            protocol_counts["Other"] += 1
        else:
            protocol_counts[protocol] += 1

        if DNS in packet:
            dns = packet[DNS]
            dns_qr = int(dns.qr)
            dns_rcode = int(dns.rcode)
            dns_id = int(dns.id)
            dns_qname = _dns_qname(packet)

        ether_src = str(packet.src).lower() if getattr(packet, "src", None) else None
        packet_length = len(packet)
        if IP in packet:
            ip_total_length = int(packet[IP].len) if packet[IP].len is not None else None
            ip_flags = int(packet[IP].flags)
        elif IPv6 in packet:
            ip_total_length = 40 + int(packet[IPv6].plen)
            ip_flags = None
        else:
            ip_total_length = None
            ip_flags = None

        packet_details.append({
            "packet_number": packet_number,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "ip_version": ip_version,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "tcp_flags": tcp_flags,
            "tcp_seq": tcp_seq,
            "tcp_ack": tcp_ack,
            "tcp_payload_length": tcp_payload_length,
            "packet_length": packet_length,
            "ip_total_length": ip_total_length,
            "ip_flags": ip_flags,
            "ether_src": ether_src,
            "dns_qr": dns_qr,
            "dns_rcode": dns_rcode,
            "dns_id": dns_id,
            "dns_qname": dns_qname,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "icmp_mtu": icmp_mtu,
            "arp_operation": arp_operation,
            "arp_sender_ip": arp_sender_ip,
            "arp_target_ip": arp_target_ip,
            "arp_sender_mac": arp_sender_mac,
            "arp_target_mac": arp_target_mac,
        })

    return packet_details, protocol_counts
