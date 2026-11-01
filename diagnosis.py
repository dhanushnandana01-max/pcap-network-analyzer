"""Rule-based diagnostics for common problems visible in offline PCAPs."""

from collections import defaultdict


DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def _finding(title, severity, evidence, causes, fixes):
    """Keep a stable finding schema for the existing Streamlit interface."""
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "possible_causes": causes,
        "suggested_fixes": fixes,
    }


def diagnose_packets(
    packet_details,
    scan_threshold=10,
    scan_window=10.0,
    response_timeout=3.0,
    retransmission_window=60.0,
    delay_threshold=1.0,
):
    """Analyze parsed packet metadata and return human-readable findings.

    Detection is heuristic. A PCAP shows only traffic visible at its capture
    point; findings indicate evidence, not proof of root cause.
    """
    if scan_threshold < 1:
        raise ValueError("scan_threshold must be at least 1")
    if scan_window < 0:
        raise ValueError("scan_window cannot be negative")
    if response_timeout < 0:
        raise ValueError("response_timeout cannot be negative")
    if retransmission_window < 0:
        raise ValueError("retransmission_window cannot be negative")
    if delay_threshold < 0:
        raise ValueError("delay_threshold cannot be negative")

    packets = sorted(packet_details, key=lambda p: float(p.get("timestamp", 0)))
    if not packets:
        return [_finding(
            "No issue detected by current checks", "Info",
            "The capture contains no packets to analyze.", [], [],
        )]

    findings = []
    capture_end = max(float(p.get("timestamp", 0)) for p in packets)

    syn_attempts = defaultdict(list)
    scan_traffic = defaultdict(list)
    reset_connections = set()
    slow_handshakes = []

    # TCP connection attempts, responses, resets, and handshake latency.
    for packet in packets:
        if packet.get("protocol") != "TCP":
            continue
        src, dst = packet.get("source_ip"), packet.get("destination_ip")
        sport, dport = packet.get("source_port"), packet.get("destination_port")
        timestamp = float(packet.get("timestamp", 0))
        flags = packet.get("tcp_flags") or ""
        if None in (src, dst, sport, dport):
            continue

        is_syn = "S" in flags
        is_ack = "A" in flags
        is_rst = "R" in flags

        if is_syn and not is_ack:
            key = (src, dst, sport, dport)
            syn_attempts[key].append({
                "timestamp": timestamp,
                "packet_number": packet.get("packet_number"),
                "seq": packet.get("tcp_seq"),
                "responded": False,
                "response_type": None,
            })
            scan_traffic[(src, dst)].append({
                "timestamp": timestamp,
                "destination_port": dport,
                "packet_number": packet.get("packet_number"),
            })

        if (is_syn and is_ack) or is_rst:
            reverse_key = (dst, src, dport, sport)
            for attempt in syn_attempts.get(reverse_key, []):
                if attempt["responded"]:
                    continue
                elapsed = timestamp - attempt["timestamp"]
                if elapsed < 0 or elapsed > response_timeout:
                    continue
                if is_syn and is_ack:
                    attempt_seq = attempt.get("seq")
                    response_ack = packet.get("tcp_ack")
                    if (attempt_seq is not None and response_ack is not None
                            and response_ack != ((attempt_seq + 1) & 0xFFFFFFFF)):
                        continue
                attempt["responded"] = True
                attempt["response_type"] = "RST" if is_rst else "SYN-ACK"
                if is_syn and is_ack and elapsed >= delay_threshold:
                    slow_handshakes.append({
                        "src": reverse_key[0], "dst": reverse_key[1],
                        "sport": reverse_key[2], "dport": reverse_key[3],
                        "rtt": elapsed,
                        "syn_packet": attempt.get("packet_number"),
                        "response_packet": packet.get("packet_number"),
                    })

        if is_rst:
            reset_key = (src, dst, sport, dport)
            if reset_key not in reset_connections:
                reset_connections.add(reset_key)
                findings.append(_finding(
                    "TCP reset observed", "Medium",
                    f"TCP RST observed from {src}:{sport} to {dst}:{dport} at {timestamp:.6f}.",
                    [
                        "The destination service may have rejected the connection.",
                        "An endpoint or intermediary may have forcibly closed it.",
                    ],
                    [
                        "Check whether the destination service is running.",
                        "Review endpoint and firewall logs for the connection.",
                    ],
                ))

    # Possible port scans: distinct destination ports in a sliding window.
    scan_pairs = set()
    for (src, dst), attempts in scan_traffic.items():
        attempts.sort(key=lambda item: item["timestamp"])
        left = 0
        ports_in_window = defaultdict(int)
        for right, current in enumerate(attempts):
            current_time = current["timestamp"]
            current_port = current["destination_port"]
            ports_in_window[current_port] += 1
            while left <= right and current_time - attempts[left]["timestamp"] > scan_window:
                old_port = attempts[left]["destination_port"]
                ports_in_window[old_port] -= 1
                if ports_in_window[old_port] == 0:
                    del ports_in_window[old_port]
                left += 1
            if len(ports_in_window) >= scan_threshold:
                scanned_ports = sorted(ports_in_window)
                scan_pairs.add((src, dst))
                first_attempt = attempts[left]
                findings.append(_finding(
                    "Possible TCP port scan", "Medium",
                    f"{src} sent SYN packets to {len(scanned_ports)} distinct ports on {dst} "
                    f"between {first_attempt['timestamp']:.6f} and {current['timestamp']:.6f} "
                    f"({scan_window}-second window). Ports observed: {scanned_ports[:20]}.",
                    [
                        "A host may be checking which services are reachable.",
                        "An authorized vulnerability scanner may be running.",
                        "The traffic may be reconnaissance.",
                    ],
                    [
                        "Confirm whether the source host is an authorized scanner.",
                        "Review firewall and endpoint logs for the destination.",
                        "Investigate unexpected scanning activity.",
                    ],
                ))
                break

    # Unanswered SYN attempts (only when the capture covers the timeout).
    unanswered_groups = defaultdict(list)
    for (src, dst, sport, dport), attempts in syn_attempts.items():
        for attempt in attempts:
            if attempt["responded"]:
                continue
            if capture_end - attempt["timestamp"] < response_timeout:
                continue
            if (src, dst) in scan_pairs:
                continue
            unanswered_groups[(src, dst)].append({
                "source_port": sport,
                "destination_port": dport,
                "timestamp": attempt["timestamp"],
                "packet_number": attempt["packet_number"],
            })

    for (src, dst), attempts in unanswered_groups.items():
        ports = sorted({a["destination_port"] for a in attempts})
        packet_numbers = sorted({a["packet_number"] for a in attempts if a["packet_number"] is not None})
        first_time = min(a["timestamp"] for a in attempts)
        last_time = max(a["timestamp"] for a in attempts)
        findings.append(_finding(
            "TCP connection attempts without observed responses", "Medium",
            f"{src} sent {len(attempts)} SYN packet(s) to {dst} across {len(ports)} destination port(s), "
            f"without a matching SYN-ACK or RST within {response_timeout} seconds. "
            f"Destination ports: {ports[:20]}. Observed time range: {first_time:.6f}–{last_time:.6f}. "
            f"Packet numbers: {packet_numbers[:20]}.",
            [
                "The destination host or service may be unavailable.",
                "A firewall may be filtering the traffic.",
                "The capture may not include the return traffic.",
                "A response may have arrived after the configured timeout.",
            ],
            [
                "Verify destination host and service availability.",
                "Check firewall rules along the communication path.",
                "Capture traffic at both endpoints to confirm whether replies are missing.",
            ],
        ))

    # Repeated SYNs are kept separate from TCP data-segment retransmissions.
    for (src, dst, sport, dport), attempts in syn_attempts.items():
        if len(attempts) > 1:
            findings.append(_finding(
                "Repeated TCP SYN attempts", "Low",
                f"{src}:{sport} sent {len(attempts)} SYN packets to {dst}:{dport}. "
                "This may represent SYN retries or repeated connection attempts.",
                [
                    "The client may be retrying a connection that is not completing.",
                    "Packet loss or delayed responses may be causing retries.",
                ],
                [
                    "Check service availability and packet loss.",
                    "Compare retry timing with the connection timeout.",
                ],
            ))

    # TCP data retransmission heuristic: same directional flow, sequence
    # number, and payload length repeated within a bounded observation window.
    first_segments = {}
    retransmitted_by_flow = defaultdict(list)
    for packet in packets:
        if packet.get("protocol") != "TCP":
            continue
        payload_len = int(packet.get("tcp_payload_length") or 0)
        seq = packet.get("tcp_seq")
        src, dst = packet.get("source_ip"), packet.get("destination_ip")
        sport, dport = packet.get("source_port"), packet.get("destination_port")
        if payload_len <= 0 or seq is None or None in (src, dst, sport, dport):
            continue
        timestamp = float(packet.get("timestamp", 0))
        flow = (src, dst, sport, dport)
        segment_key = flow + (int(seq), payload_len)
        previous = first_segments.get(segment_key)
        if previous is None or timestamp - previous["timestamp"] > retransmission_window:
            first_segments[segment_key] = {
                "timestamp": timestamp,
                "packet_number": packet.get("packet_number"),
            }
        elif timestamp > previous["timestamp"]:
            retransmitted_by_flow[flow].append({
                "seq": int(seq), "payload_length": payload_len,
                "first_packet": previous["packet_number"],
                "repeat_packet": packet.get("packet_number"),
                "delay": timestamp - previous["timestamp"],
            })
    for (src, dst, sport, dport), repeats in retransmitted_by_flow.items():
        unique_segments = {(r["seq"], r["payload_length"]) for r in repeats}
        packet_numbers = sorted({
            n for r in repeats for n in (r["first_packet"], r["repeat_packet"]) if n is not None
        })
        findings.append(_finding(
            "Possible TCP data retransmissions", "Medium",
            f"{src}:{sport} to {dst}:{dport}: {len(repeats)} repeated data segment observation(s) "
            f"across {len(unique_segments)} sequence/payload signature(s) within "
            f"{retransmission_window} seconds. Packet numbers: {packet_numbers[:20]}. "
            "Repeated sequence/payload signatures can also result from duplicate capture points.",
            [
                "Packet loss may have caused the sender to retransmit data.",
                "The receiver may not have acknowledged the original segment.",
                "A capture from multiple interfaces may contain duplicate observations.",
            ],
            [
                "Check TCP sequence and ACK progression at both endpoints.",
                "Inspect interface counters and packet-loss statistics.",
                "Confirm the capture does not combine mirrored traffic from multiple points.",
            ],
        ))

    # DNS failure responses and query-to-response latency.
    dns_queries = defaultdict(list)
    dns_failures = []
    slow_dns = []
    for packet in packets:
        if packet.get("dns_qr") is None:
            continue
        src, dst = packet.get("source_ip"), packet.get("destination_ip")
        sport, dport = packet.get("source_port"), packet.get("destination_port")
        dns_id, qname = packet.get("dns_id"), packet.get("dns_qname") or "<unknown name>"
        transport = packet.get("protocol")
        timestamp = float(packet.get("timestamp", 0))
        if None in (src, dst, sport, dport, dns_id):
            continue

        if int(packet["dns_qr"]) == 0:
            key = (src, dst, sport, dport, int(dns_id), qname, transport)
            dns_queries[key].append({
                "timestamp": timestamp,
                "packet_number": packet.get("packet_number"),
            })
        else:
            rcode = int(packet.get("dns_rcode") or 0)
            if rcode != 0:
                dns_failures.append({
                    "server": src, "client": dst, "name": qname,
                    "rcode": rcode, "timestamp": timestamp,
                    "packet_number": packet.get("packet_number"),
                })
            reverse_key = (dst, src, dport, sport, int(dns_id), qname, transport)
            for query in dns_queries.get(reverse_key, []):
                if query.get("matched"):
                    continue
                elapsed = timestamp - query["timestamp"]
                if elapsed < 0:
                    continue
                query["matched"] = True
                if elapsed >= delay_threshold:
                    slow_dns.append({
                        "client": dst, "server": src, "name": qname,
                        "rtt": elapsed,
                        "query_packet": query.get("packet_number"),
                        "response_packet": packet.get("packet_number"),
                    })
                break

    if dns_failures:
        details = []
        for item in dns_failures[:10]:
            code_name = DNS_RCODE_NAMES.get(item["rcode"], f"RCODE {item['rcode']}")
            details.append(
                f"{item['name']} returned {code_name} from {item['server']} "
                f"to {item['client']} at {item['timestamp']:.6f}"
            )
        has_server_error = any(item["rcode"] in (1, 2, 4, 5) for item in dns_failures)
        findings.append(_finding(
            "DNS failure response observed", "Medium" if has_server_error else "Low",
            f"Observed {len(dns_failures)} DNS response(s) with non-zero response codes: "
            + "; ".join(details) + ("." if len(dns_failures) <= 10 else "; additional responses omitted."),
            [
                "NXDOMAIN can mean the queried name does not exist or was misspelled.",
                "SERVFAIL or REFUSED can indicate resolver, upstream, policy, or zone problems.",
            ],
            [
                "Verify the queried domain name and DNS server configuration.",
                "For SERVFAIL, inspect resolver logs and upstream DNS reachability.",
                "For REFUSED, review DNS server access-control and query policies.",
            ],
        ))

    if slow_dns:
        examples = "; ".join(
            f"{r['name']} {r['rtt']:.3f}s ({r['client']} → {r['server']})"
            for r in slow_dns[:10]
        )
        findings.append(_finding(
            "Slow DNS responses observed", "Low" if max(r["rtt"] for r in slow_dns) < 3 else "Medium",
            f"{len(slow_dns)} matched DNS response(s) took at least {delay_threshold:.3f} seconds. "
            f"Examples: {examples}.",
            [
                "The configured resolver or an upstream DNS server may be responding slowly.",
                "Network congestion, packet loss, or resolver load may increase response time.",
            ],
            [
                "Compare response times across configured DNS resolvers.",
                "Check resolver health, upstream reachability, and packet loss.",
            ],
        ))

    if slow_handshakes:
        examples = "; ".join(
            f"{r['src']}:{r['sport']} → {r['dst']}:{r['dport']} {r['rtt']:.3f}s"
            for r in slow_handshakes[:10]
        )
        findings.append(_finding(
            "Slow TCP connection handshakes observed", "Low" if max(r["rtt"] for r in slow_handshakes) < 3 else "Medium",
            f"{len(slow_handshakes)} matched TCP SYN-to-SYN-ACK handshake(s) took at least "
            f"{delay_threshold:.3f} seconds. Examples: {examples}.",
            [
                "Network path latency or congestion may be increasing round-trip time.",
                "A server under load may be slow to accept new connections.",
                "Packet loss and retransmission may delay handshake completion.",
            ],
            [
                "Compare handshake timing at both endpoints.",
                "Inspect path latency, packet loss, and server load.",
            ],
        ))

    # Detect conflicting ARP sender mappings. Do not infer a host's MAC from
    # arbitrary routed IP traffic: Ethernet source MACs identify the local
    # Layer-2 hop, not necessarily the end-to-end IP source.
    ip_to_macs = defaultdict(set)
    for packet in packets:
        if packet.get("protocol") != "ARP":
            continue
        ip = packet.get("arp_sender_ip")
        mac = packet.get("arp_sender_mac")
        if not ip or not mac or ip in ("0.0.0.0", "::"):
            continue
        normalized_mac = str(mac).lower()
        if normalized_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue
        ip_to_macs[ip].add(normalized_mac)

    for ip, mac_addresses in ip_to_macs.items():
        if len(mac_addresses) > 1:
            mac_details = sorted(mac_addresses)
            findings.append(_finding(
                "Possible duplicate IP address / ARP conflict", "High",
                f"ARP sender IP {ip} was claimed by multiple MAC addresses: "
                + ", ".join(mac_details) + ". This is a conflict indicator, not definitive proof.",
                [
                    "Two devices may be configured with the same IP address.",
                    "A device may have changed network interfaces or MAC address during the capture.",
                    "Proxy ARP, virtualization, spoofing, or multi-point capture may create similar evidence.",
                ],
                [
                    "Check the address leases and static IP assignments for the affected address.",
                    "Inspect ARP tables on the relevant hosts and gateway.",
                    "Verify whether proxy ARP or multiple capture points explain the observations.",
                ],
            ))

    # Explicit Path MTU Discovery feedback. Fragmentation alone is not treated
    # as proof of an MTU mismatch.
    mtu_feedback = []
    for packet in packets:
        if packet.get("protocol") != "ICMP":
            continue
        icmp_type = packet.get("icmp_type")
        icmp_code = packet.get("icmp_code")
        is_ipv4_frag_needed = icmp_type == 3 and icmp_code == 4
        is_ipv6_packet_too_big = icmp_type == 2 and packet.get("ip_version") == 6
        if is_ipv4_frag_needed or is_ipv6_packet_too_big:
            mtu_feedback.append(packet)
    if mtu_feedback:
        examples = []
        for packet in mtu_feedback[:10]:
            mtu = packet.get("icmp_mtu")
            mtu_text = f", advertised MTU {mtu} bytes" if mtu else ""
            examples.append(
                f"packet {packet.get('packet_number', '?')}: {packet.get('source_ip')} → "
                f"{packet.get('destination_ip')}{mtu_text}"
            )
        findings.append(_finding(
            "Possible Path MTU issue indicated", "Medium",
            f"Observed {len(mtu_feedback)} ICMP message(s) indicating that a packet was too large "
            "for a path link (IPv4 fragmentation needed or IPv6 Packet Too Big). "
            + "; ".join(examples) + ".",
            [
                "The packet size may exceed the path MTU.",
                "Path MTU Discovery feedback may be blocked or ignored elsewhere on the path.",
                "A tunnel or encapsulation overhead may reduce the effective path MTU.",
            ],
            [
                "Check interface and tunnel MTU settings along the path.",
                "Allow required ICMP fragmentation-needed and ICMPv6 Packet Too Big messages.",
                "Verify Path MTU Discovery behavior from both endpoints.",
            ],
        ))

    if not findings:
        findings.append(_finding(
            "No issue detected by current checks", "Info",
            "No TCP scan, unanswered SYN, reset, repeated data segment, DNS failure, "
            "observed IP/MAC conflict, explicit MTU feedback, or slow matched response "
            "was detected by the current rules. This does not guarantee the network is free of problems.",
            [], [],
        ))

    return findings
