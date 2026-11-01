
from collections import defaultdict


def diagnose_packets(
    packet_details,
    scan_threshold=10,
    scan_window=10.0,
    response_timeout=3.0,
):
    """
    Rule-based TCP triage for offline packet captures.

    A SYN is reported as unanswered only if the capture extends at least
    response_timeout seconds beyond that SYN and no matching SYN-ACK or RST
    was observed during the timeout.

    Related unanswered attempts are grouped by source and destination IP.
    """
    if scan_threshold < 1:
        raise ValueError("scan_threshold must be at least 1")

    if scan_window < 0:
        raise ValueError("scan_window cannot be negative")

    if response_timeout < 0:
        raise ValueError("response_timeout cannot be negative")

    findings = []

    packets = sorted(
        packet_details,
        key=lambda packet: float(packet.get("timestamp", 0)),
    )

    if not packets:
        return [{
            "title": "No issue detected by current checks",
            "severity": "Info",
            "evidence": "The capture contains no packets to analyze.",
            "possible_causes": [],
            "suggested_fixes": [],
        }]

    capture_end = max(
        float(packet.get("timestamp", 0))
        for packet in packets
    )

    syn_attempts = defaultdict(list)
    scan_traffic = defaultdict(list)
    reset_connections = set()

    # Process packets chronologically so responses only match earlier SYNs.
    for packet in packets:
        if packet.get("protocol") != "TCP":
            continue

        src = packet.get("source_ip")
        dst = packet.get("destination_ip")
        sport = packet.get("source_port")
        dport = packet.get("destination_port")
        timestamp = float(packet.get("timestamp", 0))
        flags = packet.get("tcp_flags") or ""

        if None in (src, dst, sport, dport):
            continue

        is_syn = "S" in flags
        is_ack = "A" in flags
        is_rst = "R" in flags

        # SYN without ACK: initiate a connection attempt.
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

        # SYN-ACK or RST may answer an earlier SYN.
        if (is_syn and is_ack) or is_rst:
            reverse_key = (dst, src, dport, sport)

            for attempt in syn_attempts.get(reverse_key, []):
                if attempt["responded"]:
                    continue

                elapsed = timestamp - attempt["timestamp"]

                if elapsed < 0 or elapsed > response_timeout:
                    continue

                # Validate SYN-ACK acknowledgement when sequence data exists.
                if is_syn and is_ack:
                    attempt_seq = attempt.get("seq")
                    response_ack = packet.get("tcp_ack")

                    if (
                        attempt_seq is not None
                        and response_ack is not None
                        and response_ack != ((attempt_seq + 1) & 0xFFFFFFFF)
                    ):
                        continue

                attempt["responded"] = True
                attempt["response_type"] = "RST" if is_rst else "SYN-ACK"

        # Report each reset direction once.
        if is_rst:
            reset_key = (src, dst, sport, dport)

            if reset_key not in reset_connections:
                reset_connections.add(reset_key)

                findings.append({
                    "title": "TCP reset observed",
                    "severity": "Medium",
                    "evidence": (
                        f"TCP RST observed from {src}:{sport} to "
                        f"{dst}:{dport} at {timestamp:.6f}."
                    ),
                    "possible_causes": [
                        "The destination service may have rejected the connection.",
                        "An endpoint or intermediary may have forcibly closed it.",
                    ],
                    "suggested_fixes": [
                        "Check whether the destination service is running.",
                        "Review endpoint and firewall logs for the connection.",
                    ],
                })

    # Detect possible port scans using a sliding time window.
    scan_pairs = set()

    for (src, dst), attempts in scan_traffic.items():
        attempts.sort(key=lambda item: item["timestamp"])

        left = 0
        ports_in_window = defaultdict(int)

        for right, current in enumerate(attempts):
            current_time = current["timestamp"]
            current_port = current["destination_port"]
            ports_in_window[current_port] += 1

            while (
                left <= right
                and current_time - attempts[left]["timestamp"] > scan_window
            ):
                old_port = attempts[left]["destination_port"]
                ports_in_window[old_port] -= 1

                if ports_in_window[old_port] == 0:
                    del ports_in_window[old_port]

                left += 1

            if len(ports_in_window) >= scan_threshold:
                scanned_ports = sorted(ports_in_window.keys())
                scan_pairs.add((src, dst))

                first_attempt = attempts[left]
                last_attempt = current

                findings.append({
                    "title": "Possible TCP port scan",
                    "severity": "Medium",
                    "evidence": (
                        f"{src} sent SYN packets to "
                        f"{len(scanned_ports)} distinct ports on {dst} "
                        f"between {first_attempt['timestamp']:.6f} and "
                        f"{last_attempt['timestamp']:.6f} "
                        f"({scan_window}-second window). "
                        f"Ports observed: {scanned_ports[:20]}."
                    ),
                    "possible_causes": [
                        "A host may be checking which services are reachable.",
                        "An authorized vulnerability scanner may be running.",
                        "The traffic may be reconnaissance.",
                    ],
                    "suggested_fixes": [
                        "Confirm whether the source host is an authorized scanner.",
                        "Review firewall and endpoint logs for the destination.",
                        "Investigate unexpected scanning activity.",
                    ],
                })

                # One scan finding per source-destination pair.
                break

    # Group unanswered attempts by source and destination IP.
    unanswered_groups = defaultdict(list)

    for (src, dst, sport, dport), attempts in syn_attempts.items():
        for attempt in attempts:
            if attempt["responded"]:
                continue

            # Do not claim a timeout if the capture ended too soon.
            elapsed_at_capture_end = capture_end - attempt["timestamp"]

            if elapsed_at_capture_end < response_timeout:
                continue

            # Scan findings summarize the same source-destination behavior.
            if (src, dst) in scan_pairs:
                continue

            unanswered_groups[(src, dst)].append({
                "source_port": sport,
                "destination_port": dport,
                "timestamp": attempt["timestamp"],
                "packet_number": attempt["packet_number"],
            })

    for (src, dst), attempts in unanswered_groups.items():
        ports = sorted({
            attempt["destination_port"]
            for attempt in attempts
        })

        packet_numbers = sorted({
            attempt["packet_number"]
            for attempt in attempts
            if attempt["packet_number"] is not None
        })

        first_time = min(attempt["timestamp"] for attempt in attempts)
        last_time = max(attempt["timestamp"] for attempt in attempts)

        findings.append({
            "title": "TCP connection attempts without observed responses",
            "severity": "Medium",
            "evidence": (
                f"{src} sent {len(attempts)} SYN packet(s) to {dst} "
                f"across {len(ports)} destination port(s), without a "
                f"matching SYN-ACK or RST within {response_timeout} seconds. "
                f"Destination ports: {ports[:20]}. "
                f"Observed time range: {first_time:.6f}–{last_time:.6f}. "
                f"Packet numbers: {packet_numbers[:20]}."
            ),
            "possible_causes": [
                "The destination host or service may be unavailable.",
                "A firewall may be filtering the traffic.",
                "The capture may not include the return traffic.",
                "A response may have arrived after the configured timeout.",
            ],
            "suggested_fixes": [
                "Verify destination host and service availability.",
                "Check firewall rules along the communication path.",
                "Capture traffic at both endpoints to confirm whether replies are missing.",
            ],
        })

    # Report repeated SYN attempts per flow.
    for (src, dst, sport, dport), attempts in syn_attempts.items():
        if len(attempts) > 1:
            findings.append({
                "title": "Repeated TCP SYN attempts",
                "severity": "Low",
                "evidence": (
                    f"{src}:{sport} sent {len(attempts)} SYN packets "
                    f"to {dst}:{dport}. This may represent retransmissions "
                    f"or repeated connection attempts."
                ),
                "possible_causes": [
                    "The client may be retrying a connection that is not completing.",
                    "Packet loss or delayed responses may be causing retries.",
                ],
                "suggested_fixes": [
                    "Check service availability and packet loss.",
                    "Compare retransmission timing with the connection timeout.",
                ],
            })

    if not findings:
        findings.append({
            "title": "No issue detected by current checks",
            "severity": "Info",
            "evidence": (
                "No unanswered TCP SYN attempts, TCP resets, or possible "
                "port scans were detected by the current rules. "
                "This does not guarantee the network is free of problems."
            ),
            "possible_causes": [],
            "suggested_fixes": [],
        })

    return findings
