"""Deterministic unit tests for diagnosis rules; no PCAP or Scapy required."""

import unittest
from diagnosis import diagnose_packets


def pkt(number, timestamp, protocol="TCP", **kwargs):
    base = {
        "packet_number": number,
        "timestamp": float(timestamp),
        "protocol": protocol,
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": 50000,
        "destination_port": 443,
        "tcp_flags": "",
        "tcp_seq": None,
        "tcp_ack": None,
        "tcp_payload_length": 0,
    }
    base.update(kwargs)
    return base


class DiagnosisTests(unittest.TestCase):
    def titles(self, packets, **kwargs):
        return {item["title"] for item in diagnose_packets(packets, **kwargs)}

    def test_existing_tcp_reset(self):
        packets = [pkt(1, 1, tcp_flags="R")]
        self.assertIn("TCP reset observed", self.titles(packets))

    def test_existing_port_scan(self):
        packets = [
            pkt(i, i * 0.1, source_port=40000 + i, destination_port=20 + i,
                tcp_flags="S", tcp_seq=i)
            for i in range(1, 11)
        ]
        self.assertIn("Possible TCP port scan", self.titles(packets))

    def test_tcp_data_retransmission(self):
        packets = [
            pkt(1, 1, tcp_seq=1000, tcp_payload_length=120),
            pkt(2, 1.4, tcp_seq=1000, tcp_payload_length=120),
        ]
        self.assertIn("Possible TCP data retransmissions", self.titles(packets))

    def test_dns_nxdomain(self):
        packets = [pkt(1, 1, "UDP", source_port=53, destination_port=53000,
                       source_ip="8.8.8.8", destination_ip="10.0.0.1",
                       dns_qr=1, dns_rcode=3, dns_id=77, dns_qname="missing.example")]
        self.assertIn("DNS failure response observed", self.titles(packets))

    def test_arp_conflict(self):
        packets = [
            pkt(1, 1, "ARP", source_ip=None, destination_ip=None,
                arp_sender_ip="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:aa"),
            pkt(2, 2, "ARP", source_ip=None, destination_ip=None,
                arp_sender_ip="10.0.0.9", arp_sender_mac="bb:bb:bb:bb:bb:bb"),
        ]
        self.assertIn("Possible duplicate IP address / ARP conflict", self.titles(packets))

    def test_ipv4_mtu_feedback(self):
        packets = [pkt(1, 1, "ICMP", ip_version=4, icmp_type=3,
                       icmp_code=4, icmp_mtu=1400)]
        self.assertIn("Possible Path MTU issue indicated", self.titles(packets))

    def test_slow_dns_response(self):
        packets = [
            pkt(1, 1, "UDP", source_ip="10.0.0.1", destination_ip="8.8.8.8",
                source_port=53000, destination_port=53, dns_qr=0, dns_rcode=0,
                dns_id=99, dns_qname="example.com"),
            pkt(2, 2.5, "UDP", source_ip="8.8.8.8", destination_ip="10.0.0.1",
                source_port=53, destination_port=53000, dns_qr=1, dns_rcode=0,
                dns_id=99, dns_qname="example.com"),
        ]
        self.assertIn("Slow DNS responses observed", self.titles(packets))

    def test_slow_tcp_handshake(self):
        packets = [
            pkt(1, 1, source_ip="10.0.0.1", destination_ip="10.0.0.2",
                source_port=50000, destination_port=443, tcp_flags="S", tcp_seq=100),
            pkt(2, 2.5, source_ip="10.0.0.2", destination_ip="10.0.0.1",
                source_port=443, destination_port=50000, tcp_flags="SA",
                tcp_seq=200, tcp_ack=101),
        ]
        self.assertIn("Slow TCP connection handshakes observed", self.titles(packets))

    def test_fast_tcp_handshake_is_not_flagged_as_slow(self):
        packets = [
            pkt(1, 1, source_ip="10.0.0.1", destination_ip="10.0.0.2",
                source_port=50000, destination_port=443, tcp_flags="S", tcp_seq=100),
            pkt(2, 1.1, source_ip="10.0.0.2", destination_ip="10.0.0.1",
                source_port=443, destination_port=50000, tcp_flags="SA",
                tcp_seq=200, tcp_ack=101),
        ]
        self.assertNotIn("Slow TCP connection handshakes observed", self.titles(packets))

    def test_capture_too_short_does_not_claim_unanswered_syn(self):
        packets = [
            pkt(1, 1, tcp_flags="S", tcp_seq=100),
            pkt(2, 2, "UDP", source_port=1000, destination_port=1001),
        ]
        self.assertNotIn("TCP connection attempts without observed responses", self.titles(packets))

    def test_finding_schema_unchanged(self):
        result = diagnose_packets([pkt(1, 1, tcp_flags="R")])[0]
        self.assertEqual(
            set(result),
            {"title", "severity", "evidence", "possible_causes", "suggested_fixes"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
