from pathlib import Path

from scapy.all import (
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    Raw,
    wrpcap,
)
from scapy.layers.inet6 import ICMPv6EchoRequest


SAMPLES_DIR = Path("samples")
SAMPLES_DIR.mkdir(exist_ok=True)

BASE_TIME = 1760000000.0

# Explicit MAC addresses avoid Scapy attempting network neighbor resolution.
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def save_pcap(filename, packets):
    """Save packets to the samples directory."""
    path = SAMPLES_DIR / filename
    wrpcap(str(path), packets)
    print(f"Created: {path}")


def make_tcp_packet(src, dst, sport, dport, flags, seq=1000, ack=0):
    """Create a TCP packet with explicit Ethernet and IP addresses."""
    return (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=src, dst=dst)
        / TCP(
            sport=sport,
            dport=dport,
            flags=flags,
            seq=seq,
            ack=ack,
        )
    )


def create_dns_query():
    packet = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / Raw(load=b"DNS query")
    )
    packet.time = BASE_TIME
    save_pcap("dns_query.pcap", [packet])


def create_icmp_echo():
    packets = []

    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / ICMP(type=8, code=0)
    )
    request.time = BASE_TIME

    reply = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="192.168.1.1", dst="192.168.1.10")
        / ICMP(type=0, code=0)
    )
    reply.time = BASE_TIME + 0.1

    packets.extend([request, reply])
    save_pcap("icmp_echo.pcap", packets)


def create_ipv6_icmp_echo():
    packet = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / ICMPv6EchoRequest()
    )
    packet.time = BASE_TIME
    save_pcap("ipv6_icmp_echo.pcap", [packet])


def create_normal_tcp_handshake():
    syn = make_tcp_packet(
        "192.168.1.10", "192.168.1.20",
        50000, 80, "S", seq=1000,
    )
    syn.time = BASE_TIME

    syn_ack = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(
            sport=80,
            dport=50000,
            flags="SA",
            seq=2000,
            ack=1001,
        )
    )
    syn_ack.time = BASE_TIME + 0.1

    ack = make_tcp_packet(
        "192.168.1.10", "192.168.1.20",
        50000, 80, "A", seq=1001, ack=2001,
    )
    ack.time = BASE_TIME + 0.2

    save_pcap("normal_tcp_handshake.pcap", [syn, syn_ack, ack])


def create_possible_port_scan():
    packets = []

    for i, port in enumerate(range(20, 32)):
        packet = make_tcp_packet(
            "192.168.1.20", "192.168.1.50",
            51000 + i, port, "S", seq=1000 + i,
        )
        packet.time = BASE_TIME + i * 0.5
        packets.append(packet)

    save_pcap("possible_port_scan.pcap", packets)


def create_repeated_syn():
    packets = []

    for i in range(3):
        packet = make_tcp_packet(
            "192.168.1.30", "192.168.1.60",
            51000, 443, "S", seq=1000,
        )
        packet.time = BASE_TIME + i * 1.0
        packets.append(packet)

    save_pcap("repeated_syn.pcap", packets)


def create_spread_out_ports():
    packets = []

    for i, port in enumerate(range(1000, 1012)):
        packet = make_tcp_packet(
            "192.168.1.40", "192.168.1.70",
            52000 + i, port, "S", seq=2000 + i,
        )
        packet.time = BASE_TIME + i * 15.0
        packets.append(packet)

    save_pcap("spread_out_ports.pcap", packets)


def create_tcp_reset():
    packet = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="192.168.1.80", dst="192.168.1.50")
        / TCP(
            sport=443,
            dport=52000,
            flags="R",
            seq=3000,
            ack=0,
        )
    )
    packet.time = BASE_TIME
    save_pcap("tcp_reset.pcap", [packet])


def create_unanswered_syn():
    syn = make_tcp_packet(
        "192.168.1.50", "192.168.1.90",
        53000, 8080, "S", seq=4000,
    )
    syn.time = BASE_TIME

    # A later unrelated packet extends the capture beyond the 3-second
    # response timeout without providing a response to the SYN.
    later_packet = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="192.168.1.99", dst="192.168.1.100")
        / UDP(sport=40000, dport=40001)
        / Raw(load=b"capture continues")
    )
    later_packet.time = BASE_TIME + 4.0

    save_pcap("unanswered_syn.pcap", [syn, later_packet])


def create_test_pcap():
    """Create a basic TCP handshake test capture."""
    syn = make_tcp_packet(
        "10.0.0.1", "10.0.0.2",
        40000, 443, "S", seq=5000,
    )
    syn.time = BASE_TIME

    syn_ack = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(
            sport=443,
            dport=40000,
            flags="SA",
            seq=6000,
            ack=5001,
        )
    )
    syn_ack.time = BASE_TIME + 0.1

    ack = make_tcp_packet(
        "10.0.0.1", "10.0.0.2",
        40000, 443, "A", seq=5001, ack=6001,
    )
    ack.time = BASE_TIME + 0.2

    save_pcap("test.pcap", [syn, syn_ack, ack])


def main():
    create_dns_query()
    create_icmp_echo()
    create_ipv6_icmp_echo()
    create_normal_tcp_handshake()
    create_possible_port_scan()
    create_repeated_syn()
    create_spread_out_ports()
    create_tcp_reset()
    create_unanswered_syn()
    create_test_pcap()

    print("\nAll test PCAPs generated.")


if __name__ == "__main__":
    main()