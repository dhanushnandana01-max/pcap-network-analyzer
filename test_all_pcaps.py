
from pathlib import Path
from packet_parser import analyze_pcap
from diagnosis import diagnose_packets

sample_dir = Path("samples")
pcap_files = sorted(sample_dir.glob("*.pcap"))

if not pcap_files:
    print("No PCAP files found in samples/")
    raise SystemExit

for pcap_file in pcap_files:
    print(f"\n{'=' * 60}")
    print(f"FILE: {pcap_file.name}")
    print("=" * 60)

    try:
        packet_details, protocol_counts = analyze_pcap(str(pcap_file))
        findings = diagnose_packets(packet_details)

        print(f"Packets: {len(packet_details)}")
        print(f"Protocols: {protocol_counts}")

        for finding in findings:
            print(
                f"[{finding['severity']}] "
                f"{finding['title']}"
            )
            print(f"Evidence: {finding['evidence']}")

    except Exception as error:
        print(f"ERROR processing {pcap_file.name}: {error}")
