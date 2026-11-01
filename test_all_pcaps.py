"""Run diagnosis against every PCAP in samples/ and report failures clearly."""

from pathlib import Path
from packet_parser import analyze_pcap
from diagnosis import diagnose_packets


def main():
    sample_dir = Path("samples")
    pcap_files = sorted(sample_dir.glob("*.pcap")) + sorted(sample_dir.glob("*.pcapng"))
    if not pcap_files:
        print("No PCAP/PCAPNG files found in samples/")
        return 1

    errors = 0
    for pcap_file in pcap_files:
        print(f"\n{'=' * 60}\nFILE: {pcap_file.name}\n{'=' * 60}")
        try:
            packet_details, protocol_counts = analyze_pcap(str(pcap_file))
            findings = diagnose_packets(packet_details)
            print(f"Packets analyzed: {len(packet_details)}")
            print(f"Protocols: {protocol_counts}")
            for finding in findings:
                print(f"[{finding['severity']}] {finding['title']}")
                print(f"Evidence: {finding['evidence']}")
        except Exception as error:
            errors += 1
            print(f"ERROR processing {pcap_file.name}: {error}")

    print(f"\nCompleted: {len(pcap_files) - errors}/{len(pcap_files)} capture(s) processed successfully.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
