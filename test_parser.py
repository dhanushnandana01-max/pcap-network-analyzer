
from packet_parser import analyze_pcap
from diagnosis import diagnose_packets

file_path = "samples/repeated_syn.pcap"

packet_details, protocol_counts = analyze_pcap(file_path)

print(f"Total packets: {len(packet_details)}")

print("\nProtocol counts:")
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")

print("\nFirst 5 packets:")
for packet in packet_details[:5]:
    print(packet)

findings = diagnose_packets(packet_details)

print("\n========== DIAGNOSIS ==========")

for finding in findings:
    print(f"\n[{finding['severity']}] {finding['title']}")
    print("Evidence:", finding["evidence"])

    for cause in finding["possible_causes"]:
        print("Possible cause:", cause)

    for fix in finding["suggested_fixes"]:
        print("Suggested check/fix:", fix)
