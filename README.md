# PCAP Network Analyzer

A web-based network traffic analysis tool that examines uploaded packet-capture files, summarizes network activity, detects selected suspicious patterns and troubleshooting indicators, and presents evidence-based diagnostic suggestions.

**Live application:** https://pcap-network-analyzer.streamlit.app/  
**Source code:** https://github.com/dhanushnandana01-max/pcap-network-analyzer

---

## What can the website do?

### 1. Upload and analyze packet captures

- Upload a packet-capture file through the web interface.
- Analyze captured traffic offline; the application does not need to generate network traffic to inspect a capture.
- Extract packet metadata such as timestamps, source and destination IP addresses, protocols, port numbers, TCP flags, and selected protocol-specific fields.

The parser supports PCAP/PCAPNG input through Scapy. Analysis is limited to the packets and fields available in the uploaded capture.

### 2. View a network-traffic overview

The **Overview** section presents a quick summary of the selected capture, including:

- Total packets analyzed.
- TCP, UDP, and ICMP packet counts (ARP packets are retained for diagnostics and included in the parser's `Other` count).
- Protocol distribution visualization.
- Finding counts grouped by severity: High, Medium, Low, and Info.
- A quick summary indicating whether the current rules reported findings.

### 3. Detect selected network issues

The diagnosis engine applies rule-based checks to the captured packets. Current checks include:

| Detection | What the analyzer looks for |
|---|---|
| Possible TCP port scan | SYN packets from one source to at least 10 distinct destination ports on one destination within the default 10-second window. |
| TCP connection attempts without observed responses | TCP SYN attempts without a matching SYN-ACK or RST, provided the capture extends at least the default 3-second response timeout beyond the attempt. |
| Repeated TCP SYN attempts | Multiple SYN attempts for the same source/destination address and port combination. These may be retries or separate connection attempts. |
| TCP resets | TCP packets carrying the RST flag. |
| Possible TCP data retransmissions | Repeated same-direction TCP data segments with the same sequence number and payload length, observed within the default 60-second window. |
| DNS failure responses | DNS responses with a non-zero response code, including NXDOMAIN, SERVFAIL, and REFUSED. |
| Slow DNS responses | Matched DNS query/response pairs whose observed response time meets or exceeds the default 1-second threshold. |
| Possible duplicate IP / ARP conflict | The same ARP sender IP address claimed by more than one sender MAC address in the capture. |
| Possible Path MTU issue | IPv4 ICMP Fragmentation Needed messages or IPv6 ICMP Packet Too Big messages. |
| Slow TCP connection handshakes | Matched TCP SYN-to-SYN-ACK handshakes whose observed round-trip time meets or exceeds the default 1-second threshold. |

The default thresholds are configurable in `diagnose_packets()` in `diagnosis.py`:

```python
diagnose_packets(
    packet_details,
    scan_threshold=10,
    scan_window=10.0,
    response_timeout=3.0,
    retransmission_window=60.0,
    delay_threshold=1.0,
)
```

All time values are in seconds.

### 4. Inspect diagnostic findings

The **Diagnosis** section displays detected findings with severity levels:

- **High**
- **Medium**
- **Low**
- **Info**

Users can filter findings by severity and expand a finding to inspect its:

- Title and severity.
- Evidence observed in the capture.
- Possible causes.
- Suggested troubleshooting steps.

The application reports indicators and supporting packet evidence; it does not claim that a heuristic finding proves a root cause.

### 5. Inspect packet-level details

The **Packet Details** section displays the parsed packet records in a table. Available fields include packet number, timestamp, source and destination IP addresses, protocol, source and destination ports, and TCP flags when applicable.

Packet details can be downloaded as a CSV file for further analysis.

### 6. Export analysis reports

The **Export** section provides downloads for:

- A JSON diagnosis report.
- A CSV file containing diagnostic findings.

Packet details can also be downloaded separately from the Packet Details section.

---

## Technology stack

- **Python** — application and analysis logic.
- **Streamlit** — interactive web interface.
- **Scapy** — PCAP/PCAPNG parsing and packet-layer inspection.
- **Pandas** — tabular packet and finding data handling.

---

## Run locally

### Prerequisites

- Python installed.
- Git installed (to clone the repository).

### 1. Clone the repository

```bash
git clone https://github.com/dhanushnandana01-max/pcap-network-analyzer.git
cd pcap-network-analyzer
```

### 2. Create and activate a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Start the application

```bash
streamlit run app.py
```

Streamlit will print a local URL in the terminal. Open that URL in a browser to use the application.

---

## Run the tests

Run the diagnosis unit tests:

```bash
python -m unittest -v test_diagnostics.py
```

Run the PCAP regression suite:

```bash
python test_all_pcaps.py
```

The unit tests use synthetic packet metadata to test the diagnosis rules. The PCAP regression suite analyzes the capture files located in `samples/` and requires the project dependencies to be installed.

---

## Important limitations

This project is a packet-capture triage tool, not a full network-monitoring or intrusion-prevention system.

- **Offline analysis:** it analyzes uploaded captures; it does not perform continuous live packet capture or automatically block traffic.
- **Capture visibility matters:** packets absent from the capture cannot be analyzed. Missing return traffic may be caused by capture placement or an incomplete capture, not necessarily by a network fault.
- **Heuristic detections are not proof:** port scans, retransmissions, delays, and ARP conflicts are reported from observable patterns and should be investigated in context.
- **TCP retransmission heuristic:** matching sequence numbers and payload lengths can also appear when traffic is duplicated by capture configuration or multiple observation points.
- **DNS interpretation:** NXDOMAIN can be a valid answer when a queried name does not exist; a non-zero DNS response code is not automatically a resolver malfunction.
- **ARP conflict visibility:** a possible conflict is only detectable when claims for the same sender IP from different MAC addresses appear in the capture. Proxy ARP, a changed interface, virtualization, or a multi-point capture can create similar observations.
- **MTU interpretation:** the analyzer looks for explicit Path MTU Discovery feedback. Ordinary IP fragmentation alone is not treated as proof of an MTU mismatch.
- **Delay thresholds:** the default 1-second threshold is a configurable starting point, not a universal definition of slow networking. Network conditions and application requirements vary.
- **No automatic remediation:** suggested fixes are troubleshooting guidance. The application does not change device, firewall, DNS, or router configurations.

A result of **“No issue detected by current checks”** means only that these rules did not find a matching pattern in the visible packets. It does not guarantee that the network is healthy or secure.

---

## Project structure

```text
pcap-network-analyzer/
├── app.py                  # Streamlit application interface
├── packet_parser.py        # PCAP/PCAPNG parsing and packet metadata extraction
├── diagnosis.py            # Rule-based network diagnostics
├── requirements.txt        # Python dependencies
├── samples/                # Sample packet captures used for regression testing
├── test_diagnostics.py     # Unit tests for diagnosis rules
├── test_all_pcaps.py       # Runs diagnosis against sample captures
└── README.md
```

Additional development and test files may be present in the repository.

---

## Disclaimer

This tool is intended for educational, diagnostic, and authorized network-troubleshooting use. Analyze packet captures that you own or are authorized to inspect. Findings should be validated with appropriate network tools, endpoint logs, and administrator review before making operational decisions.
