# PCAP Network Analyzer

A Python project for analyzing network packet captures and identifying a few common TCP connection patterns that may need investigation.

The application uses Scapy to read PCAP files, applies custom detection rules, and presents the results in a Streamlit dashboard.

## What it does

- Reads packet capture files for offline analysis.
- Displays packet counts and protocol statistics for TCP, UDP, ICMP, and other traffic.
- Identifies TCP SYN attempts that do not receive an observed response within a configured time.
- Flags repeated TCP SYN attempts and observed TCP reset packets.
- Detects possible TCP port scans based on SYN packets sent to multiple destination ports within a time window.
- Shows evidence for detected patterns, including relevant endpoints, ports, timestamps, and packet numbers.
- Provides CSV and JSON downloads for analysis results.

## Detection Rules

The current implementation uses the following default thresholds:

| Rule | Detection condition | Severity |
|---|---|---|
| Possible TCP port scan | SYN packets to at least 10 distinct destination ports on the same destination within 10 seconds | Medium |
| Unanswered TCP SYN | No matching SYN-ACK or RST observed within 3 seconds | Medium |
| Repeated TCP SYN attempts | Multiple SYN attempts for the same endpoint pair | Low |
| TCP reset | A TCP RST packet is observed | Medium |

These are simple heuristic rules. They can identify patterns worth investigating, but they do not establish that an attack occurred.

## Built With

- Python
- [Scapy](https://scapy.net/) — reading and parsing packet captures
- [Streamlit](https://streamlit.io/) — dashboard interface
- [pandas](https://pandas.pydata.org/) — tabular data handling

## Project Structure

```text
pcap-network-analyzer/
├── app.py
├── packet_parser.py
├── diagnosis.py
├── make_test_pcaps.py
├── test_parser.py
├── test_all_pcaps.py
├── requirements.txt
├── samples/
└── README.md
```

## Getting Started

### Requirements

- Python 3.10 or newer
- pip

### 1. Clone the repository

```bash
git clone https://github.com/dhanushnandana01-max/pcap-network-analyzer.git
cd pcap-network-analyzer
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Start the application

```bash
streamlit run app.py
```

Open the local URL shown in the terminal, usually `http://localhost:8501`.

## Running the Tests

Run the regression tests against the included sample captures:

```bash
python test_all_pcaps.py
```

The samples include DNS, ICMP, IPv6 ICMP, a normal TCP handshake, possible port scans, repeated SYN attempts, unanswered SYN attempts, and TCP resets.

To regenerate the sample captures:

```bash
python make_test_pcaps.py
```

## Limitations

- The analyzer performs offline PCAP analysis; it does not capture live network traffic.
- Detection is limited to the rules described above.
- Results may include false positives or miss patterns outside the implemented checks.
- A report with no findings does not mean the traffic is safe.
- The project is an educational prototype, not a replacement for a production network security monitoring system.

## Safe Use

Use this tool only with packet captures you own or are authorized to analyze. The included sample captures are intended for testing and demonstration.
