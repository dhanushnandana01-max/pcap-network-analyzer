
import streamlit as st
import tempfile
import os
import json
import pandas as pd

from packet_parser import analyze_pcap
from diagnosis import diagnose_packets


st.set_page_config(
    page_title="PCAP Network Analyzer",
    page_icon="🔎",
    layout="wide"
)

st.title("🔎 PCAP Network Analyzer")
st.caption(
    "Analyze packet captures, identify suspicious network patterns, "
    "and review evidence-based diagnostic suggestions."
)

# Upload and reset controls
uploaded_file = st.file_uploader(
    "Upload a PCAP file",
    type=["pcap", "pcapng"]
)

col_upload, col_reset = st.columns([4, 1])

with col_reset:
    if st.button("Clear analysis", use_container_width=True):
        st.session_state.pop("analysis_results", None)
        st.rerun()

if uploaded_file:
    st.info(f"Selected file: **{uploaded_file.name}**")

    if st.button("Analyze PCAP", type="primary"):
        temp_path = None

        try:
            suffix = os.path.splitext(uploaded_file.name)[1] or ".pcap"

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=suffix
            ) as temp_file:
                temp_file.write(uploaded_file.getvalue())
                temp_path = temp_file.name

            with st.spinner("Analyzing packets..."):
                packet_details, protocol_counts = analyze_pcap(temp_path)
                findings = diagnose_packets(packet_details)

            st.session_state["analysis_results"] = {
                "filename": uploaded_file.name,
                "packet_details": packet_details,
                "protocol_counts": protocol_counts,
                "findings": findings
            }

        except Exception as error:
            st.error(f"Analysis failed: {error}")

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

results = st.session_state.get("analysis_results")

if results:
    packet_details = results["packet_details"]
    protocol_counts = results["protocol_counts"]
    findings = results["findings"]

    # Protocol counts include packets that may not have extracted details.
    total_packets = sum(protocol_counts.values())

    severity_counts = {
        severity: sum(
            finding.get("severity") == severity
            for finding in findings
        )
        for severity in ["High", "Medium", "Low", "Info"]
    }

    st.divider()
    st.subheader(f"Analysis Results: {results['filename']}")

    # Packet statistics
    metric_cols = st.columns(5)

    metric_cols[0].metric("Total Packets", total_packets)
    metric_cols[1].metric("TCP", protocol_counts.get("TCP", 0))
    metric_cols[2].metric("UDP", protocol_counts.get("UDP", 0))
    metric_cols[3].metric("ICMP", protocol_counts.get("ICMP", 0))
    metric_cols[4].metric("Other", protocol_counts.get("Other", 0))

    # Finding counts
    st.subheader("Finding Summary")
    severity_cols = st.columns(4)

    for column, severity in zip(
        severity_cols,
        ["High", "Medium", "Low", "Info"]
    ):
        column.metric(severity, severity_counts[severity])

    overview_tab, findings_tab, packets_tab, export_tab = st.tabs(
        ["Overview", "Diagnosis", "Packet Details", "Export"]
    )

    # Overview
    with overview_tab:
        st.subheader("Protocol Distribution")

        protocol_df = pd.DataFrame({
            "Protocol": list(protocol_counts.keys()),
            "Packets": list(protocol_counts.values())
        })

        st.bar_chart(
            protocol_df.set_index("Protocol"),
            y="Packets"
        )

        st.subheader("Analysis Status")

        if total_packets == 0:
            st.warning(
                "The capture contains no packets. No meaningful network "
                "diagnosis could be performed."
            )
        elif not packet_details:
            st.warning(
                "Packets were present, but no supported packet details "
                "could be extracted."
            )
        elif not findings or all(
            finding.get("severity") == "Info"
            for finding in findings
        ):
            st.success(
                "No suspicious patterns were detected by the current rules. "
                "This does not guarantee the network is free of problems."
            )
        else:
            st.warning(
                f"{len(findings)} finding(s) generated. "
                "Review the Diagnosis tab for evidence and suggested checks."
            )

    # Diagnosis
    with findings_tab:
        st.subheader("Diagnostic Findings")

        severity_filter = st.multiselect(
            "Filter by severity",
            options=["High", "Medium", "Low", "Info"],
            default=["High", "Medium", "Low", "Info"]
        )

        filtered_findings = [
            finding for finding in findings
            if finding.get("severity", "Info") in severity_filter
        ]

        if not filtered_findings:
            st.info("No findings match the selected severity filters.")
        else:
            for index, finding in enumerate(filtered_findings, start=1):
                severity = finding.get("severity", "Info")
                title = finding.get("title", "Untitled finding")

                with st.expander(
                    f"{index}. {severity} — {title}",
                    expanded=(severity in ["High", "Medium"])
                ):
                    evidence = finding.get(
                        "evidence",
                        "No evidence provided."
                    )

                    if severity == "High":
                        st.error(f"**Evidence:** {evidence}")
                    elif severity == "Medium":
                        st.warning(f"**Evidence:** {evidence}")
                    elif severity == "Low":
                        st.info(f"**Evidence:** {evidence}")
                    else:
                        st.write(f"**Evidence:** {evidence}")

                    causes = finding.get("possible_causes", [])
                    if causes:
                        st.markdown("**Possible causes**")
                        for cause in causes:
                            st.markdown(f"- {cause}")

                    fixes = finding.get("suggested_fixes", [])
                    if fixes:
                        st.markdown("**Suggested checks / fixes**")
                        for fix in fixes:
                            st.markdown(f"- {fix}")

    # Packet details
    with packets_tab:
        st.subheader("Packet Details")

        packet_df = pd.DataFrame(packet_details)

        if packet_df.empty:
            st.info("No supported packet details were extracted.")
        else:
            if "timestamp" in packet_df.columns:
                packet_df["timestamp"] = pd.to_datetime(
                    packet_df["timestamp"],
                    unit="s",
                    errors="coerce"
                )

            st.dataframe(
                packet_df,
                use_container_width=True,
                hide_index=True
            )

            st.download_button(
                label="Download packet details (CSV)",
                data=packet_df.to_csv(index=False).encode("utf-8"),
                file_name="packet_details.csv",
                mime="text/csv"
            )

    # Export
    with export_tab:
        st.subheader("Download Analysis")

        report = {
            "filename": results["filename"],
            "total_packets": total_packets,
            "protocol_counts": protocol_counts,
            "severity_counts": severity_counts,
            "findings": findings
        }

        st.download_button(
            label="Download diagnosis report (JSON)",
            data=json.dumps(report, indent=2, default=str),
            file_name="diagnosis_report.json",
            mime="application/json"
        )

        st.download_button(
            label="Download findings (CSV)",
            data=pd.DataFrame(findings).to_csv(index=False).encode("utf-8"),
            file_name="findings.csv",
            mime="text/csv"
        )
