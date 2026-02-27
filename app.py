import streamlit as st
import pandas as pd
from pathlib import Path

from pii_detection import file_scanner, pii_detector
from risk_scoring.pii_classification import classify_pii_dicts
from utils import temp_storage

# Page config
st.set_page_config(
    page_title="AI PII Leakage Scanner",
    page_icon="🔎",
    layout="wide"
)

# Title
st.title("🔎 AI-Powered PII Leakage Scanner")
st.markdown("Upload a file to detect exposed Personal Identifiable Information (PII).")

# File uploader
uploaded_file = st.file_uploader(
    "Upload a file (txt, py, json)",
    type=["txt", "py", "json"]
)

# Scan button
scan_button = st.button("🚀 Scan File")


def analyze_uploaded_file(uploaded_file):
    """
    Run the actual PII detection + classification pipeline on the uploaded file.

    Returns:
        df: DataFrame with columns [Type, Value, File, Line, Risk]
        overall_score: int 0–100
        risk_level: str ("Low", "Medium", "High")
    """
    raw_bytes = uploaded_file.getvalue()

    # Scan bytes into LineRecord stream.
    records_iter = list(
        file_scanner.scan_bytes(
            raw_bytes,
            filename=uploaded_file.name,
        )
    )

    # Detect PII dictionaries.
    pii_dicts = pii_detector.detect_pii_dicts(records_iter)

    # If nothing found, return empty results and low risk.
    if not pii_dicts:
        empty_df = pd.DataFrame(columns=["Type", "Value", "File", "Line", "Risk"])
        return empty_df, 0, "Low"

    # Classify PII into risk levels / severity weights.
    classified = classify_pii_dicts(pii_dicts)

    # Build table for display.
    display_rows = []
    severity_scores = []
    for item in classified:
        display_rows.append(
            {
                "Type": item["type"].title(),
                "Value": item["value"],
                "File": Path(item["file"]).name,
                "Line": item["line_number"],
                "Risk": item["risk_level"].title(),
            }
        )
        severity_scores.append(float(item["severity_weight"]))

    df = pd.DataFrame(display_rows)

    # Simple aggregation: average severity_weight mapped to 0–100.
    avg_severity = sum(severity_scores) / len(severity_scores)
    overall_score = int(round(avg_severity * 100))

    if overall_score >= 70:
        risk_level = "High"
    elif overall_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return df, overall_score, risk_level

# Session key for last scan id. PII is never stored in session_state; only the id.
# Actual results live in temp_storage and expire after TTL (default 10 minutes).
SCAN_ID_KEY = "pii_last_scan_id"


def _get_display_payload(scan_id: str):
    """Return stored (df, overall_score, risk_level) if scan_id is still valid."""
    payload = temp_storage.get(scan_id)
    if payload is None:
        return None
    return payload.get("df"), payload.get("overall_score"), payload.get("risk_level")


# When Scan is clicked
if scan_button:

    if uploaded_file is None:
        st.warning("⚠️ Please upload a file before scanning.")
    else:
        st.success("✅ File uploaded successfully. Scanning...")

        # Run real backend pipeline on the uploaded file.
        df, overall_score, risk_level = analyze_uploaded_file(uploaded_file)

        # Store results in memory only, with TTL (default 10 min). No disk storage.
        display_payload = {
            "df": df,
            "overall_score": overall_score,
            "risk_level": risk_level,
        }
        scan_id = temp_storage.add(display_payload, ttl_seconds=temp_storage.DEFAULT_TTL_SECONDS)
        st.session_state[SCAN_ID_KEY] = scan_id

        # Layout columns
        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("📋 Detected PII")
            if df.empty:
                st.info("No PII detected in this file.")
            else:
                st.dataframe(df, use_container_width=True)

        with col2:
            st.subheader("🚨 Overall Risk Score")
            st.metric(label="Risk Score", value=f"{overall_score}/100")

            if risk_level == "High":
                st.error("🔴 High Risk")
            elif risk_level == "Medium":
                st.warning("🟠 Medium Risk")
            else:
                st.success("🟢 Low Risk")

        # Mitigation Section
        st.markdown("---")
        with st.expander("🛡 Mitigation Recommendations"):
            st.write("""
            • Remove hardcoded credentials  
            • Use environment variables  
            • Rotate exposed secrets immediately  
            • Apply role-based access control  
            • Enable monitoring and logging  
            """)

else:
    # Show last scan results from temp storage if still valid (within TTL).
    last_scan_id = st.session_state.get(SCAN_ID_KEY)
    if last_scan_id:
        result = _get_display_payload(last_scan_id)
        if result is not None:
            df, overall_score, risk_level = result
            col1, col2 = st.columns([2, 1])
            with col1:
                st.subheader("📋 Detected PII (last scan)")
                if df.empty:
                    st.info("No PII detected in this file.")
                else:
                    st.dataframe(df, use_container_width=True)
            with col2:
                st.subheader("🚨 Overall Risk Score")
                st.metric(label="Risk Score", value=f"{overall_score}/100")
                if risk_level == "High":
                    st.error("🔴 High Risk")
                elif risk_level == "Medium":
                    st.warning("🟠 Medium Risk")
                else:
                    st.success("🟢 Low Risk")
            st.caption("Results are held in memory only and expire after 10 minutes.")
        else:
            st.info("Upload a file and click 'Scan File' to begin.")
            if SCAN_ID_KEY in st.session_state:
                del st.session_state[SCAN_ID_KEY]
    else:
        st.info("Upload a file and click 'Scan File' to begin.")