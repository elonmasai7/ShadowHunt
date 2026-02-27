import pandas as pd
import requests
import streamlit as st

API = "http://backend:8000"

st.set_page_config(page_title="ShadowHunt", layout="wide")
st.title("ShadowHunt - ATT&CK Simulation Monitor")

with st.sidebar:
    st.header("Adversary Emulation")
    profile = st.selectbox("Profile", ["low", "medium", "high"], index=1)
    include_noise = st.checkbox("Include realistic noise", value=True)
    evasion = st.checkbox("Use benign encoded markers (evasion)", value=False)

    if st.button("Run Attack Chain"):
        requests.post(
            f"{API}/start_chain",
            json={"profile": profile, "include_noise": include_noise, "evasion": evasion},
            timeout=15,
        )

    st.divider()
    st.header("Detection Hardening")
    if st.button("Set Legacy Mode"):
        requests.post(f"{API}/detection/mode/legacy", timeout=10)
    if st.button("Set Hardened Mode"):
        requests.post(f"{API}/detection/mode/hardened", timeout=10)

st.subheader("Technique Simulators")
c1, c2, c3 = st.columns(3)
if c1.button("Run T1078"):
    requests.post(f"{API}/start_sim", json={"technique": "T1078"}, timeout=10)
if c2.button("Run T1003"):
    requests.post(f"{API}/start_sim", json={"technique": "T1003"}, timeout=10)
if c3.button("Run T1021"):
    requests.post(f"{API}/start_sim", json={"technique": "T1021"}, timeout=10)

try:
    report = requests.get(f"{API}/report", timeout=10).json()
    alerts = requests.get(f"{API}/detect", timeout=10).json().get("alerts", [])
    coverage = requests.get(f"{API}/coverage", timeout=10).json()
except Exception as exc:
    st.error(f"Backend unavailable: {exc}")
    st.stop()

event_counts = report.get("event_counts", {})

st.subheader("Event Volume")
if event_counts:
    st.bar_chart(pd.DataFrame([event_counts]).T.rename(columns={0: "count"}))
else:
    st.info("No simulation events yet.")

st.subheader("Coverage Score")
k1, k2, k3, k4 = st.columns(4)
k1.metric("Coverage %", f"{coverage.get('coverage_score', 0.0):.2f}")
totals = coverage.get("totals", {})
k2.metric("Executed", totals.get("executed", 0))
k3.metric("Detected", totals.get("detected", 0))
k4.metric("False Positives", totals.get("false_positives", 0))
st.caption(f"Detection mode: {coverage.get('detection_mode', 'legacy')}")

st.subheader("ATT&CK Gap Analysis")
summary_df = pd.DataFrame(coverage.get("summary", []))
if not summary_df.empty:
    st.dataframe(summary_df, use_container_width=True)
    gap_df = pd.DataFrame(coverage.get("gaps", []))
    if not gap_df.empty:
        st.warning("Coverage gaps detected")
        st.dataframe(gap_df, use_container_width=True)
    else:
        st.success("No ATT&CK gaps for currently simulated techniques")
else:
    st.info("No coverage data yet.")

st.subheader("Recent Alerts (Privacy-preserved)")
if alerts:
    st.dataframe(pd.DataFrame(alerts).tail(100), use_container_width=True)
else:
    st.info("No alerts yet.")
