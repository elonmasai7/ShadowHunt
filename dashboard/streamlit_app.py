import json
import threading
import time

import pandas as pd
import requests
import streamlit as st
from websocket import create_connection

API = "http://backend:8000"
WS = "ws://backend:8000/ws/telemetry"


def api_get(path: str) -> dict:
    return requests.get(f"{API}{path}", timeout=10).json()


def api_post(path: str, payload: dict | None = None) -> dict:
    return requests.post(f"{API}{path}", json=payload or {}, timeout=15).json()


def start_ws_listener() -> None:
    if st.session_state.get("ws_started"):
        return
    st.session_state.ws_started = True
    st.session_state.live_messages = []

    def worker() -> None:
        while True:
            try:
                ws = create_connection(WS, timeout=10)
                while True:
                    raw = ws.recv()
                    msg = json.loads(raw)
                    buf = st.session_state.live_messages
                    buf.append(msg)
                    if len(buf) > 300:
                        del buf[: len(buf) - 300]
            except Exception:
                time.sleep(1)

    threading.Thread(target=worker, daemon=True).start()


st.set_page_config(page_title="ShadowHunt Real Dashboard", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: radial-gradient(circle at top left, #16263a 0%, #0a1018 60%, #080b10 100%); color: #e4eef8; }
    .panel { border: 1px solid #203247; border-radius: 12px; padding: 14px; background: rgba(17,26,39,0.75); }
    </style>
    """,
    unsafe_allow_html=True,
)
st.title("ShadowHunt: Operational Real-Time Threat Simulation")
start_ws_listener()

with st.sidebar:
    st.header("Control Panel")
    profile = st.selectbox("Profile", ["low", "medium", "high"], index=1)
    include_noise = st.checkbox("Include Noise", value=True)
    evasion_mode = st.checkbox("Toggle Evasion Mode", value=False)
    anonymize = st.checkbox("Log Anonymization", value=True)
    technique = st.selectbox("Trigger Specific Technique", ["T1078", "T1003", "T1021", "BRUTE", "EVASION"])
    attack_count = st.slider("Technique Iterations", 5, 60, 15)
    c1, c2 = st.columns(2)
    if c1.button("Start Simulation"):
        api_post("/start_simulation", {"profile": profile, "include_noise": include_noise, "evasion": evasion_mode})
    if c2.button("Stop Simulation"):
        api_post("/stop_sim")
    c3, c4 = st.columns(2)
    if c3.button("Trigger Attack"):
        api_post("/trigger_attack", {"technique": technique, "evasion": evasion_mode, "count": attack_count})
    if c4.button("Reset Lab"):
        api_post("/lab/reset")
    if st.button("Set Legacy v1"):
        api_post("/detection/mode/legacy")
    if st.button("Set Hardened v2"):
        api_post("/detection/mode/hardened")
    api_post("/privacy/anonymize", {"enabled": anonymize})
    if st.button("Export Report (JSON + PDF)"):
        rep = api_get("/generate_report")
        st.success(f"Generated: {rep.get('json_report')} and {rep.get('pdf_report')}")

metrics = api_get("/get_metrics")
coverage = api_get("/coverage")
alerts = api_get("/get_alerts").get("alerts", [])
replay = api_get("/replay").get("events", [])
timeline = coverage.get("summary", [])

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Simulation", "RUNNING" if metrics.get("running") else "IDLE")
k2.metric("CPU %", f"{metrics.get('cpu_percent', 0):.1f}")
k3.metric("Memory %", f"{metrics.get('memory_percent', 0):.1f}")
k4.metric("Network MB", metrics.get("network_mbps", 0))
k5.metric("PCAP Capture", "ON" if metrics.get("pcap_enabled") else "OFF")

c1, c2 = st.columns([2, 1])
with c1:
    st.subheader("Live Attack Feed Timeline")
    if replay:
        feed = pd.DataFrame(replay).tail(80)[["ts", "technique", "action", "result"]]
        st.dataframe(feed, use_container_width=True, height=280)
    else:
        st.info("No live events yet.")
with c2:
    st.subheader("False Positive Rate")
    st.metric("FPR %", f"{metrics.get('false_positive_rate', 0):.2f}")
    st.subheader("ML Anomaly Confidence")
    conf = [a.get("ml_confidence", 0.0) for a in alerts if "ml_confidence" in a][-40:]
    if conf:
        st.line_chart(pd.DataFrame({"confidence": conf}))
    else:
        st.caption("Awaiting ML telemetry")

r1, r2 = st.columns(2)
with r1:
    st.subheader("ATT&CK Matrix Coverage Heatmap")
    cov_rows = coverage.get("summary", [])
    if cov_rows:
        heat = pd.DataFrame(cov_rows)
        heat["coverage"] = (heat["detected"] / heat["executed"].clip(lower=1) * 100).round(2)
        st.dataframe(
            heat[["technique", "executed", "detected", "coverage"]],
            use_container_width=True,
            height=230,
        )
    else:
        st.info("No coverage records.")
with r2:
    st.subheader("Detection vs Evasion Success")
    evasion_success = metrics.get("evasion_success_rate", 0)
    det_rate = coverage.get("coverage_score", 0)
    graph = pd.DataFrame(
        [{"metric": "Detection", "value": det_rate}, {"metric": "Evasion Success", "value": evasion_success}]
    ).set_index("metric")
    st.bar_chart(graph)

s1, s2 = st.columns(2)
with s1:
    st.subheader("Active Alerts Panel")
    if alerts:
        st.dataframe(pd.DataFrame(alerts).tail(100), use_container_width=True, height=300)
    else:
        st.info("No alerts yet.")
with s2:
    st.subheader("Attack Chain Visualization")
    if replay:
        graph_df = pd.DataFrame(replay).tail(60)
        chain = graph_df[["step_number", "technique", "action"]].fillna("")
        st.dataframe(chain, use_container_width=True, height=300)
    else:
        st.caption("Start simulation to populate chain graph.")

st.subheader("Attack Replay Mode")
if replay:
    idx = st.slider("Replay Event", 0, len(replay) - 1, len(replay) - 1)
    st.json(replay[idx])
else:
    st.caption("Replay buffer empty.")
