import streamlit as st
import requests
import pandas as pd
from datetime import datetime

API = "http://backend:8000"
st.set_page_config(page_title="ShadowHunt System", layout="wide")
st.title("ShadowHunt - Real System Telemetry")

if st.button("Refresh"):
    st.rerun()

try:
    metrics = requests.get(f"{API}/system/metrics", timeout=10).json()
    status = requests.get(f"{API}/system/status", timeout=10).json()
    coverage = requests.get(f"{API}/coverage", timeout=10).json()
except Exception as exc:
    st.error(f"Failed to load system metrics: {exc}")
    st.stop()

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("CPU %", f"{metrics['cpu_percent']:.1f}")
k2.metric("Memory %", f"{metrics['memory_percent']:.1f}")
k3.metric("Disk %", f"{metrics['disk_percent']:.1f}")
k4.metric("Model Ready", "Yes" if status.get("model_present") else "No")
k5.metric("Coverage %", f"{coverage.get('coverage_score', 0.0):.2f}")

st.subheader("Resource Snapshot")
snapshot = pd.DataFrame([
    {"metric": "memory_used_mb", "value": metrics["memory_used_mb"]},
    {"metric": "memory_total_mb", "value": metrics["memory_total_mb"]},
    {"metric": "disk_used_gb", "value": metrics["disk_used_gb"]},
    {"metric": "disk_total_gb", "value": metrics["disk_total_gb"]},
])
st.dataframe(snapshot, use_container_width=True)

st.subheader("Pipeline Status")
st.write(
    {
        "event_files": status.get("event_files", 0),
        "alert_files": status.get("alert_files", 0),
        "detection_mode": status.get("detection_mode", "legacy"),
        "last_updated": datetime.utcnow().isoformat() + "Z",
    }
)
