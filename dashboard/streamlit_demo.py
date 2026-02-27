import json
from pathlib import Path

import pandas as pd
import streamlit as st

DATASET = Path("/app/demo_data/demo_dataset.json")

st.set_page_config(page_title="ShadowHunt Demo Mode", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: linear-gradient(145deg, #10161f 0%, #0d121b 45%, #15100f 100%); color: #edf4ff; }
    .glass { border: 1px solid #2b3c4f; border-radius: 14px; padding: 12px; background: rgba(20, 28, 38, 0.68); }
    </style>
    """,
    unsafe_allow_html=True,
)
st.title("ShadowHunt Demo Dashboard (Presentation Mode)")

if not DATASET.exists():
    st.error("Demo dataset missing: /app/demo_data/demo_dataset.json")
    st.stop()

payload = json.loads(DATASET.read_text(encoding="utf-8"))
events = payload["events"]
alerts_v1 = payload["alerts_v1"]
alerts_v2 = payload["alerts_v2"]
privacy = payload["privacy_samples"]

scene = st.selectbox("Animated Threat Scenario", ["Credential Access Story", "Lateral Movement Story", "Evasion Story"])
scene_steps = payload["storytelling"][scene]
step = st.slider("Attack Storytelling Step", 1, len(scene_steps), 1)
st.info(scene_steps[step - 1])

c1, c2, c3, c4 = st.columns(4)
c1.metric("Scenario Events", len(events))
c2.metric("Alerts v1 (Bypassed)", len(alerts_v1))
c3.metric("Alerts v2 (Patched)", len(alerts_v2))
improvement = round(((len(alerts_v2) - len(alerts_v1)) / max(len(alerts_v1), 1)) * 100, 2)
c4.metric("Detection Delta %", improvement)

r1, r2 = st.columns(2)
with r1:
    st.subheader("Detection Improvements: v1 vs v2")
    v1_hits = sum(1 for x in alerts_v1 if x.get("detected"))
    v2_hits = sum(1 for x in alerts_v2 if x.get("detected"))
    compare_df = pd.DataFrame(
        [{"version": "v1", "detected": v1_hits}, {"version": "v2", "detected": v2_hits}]
    ).set_index("version")
    st.bar_chart(compare_df)
with r2:
    st.subheader("Detection vs Evasion")
    evasion_v1 = sum(1 for x in alerts_v1 if x.get("alert_type") == "rule_bypassed")
    evasion_v2 = sum(1 for x in alerts_v2 if x.get("alert_type") == "rule_bypassed")
    ev_df = pd.DataFrame(
        [{"mode": "v1", "evasion_success": evasion_v1}, {"mode": "v2", "evasion_success": evasion_v2}]
    ).set_index("mode")
    st.line_chart(ev_df)

st.subheader("Interactive MITRE ATT&CK Coverage Explorer")
mitre_df = pd.DataFrame(payload["mitre_coverage"])
chosen = st.multiselect("Filter techniques", sorted(mitre_df["technique"].unique()))
if chosen:
    mitre_df = mitre_df[mitre_df["technique"].isin(chosen)]
st.dataframe(mitre_df, use_container_width=True)

s1, s2 = st.columns(2)
with s1:
    st.subheader("Privacy Comparison: Raw vs Anonymized")
    st.dataframe(pd.DataFrame(privacy), use_container_width=True, height=240)
with s2:
    st.subheader("CTF-Style Scoring")
    points = payload["ctf_score"]
    st.metric("Blue Team Score", points["blue_team"])
    st.metric("Red Team Score", points["red_team"])
    st.metric("Privacy Bonus", points["privacy_bonus"])
    st.metric("Total", points["total"])

st.subheader("Preloaded Telemetry Feed")
feed = pd.DataFrame(events)[["ts", "technique", "action", "result"]]
st.dataframe(feed, use_container_width=True, height=320)
