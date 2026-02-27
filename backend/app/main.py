from datetime import datetime, timezone
import glob
import json
import os
import subprocess

from fastapi import FastAPI
from pydantic import BaseModel
import psutil

app = FastAPI(title="ShadowHunt API", version="0.2.0")


class SimRequest(BaseModel):
    technique: str


class ChainRequest(BaseModel):
    profile: str = "medium"
    include_noise: bool = True
    evasion: bool = False


SIM_MAP = {
    "T1078": "/simulations/t1078_valid_accounts_sim.py",
    "T1003": "/simulations/t1003_credential_access_sim.py",
    "T1021": "/simulations/t1021_lateral_movement_sim.py",
}
PROFILES = ["low", "medium", "high"]


@app.get("/")
def root():
    return {"service": "shadowhunt-backend", "status": "ok"}


@app.get("/profiles")
def profiles():
    return {"profiles": PROFILES}


@app.post("/start_sim")
def start_sim(req: SimRequest):
    script = SIM_MAP.get(req.technique)
    if not script:
        return {"ok": False, "error": "Unsupported technique"}
    subprocess.Popen(["python", script])
    return {"ok": True, "started": req.technique}


@app.post("/start_chain")
def start_chain(req: ChainRequest):
    if req.profile not in PROFILES:
        return {"ok": False, "error": "Unsupported profile"}

    cmd = ["python", "/simulations/attack_chain_sim.py", "--profile", req.profile]
    if req.include_noise:
        cmd.append("--noise")
    if req.evasion:
        cmd.append("--evasion")

    subprocess.Popen(cmd)
    return {
        "ok": True,
        "started": "attack_chain",
        "profile": req.profile,
        "noise": req.include_noise,
        "evasion": req.evasion,
    }


@app.post("/detection/mode/{mode}")
def set_detection_mode(mode: str):
    if mode not in ["legacy", "hardened"]:
        return {"ok": False, "error": "mode must be legacy or hardened"}

    subprocess.run(["python", "/simulations/set_detection_mode.py", "--mode", mode], check=False)
    return {"ok": True, "mode": mode}


@app.get("/detect")
def detect():
    path = "/data/alerts/ml_alerts_private.jsonl"
    if not os.path.exists(path):
        return {"alerts": []}

    alerts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            alerts.append(json.loads(line))
    return {"alerts": alerts[-200:]}


@app.get("/coverage")
def coverage():
    path = "/data/alerts/coverage.json"
    if not os.path.exists(path):
        return {
            "coverage_score": 0.0,
            "summary": [],
            "gaps": [],
            "totals": {"executed": 0, "detected": 0, "false_positives": 0},
            "detection_mode": "legacy",
        }

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/report")
def report():
    files = glob.glob("/data/events/*.jsonl")
    counts = {}
    for p in files:
        name = os.path.basename(p)
        key = name.replace("_events.jsonl", "").upper()
        with open(p, "r", encoding="utf-8") as f:
            counts[key] = sum(1 for _ in f)
    return {"event_counts": counts}


@app.get("/system/metrics")
def system_metrics():
    disk = psutil.disk_usage("/")
    mem = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=0.2)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "memory_used_mb": round(mem.used / (1024 * 1024), 2),
        "memory_total_mb": round(mem.total / (1024 * 1024), 2),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / (1024 * 1024 * 1024), 2),
        "disk_total_gb": round(disk.total / (1024 * 1024 * 1024), 2),
    }


@app.get("/system/status")
def system_status():
    event_files = glob.glob("/data/events/*.jsonl")
    alert_files = glob.glob("/data/alerts/*.jsonl")
    mode_file = "/data/config/detection_mode.json"
    mode = "legacy"
    if os.path.exists(mode_file):
        with open(mode_file, "r", encoding="utf-8") as f:
            mode = json.load(f).get("mode", "legacy")

    return {
        "event_files": len(event_files),
        "alert_files": len(alert_files),
        "model_present": os.path.exists("/data/models/iforest.joblib"),
        "detection_mode": mode,
    }
