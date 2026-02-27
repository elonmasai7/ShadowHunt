from datetime import datetime, timezone
from pathlib import Path
import asyncio
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import psutil

from .reporting import generate_report
from .simulation_engine import AttackRequest, AttackSimulationEngine
from .telemetry import RuntimeState, TelemetryHub

app = FastAPI(title="ShadowHunt API", version="1.0.0")

PROFILES = ["low", "medium", "high"]

state = RuntimeState()
telemetry = TelemetryHub(state)
engine = AttackSimulationEngine(state, telemetry)


class SimRequest(BaseModel):
    technique: str
    evasion: bool = False
    count: int = 20


class ChainRequest(BaseModel):
    profile: str = "medium"
    include_noise: bool = True
    evasion: bool = False


class ToggleRequest(BaseModel):
    enabled: bool = True


@app.on_event("startup")
async def startup() -> None:
    telemetry.set_loop(asyncio.get_running_loop())
    Path("/data/events").mkdir(parents=True, exist_ok=True)
    Path("/data/alerts").mkdir(parents=True, exist_ok=True)
    Path("/data/reports").mkdir(parents=True, exist_ok=True)


@app.get("/")
def root():
    return {"service": "shadowhunt-backend", "status": "ok", "mode": state.mode}


@app.get("/profiles")
def profiles():
    return {"profiles": PROFILES}


@app.post("/start_sim")
def start_sim(req: SimRequest):
    return engine.trigger_attack(AttackRequest(technique=req.technique, evasion=req.evasion, count=req.count))


@app.post("/trigger_attack")
def trigger_attack(req: SimRequest):
    return engine.trigger_attack(AttackRequest(technique=req.technique, evasion=req.evasion, count=req.count))


@app.post("/start_chain")
@app.post("/start_simulation")
def start_chain(req: ChainRequest):
    if req.profile not in PROFILES:
        return {"ok": False, "error": "Unsupported profile"}
    started = engine.start_chain(req.profile, req.include_noise, req.evasion)
    if not started:
        return {"ok": False, "error": "Simulation already running"}
    return {
        "ok": True,
        "started": "attack_chain",
        "profile": req.profile,
        "noise": req.include_noise,
        "evasion": req.evasion,
    }


@app.post("/stop_sim")
@app.post("/stop_simulation")
def stop_sim():
    engine.stop()
    return {"ok": True, "stopped": True}


@app.post("/detection/mode/{mode}")
def set_detection_mode(mode: str):
    if mode not in ["legacy", "hardened"]:
        return {"ok": False, "error": "mode must be legacy or hardened"}
    with state.lock:
        state.mode = mode
    telemetry.publish({"kind": "mode_change", "mode": mode, "snapshot": state.snapshot()})
    return {"ok": True, "mode": mode}


@app.post("/privacy/anonymize")
def set_anonymize(req: ToggleRequest):
    with state.lock:
        state.anonymize_logs = req.enabled
    return {"ok": True, "anonymize_logs": state.anonymize_logs}


@app.post("/lab/reset")
def reset_lab():
    engine.stop()
    state.clear()
    for p in Path("/data/events").glob("*.jsonl"):
        p.unlink(missing_ok=True)
    for p in Path("/data/alerts").glob("*.jsonl"):
        p.unlink(missing_ok=True)
    return {"ok": True}


@app.get("/detect")
@app.get("/get_alerts")
def detect():
    return {"alerts": state.snapshot()["alerts"]}


@app.get("/coverage")
def coverage():
    snap = state.snapshot()
    executed = sum(snap["mitre_coverage"].values())
    detected = sum(1 for a in snap["alerts"] if a.get("detected"))
    coverage_score = round((detected / executed) * 100, 2) if executed else 0.0
    summary = [
        {
            "technique": k,
            "executed": v,
            "detected": sum(
                1 for a in snap["alerts"] if a.get("technique") == k and a.get("detected")
            ),
        }
        for k, v in snap["mitre_coverage"].items()
    ]
    return {
        "coverage_score": coverage_score,
        "summary": summary,
        "gaps": [row for row in summary if row["executed"] > row["detected"]],
        "totals": {
            "executed": executed,
            "detected": detected,
            "false_positives": snap["false_positives"],
        },
        "detection_mode": snap["mode"],
    }


@app.get("/report")
def report():
    snap = state.snapshot()
    counts = {}
    for event in snap["attack_timeline"]:
        technique = event.get("technique", "N/A")
        counts[technique] = counts.get(technique, 0) + 1
    return {"event_counts": counts}


@app.get("/generate_report")
def get_generate_report():
    return generate_report(state)


@app.get("/replay")
def replay():
    return {"events": state.snapshot()["replay_events"]}


@app.get("/get_metrics")
@app.get("/system/metrics")
def system_metrics():
    disk = psutil.disk_usage("/")
    mem = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=0.2)
    snap = state.snapshot()
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "memory_used_mb": round(mem.used / (1024 * 1024), 2),
        "memory_total_mb": round(mem.total / (1024 * 1024), 2),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / (1024 * 1024 * 1024), 2),
        "disk_total_gb": round(disk.total / (1024 * 1024 * 1024), 2),
        "network_mbps": round(psutil.net_io_counters().bytes_sent / (1024 * 1024), 2),
        "pcap_enabled": snap["pcap_enabled"],
        "running": snap["running"],
        "false_positive_rate": round((snap["false_positives"] / max(snap["alert_count"], 1)) * 100, 2),
        "ml_anomaly_latest": snap["ml_confidence"][-1]["confidence"] if snap["ml_confidence"] else 0.0,
        "evasion_success_rate": round((snap["evasion_success"] / max(snap["evasion_attempts"], 1)) * 100, 2),
    }


@app.get("/system/status")
def system_status():
    snap = state.snapshot()
    return {
        "event_files": len(list(Path("/data/events").glob("*.jsonl"))),
        "alert_files": len(list(Path("/data/alerts").glob("*.jsonl"))),
        "model_present": True,
        "detection_mode": snap["mode"],
        "running": snap["running"],
    }


@app.websocket("/ws/telemetry")
async def ws_telemetry(ws: WebSocket):
    await telemetry.connect(ws)
    try:
        while True:
            await ws.send_json({"kind": "snapshot", "snapshot": state.snapshot()})
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        telemetry.disconnect(ws)
    except Exception:
        telemetry.disconnect(ws)
