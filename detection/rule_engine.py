import base64
import glob
import json
import os
from datetime import datetime, timezone

MODE_FILE = "/data/config/detection_mode.json"
OUT_ALERTS = "/data/alerts/rule_alerts.jsonl"
OUT_COVERAGE = "/data/alerts/coverage.json"

KNOWN_TECHNIQUES = ["T1078", "T1003", "T1021"]


def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_mode() -> str:
    if not os.path.exists(MODE_FILE):
        return "legacy"
    with open(MODE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("mode", "legacy")


def read_events():
    events = []
    for p in glob.glob("/data/events/*.jsonl"):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def decode_marker(marker: str, encoding: str) -> str:
    if not marker:
        return ""
    try:
        if encoding == "plain":
            return marker
        if encoding == "base64":
            return base64.b64decode(marker.encode("utf-8")).decode("utf-8")
        if encoding == "xor":
            raw = bytes.fromhex(marker)
            return bytes([b ^ 0x23 for b in raw]).decode("utf-8")
    except Exception:
        return ""
    return ""


def make_rule_alert(event: dict, mode: str):
    etype = event.get("event_type")
    technique = event.get("technique")

    if etype == "noise":
        # Controlled false positives for realism
        if event.get("false_positive_candidate"):
            return {
                "ts": now_ts(),
                "detector": "rule_engine",
                "technique": "N/A",
                "severity": "low",
                "alert_type": "false_positive",
                "detected": True,
                "is_false_positive": True,
                "reason": "benign_noise_trigger",
                "source_event_id": event.get("id"),
                "adversary_profile": event.get("adversary_profile"),
            }
        return None

    if etype != "attack_step" or technique not in KNOWN_TECHNIQUES:
        return None

    decoded = decode_marker(event.get("marker", ""), event.get("marker_encoding", "plain"))
    expected = f"SHADOWHUNT_{technique}_SIM"

    if mode == "legacy":
        detected = event.get("marker_encoding") == "plain" and expected in event.get("marker", "")
        return {
            "ts": now_ts(),
            "detector": "rule_engine",
            "technique": technique,
            "severity": "medium" if detected else "info",
            "alert_type": "attack_detection" if detected else "evasion_missed",
            "detected": detected,
            "is_false_positive": False,
            "reason": "direct_marker_match" if detected else "encoded_marker_bypass",
            "source_event_id": event.get("id"),
            "attack_id": event.get("attack_id"),
            "adversary_profile": event.get("adversary_profile"),
            "encoding": event.get("marker_encoding"),
        }

    detected = expected in decoded
    return {
        "ts": now_ts(),
        "detector": "rule_engine",
        "technique": technique,
        "severity": "high" if detected else "info",
        "alert_type": "attack_detection" if detected else "evasion_unknown",
        "detected": detected,
        "is_false_positive": False,
        "reason": "decoded_marker_match" if detected else "decode_failed",
        "source_event_id": event.get("id"),
        "attack_id": event.get("attack_id"),
        "adversary_profile": event.get("adversary_profile"),
        "encoding": event.get("marker_encoding"),
    }


def build_coverage(events: list, alerts: list, mode: str):
    executed = {t: 0 for t in KNOWN_TECHNIQUES}
    detected = {t: 0 for t in KNOWN_TECHNIQUES}

    for e in events:
        t = e.get("technique")
        if e.get("event_type") == "attack_step" and t in executed:
            executed[t] += 1

    for a in alerts:
        t = a.get("technique")
        if a.get("detected") and t in detected:
            detected[t] += 1

    summary = []
    gaps = []
    for t in KNOWN_TECHNIQUES:
        ex = executed[t]
        dt = detected[t]
        rate = round((dt / ex) * 100, 2) if ex else 0.0
        row = {
            "technique": t,
            "executed": ex,
            "detected": dt,
            "detection_rate": rate,
            "gap": ex > dt,
        }
        summary.append(row)
        if row["gap"]:
            gaps.append({"technique": t, "missing": ex - dt})

    all_executed = sum(executed.values())
    all_detected = sum(detected.values())
    coverage_score = round((all_detected / all_executed) * 100, 2) if all_executed else 0.0

    return {
        "ts": now_ts(),
        "detection_mode": mode,
        "coverage_score": coverage_score,
        "totals": {
            "executed": all_executed,
            "detected": all_detected,
            "false_positives": sum(1 for a in alerts if a.get("is_false_positive")),
        },
        "summary": summary,
        "gaps": gaps,
    }


if __name__ == "__main__":
    os.makedirs("/data/alerts", exist_ok=True)
    mode = get_mode()
    events = read_events()
    alerts = []

    with open(OUT_ALERTS, "w", encoding="utf-8") as f:
        for e in events:
            alert = make_rule_alert(e, mode)
            if alert is None:
                continue
            alerts.append(alert)
            f.write(json.dumps(alert) + "\n")

    coverage = build_coverage(events, alerts, mode)
    with open(OUT_COVERAGE, "w", encoding="utf-8") as f:
        json.dump(coverage, f)

    print(f"rule_engine mode={mode} alerts={len(alerts)}")
