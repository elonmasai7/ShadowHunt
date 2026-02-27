import json
import time
import uuid
from datetime import datetime, timezone

OUT = "/data/events/t1003_events.jsonl"
steps = [
    "lsass_access_attempt_sim",
    "memory_read_marker_sim",
    "credential_artifact_detected_sim",
]


def emit(step, attack_id, step_number, total_steps):
    event = {
        "id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "event_type": "attack_step",
        "attack_id": attack_id,
        "step_number": step_number,
        "total_steps": total_steps,
        "technique": "T1003",
        "label": "credential_access_sim",
        "step": step,
        "host": "victim-linux-01",
        "result": "success",
        "marker": "SHADOWHUNT_T1003_SIM",
        "marker_encoding": "plain",
        "adversary_profile": "medium",
        "note": "no real dumping performed; synthetic marker",
    }
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


if __name__ == "__main__":
    attack_id = str(uuid.uuid4())
    total = len(steps)
    for idx, s in enumerate(steps, start=1):
        emit(s, attack_id, idx, total)
        time.sleep(1)
