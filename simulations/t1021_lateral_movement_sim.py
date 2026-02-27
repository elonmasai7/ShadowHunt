import json
import time
import random
import uuid
from datetime import datetime, timezone

OUT = "/data/events/t1021_events.jsonl"
pairs = [("10.10.0.21", "10.10.0.31"), ("10.10.0.22", "10.10.0.32")]


def emit(src, dst, proto, attack_id, step_number, total_steps):
    event = {
        "id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "event_type": "attack_step",
        "attack_id": attack_id,
        "step_number": step_number,
        "total_steps": total_steps,
        "technique": "T1021",
        "label": "lateral_movement_sim",
        "src_ip": src,
        "dst_ip": dst,
        "proto": proto,
        "result": "success",
        "marker": "SHADOWHUNT_T1021_SIM",
        "marker_encoding": "plain",
        "adversary_profile": "medium",
    }
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


if __name__ == "__main__":
    total = 20
    attack_id = str(uuid.uuid4())
    for idx in range(total):
        src, dst = random.choice(pairs)
        emit(src, dst, random.choice(["smb", "rdp", "winrm"]), attack_id, idx + 1, total)
        time.sleep(0.3)
