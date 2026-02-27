import json
import time
import random
import uuid
from datetime import datetime, timezone

OUT = "/data/events/t1078_events.jsonl"
users = ["alice", "bob", "svc_backup", "guest"]
sources = ["10.10.0.11", "10.10.0.12", "10.10.0.13"]


def emit(event):
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


if __name__ == "__main__":
    attack_id = str(uuid.uuid4())
    total = 40
    for i in range(total):
        success = random.random() > 0.35
        event = {
            "id": str(uuid.uuid4()),
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_type": "attack_step",
            "attack_id": attack_id,
            "step_number": i + 1,
            "total_steps": total,
            "technique": "T1078",
            "label": "valid_accounts_sim",
            "src_ip": random.choice(sources),
            "username": random.choice(users),
            "action": "auth_attempt",
            "result": "success" if success else "failure",
            "marker": "SHADOWHUNT_T1078_SIM",
            "marker_encoding": "plain",
            "adversary_profile": "medium",
            "note": "synthetic-event-only",
        }
        emit(event)
        time.sleep(0.2)
