import argparse
import base64
import json
import os
import random
import time
import uuid
from datetime import datetime, timezone

from profiles import choose_profile, maybe

EVENT_OUT = "/data/events/attack_chain_events.jsonl"
NOISE_OUT = "/data/events/noise_events.jsonl"

CHAIN_TEMPLATE = [
    ("T1078", "initial_access_via_valid_accounts_sim"),
    ("T1003", "credential_access_marker_sim"),
    ("T1021", "lateral_movement_service_use_sim"),
]


def ts():
    return datetime.now(timezone.utc).isoformat()


def ensure_data_dir():
    os.makedirs("/data/events", exist_ok=True)


def encode_marker(marker: str, method: str) -> str:
    raw = marker.encode("utf-8")
    if method == "base64":
        return base64.b64encode(raw).decode("utf-8")
    if method == "xor":
        return bytes([b ^ 0x23 for b in raw]).hex()
    return marker


def write_jsonl(path: str, event: dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def emit_chain(profile_name: str, include_noise: bool, force_evasion: bool):
    cfg = choose_profile(profile_name)
    attack_id = str(uuid.uuid4())
    total_steps = cfg["chain_repeats"] * len(CHAIN_TEMPLATE)
    step_number = 0

    for _ in range(cfg["chain_repeats"]):
        for technique, action in CHAIN_TEMPLATE:
            step_number += 1
            use_evasion = force_evasion or maybe(cfg["evasion_rate"])
            marker = f"SHADOWHUNT_{technique}_SIM"
            encoding = random.choice(["base64", "xor"]) if use_evasion else "plain"
            marker_payload = encode_marker(marker, encoding)

            event = {
                "id": str(uuid.uuid4()),
                "ts": ts(),
                "event_type": "attack_step",
                "attack_id": attack_id,
                "step_number": step_number,
                "total_steps": total_steps,
                "technique": technique,
                "action": action,
                "adversary_profile": profile_name,
                "src_ip": random.choice(["10.10.0.11", "10.10.0.12", "10.10.0.13"]),
                "dst_ip": random.choice(["10.10.0.31", "10.10.0.32", "10.10.0.33"]),
                "result": "success",
                "marker": marker_payload,
                "marker_encoding": encoding,
                "note": "synthetic-chain-event-only",
            }
            write_jsonl(EVENT_OUT, event)
            time.sleep(cfg["step_delay"])

    if include_noise:
        for _ in range(cfg["noise_events"]):
            n = {
                "id": str(uuid.uuid4()),
                "ts": ts(),
                "event_type": "noise",
                "attack_id": None,
                "technique": None,
                "action": random.choice([
                    "backup_job_completed",
                    "service_restart",
                    "package_update",
                    "healthcheck_passed",
                    "user_login_normal",
                ]),
                "adversary_profile": profile_name,
                "src_ip": random.choice(["10.10.0.40", "10.10.0.41", "10.10.0.42"]),
                "dst_ip": random.choice(["10.10.0.50", "10.10.0.51"]),
                "false_positive_candidate": maybe(cfg["false_positive_rate"]),
                "result": "benign",
                "note": "synthetic-noise-event",
            }
            write_jsonl(NOISE_OUT, n)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="medium", choices=["low", "medium", "high"])
    parser.add_argument("--noise", action="store_true")
    parser.add_argument("--evasion", action="store_true")
    args = parser.parse_args()

    ensure_data_dir()
    emit_chain(args.profile, include_noise=args.noise, force_evasion=args.evasion)
