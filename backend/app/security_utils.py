import hashlib
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def maybe(probability: float) -> bool:
    return random.random() < probability


def anonymize_event(event: dict[str, Any], enabled: bool) -> dict[str, Any]:
    if not enabled:
        return dict(event)
    clone = dict(event)
    for pii_key in ("src_ip", "dst_ip", "username", "host", "target_host"):
        value = clone.get(pii_key)
        if value:
            clone[pii_key] = hash_value(str(value))
    return clone


def write_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def add_dp_noise(value: float, epsilon: float = 1.0) -> float:
    # Lightweight Laplace-like noise for dashboard metrics without extra dependency.
    scale = 1.0 / max(epsilon, 1e-6)
    u = random.random() - 0.5
    sign = -1.0 if u < 0 else 1.0
    return value - (scale * sign * (0.0 if u == 0 else (abs(u) / max(abs(u), 1e-9))))
