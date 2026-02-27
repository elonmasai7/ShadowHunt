import json
import os

RULE = "/data/alerts/rule_alerts.jsonl"
ML = "/data/alerts/ml_alerts.jsonl"
OUT = "/data/alerts/combined_alerts.jsonl"


def read_jsonl(path: str):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


if __name__ == "__main__":
    rows = read_jsonl(RULE) + read_jsonl(ML)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"merged alerts {len(rows)}")
