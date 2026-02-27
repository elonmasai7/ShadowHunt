import json
import hashlib
import os
from diffprivlib.mechanisms import Laplace

INP = "/data/alerts/combined_alerts.jsonl"
OUT = "/data/alerts/ml_alerts_private.jsonl"


def h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


if __name__ == "__main__":
    mech = Laplace(epsilon=1.0, sensitivity=1.0)
    count = 0
    if not os.path.exists(INP):
        print("No alerts yet; skipping anonymization")
    else:
        with open(INP, "r", encoding="utf-8") as fi, open(OUT, "w", encoding="utf-8") as fo:
            for line in fi:
                e = json.loads(line)
                if e.get("src_ip"):
                    e["src_ip"] = h(str(e["src_ip"]))
                if e.get("dst_ip"):
                    e["dst_ip"] = h(str(e["dst_ip"]))
                if e.get("username"):
                    e["username"] = h(str(e["username"]))
                count += 1
                fo.write(json.dumps(e) + "\n")

        noisy = mech.randomise(count)
        with open("/data/alerts/private_metrics.json", "w", encoding="utf-8") as f:
            json.dump({"alerts_count_dp": noisy}, f)
        print(f"anonymized {count} alerts")
