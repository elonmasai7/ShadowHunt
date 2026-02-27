import glob
import json
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib


def load_rows():
    rows = []
    for p in glob.glob("/data/events/*.jsonl"):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                e = json.loads(line)
                rows.append(
                    {
                        "is_fail": 1 if e.get("result") == "failure" else 0,
                        "proto_smb": 1 if e.get("proto") == "smb" else 0,
                        "proto_rdp": 1 if e.get("proto") == "rdp" else 0,
                        "is_attack": 1 if e.get("event_type") == "attack_step" else 0,
                        "is_noise": 1 if e.get("event_type") == "noise" else 0,
                        "is_encoded": 1 if e.get("marker_encoding", "plain") != "plain" else 0,
                    }
                )
    return pd.DataFrame(rows).fillna(0)


if __name__ == "__main__":
    df = load_rows()
    if df.empty:
        print("No events yet; skipping training")
    else:
        X = df[["is_fail", "proto_smb", "proto_rdp", "is_attack", "is_noise", "is_encoded"]]
        model = IsolationForest(contamination=0.12, random_state=42)
        model.fit(X)
        joblib.dump(model, "/data/models/iforest.joblib")
        print(f"trained {len(df)} rows")
