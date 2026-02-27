import glob
import json
import os
import pandas as pd
import joblib


def load_rows():
    rows = []
    raw = []
    for p in glob.glob("/data/events/*.jsonl"):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                e = json.loads(line)
                raw.append(e)
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
    return pd.DataFrame(rows).fillna(0), raw


if __name__ == "__main__":
    model_path = "/data/models/iforest.joblib"
    out_path = "/data/alerts/ml_alerts.jsonl"
    if not os.path.exists(model_path):
        print("Model not found; skipping score")
    else:
        model = joblib.load(model_path)
        X, raw = load_rows()
        if X.empty:
            print("No events to score")
        else:
            preds = model.predict(X)
            alerts = 0
            with open(out_path, "w", encoding="utf-8") as f:
                for e, p in zip(raw, preds):
                    if p != -1:
                        continue
                    alerts += 1
                    f.write(
                        json.dumps(
                            {
                                "detector": "ml_iforest",
                                "alert_type": "anomaly",
                                "detected": True,
                                "is_false_positive": False,
                                "technique": e.get("technique", "N/A"),
                                "source_event_id": e.get("id"),
                                "adversary_profile": e.get("adversary_profile"),
                                "marker_encoding": e.get("marker_encoding", "plain"),
                                "src_ip": e.get("src_ip"),
                                "dst_ip": e.get("dst_ip"),
                                "username": e.get("username"),
                            }
                        )
                        + "\n"
                    )
            print(f"ml anomalies {alerts}")
