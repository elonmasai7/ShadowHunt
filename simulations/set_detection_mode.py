import argparse
import json
import os

MODE_FILE = "/data/config/detection_mode.json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["legacy", "hardened"], required=True)
    args = parser.parse_args()

    os.makedirs("/data/config", exist_ok=True)
    with open(MODE_FILE, "w", encoding="utf-8") as f:
        json.dump({"mode": args.mode}, f)
    print(f"detection mode set to {args.mode}")
