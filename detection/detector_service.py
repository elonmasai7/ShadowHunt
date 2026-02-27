import subprocess
import time

if __name__ == "__main__":
    while True:
        subprocess.run(["python", "/app/rule_engine.py"], check=False)
        subprocess.run(["python", "/app/ml/train.py"], check=False)
        subprocess.run(["python", "/app/ml/score.py"], check=False)
        subprocess.run(["python", "/app/merge_alerts.py"], check=False)
        subprocess.run(["python", "/app/privacy/anonymize.py"], check=False)
        time.sleep(10)
