import random
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .security_utils import anonymize_event, maybe, utc_ts, write_jsonl
from .telemetry import RuntimeState, TelemetryHub


EVENT_FILE = Path("/data/events/realtime_events.jsonl")
ALERT_FILE = Path("/data/alerts/live_alerts.jsonl")


@dataclass
class AttackRequest:
    technique: str
    evasion: bool = False
    count: int = 20


class AttackSimulationEngine:
    def __init__(self, state: RuntimeState, telemetry: TelemetryHub):
        self.state = state
        self.telemetry = telemetry
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.failure_window: dict[str, int] = {}

    def is_running(self) -> bool:
        return self.worker is not None and self.worker.is_alive()

    def start_chain(self, profile: str, include_noise: bool, evasion: bool) -> bool:
        if self.is_running():
            return False
        self.stop_event.clear()
        self.worker = threading.Thread(
            target=self._run_chain, args=(profile, include_noise, evasion), daemon=True
        )
        self.worker.start()
        with self.state.lock:
            self.state.running = True
        return True

    def stop(self) -> None:
        self.stop_event.set()
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=2.0)
        with self.state.lock:
            self.state.running = False

    def trigger_attack(self, req: AttackRequest) -> dict[str, Any]:
        attack_id = str(uuid.uuid4())
        for idx in range(req.count):
            if self.stop_event.is_set():
                break
            event = self._generate_event(req.technique, attack_id, idx + 1, req.count, req.evasion)
            self._process_event(event)
            time.sleep(0.15)
        return {"ok": True, "attack_id": attack_id, "technique": req.technique, "count": req.count}

    def _run_chain(self, profile: str, include_noise: bool, evasion: bool) -> None:
        profile_rounds = {"low": 1, "medium": 2, "high": 3}.get(profile, 2)
        chain = ["T1078", "T1003", "T1021", "BRUTE", "EVASION"]
        attack_id = str(uuid.uuid4())
        total = profile_rounds * len(chain) * 4
        step = 0
        for _ in range(profile_rounds):
            for technique in chain:
                for _ in range(4):
                    if self.stop_event.is_set():
                        with self.state.lock:
                            self.state.running = False
                        return
                    step += 1
                    event = self._generate_event(technique, attack_id, step, total, evasion)
                    self._process_event(event)
                    time.sleep(0.25 if profile == "high" else 0.35)
            if include_noise:
                for _ in range(6):
                    if self.stop_event.is_set():
                        with self.state.lock:
                            self.state.running = False
                        return
                    noise = self._noise_event(attack_id)
                    self._process_event(noise)
                    time.sleep(0.2)
        with self.state.lock:
            self.state.running = False

    def _base_event(self, technique: str, attack_id: str, step: int, total_steps: int) -> dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "ts": utc_ts(),
            "event_type": "attack_step",
            "technique": technique,
            "attack_id": attack_id,
            "step_number": step,
            "total_steps": total_steps,
            "src_ip": random.choice(["10.0.21.11", "10.0.21.12", "10.0.21.13"]),
            "dst_ip": random.choice(["10.0.22.31", "10.0.22.32", "10.0.22.33"]),
            "host": random.choice(["victim-ubuntu-1", "victim-ubuntu-2"]),
            "target_host": random.choice(["ad-mock", "db-sim", "web-sim"]),
            "containerized_victim": True,
            "ad_simulated": True,
            "network_namespace": "shadow_net",
            "result": "success",
        }

    def _generate_event(self, technique: str, attack_id: str, step: int, total_steps: int, evasion: bool) -> dict[str, Any]:
        event = self._base_event(technique, attack_id, step, total_steps)
        if technique == "T1078":
            event.update(
                {
                    "username": random.choice(["alice", "bob", "svc_ops"]),
                    "action": "valid_account_login",
                    "mitre": "T1078",
                }
            )
        elif technique == "T1003":
            event.update(
                {
                    "username": "SYSTEM",
                    "action": "credential_dump_marker",
                    "mitre": "T1003",
                }
            )
        elif technique == "T1021":
            event.update(
                {
                    "action": random.choice(["impacket_wmiexec", "impacket_psexec", "rdp_spread"]),
                    "proto": random.choice(["smb", "rdp"]),
                    "mitre": "T1021",
                }
            )
        elif technique == "BRUTE":
            event.update(
                {
                    "action": "bruteforce_attempt",
                    "username": random.choice(["admin", "root", "guest"]),
                    "mitre": "T1110",
                    "result": "failure" if maybe(0.8) else "success",
                }
            )
        else:
            event.update(
                {
                    "action": "obfuscated_payload_delivery",
                    "mitre": "T1027",
                    "marker_encoding": random.choice(["base64", "xor", "plain"]),
                }
            )
        if evasion:
            event["evasion_mode"] = True
            event["marker_encoding"] = random.choice(["base64", "xor"])
        return event

    def _noise_event(self, attack_id: str) -> dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "ts": utc_ts(),
            "event_type": "noise",
            "attack_id": attack_id,
            "technique": "NOISE",
            "action": random.choice(["cron_job", "patch_install", "normal_user_login"]),
            "src_ip": random.choice(["10.0.25.1", "10.0.25.2"]),
            "dst_ip": random.choice(["10.0.25.11", "10.0.25.12"]),
            "result": "benign",
            "false_positive_candidate": maybe(0.15),
        }

    def _alert_from_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        mode = self.state.mode
        is_attack = event.get("event_type") == "attack_step"
        technique = event.get("technique", "N/A")

        if event.get("event_type") == "noise" and event.get("false_positive_candidate"):
            alerts.append(
                {
                    "ts": utc_ts(),
                    "detector": "hids_ossec_sim",
                    "severity": "low",
                    "alert_type": "false_positive",
                    "technique": "N/A",
                    "detected": True,
                    "is_false_positive": True,
                    "reason": "benign_noise_signature_match",
                }
            )

        if is_attack:
            # Rule-based simulation (Suricata/Snort-like)
            evasion_attempt = bool(event.get("evasion_mode")) or event.get("marker_encoding") in {"base64", "xor"}
            if evasion_attempt:
                with self.state.lock:
                    self.state.evasion_attempts += 1
            detected_rule = not (mode == "legacy" and evasion_attempt)
            if evasion_attempt and not detected_rule:
                with self.state.lock:
                    self.state.evasion_success += 1
            alerts.append(
                {
                    "ts": utc_ts(),
                    "detector": "suricata_snort_sim",
                    "severity": "high" if technique in {"T1003", "T1021"} else "medium",
                    "alert_type": "rule_match" if detected_rule else "rule_bypassed",
                    "technique": technique,
                    "detected": detected_rule,
                    "is_false_positive": False,
                    "reason": "signature_match" if detected_rule else "obfuscated_marker_evasion",
                }
            )

            # HIDS simulation: brute-force failures
            if technique == "BRUTE":
                user = event.get("username", "unknown")
                failed = event.get("result") == "failure"
                if failed:
                    self.failure_window[user] = self.failure_window.get(user, 0) + 1
                if self.failure_window.get(user, 0) >= 4:
                    alerts.append(
                        {
                            "ts": utc_ts(),
                            "detector": "hids_ossec_sim",
                            "severity": "high",
                            "alert_type": "bruteforce_pattern",
                            "technique": "BRUTE",
                            "detected": True,
                            "is_false_positive": False,
                            "reason": "repeated_auth_failures",
                        }
                    )

            # ML anomaly simulation
            score = random.uniform(0.45, 0.99) if is_attack else random.uniform(0.05, 0.35)
            is_anomaly = score > 0.72
            alerts.append(
                {
                    "ts": utc_ts(),
                    "detector": "ml_isolation_forest_sim",
                    "severity": "medium" if is_anomaly else "info",
                    "alert_type": "anomaly",
                    "technique": technique,
                    "detected": is_anomaly,
                    "is_false_positive": False,
                    "ml_confidence": round(score, 3),
                    "reason": "isolation_forest_score",
                }
            )
        return alerts

    def _process_event(self, event: dict[str, Any]) -> None:
        write_jsonl(EVENT_FILE, event)
        alerts = self._alert_from_event(event)
        for alert in alerts:
            write_jsonl(ALERT_FILE, alert)

        safe_event = anonymize_event(event, self.state.anonymize_logs)
        safe_alerts = [anonymize_event(a, self.state.anonymize_logs) for a in alerts]
        with self.state.lock:
            self.state.attack_count += 1 if event.get("event_type") == "attack_step" else 0
            self.state.replay_events.append(safe_event)
            self.state.attack_timeline.append(
                {
                    "ts": safe_event["ts"],
                    "technique": safe_event.get("technique", "N/A"),
                    "action": safe_event.get("action", "N/A"),
                    "result": safe_event.get("result", "N/A"),
                }
            )
            technique = safe_event.get("technique")
            if technique in self.state.mitre_coverage:
                self.state.mitre_coverage[technique] += 1
            for alert in safe_alerts:
                self.state.alerts.append(alert)
                self.state.alert_count += 1
                if alert.get("is_false_positive"):
                    self.state.false_positives += 1
                if alert.get("detector") == "ml_isolation_forest_sim":
                    self.state.ml_confidence.append(
                        {
                            "ts": alert.get("ts"),
                            "confidence": alert.get("ml_confidence", 0.0),
                            "technique": alert.get("technique", "N/A"),
                        }
                    )

        self.telemetry.publish({"kind": "event", "event": safe_event, "alerts": safe_alerts, "snapshot": self.state.snapshot()})
