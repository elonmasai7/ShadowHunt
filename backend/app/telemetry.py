import asyncio
import json
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket


@dataclass
class RuntimeState:
    running: bool = False
    mode: str = "legacy"
    anonymize_logs: bool = True
    pcap_enabled: bool = True
    false_positives: int = 0
    evasion_attempts: int = 0
    evasion_success: int = 0
    attack_count: int = 0
    alert_count: int = 0
    ml_confidence: list[dict[str, Any]] = field(default_factory=list)
    attack_timeline: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    replay_events: list[dict[str, Any]] = field(default_factory=list)
    mitre_coverage: dict[str, int] = field(default_factory=lambda: {"T1078": 0, "T1003": 0, "T1021": 0, "BRUTE": 0, "EVASION": 0})
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "running": self.running,
                "mode": self.mode,
                "anonymize_logs": self.anonymize_logs,
                "pcap_enabled": self.pcap_enabled,
                "false_positives": self.false_positives,
                "evasion_attempts": self.evasion_attempts,
                "evasion_success": self.evasion_success,
                "attack_count": self.attack_count,
                "alert_count": self.alert_count,
                "ml_confidence": self.ml_confidence[-200:],
                "attack_timeline": self.attack_timeline[-300:],
                "alerts": self.alerts[-300:],
                "replay_events": self.replay_events[-500:],
                "mitre_coverage": self.mitre_coverage,
            }

    def clear(self) -> None:
        with self.lock:
            self.false_positives = 0
            self.evasion_attempts = 0
            self.evasion_success = 0
            self.attack_count = 0
            self.alert_count = 0
            self.ml_confidence.clear()
            self.attack_timeline.clear()
            self.alerts.clear()
            self.replay_events.clear()
            self.mitre_coverage = {"T1078": 0, "T1003": 0, "T1021": 0, "BRUTE": 0, "EVASION": 0}


class TelemetryHub:
    def __init__(self, state: RuntimeState):
        self.state = state
        self.connections: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._buffer: deque[dict[str, Any]] = deque(maxlen=1000)

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.connections.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.connections.discard(ws)

    def publish(self, event: dict[str, Any]) -> None:
        self._buffer.append(event)
        if self.loop:
            asyncio.run_coroutine_threadsafe(self._broadcast(event), self.loop)

    async def _broadcast(self, event: dict[str, Any]) -> None:
        if not self.connections:
            return
        msg = json.dumps(event)
        stale: list[WebSocket] = []
        for ws in self.connections:
            try:
                await ws.send_text(msg)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)
