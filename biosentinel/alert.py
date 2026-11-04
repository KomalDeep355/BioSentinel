"""Alerting. WATCH -> warning, QUARANTINED -> critical. Sinks never raise: alerting must not
be able to break detection. Each (agent, state) alerts once until the agent returns to HEALTHY."""
from __future__ import annotations
import json
import sys
import time
from dataclasses import asdict, dataclass, field

import httpx

from .config import Config

SEV = {"WATCH": "warning", "QUARANTINED": "critical"}


@dataclass
class Alert:
    severity: str
    agent_id: str
    step: int
    state: str
    title: str
    signals: dict = field(default_factory=dict)
    cusum: float = 0.0
    verdict: str = ""
    confidence: str = ""
    ts: float = field(default_factory=time.time)

    def text(self) -> str:
        top = ", ".join(sorted(self.signals, key=self.signals.get, reverse=True)[:3]) or "cusum drift"
        t = f"[{self.severity.upper()}] {self.title}: {self.agent_id} at step {self.step} (cusum {self.cusum}; {top})"
        if self.verdict:
            t += f" | {self.verdict} | confidence {self.confidence}"
        return t


class ConsoleSink:
    def send(self, a: Alert) -> None:
        print(a.text(), file=sys.stderr)


class FileSink:
    def __init__(self, path: str):
        self.path = path

    def send(self, a: Alert) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(asdict(a)) + "\n")


class WebhookSink:
    def __init__(self, url: str, style: str = "slack"):
        self.url, self.style = url, style

    def send(self, a: Alert) -> None:
        body = {"slack": {"text": a.text()}, "discord": {"content": a.text()}}.get(self.style, asdict(a))
        httpx.post(self.url, json=body, timeout=10)


class MemorySink:
    def __init__(self):
        self.alerts: list[Alert] = []

    def send(self, a: Alert) -> None:
        self.alerts.append(a)


class AlertRouter:
    def __init__(self, cfg: Config | None = None, sinks: list | None = None):
        cfg = cfg or Config()
        self.sinks = sinks if sinks is not None else []
        if sinks is None:
            if cfg.alert_console:
                self.sinks.append(ConsoleSink())
            if cfg.alert_file:
                self.sinks.append(FileSink(cfg.alert_file))
            if cfg.alert_webhook_url:
                self.sinks.append(WebhookSink(cfg.alert_webhook_url, cfg.alert_webhook_style))
        self.history: list[Alert] = []
        self._seen: set = set()

    def emit(self, a: Alert) -> bool:
        key = (a.agent_id, a.state)
        if key in self._seen:
            return False
        self._seen.add(key)
        self.history.append(a)
        for s in self.sinks:
            try:
                s.send(a)
            except Exception:
                pass
        return True

    def resolve(self, agent_id: str) -> None:
        self._seen = {k for k in self._seen if k[0] != agent_id}
