from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentEvent:
    agent_id: str
    step: int
    text: str
    tool: str = "none"
    destination: Optional[str] = None
    payload_len: int = 0
    cpu: float = 0.3
    err_rate: float = 0.01
    latency_ms: float = 120.0


@dataclass
class Verdict:
    agent_id: str
    step: int
    state: str
    score: float
    cusum: float
    multiplier: float
    signals: dict = field(default_factory=dict)
    blocked: bool = False
    quarantined_now: bool = False
