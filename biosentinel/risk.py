from __future__ import annotations
from .config import Config


class RiskAdjuster:
    """Environment-aware thresholds: when the node looks unhealthy, tolerate less."""

    def __init__(self, cfg: Config, alpha: float = 0.3):
        self.cfg, self.alpha = cfg, alpha
        self.vol: dict[str, float] = {}

    def update(self, key: str, cpu: float, err_rate: float, latency_ms: float) -> float:
        raw = (min(err_rate / 0.15, 1.0) * 0.5
               + min(max(cpu - 0.6, 0.0) / 0.4, 1.0) * 0.3
               + min(latency_ms / 1000.0, 1.0) * 0.2)
        v = self.alpha * min(raw, 1.0) + (1 - self.alpha) * self.vol.get(key, 0.0)
        self.vol[key] = v
        return v

    def multiplier(self, vol: float) -> float:
        return 1.0 - self.cfg.env_tighten * vol
