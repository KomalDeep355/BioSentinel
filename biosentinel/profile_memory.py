"""Stateful behavioural profile memory: a per-agent running baseline.

Learns (a) running mean/std of text features, (b) a character language model,
(c) the set of tools and external destinations the agent normally uses.
Only clearly-normal steps are learned, so an attacker cannot slowly poison the baseline.
"""
from __future__ import annotations
import math
from dataclasses import dataclass, field

from .config import Config
from .features import BigramLM

Z_FEATURES = {
    "entropy": (True, 0.15),
    "compression": (True, 0.05),
    "encoded": (False, 0.03),
    "surprisal": (False, 0.25),
}


class Welford:
    def __init__(self):
        self.n, self.mean, self.m2 = 0, 0.0, 0.0

    def add(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0


@dataclass
class AgentProfile:
    stats: dict = field(default_factory=lambda: {f: Welford() for f in Z_FEATURES})
    lm: BigramLM = field(default_factory=BigramLM)
    tools: set = field(default_factory=set)
    dests: set = field(default_factory=set)
    buffer: list = field(default_factory=list)
    ready: bool = False


class ProfileMemory:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.profiles: dict[str, AgentProfile] = {}

    def _p(self, agent_id: str) -> AgentProfile:
        return self.profiles.setdefault(agent_id, AgentProfile())

    def surprisal(self, agent_id: str, text: str):
        p = self._p(agent_id)
        return p.lm.surprisal(text) if p.ready else None

    def evaluate(self, agent_id: str, feats: dict, tool: str, ext_dest):
        p = self._p(agent_id)
        if not p.ready:
            return {"ready": False, "z": {}, "new_tool": False, "new_dest": False}
        z = {}
        for name in Z_FEATURES:
            w = p.stats[name]
            sd = max(w.std(), Z_FEATURES[name][1])
            z[name] = (feats[name] - w.mean) / sd
        return {
            "ready": True,
            "z": z,
            "new_tool": tool not in p.tools,
            "new_dest": bool(ext_dest) and ext_dest not in p.dests,
        }

    def learn(self, agent_id: str, text: str, feats: dict, tool: str, ext_dest) -> None:
        p = self._p(agent_id)
        p.tools.add(tool)
        if ext_dest:
            p.dests.add(ext_dest)
        if not p.ready:
            p.buffer.append((text, dict(feats)))
            if len(p.buffer) >= self.cfg.warmup:
                self._bootstrap(p)
            return
        p.lm.train(text)
        for name in Z_FEATURES:
            p.stats[name].add(feats[name])

    @staticmethod
    def _bootstrap(p: AgentProfile) -> None:
        for text, _ in p.buffer:
            p.lm.train(text)
        for text, f in p.buffer:
            p.lm.train(text, -1)
            f["surprisal"] = p.lm.surprisal(text)
            p.lm.train(text, +1)
            for name in Z_FEATURES:
                p.stats[name].add(f[name])
        p.ready, p.buffer = True, []

    def snapshot(self, agent_id: str) -> dict:
        p = self._p(agent_id)
        return {
            "ready": p.ready,
            "tools": sorted(p.tools),
            "external_destinations": sorted(p.dests),
            "features": {k: {"mean": round(w.mean, 3), "std": round(w.std(), 3), "n": w.n}
                         for k, w in p.stats.items()},
        }
