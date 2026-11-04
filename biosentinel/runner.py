from __future__ import annotations
from .config import Config
from .pipeline import Sentinel
from .store import Store


def fresh_sentinel(cfg: Config | None = None, llm=None) -> Sentinel:
    cfg = cfg or Config()
    cfg.db_path = ":memory:"
    return Sentinel(Store(":memory:"), cfg, llm)


def run_scenario(sc, sentinel: Sentinel):
    return [sentinel.ingest(ev) for ev in sc.events]


def detection_steps(verdicts):
    warn = next((v.step for v in verdicts if v.state in ("WATCH", "QUARANTINED")), None)
    quar = next((v.step for v in verdicts if v.quarantined_now), None)
    return warn, quar
