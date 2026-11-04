"""Sentinel: ingest -> features -> baseline -> score -> CUSUM state machine -> persist -> quarantine."""
from __future__ import annotations
import os
import json
from dataclasses import dataclass
from typing import Optional

from .auditlog import AuditLog
from .provenance import Provenance
from .alert import SEV, Alert, AlertRouter
from .auditor import ForensicAuditor
from .config import Config
from .detector import score_event
from .engine import make_engine
from .features import extract, redact
from .llm import LLM
from .models import AgentEvent, Verdict
from .profile_memory import ProfileMemory
from .risk import RiskAdjuster
from .store import Store


@dataclass
class AgentState:
    cusum: float = 0.0
    state: str = "HEALTHY"
    first_warn: Optional[int] = None
    quarantined_at: Optional[int] = None


def is_external(dest: Optional[str], cfg: Config) -> bool:
    if not dest:
        return False
    return not any(dest.endswith(s) or dest == s.lstrip(".") for s in cfg.internal_suffixes)


class Sentinel:
    def __init__(self, store: Store | None = None, cfg: Config | None = None,
                 llm: LLM | None = None, auto_investigate: bool = True):
        self.cfg = cfg or Config()
        self.store = store or Store(self.cfg.db_path)
        self.engine = make_engine(self.cfg, self.store)
        self.llm = llm or LLM.auditor(self.cfg)
        self.profile = ProfileMemory(self.cfg)
        self.risk = RiskAdjuster(self.cfg)
        self.auditor = ForensicAuditor(self.engine, self.cfg, self.llm)
        self.auto = auto_investigate
        self.state: dict[str, AgentState] = {}
        self.reports: dict[str, object] = {}
        self.alerts = AlertRouter(self.cfg)
        self.on_event = None
        self.audit = AuditLog(os.getenv("BIOSENTINEL_AUDIT") or None)
        self.provenance = Provenance()
    def allow_tool_call(self, agent_id: str) -> bool:
        return self.state.get(agent_id, AgentState()).state != "QUARANTINED"

    def ingest(self, ev: AgentEvent) -> Verdict:
        v = self._ingest(ev)
        self._announce(ev, v)
        return v

    def _announce(self, ev: AgentEvent, v: Verdict) -> None:
        """Alerts + live-feed events. Must never raise: monitoring cannot break detection."""
        try:
            self.audit.append({"kind": "step", "agent_id": ev.agent_id, "step": ev.step, "tool": ev.tool,
                               "destination": ev.destination, "state": v.state, "score": v.score,
                               "signals": list(v.signals), "blocked": v.blocked})
            if v.state == "HEALTHY":
                self.alerts.resolve(ev.agent_id)
            elif not v.blocked:
                rep = self.reports.get(ev.agent_id) if v.quarantined_now else None
                self.alerts.emit(Alert(
                    SEV[v.state], ev.agent_id, ev.step, v.state,
                    "Early warning" if v.state == "WATCH" else "Agent quarantined",
                    v.signals, v.cusum, rep.verdict if rep else "", rep.confidence if rep else ""))
            if self.on_event:
                self.on_event({"type": "step", "agent_id": ev.agent_id, "step": ev.step,
                               "tool": ev.tool, "destination": ev.destination,
                               "text": redact(ev.text, 200), "state": v.state, "score": v.score,
                               "cusum": v.cusum, "signals": v.signals, "blocked": v.blocked})
                rep = self.reports.get(ev.agent_id)
                if v.quarantined_now and rep:
                    self.on_event({"type": "verdict", "agent_id": ev.agent_id, "step": ev.step,
                                   "verdict": rep.verdict, "confidence": rep.confidence,
                                   "markdown": rep.to_markdown()})
        except Exception:
            pass

    def _ingest(self, ev: AgentEvent) -> Verdict:
        cfg = self.cfg
        st = self.state.setdefault(ev.agent_id, AgentState())
        if st.state == "QUARANTINED":
            return Verdict(ev.agent_id, ev.step, "QUARANTINED", 0.0, st.cusum, 1.0, {}, blocked=True)

        feats = extract(ev.text)
        feats["surprisal"] = self.profile.surprisal(ev.agent_id, ev.text)
        ext = is_external(ev.destination, cfg)
        ext_dest = ev.destination if ext else None

        vol = self.risk.update(ev.agent_id, ev.cpu, ev.err_rate, ev.latency_ms)
        mult = self.risk.multiplier(vol)

        pe = self.profile.evaluate(ev.agent_id, feats, ev.tool, ext_dest)
        score, signals = score_event(cfg, feats, pe)
        st.cusum = max(0.0, st.cusum + score - cfg.cusum_k)

        if score >= cfg.hard_trip * mult or st.cusum >= cfg.quarantine_h * mult:
            new = "QUARANTINED"
        elif st.cusum >= cfg.warn_h * mult:
            new = "WATCH"
        else:
            new = "HEALTHY"
        if new != "HEALTHY" and st.first_warn is None:
            st.first_warn = ev.step
        st.state = new

        if new == "HEALTHY" and score < cfg.learn_below:
            self.profile.learn(ev.agent_id, ev.text, feats, ev.tool, ext_dest)

        self._persist(ev, feats, ext, vol, mult, score, signals, new, st.cusum)

        quarantined_now = new == "QUARANTINED"
        if quarantined_now:
            st.quarantined_at = ev.step
            reason = ", ".join(sorted(signals, key=signals.get, reverse=True)[:4]) or "cusum"
            self.store.insert("quarantine_log", {"agent_id": ev.agent_id, "step": ev.step, "reason": reason})
            if self.auto:
                self.reports[ev.agent_id] = self.auditor.investigate(ev.agent_id, ev.step)
        return Verdict(ev.agent_id, ev.step, new, round(score, 2), round(st.cusum, 2),
                       round(mult, 3), signals, quarantined_now=quarantined_now)

    def _persist(self, ev, feats, ext, vol, mult, score, signals, state, cusum):
        s = self.store
        s.insert("agent_events", {
            "agent_id": ev.agent_id, "step": ev.step, "length": feats["length"],
            "entropy": feats["entropy"], "compression": feats["compression"],
            "encoded": feats["encoded"], "surprisal": feats["surprisal"],
            "secret_hits": feats["secret_hits"], "inj_hits": feats["inj_hits"],
            "obfusc_hits": feats["obfusc_hits"], "snippet": redact(ev.text)})
        s.insert("tool_calls", {
            "agent_id": ev.agent_id, "step": ev.step, "tool": ev.tool,
            "destination": ev.destination or "", "destination_external": int(ext),
            "payload_len": ev.payload_len})
        s.insert("env_telemetry", {
            "agent_id": ev.agent_id, "step": ev.step, "cpu": ev.cpu, "err_rate": ev.err_rate,
            "latency_ms": ev.latency_ms, "volatility": vol})
        s.insert("detections", {
            "agent_id": ev.agent_id, "step": ev.step, "score": score, "cusum": cusum,
            "multiplier": mult, "state": state, "signals": json.dumps(signals)})