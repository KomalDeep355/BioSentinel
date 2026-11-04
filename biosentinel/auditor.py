"""Forensic auditor: planner -> SQL executors -> evaluator -> writer, with a citation guard.

Every claim in the report cites an evidence id (Q1..Q7). Each evidence item stores the exact
SQL that ran, its hash and the returned rows, so a third party can re-run it. Hypotheses the
data does NOT support are reported as RULED OUT - that is part of the explanation.
"""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass, field

from .config import Config

P = "agent_id = ? AND step <= ?"
QUERIES = {
    "Q1": ("encoded_payload",
           "SELECT step, ROUND(encoded, 2) AS encoded, ROUND(entropy, 2) AS entropy FROM {events} "
           f"WHERE {P} AND encoded > 0.25 ORDER BY step"),
    "Q2": ("secret_exfiltration",
           "SELECT e.step, t.tool, t.destination, e.secret_hits FROM {events} e JOIN {tools} t "
           "ON e.agent_id = t.agent_id AND e.step = t.step "
           "WHERE e.agent_id = ? AND e.step <= ? AND e.secret_hits > 0 AND t.destination_external = 1 "
           "ORDER BY e.step"),
    "Q3": ("injection_markers",
           "SELECT step, inj_hits, snippet FROM {events} "
           f"WHERE {P} AND inj_hits > 0 ORDER BY step"),
    "Q4": ("external_traffic",
           "SELECT destination, COUNT(*) AS calls, MIN(step) AS first_step FROM {tools} "
           f"WHERE {P} AND destination_external = 1 GROUP BY destination"),
    "Q5": ("repetitive_probing",
           "SELECT step, ROUND(entropy, 2) AS entropy, ROUND(compression, 2) AS compression FROM {events} "
           f"WHERE {P} AND compression < 0.8 ORDER BY step"),
    "Q6": ("environment",
           "SELECT ROUND(AVG(volatility), 2) AS avg_vol, ROUND(MAX(volatility), 2) AS max_vol FROM {env} "
           f"WHERE {P}"),
    "Q7": ("detection_trajectory",
           "SELECT step, ROUND(score, 2) AS score, ROUND(cusum, 2) AS cusum, "
           "ROUND(multiplier, 2) AS multiplier, state FROM {det} "
           f"WHERE {P} AND state <> 'HEALTHY' ORDER BY step"),
}
SOURCE = {"Q1": {"events"}, "Q2": {"events", "tools"}, "Q3": {"events"}, "Q4": {"tools"},
          "Q5": {"events"}, "Q6": {"env"}, "Q7": {"det"}}


@dataclass
class Evidence:
    qid: str
    name: str
    sql: str
    sql_hash: str
    rows: list


@dataclass
class Finding:
    hid: str
    title: str
    status: str
    why: str
    cites: list


@dataclass
class Report:
    agent_id: str
    step: int
    engine: str
    findings: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    verdict: str = ""
    confidence: str = ""
    narrative: str = ""
    narrative_source: str = "template"

    def to_markdown(self) -> str:
        out = [f"# Incident report: `{self.agent_id}` quarantined at step {self.step}",
               f"*Evidence engine: {self.engine}*", "",
               f"**Verdict:** {self.verdict}  \n**Confidence:** {self.confidence}", "",
               f"## Explanation ({self.narrative_source})", self.narrative, "", "## Hypotheses"]
        for f in self.findings:
            cites = " ".join(f"[{c}]" for c in f.cites)
            out.append(f"- **{f.status}** - {f.title}: {f.why} {cites}")
        out += ["", "## Evidence (re-runnable)"]
        for e in self.evidence.values():
            out += [f"### {e.qid} {e.name}  (sql sha256:{e.sql_hash})", "```sql", e.sql, "```",
                    f"rows returned: {len(e.rows)}"]
            for r in e.rows[:5]:
                out.append(f"- {r}")
        return "\n".join(out)


CITE = re.compile(r"\[(Q\d+)\]")


def verify_citations(text: str, valid: set) -> bool:
    ids = set(CITE.findall(text))
    return bool(ids) and ids <= valid


class ForensicAuditor:
    def __init__(self, engine, cfg: Config, llm=None):
        self.engine, self.cfg, self.llm = engine, cfg, llm

    def _gather(self, agent_id: str, step: int) -> dict:
        ev = {}
        for qid, (name, tmpl) in QUERIES.items():
            sql = tmpl.format(**self.engine.tables)
            rows = self.engine.query(sql, (agent_id, step))
            ev[qid] = Evidence(qid, name, sql, hashlib.sha256(sql.encode()).hexdigest()[:12], rows)
        return ev

    def investigate(self, agent_id: str, step: int) -> Report:
        ev = self._gather(agent_id, step)
        R = {k: v.rows for k, v in ev.items()}
        F: list[Finding] = []

        def first(rows):
            return rows[0]["step"] if rows else None

        r = R["Q1"]
        F.append(Finding("H1", "Obfuscated / encoded payload in agent text",
                         "SUPPORTED" if r else "RULED_OUT",
                         (f"{len(r)} step(s) with encoded-content density > 0.25, first at step {first(r)}."
                          if r else "no step had encoded-content density above 0.25."), ["Q1"]))
        r = R["Q2"]
        F.append(Finding("H2", "Secrets sent to an external destination",
                         "SUPPORTED" if r else "RULED_OUT",
                         (f"secret-shaped strings left via {r[0]['tool']} to {r[0]['destination']} at step "
                          f"{r[0]['step']} (join of event text x tool-call logs)." if r else
                          "no secret-shaped string coincided with an external tool call."), ["Q2"]))
        r = R["Q3"]
        F.append(Finding("H3", "Prompt-injection / system-prompt disclosure attempt",
                         "SUPPORTED" if r else "RULED_OUT",
                         (f"injection phrases at {len(r)} step(s), first at step {first(r)}." if r else
                          "no injection phrases observed."), ["Q3"]))
        r = R["Q4"]
        F.append(Finding("H4", "Traffic to destinations outside the allow-list",
                         "SUPPORTED" if r else "RULED_OUT",
                         (f"{len(r)} external destination(s): " + ", ".join(
                             f"{x['destination']} ({x['calls']} calls, first step {x['first_step']})" for x in r)
                          if r else "no external destinations contacted."), ["Q4"]))
        r = R["Q5"]
        F.append(Finding("H5", "Repetitive / low-entropy probing (e.g. credential guessing)",
                         "SUPPORTED" if r else "RULED_OUT",
                         (f"{len(r)} highly compressible (repetitive) step(s), first at step {first(r)}." if r
                          else "text compressibility stayed in the normal range."), ["Q5"]))
        env, traj = R["Q6"][0] if R["Q6"] else {}, R["Q7"]
        last = traj[-1] if traj else None
        content = any(f.status == "SUPPORTED" for f in F)
        needs_tightening = bool(last and last["cusum"] < self.cfg.quarantine_h and last["score"] < self.cfg.hard_trip)
        if (env.get("max_vol") or 0) >= 0.5 and (not content or needs_tightening):
            st, why = "SUPPORTED", f"environment volatility peaked at {env['max_vol']}; alert may be noise-driven."
        else:
            st = "RULED_OUT"
            why = (f"peak volatility {env.get('max_vol', 0)} (avg {env.get('avg_vol', 0)}); "
                   + ("the alert would also have fired at the un-tightened threshold."
                      if not needs_tightening else "alert depended on env-tightened threshold - review manually."))
        F.append(Finding("H6", "False positive caused by a volatile environment", st, why, ["Q6", "Q7"]))
        if traj:
            F.append(Finding("H7", "Early warning preceded quarantine", "CONTEXT",
                             f"first non-healthy step {traj[0]['step']}, quarantined at step {step} "
                             f"(lead {step - traj[0]['step']} step(s)).", ["Q7"]))

        supported = [f for f in F if f.status == "SUPPORTED" and f.hid in {"H1", "H2", "H3", "H5"}]
        srcs = set().union(*[SOURCE[c] for f in supported for c in f.cites]) if supported else set()
        rep = Report(agent_id, step, getattr(self.engine, "name", "?"), F, ev)
        rep.verdict = ("Likely compromise - " + "; ".join(f.title for f in supported)) if supported \
            else "Behavioural drift without a confirmed malicious artefact - human review"
        rep.confidence = "High" if {"events", "tools"} <= srcs else "Medium" if srcs else "Low"
        rep.narrative = self._write(rep, set(ev))
        return rep

    def _template(self, rep: Report) -> str:
        sup = [f for f in rep.findings if f.status == "SUPPORTED"]
        lines = [f"{f.why} {' '.join(f'[{c}]' for c in f.cites)}" for f in sup]
        out = [f"- {l}" for l in lines] or ["- No hypothesis was confirmed by the evidence [Q7]."]
        ruled = [f.title for f in rep.findings if f.status == "RULED_OUT"]
        if ruled:
            out.append("- Ruled out: " + "; ".join(ruled) + " [Q1] [Q2] [Q3] [Q6]")
        return "\n".join(out)

    def _write(self, rep: Report, valid: set) -> str:
        base = self._template(rep)
        if self.llm and getattr(self.llm, "enabled", False):
            facts = "\n".join(f"{f.hid} {f.status}: {f.title}: {f.why} {' '.join(f'[{c}]' for c in f.cites)}"
                              for f in rep.findings)
            txt = self.llm.complete(
                "You write incident explanations for a security team. Use ONLY the findings given. "
                "Cite evidence ids like [Q2] after each claim. Add no new facts or numbers. Max 6 sentences.",
                facts)
            if txt and verify_citations(txt, valid):
                rep.narrative_source = "Muse Spark via Meta Model API (citation-checked)"
                return txt.strip()
        return base