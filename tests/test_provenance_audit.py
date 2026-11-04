from biosentinel.auditlog import AuditLog
from biosentinel.live_agent import ScriptedLLM, run_live_agent
from biosentinel.provenance import Provenance
from biosentinel.runner import fresh_sentinel


def test_audit_chain_verifies_and_detects_tampering():
    log = AuditLog()
    for i in range(6):
        log.append({"step": i, "state": "HEALTHY"})
    assert log.verify() == (True, None)
    log.entries[3]["record"]["state"] = "QUARANTINED"
    ok, bad = log.verify()
    assert not ok and bad == 3


def test_audit_chain_detects_deleted_entry():
    log = AuditLog()
    for i in range(5):
        log.append({"step": i})
    del log.entries[2]
    assert log.verify()[0] is False


def test_provenance_flags_untrusted_content_going_external():
    p = Provenance()
    p.mark_untrusted("a", "vendor_notes.txt", "The confidential supplier price floor is forty one point seven percent.")
    hit = p.check_egress("a", "partner.example", "FYI the confidential supplier price floor is forty one point seven")
    assert hit and hit["rule"] == "untrusted_egress"


def test_provenance_allows_internal_and_unrelated_external():
    p = Provenance()
    p.mark_untrusted("a", "doc", "The confidential supplier price floor is forty one point seven percent.")
    assert p.check_egress("a", "team.corp.internal", "price floor is forty one point seven percent") is None
    assert p.check_egress("a", "partner.example", "Meeting moved to Thursday afternoon.") is None


def _run(attack, variant="injection"):
    s = fresh_sentinel()
    ev = []
    s.on_event = ev.append
    out = run_live_agent(s, ScriptedLLM(attack, variant), "task", attack, mode="scripted", variant=variant)
    return s, out, ev


def test_normal_run_finishes_and_audit_verifies():
    s, out, ev = _run(False)
    assert out["outcome"] == "finished"
    assert s.audit.verify()[0] is True and len(s.audit.entries) > 30


def test_injection_run_is_blocked():
    _, out, _ = _run(True, "injection")
    assert out["outcome"] in ("blocked", "blocked_by_policy")


def test_stealth_run_is_stopped_by_provenance_policy():
    s, out, ev = _run(True, "stealth")
    assert out["outcome"] == "blocked_by_policy"
    assert any(e["type"] == "policy_block" for e in ev)
    assert any(e["record"].get("kind") == "policy_block" for e in s.audit.entries)