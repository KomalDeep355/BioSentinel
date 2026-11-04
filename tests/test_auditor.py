import re
from biosentinel import scenarios
from biosentinel.auditor import verify_citations
from biosentinel.runner import fresh_sentinel, run_scenario


def report_for(name, **kw):
    s = fresh_sentinel()
    sc = scenarios.build(name, 0, **kw)
    run_scenario(sc, s)
    return s.reports[sc.events[0].agent_id]


def test_exfil_report_is_supported_by_two_sources():
    r = report_for("poisoned_dependency", stealth=True)
    status = {f.hid: f.status for f in r.findings}
    assert status["H2"] == "SUPPORTED" and status["H4"] == "SUPPORTED"
    assert r.confidence == "High"


def test_injection_report_cites_injection_hypothesis():
    r = report_for("prompt_leak", stealth=True)
    assert {f.hid: f.status for f in r.findings}["H3"] == "SUPPORTED"


def test_unsupported_hypotheses_are_ruled_out_not_ignored():
    r = report_for("weak_key_gatekeeper")
    status = {f.hid: f.status for f in r.findings}
    assert status["H5"] == "SUPPORTED" and status["H2"] == "RULED_OUT"


def test_every_citation_in_report_exists():
    r = report_for("obfuscated_rce")
    assert verify_citations(r.narrative, set(r.evidence))


def test_citation_guard_rejects_invented_ids_and_uncited_text():
    assert not verify_citations("Bad claim [Q99]", {"Q1"})
    assert not verify_citations("No citations at all", {"Q1"})


def test_evidence_sql_is_hashed_and_rerunnable():
    r = report_for("poisoned_dependency")
    for e in r.evidence.values():
        assert len(e.sql_hash) == 12 and "?" in e.sql


def test_secrets_never_persisted():
    s = fresh_sentinel()
    sc = scenarios.build("poisoned_dependency", 0)
    run_scenario(sc, s)
    rows = s.store.query("SELECT snippet FROM agent_events")
    assert all("sk-FAKE" not in r["snippet"] and "hunter2" not in r["snippet"] for r in rows)
