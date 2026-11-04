# BioSentinel

**A runtime firewall for AI agents. It does not trust the model to refuse an attack. It watches what the agent does, and it stops the dangerous tool call before it leaves.**

Built for the Meta Global AI Developer Hackathon (Oct 27 - Nov 4, 2026). Problem statement: *Push the Frontier* (software and agents).

> Demo video: `<link>` | Live demo: `<link or "run locally, see below">` | Hackathon track: Indie Developer

## The problem
Agents read content they cannot trust: web pages, documents, emails. A hostile instruction hidden in that content can make an agent leak secrets or take actions its user never asked for. Training a model to refuse helps, but it cannot be the only defense, because a fooled model still holds the keys. BioSentinel puts a decision point outside the model.

## What it does
1. **Gateway.** Every tool call goes through BioSentinel first. A quarantined agent's next call is refused.
2. **Behavioural detector.** It learns each agent's own normal (text statistics, tools, destinations) and scores drift with a CUSUM state machine.
3. **Provenance policy.** Content fetched from untrusted sources may not be sent to an external destination, and credential-like strings may not leave at all.
4. **Forensic report.** After an incident, an auditor writes a report where each claim cites a re-runnable SQL query.
5. **Tamper-evident audit log.** Every decision is hash-chained, so editing history is detectable.
6. **Attack lab.** A sandbox with a mock website, a fake secret and an attacker inbox. Run the same attack with BioSentinel off and on, or type your own attacker text live.

## Try it in 2 minutes
```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q                                      # 50 tests
uvicorn biosentinel.api:app --reload                     # open http://127.0.0.1:8000
```
In the **Live agent feed** panel (bottom right), open the Attack lab: pick *Explicit injection*, untick *BioSentinel on*, click **Launch** and watch the fake secret land in the attacker inbox. Tick it back on and launch again: the email never leaves.

## Meta models used
- **Muse Spark Open**, served through Baseten (`meta-models/muse-spark-open-1026`), runs the monitored agent: it reads the page and decides which tool to call. <EDIT THIS LINE to match exactly what you ran. If you ran something else, say so.>
- The Meta Model API was not used (billing could not be set up on my account).
- Without keys, replay buttons use a **scripted stand-in that always obeys**. The dashboard labels it. It is for rehearsal, not a model result.

Configure it in `.env` (copy `.env.example`).

## Results
Run `python scripts/run_lab_eval.py --mode live --runs 10`; it writes `reports/lab_eval.md`.
<PASTE THE TABLE HERE. Only claim numbers that file contains.>

How to read it: with BioSentinel off, *leaked* shows how often the agent obeyed the attack. With it on, it should drop. On the no-attack control, *task finished* must stay at n/n: that is the false-positive check.

## What was built during the hackathon vs. what existed before
See [docs/PRIOR_WORK.md](docs/PRIOR_WORK.md). In short: the detector, gateway and forensic auditor predate the event. Built during it: the tool-using agent loop, the sandboxed attack lab, the provenance policy, the hash-chained audit log, the live feed and dashboard panel, the Muse Spark Open wiring, the evaluation script and the deployment files.

## Honest limits
- Scenarios and attacks are **synthetic**. Results say nothing about real-world detection rates.
- Provenance uses text overlap and secret patterns. A model that paraphrases a leak can slip past it. The detector alone did not catch the stealth attack in my tests; the gateway rules did.
- The baseline is warmed up from recorded benign traffic. A real model's output differs, so thresholds need calibration per agent.
- The audit log is tamper-**evident**, not tamper-proof: someone who can rewrite the whole chain can forge it.
- Everything runs against a sandbox. The agent's browse tool can only open the mock site, and all secrets are fake.

## Roadmap
Drop-in proxy (change one `base_url`), an `@guard` SDK, MCP gateway, human approval for risky actions, SIEM/OpenTelemetry export, policy files, red-team runs in CI, and a trained injection classifier compared against Meta's LlamaFirewall.

## Related work
Meta's LlamaFirewall (PromptGuard 2, AlignmentCheck), ActGuard (pre-execution action auditing), AgentDojo and InjecAgent (benchmarks). BioSentinel complements message-level guardrails with per-agent behaviour baselines, provenance and verifiable evidence.

## Layout
`biosentinel/` core and API | `dashboard/` UI | `docs/` architecture and prior work | `scripts/` evaluation | `tests/` 50 tests | `Dockerfile` deployment