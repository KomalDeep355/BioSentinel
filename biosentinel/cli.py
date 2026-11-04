"""python -m biosentinel.cli demo [scenario|all]   |   python -m biosentinel.cli eval [--seeds N]"""
from __future__ import annotations
import argparse
from pathlib import Path

from . import scenarios
from .runner import detection_steps, fresh_sentinel, run_scenario

REPORTS = Path("reports")


def demo(names):
    REPORTS.mkdir(exist_ok=True)
    for name in names:
        sc = scenarios.build(name, seed=1)
        s = fresh_sentinel()
        vs = run_scenario(sc, s)
        print(f"\n=== {name}: {sc.description}")
        for v in vs:
            if v.state != "HEALTHY" or v.step in (sc.drift_start, sc.breach_step):
                tag = "<-- QUARANTINED" if v.quarantined_now else ""
                print(f"  step {v.step:3d} {v.state:11s} score={v.score:5.2f} cusum={v.cusum:5.2f} "
                      f"signals={list(v.signals)} {tag}")
        warn, quar = detection_steps(vs)
        print(f"  drift starts {sc.drift_start} | first warning {warn} | quarantine {quar} | "
              f"actual breach {sc.breach_step}")
        rep = s.reports.get(sc.events[0].agent_id)
        if rep:
            (REPORTS / f"{name}.md").write_text(rep.to_markdown())
            print(f"  report -> reports/{name}.md  (verdict: {rep.verdict}; confidence {rep.confidence})")


def evaluate(n_seeds: int):
    REPORTS.mkdir(exist_ok=True)
    rows = ["| scenario | mode | detected | median warn lead* | median quarantine lead* |",
            "|---|---|---|---|---|"]
    for name in scenarios.SCENARIOS:
        for stealth in (False, True):
            leads_w, leads_q, hit = [], [], 0
            for seed in range(n_seeds):
                sc = scenarios.build(name, seed, noisy_env=seed % 2 == 0, stealth=stealth)
                vs = run_scenario(sc, fresh_sentinel())
                w, q = detection_steps(vs)
                if q is not None:
                    hit += 1
                    leads_q.append(sc.breach_step - q)
                    leads_w.append(sc.breach_step - (w if w is not None else q))
            med = lambda x: sorted(x)[len(x) // 2] if x else "-"
            rows.append(f"| {name} | {'stealth' if stealth else 'gradual'} | {hit}/{n_seeds} | "
                        f"{med(leads_w)} | {med(leads_q)} |")
    fp = 0
    for seed in range(n_seeds):
        vs = run_scenario(scenarios.build(None, seed, noisy_env=seed % 2 == 0), fresh_sentinel())
        fp += detection_steps(vs)[1] is not None
    out = "\n".join(rows) + f"\n\n*lead = steps between detection and the simulated breach step " \
          f"(positive = detected before the breach, 0 = at the breach).\n" \
          f"Benign-only runs with false quarantine: {fp}/{n_seeds}\n\n" \
          "CAVEAT: scenarios are synthetic fixtures written by the authors; these numbers show the " \
          "mechanism works, NOT real-world accuracy.\n"
    print(out)
    (REPORTS / "eval_results.md").write_text(out)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("scenario", nargs="?", default="all")
    e = sub.add_parser("eval"); e.add_argument("--seeds", type=int, default=20)
    x = sub.add_parser("export"); x.add_argument("--out", default="export_csv")
    a = ap.parse_args()
    if a.cmd == "demo":
        demo(list(scenarios.SCENARIOS) if a.scenario == "all" else [a.scenario])
    elif a.cmd == "eval":
        evaluate(a.seeds)
    else:
        s = fresh_sentinel()
        for n in scenarios.SCENARIOS:
            run_scenario(scenarios.build(n, 1), s)
        print("\n".join(s.store.export_csv(a.out)))


if __name__ == "__main__":
    main()