# 3-minute demo script
0:00-0:20  Problem: agents misbehave inside "valid" traffic; teams find out days later. Show the one-line pitch.
0:20-0:50  Architecture slide: sentinel -> telemetry -> Zetaris -> forensic auditor. Name the sponsor pieces.
0:50-1:40  Live: dashboard, run `poisoned_dependency` (gradual). Point at WATCH (early warning), then QUARANTINED
           before the breach step. Show /allow/{agent} returning false.
1:40-2:30  Report: read two cited claims, open Q2 and show the SQL running through Zetaris (the join across sources).
           Show a RULED_OUT hypothesis and the environment false-positive check.
2:30-2:50  Honest limit: run `prompt_leak` with stealth ticked - caught only at the breach; say how Nemotron intent
           check addresses it.
2:50-3:00  eval table + repo link.
