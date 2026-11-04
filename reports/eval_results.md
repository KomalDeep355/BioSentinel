| scenario | mode | detected | median warn lead* | median quarantine lead* |
|---|---|---|---|---|
| obfuscated_rce | gradual | 20/20 | 3 | 2 |
| obfuscated_rce | stealth | 20/20 | 0 | 0 |
| weak_key_gatekeeper | gradual | 20/20 | 8 | 7 |
| weak_key_gatekeeper | stealth | 20/20 | 0 | 0 |
| poisoned_dependency | gradual | 20/20 | 7 | 6 |
| poisoned_dependency | stealth | 20/20 | 0 | 0 |
| prompt_leak | gradual | 20/20 | 7 | 4 |
| prompt_leak | stealth | 20/20 | 0 | -1 |

*lead = steps between detection and the simulated breach step (positive = detected before the breach, 0 = at the breach).
Benign-only runs with false quarantine: 0/20

CAVEAT: scenarios are synthetic fixtures written by the authors; these numbers show the mechanism works, NOT real-world accuracy.
