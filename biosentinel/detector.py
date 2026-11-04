from __future__ import annotations
from .config import Config
from .profile_memory import Z_FEATURES


def score_event(cfg: Config, feats: dict, pe: dict):
    """Return (score, signals). Statistical drift + hard rule signals."""
    score, sig = 0.0, {}
    if pe["ready"]:
        for name, z in pe["z"].items():
            two_sided = Z_FEATURES[name][0]
            eff = (abs(z) if two_sided else z) - cfg.deadband
            eff = min(max(0.0, eff), cfg.z_cap)
            if eff > 0:
                sig[f"drift:{name}"] = round(eff, 2)
                score += eff
        if pe["new_dest"]:
            sig["new_external_destination"] = cfg.w_new_dest
            score += cfg.w_new_dest
        if pe["new_tool"]:
            sig["new_tool"] = cfg.w_new_tool
            score += cfg.w_new_tool
    if feats["secret_hits"]:
        sig["secret_pattern"] = cfg.w_secret
        score += cfg.w_secret
    if feats["inj_hits"]:
        sig["injection_marker"] = cfg.w_inject
        score += cfg.w_inject
    if feats["obfusc_hits"]:
        sig["obfuscation_call"] = cfg.w_obfusc
        score += cfg.w_obfusc
    return score, sig
