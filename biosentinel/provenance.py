"""Data provenance for the tool gateway.
Content returned by retrieval tools (documents, web pages, emails) is UNTRUSTED. Before an agent sends
anything to an EXTERNAL destination, we check whether the outgoing text was derived from untrusted content
(shared multi-word phrases or long tokens) or contains a credential-like string.
Limits: this is lexical overlap, so a model that paraphrases the leaked content can slip past it. That is
why it is one gateway signal next to the behavioural detector, not a replacement for it."""
from __future__ import annotations
import re

INTERNAL_SUFFIXES = (".internal", ".corp", "localhost")
SECRET = re.compile(r"(sk-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{8,}|\b[A-Z][A-Z0-9_]{3,}(?:KEY|SECRET|PASSWORD|TOKEN)\s*[=:]\s*\S+)")
_WORD = re.compile(r"[a-z0-9']+")


def _shingles(text: str, n: int = 4) -> set[str]:
    w = _WORD.findall(text.lower())
    return {" ".join(w[i:i + n]) for i in range(len(w) - n + 1)}


def _long_tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"\S+", text) if len(t) >= 14}


def _mask(s: str) -> str:
    return s[:6] + "..." if len(s) > 9 else s


def is_external(destination: str | None) -> bool:
    return bool(destination) and not str(destination).lower().endswith(INTERNAL_SUFFIXES)


class Provenance:
    def __init__(self):
        self._untrusted: dict[str, list[tuple[str, str]]] = {}

    def mark_untrusted(self, agent_id: str, source: str, text: str) -> None:
        self._untrusted.setdefault(agent_id, []).append((source, text))

    def check_egress(self, agent_id: str, destination: str | None, outgoing: str) -> dict | None:
        """Return a violation dict, or None if the call may proceed."""
        if not is_external(destination):
            return None
        for source, text in self._untrusted.get(agent_id, []):
            shared = _shingles(outgoing) & _shingles(text)
            tokens = _long_tokens(outgoing) & _long_tokens(text)
            if shared or tokens:
                ev = sorted(shared)[:2] + [_mask(t) for t in sorted(tokens)[:2]]
                return {"rule": "untrusted_egress", "source": source, "destination": destination, "evidence": ev,
                        "reason": f"Outgoing content to {destination} was derived from untrusted source '{source}'."}
        if SECRET.search(outgoing):
            return {"rule": "secret_egress", "source": None, "destination": destination, "evidence": [],
                    "reason": f"Credential-like string in content bound for external destination {destination}."}
        return None