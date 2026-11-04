"""Text-telemetry features. Cheap, dependency-free, explainable."""
from __future__ import annotations
import math
import re
import zlib
from collections import Counter, defaultdict

ENCODED = re.compile(r"[A-Za-z0-9+/=]{24,}")
HEXRUN = re.compile(r"\b[0-9a-fA-F]{32,}\b")
SECRET = re.compile(
    r"(?i)(?:\b[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z0-9_]*\s*[=:]\s*\S+)"
    r"|(?:\bsk-[A-Za-z0-9-]{8,})|(?:\bAKIA[0-9A-Z]{8,})"
)
INJECTION = (
    "ignore previous instructions", "ignore all previous", "disregard your instructions",
    "reveal your system prompt", "print your system prompt", "reveal your instructions",
    "developer mode",
)
OBFUSC = re.compile(r"(?i)\b(?:eval|exec|base64_decode|atob|fromcharcode)\s*\(|\bchr\s*\(")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def compression_ratio(text: str) -> float:
    b = text.encode("utf-8", "ignore")
    if len(b) < 16:
        return 1.0
    return len(zlib.compress(b)) / len(b)


def encoded_density(text: str) -> float:
    if not text:
        return 0.0
    covered = sum(len(m) for m in ENCODED.findall(text)) + sum(len(m) for m in HEXRUN.findall(text))
    return min(1.0, covered / len(text))


def extract(text: str) -> dict:
    low = text.lower()
    return {
        "entropy": shannon_entropy(text),
        "compression": compression_ratio(text),
        "encoded": encoded_density(text),
        "secret_hits": len(SECRET.findall(text)),
        "inj_hits": sum(low.count(p) for p in INJECTION),
        "obfusc_hits": len(OBFUSC.findall(text)),
        "length": len(text),
    }


def redact(text: str, limit: int = 160) -> str:
    """Never persist secrets: mask secret-shaped strings and long encoded runs."""
    t = SECRET.sub("[REDACTED]", text)
    t = ENCODED.sub(lambda m: f"[ENCODED:{len(m.group(0))}]", t)
    return t[:limit]


class BigramLM:
    """Tiny character-bigram model: a lightweight stand-in for token-perplexity drift.
    Swap for real token log-probs from a hosted model if you have them."""

    def __init__(self, k: float = 0.5, vocab: int = 128):
        self.k, self.V = k, vocab
        self.c: dict = defaultdict(Counter)
        self.tot: Counter = Counter()

    @staticmethod
    def _seq(text: str):
        return [min(ord(ch), 127) for ch in "^" + text]

    def train(self, text: str, sign: int = 1) -> None:
        s = self._seq(text)
        for a, b in zip(s, s[1:]):
            self.c[a][b] += sign
            self.tot[a] += sign

    def surprisal(self, text: str) -> float:
        s = self._seq(text)
        bits = 0.0
        for a, b in zip(s, s[1:]):
            p = (self.c[a][b] + self.k) / (self.tot[a] + self.k * self.V)
            bits -= math.log2(p)
        return bits / max(1, len(s) - 1)
