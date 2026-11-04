"""LLM access. Two roles, both via an OpenAI-compatible chat-completions endpoint:
  LLM.auditor(cfg) -> Meta Model API (Muse Spark): writes the citation-checked incident narrative.
  LLM.agent(cfg)   -> any OpenAI-compatible endpoint, e.g. Muse Spark Open on Baseten (base URL
                      https://inference.baseten.co/v1): the monitored agent whose behaviour BioSentinel watches.
UNVERIFIED: confirm base URLs, model ids and auth headers in the Meta / Baseten docs.
Everything degrades gracefully (returns None) so the offline demo still works with no keys."""
from __future__ import annotations

import httpx

from .config import Config


class LLM:
    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url, self.api_key, self.model = base_url, api_key, model
        local = base_url.startswith(("http://localhost", "http://127.0.0.1"))
        self.enabled = bool(base_url and model and (api_key or local))   # local servers need no key
        self.last_error: str | None = None

    @classmethod
    def auditor(cls, cfg: Config) -> "LLM":
        return cls(cfg.llm_base_url, cfg.llm_api_key, cfg.llm_model)

    @classmethod
    def agent(cls, cfg: Config) -> "LLM":
        return cls(cfg.agent_base_url, cfg.agent_api_key, cfg.agent_model)

    def chat(self, messages: list, max_tokens: int = 500, temperature: float = 0.1):
        if not self.enabled:
            return None
        try:
            r = httpx.post(
                self.base_url.rstrip("/") + "/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key or 'none'}"},
                json={"model": self.model, "max_tokens": max_tokens,
                      "temperature": temperature, "messages": messages},
                timeout=60,
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"].get("content")
            if not content:
                self.last_error = "Empty reply (a reasoning model may have used up max_tokens)"
            return content or None
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            return None

    def complete(self, system: str, user: str, max_tokens: int = 500):
        return self.chat(
            [{"role": "system", "content": system},
             {"role": "user", "content": user}],
            max_tokens,
        )