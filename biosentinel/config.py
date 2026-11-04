from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass
class Config:
    warmup: int = 25
    deadband: float = 3.0
    z_cap: float = 6.0
    cusum_k: float = 0.5
    warn_h: float = 3.0
    quarantine_h: float = 6.0
    hard_trip: float = 9.0
    learn_below: float = 1.0
    w_secret: float = 3.0
    w_inject: float = 3.0
    w_obfusc: float = 2.0
    w_new_dest: float = 2.0
    w_new_tool: float = 1.0
    env_tighten: float = 0.35
    internal_suffixes: tuple = (".internal", ".corp", "localhost")
    db_path: str = os.getenv("BIOSENTINEL_DB", ":memory:")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "")
    agent_base_url: str = os.getenv("AGENT_BASE_URL", "")
    agent_api_key: str = os.getenv("AGENT_API_KEY", "")
    agent_model: str = os.getenv("AGENT_MODEL", "")
    alert_console: bool = False
    alert_file: str = ""
    alert_webhook_url: str = os.getenv("ALERT_WEBHOOK_URL", "")
    alert_webhook_style: str = "slack"