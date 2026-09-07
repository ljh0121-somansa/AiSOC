"""Model-aware chat prompt builder for multi-LLM support (GPT-4o, Claude, Qwen, DeepSeek).

Adapts the message layout based on the active model family:
- Qwen / DeepSeek reasoning models: Combines system prompt and user data into a single
  HumanMessage to prevent prompt-echo monologue loops in vLLM / proxy endpoints.
- GPT-4o / Claude / Standard models: Keeps SystemMessage and HumanMessage strictly separated
  for optimal system instruction adherence and jailbreak defense.
"""

from __future__ import annotations

from typing import Any
from langchain_core.messages import HumanMessage, SystemMessage


def is_reasoning_or_open_model(model_name: str | None) -> bool:
    """Return True if the model belongs to Qwen, DeepSeek, or other open-weight reasoning families."""
    if not model_name:
        return False
    name = model_name.lower().strip()
    return any(family in name for family in ("qwen", "deepseek", "r1", "ollama", "local"))


def build_model_aware_messages(
    *,
    system_prompt: str,
    user_content: str,
    model_name: str | None = None,
) -> list[Any]:
    """Build canonical ChatML messages with strict System/Human role separation."""
    return [
        SystemMessage(content=system_prompt.strip()),
        HumanMessage(content=user_content.strip()),
    ]


def build_audit_prompt_payload(
    *,
    system_prompt: str,
    user_content: str,
    model_name: str | None = None,
) -> list[dict[str, str]]:
    """Build canonical audit ledger prompt structure with strict System/Human role separation."""
    return [
        {"role": "system", "content": system_prompt.strip()},
        {"role": "user", "content": user_content.strip()},
    ]
