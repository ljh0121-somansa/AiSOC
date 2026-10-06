"""
Copilot chat API — persistent conversation history.

Endpoints (all under ``/api/v1/copilot``):

    GET  /conversations             — list the last N conversations
    GET  /conversations/{id}        — retrieve a single conversation
    POST /chat                      — one-shot chat (creates / continues conv.)
    POST /chat/stream               — streaming NDJSON variant

Falls back to synthetic deterministic replies when ``OPENAI_API_KEY`` is
unset so the demo path never breaks.
"""

from __future__ import annotations

import os
import itertools
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.security.tenant_scope import require_console_or_service_auth

logger = structlog.get_logger()

#: Default-deny. The console reaches this router directly through a Next
#: rewrite carrying the first-party access token, so the guard resolves
#: either that session or a trusted service declaring the tenant it acts
#: for — a bearer-token-only scheme would lock the browser out.
router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"], dependencies=[Depends(require_console_or_service_auth)])


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


class CopilotMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str  # "user" | "assistant"
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class CopilotChatRequest(BaseModel):
    message: str
    conversationId: str | None = None
    context: dict[str, Any] | None = None


class CopilotChatResponse(BaseModel):
    conversationId: str
    reply: CopilotMessage
    #: ``llm`` when a model produced the reply, ``template`` when this service
    #: fell back to a canned paragraph (no API key, or the call failed).
    #: The console must label a ``template`` reply rather than presenting it as
    #: analysis of the user's environment.
    source: Literal["llm", "template"] = "llm"
    notice: str | None = None


class CopilotConversation(BaseModel):
    id: str
    title: str
    updatedAt: str
    messageCount: int


# ---------------------------------------------------------------------------
# In-memory store (demo: resets on restart; production would use Postgres)
# ---------------------------------------------------------------------------

_CONVERSATIONS: dict[str, dict[str, Any]] = {}

_SYNTHETIC_REPLIES = [
    (
        "LLM을 불러오는데에 문제가 있었습니다. 다시 시도해주세요."
    ),
]

_reply_cycle = itertools.cycle(_SYNTHETIC_REPLIES)


def _synthetic_reply(user_msg: str) -> str:
    return next(_reply_cycle)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _title_from_message(msg: str) -> str:
    return msg[:60] + ("…" if len(msg) > 60 else "")

def _build_copilot_messages(
    conversation: dict[str, Any],
    user_message: str,
) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = [
        {
            "role": "system",
            "content": (
                "You are AiSOC Copilot, an AI assistant for security operations. "
                "Help analysts investigate alerts, correlate events, and respond to threats. "
                "Be concise, technical, and actionable. Reference MITRE ATT&CK techniques "
                "when relevant. Format recommendations as numbered steps when appropriate."
                "Always respond in Korean, but keep technical terms (e.g., MITRE ATT&CK, "
                "log names, security tools, commands) in English where natural for SOC analysts."
            ),
        }
    ]
    raw_history = conversation.get("messages", [])[-10:]
    for m in raw_history:
        messages.append({"role": m["role"], "content": m["content"]})
    if not raw_history or raw_history[-1].get("content") != user_message:
        messages.append({"role": "user", "content": user_message})
    return messages


async def _get_openai_reply(
    conversation: dict[str, Any],
    user_message: str,
) -> tuple[str, str]:
    """Return ``(reply_text, source)`` where source is ``llm`` or ``template``.

    The caller must surface ``template`` to the user. This function silently
    returned a canned paragraph as a normal 200 whenever the key was missing or
    any exception fired, so an analyst read "this IP was seen in 3 other
    alerts" as real analysis of their environment. The frontend had an honest
    fallback of its own that never fired, because the backend reported success.
    """
    from app.llm.factory import resolve_api_key, resolve_model_alias

    model = resolve_model_alias("copilot")
    api_key = resolve_api_key(model) or ""
    if not api_key:
        return "⚠️ [오류] OPENAI_API_KEY가 설정되지 않았습니다.", "template"

    try:
        from app.llm.contract import safe_chat_completions_request
        from app.llm.factory import chat_completions_url

        messages = _build_copilot_messages(conversation, user_message)

        body = await safe_chat_completions_request(
            api_key=api_key,
            model=model,
            messages=messages,
            url=chat_completions_url(model),
            timeout=60.0,
            max_tokens=int(os.getenv("AISOC_COPILOT_MAX_TOKENS", "4000")),
        )
        raw_content = body["choices"][0]["message"]["content"]
        clean_content = raw_content.split("</think>", 1)[-1]
        return clean_content, "llm"
    except Exception as exc:
        logger.warning("copilot.openai_error", error=str(exc))
        return f"⚠️ [LLM 호출 실패] {str(exc)}", "template"

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/conversations")
async def list_conversations(limit: int = 20) -> dict[str, Any]:
    convs = sorted(
        _CONVERSATIONS.values(),
        key=lambda c: c["updatedAt"],
        reverse=True,
    )[:limit]
    return {
        "conversations": [
            {
                "id": c["id"],
                "title": c["title"],
                "updatedAt": c["updatedAt"],
                "messageCount": len(c["messages"]),
            }
            for c in convs
        ]
    }


@router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str) -> dict[str, Any]:
    conv = _CONVERSATIONS.get(conversation_id)
    if conv is None:
        return {"id": conversation_id, "title": "Not found", "messages": []}
    return {
        "id": conv["id"],
        "title": conv["title"],
        "messages": conv["messages"],
    }


@router.post("/chat", response_model=CopilotChatResponse)
async def chat(req: CopilotChatRequest) -> CopilotChatResponse:
    conv_id = req.conversationId or str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    if conv_id not in _CONVERSATIONS:
        _CONVERSATIONS[conv_id] = {
            "id": conv_id,
            "title": _title_from_message(req.message),
            "messages": [],
            "updatedAt": now,
        }

    conv = _CONVERSATIONS[conv_id]

    user_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": now,
    }
    conv["messages"].append(user_msg)

    reply_text, reply_source = await _get_openai_reply(conv, req.message)

    assistant_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "assistant",
        "content": reply_text,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    conv["messages"].append(assistant_msg)
    conv["updatedAt"] = assistant_msg["timestamp"]

    return CopilotChatResponse(
        conversationId=conv_id,
        reply=CopilotMessage(**assistant_msg),
        source=reply_source,
        notice=(
            "This reply came from a built-in template, not a language model. "
            "It is generic guidance and is not analysis of your environment. "
            "Configure an LLM key to get a real investigation."
            if reply_source == "template"
            else None
        ),
    )


@router.post("/chat/stream")
async def chat_stream(req: CopilotChatRequest) -> StreamingResponse:
    """Stream a chat reply as NDJSON deltas in real-time."""

    conv_id = req.conversationId or str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    if conv_id not in _CONVERSATIONS:
        _CONVERSATIONS[conv_id] = {
            "id": conv_id,
            "title": _title_from_message(req.message),
            "messages": [],
            "updatedAt": now,
        }

    conv = _CONVERSATIONS[conv_id]
    user_msg: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": now,
    }
    conv["messages"].append(user_msg)

    from app.llm.factory import resolve_api_key, resolve_model_alias, chat_completions_url

    model = resolve_model_alias("copilot")
    api_key = resolve_api_key(model) or ""
    msg_id = str(uuid.uuid4())

    async def _stream() -> AsyncIterator[bytes]:
        # Provenance first: a consumer must be able to label the answer before
        # it starts rendering tokens, not after.
        if not api_key:
            yield (json.dumps({"source": "template", "delta": "", "done": False}) + "\n").encode()
            fallback_text = "⚠️ [오류] OPENAI_API_KEY가 설정되지 않았습니다."
            yield (json.dumps({"delta": fallback_text, "done": False}) + "\n").encode()
            assistant_msg: dict[str, Any] = {
                "id": msg_id,
                "role": "assistant",
                "content": fallback_text,
                "timestamp": datetime.now(UTC).isoformat(),
            }
            conv["messages"].append(assistant_msg)
            conv["updatedAt"] = assistant_msg["timestamp"]
            yield (
                json.dumps(
                    {
                        "done": True,
                        "conversationId": conv_id,
                        "messageId": msg_id,
                    }
                )
                + "\n"
            ).encode()
            return

        yield (json.dumps({"source": "llm", "delta": "", "done": False}) + "\n").encode()
        accumulated_chunks: list[str] = []

        try:
            from app.llm.contract import safe_chat_completions_stream

            messages = _build_copilot_messages(conv, req.message)
            url = chat_completions_url(model)
            max_tokens = int(os.getenv("AISOC_COPILOT_MAX_TOKENS", "4000"))

            async for token in safe_chat_completions_stream(
                api_key=api_key,
                model=model,
                messages=messages,
                url=url,
                max_tokens=max_tokens,
            ):
                accumulated_chunks.append(token)
                yield (json.dumps({"delta": token, "done": False}) + "\n").encode()

            full_reply = "".join(accumulated_chunks)
            clean_reply = full_reply.split("</think>", 1)[-1]
            assistant_msg: dict[str, Any] = {
                "id": msg_id,
                "role": "assistant",
                "content": clean_reply,
                "timestamp": datetime.now(UTC).isoformat(),
            }
            conv["messages"].append(assistant_msg)
            conv["updatedAt"] = assistant_msg["timestamp"]
            yield (
                json.dumps(
                    {
                        "done": True,
                        "conversationId": conv_id,
                        "messageId": msg_id,
                    }
                )
                + "\n"
            ).encode()
        except Exception as exc:
            err_detail = str(exc) or type(exc).__name__
            logger.warning("copilot.stream_error", error=err_detail)
            err_msg = f"⚠️ [LLM 호출 실패] {err_detail}"
            yield (json.dumps({"delta": f"\n\n{err_msg}", "done": False, "error": err_msg}) + "\n").encode()
            assistant_msg = {
                "id": msg_id,
                "role": "assistant",
                "content": "".join(accumulated_chunks) + f"\n\n{err_msg}",
                "timestamp": datetime.now(UTC).isoformat(),
            }
            conv["messages"].append(assistant_msg)
            conv["updatedAt"] = assistant_msg["timestamp"]
            yield (
                json.dumps(
                    {
                        "done": True,
                        "conversationId": conv_id,
                        "messageId": msg_id,
                        "error": err_msg,
                    }
                )
                + "\n"
            ).encode()

    response_headers = {
        "X-Accel-Buffering": "no",
        "Cache-Control": "no-cache, no-transform",
        "Content-Type": "application/x-ndjson",
    }
    return StreamingResponse(_stream(), media_type="application/x-ndjson", headers=response_headers)
