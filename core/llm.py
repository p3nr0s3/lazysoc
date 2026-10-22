"""
LLM provider layer for LazySOC: Claude API or a local OpenAI-compatible server.

Both providers take a system prompt, a user prompt and a JSON schema, and return parsed JSON.
Callers decide what goes into the prompt; feed summaries only ever send public article text.
"""

import json
import re
from typing import Any, Dict, Optional, Tuple

import requests

from core.config import (
    AI_SUMMARY_ENABLED,
    AI_SUMMARY_MODEL,
    AI_SUMMARY_EFFORT,
    AI_DEFAULT_PROVIDER,
    LOCAL_LLM_BASE_URL,
    LOCAL_LLM_MODEL,
    LOCAL_LLM_API_KEY,
    LOCAL_LLM_TIMEOUT_SECONDS,
)

PROVIDER_CLAUDE = "claude"
PROVIDER_LOCAL = "local"


class LLMError(Exception):
    def __init__(self, error_type: str, message: str):
        super().__init__(message)
        self.error_type = error_type
        self.message = message


_client = None


def _get_client():
    global _client
    if _client is None:
        import anthropic  # imported lazily so the rest of LazySOC runs without the SDK installed

        _client = anthropic.Anthropic(max_retries=2, timeout=300.0)
    return _client


def provider_status() -> Dict[str, Any]:
    """Which providers are usable, for the UI."""
    return {
        "enabled": AI_SUMMARY_ENABLED,
        "default": AI_DEFAULT_PROVIDER if AI_DEFAULT_PROVIDER in (PROVIDER_CLAUDE, PROVIDER_LOCAL) else PROVIDER_CLAUDE,
        "providers": {
            PROVIDER_CLAUDE: {"available": AI_SUMMARY_ENABLED, "model": AI_SUMMARY_MODEL},
            PROVIDER_LOCAL: {
                "available": AI_SUMMARY_ENABLED and bool(LOCAL_LLM_BASE_URL and LOCAL_LLM_MODEL),
                "model": LOCAL_LLM_MODEL,
                "base_url": LOCAL_LLM_BASE_URL,
            },
        },
    }


def resolve_provider(provider: Optional[str]) -> str:
    provider = (provider or provider_status()["default"]).lower()
    if provider not in (PROVIDER_CLAUDE, PROVIDER_LOCAL):
        raise LLMError("BAD_PROVIDER", f"Provider tidak dikenal: {provider}")
    return provider


def complete_json(system: str, user: str, schema: Dict[str, Any], provider: Optional[str] = None) -> Tuple[Dict[str, Any], str, str]:
    """Runs one completion and returns (parsed_json, model, provider)."""
    if not AI_SUMMARY_ENABLED:
        raise LLMError("DISABLED", "Ringkasan AI dinonaktifkan (AI_SUMMARY_ENABLED=false).")
    provider = resolve_provider(provider)
    if provider == PROVIDER_LOCAL:
        data, model = _complete_local(system, user, schema)
    else:
        data, model = _complete_claude(system, user, schema)
    return data, model, provider


def _complete_claude(system: str, user: str, schema: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    try:
        import anthropic
    except ImportError:
        raise LLMError("SDK_MISSING", "Paket 'anthropic' belum terpasang (pip install -r requirements.txt).")

    try:
        response = _get_client().beta.messages.create(
            model=AI_SUMMARY_MODEL,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            output_config={
                "effort": AI_SUMMARY_EFFORT,
                "format": {"type": "json_schema", "schema": schema},
            },
            system=system,
            messages=[{"role": "user", "content": user}],
        )
    except anthropic.AuthenticationError:
        raise LLMError("AUTH", "Kredensial Claude API tidak valid atau belum diset (ANTHROPIC_API_KEY).")
    except anthropic.PermissionDeniedError:
        raise LLMError("AUTH", "API key tidak punya akses ke model ini.")
    except anthropic.RateLimitError:
        raise LLMError("THROTTLED", "Rate limit Claude API tercapai. Coba lagi sebentar.")
    except anthropic.BadRequestError as e:
        raise LLMError("BAD_REQUEST", f"Permintaan ditolak API: {e.message}")
    except anthropic.APIStatusError as e:
        raise LLMError("API_ERROR", f"Claude API error {e.status_code}.")
    except anthropic.APIConnectionError:
        raise LLMError("NETWORK_ERROR", "Tidak dapat terhubung ke Claude API.")
    except TypeError as e:
        # Raised by the SDK before sending when no API key / auth token / profile is configured.
        if "authentication" in str(e).lower():
            raise LLMError("AUTH", "ANTHROPIC_API_KEY belum diset. Isi di file .env lalu restart LazySOC, atau pilih Local LLM.")
        raise

    if response.stop_reason == "refusal":
        raise LLMError("REFUSAL", "Model menolak meringkas konten ini.")
    if response.stop_reason == "max_tokens":
        raise LLMError("TRUNCATED", "Ringkasan terpotong (max_tokens).")

    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        return json.loads(text), response.model
    except json.JSONDecodeError:
        raise LLMError("PARSE_ERROR", "Respons model bukan JSON yang valid.")


def _extract_json(text: str) -> Dict[str, Any]:
    """Local models sometimes wrap JSON in prose or code fences; take the outermost object."""
    text = (text or "").strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("PARSE_ERROR", "Respons model lokal tidak berisi JSON.")
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        raise LLMError("PARSE_ERROR", "Respons model lokal bukan JSON yang valid.")
    if not isinstance(data, dict):
        raise LLMError("PARSE_ERROR", "Respons model lokal bukan objek JSON.")
    return data


def _complete_local(system: str, user: str, schema: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if not (LOCAL_LLM_BASE_URL and LOCAL_LLM_MODEL):
        raise LLMError("NOT_CONFIGURED", "Local LLM belum dikonfigurasi (LOCAL_LLM_BASE_URL dan LOCAL_LLM_MODEL di .env).")

    headers = {"Content-Type": "application/json"}
    if LOCAL_LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LOCAL_LLM_API_KEY}"
    # Not every local server enforces json_schema, so the schema is also spelled out in the prompt.
    system_with_schema = (
        f"{system}\n\nRespond with a single JSON object only (no prose, no code fences) that matches this JSON Schema:\n"
        f"{json.dumps(schema, ensure_ascii=False)}"
    )
    body = {
        "model": LOCAL_LLM_MODEL,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_with_schema},
            {"role": "user", "content": user},
        ],
    }
    try:
        resp = requests.post(f"{LOCAL_LLM_BASE_URL}/chat/completions", headers=headers, json=body, timeout=LOCAL_LLM_TIMEOUT_SECONDS)
    except requests.Timeout:
        raise LLMError("TIMEOUT", f"Local LLM tidak merespons dalam {LOCAL_LLM_TIMEOUT_SECONDS} detik.")
    except requests.RequestException:
        raise LLMError("NETWORK_ERROR", f"Tidak dapat terhubung ke local LLM di {LOCAL_LLM_BASE_URL}.")

    if resp.status_code == 400 and "response_format" in resp.text:
        # Older servers reject response_format; retry relying on the prompt alone.
        body.pop("response_format")
        try:
            resp = requests.post(f"{LOCAL_LLM_BASE_URL}/chat/completions", headers=headers, json=body, timeout=LOCAL_LLM_TIMEOUT_SECONDS)
        except requests.RequestException:
            raise LLMError("NETWORK_ERROR", f"Tidak dapat terhubung ke local LLM di {LOCAL_LLM_BASE_URL}.")
    if resp.status_code != 200:
        raise LLMError("API_ERROR", f"Local LLM error {resp.status_code}: {resp.text[:200]}")

    try:
        payload = resp.json()
        choice = payload["choices"][0]
        content = choice["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise LLMError("PARSE_ERROR", "Format respons local LLM tidak dikenali (bukan OpenAI-compatible).")
    if choice.get("finish_reason") == "length":
        raise LLMError("TRUNCATED", "Respons local LLM terpotong (context/max tokens).")
    return _extract_json(content), payload.get("model") or LOCAL_LLM_MODEL
