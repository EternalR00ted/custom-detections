"""One way to ask any of the three model families for a JSON answer.

A model is named "<family>:<model ID>" in config/settings.yaml, and each family
is one API key, stored as a secret variable:

- claude:<model>  Anthropic API (ANTHROPIC_API_KEY)
- openai:<model>  OpenAI API (OPENAI_API_KEY)
- gemini:<model>  Gemini API (GEMINI_API_KEY)

A family without a key is skipped, and the report says so.

Every answer must match a JSON schema, and code checks it before using it.
None of the models get tools that do anything.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any

import requests

from . import observability
from .claude import Claude, Declined, Usage
from .common import env

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"


def family(spec: str) -> str:
    return spec.split(":", 1)[0] if ":" in spec else "claude"


def name(spec: str) -> str:
    return spec.split(":", 1)[1] if ":" in spec else spec


def strict(schema: dict) -> dict:
    """Copy of a JSON schema where every object lists all its properties as required and allows no others.

    OpenAI's strict structured outputs need this; Gemini and Claude accept it too.
    """
    if not isinstance(schema, dict):
        return schema
    copy = {key: strict(value) if isinstance(value, dict) else value for key, value in schema.items()}
    if copy.get("type") == "object" and "properties" in copy:
        copy["properties"] = {key: strict(value) for key, value in copy["properties"].items()}
        copy["required"] = list(copy["properties"])
        copy["additionalProperties"] = False
    if copy.get("type") == "array" and isinstance(copy.get("items"), dict):
        copy["items"] = strict(copy["items"])
    return copy


class Models:
    """Asks Claude, OpenAI or Gemini models for JSON, and counts what each call cost."""

    def __init__(self, claude: Claude | None, session: requests.Session | None = None, usage: Usage | None = None):
        self.claude = claude
        self.session = session or requests.Session()
        self.usage = usage or (claude.usage if claude else Usage())
        if claude:
            claude.usage = self.usage

    def available(self, spec: str) -> bool:
        kind = family(spec)
        if kind == "gemini":
            return bool(env("GEMINI_API_KEY"))
        if kind == "openai":
            return bool(env("OPENAI_API_KEY"))
        return self.claude is not None

    def ask_json(self, spec: str, system: str, prompt: str, schema: dict, max_tokens: int = 8000) -> dict:
        kind = family(spec)
        if kind == "claude":
            tool = {"name": "answer", "description": "Give your answer.", "input_schema": strict(schema)}
            return self.claude.ask(name(spec), system, prompt, [tool], max_tokens=max_tokens).data
        if kind == "gemini":
            return self._gemini(name(spec), system, prompt, strict(schema), max_tokens)
        if kind == "openai":
            return self._openai(name(spec), system, prompt, strict(schema), max_tokens)
        raise Declined(f"unknown model family in {spec}")

    def first_json(self, specs: list[str], system: str, prompt: str, schema: dict,
                   max_tokens: int = 8000) -> tuple[dict, str, list[str]]:
        """Ask each model in turn until one answers. Returns the answer, who answered, and why others didn't."""
        reasons = []
        for spec in specs:
            if not self.available(spec):
                reasons.append(f"{spec} isn't set up")
                continue
            try:
                return self.ask_json(spec, system, prompt, schema, max_tokens), spec, reasons
            except Declined as reason:
                reasons.append(str(reason))
        raise Declined("; ".join(reasons) or "no model to ask")

    # Providers

    def _post(self, url: str, headers: dict, body: dict, label: str) -> dict:
        for attempt in range(5):
            try:
                response = self.session.post(url, headers=headers, json=body, timeout=600)
            except requests.RequestException as error:
                raise Declined(f"{label} failed: {type(error).__name__}") from error
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 4:
                wait = response.headers.get("Retry-After", "")
                time.sleep(min(int(wait) if wait.isdigit() else 2 ** (attempt + 2), 60))
                continue
            if response.status_code >= 400:
                raise Declined(f"{label} returned {response.status_code}: {response.text[:300]}")
            return response.json()
        raise Declined(f"{label} kept returning {response.status_code}")

    def _gemini(self, model: str, system: str, prompt: str, schema: dict, max_tokens: int) -> dict:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "responseJsonSchema": schema,
                                 "maxOutputTokens": max_tokens},
        }
        headers = {"x-goog-api-key": env("GEMINI_API_KEY"), "Content-Type": "application/json"}
        with observability.chat("gemini", model, max_tokens) as call:
            data = self._post(GEMINI_URL.format(model=model), headers, body, model)
            meta = data.get("usageMetadata") or {}
            blocked = (data.get("promptFeedback") or {}).get("blockReason")
            candidates = data.get("candidates") or []
            call.tokens(meta.get("promptTokenCount", 0), meta.get("candidatesTokenCount", 0))
            call.finished(blocked or (candidates[0].get("finishReason") if candidates else "no answer"))
        self.usage.add(model, SimpleNamespace(input_tokens=meta.get("promptTokenCount", 0),
                                              output_tokens=meta.get("candidatesTokenCount", 0)))
        if blocked or not candidates:
            raise Declined(f"{model} declined ({blocked or 'no answer'})")
        candidate = candidates[0]
        if candidate.get("finishReason") not in (None, "STOP"):
            raise Declined(f"{model} stopped early ({candidate.get('finishReason')})")
        parts = (candidate.get("content") or {}).get("parts") or []
        text = "".join(part.get("text", "") for part in parts if not part.get("thought"))
        return _parse(text, model)

    def _openai(self, deployment: str, system: str, prompt: str, schema: dict, max_tokens: int) -> dict:
        body = {
            "model": deployment,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "answer", "schema": schema, "strict": True}},
            "max_completion_tokens": max_tokens,
        }
        headers = {"Authorization": f"Bearer {env('OPENAI_API_KEY')}", "Content-Type": "application/json"}
        with observability.chat("openai", deployment, max_tokens) as call:
            data = self._post(OPENAI_URL, headers, body, deployment)
            usage = data.get("usage") or {}
            choices = data.get("choices") or []
            call.tokens(usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
            call.finished(choices[0].get("finish_reason") if choices else "no answer")
        self.usage.add(deployment, SimpleNamespace(input_tokens=usage.get("prompt_tokens", 0),
                                                   output_tokens=usage.get("completion_tokens", 0)))
        if not choices:
            raise Declined(f"{deployment} gave no answer")
        message = choices[0].get("message") or {}
        if message.get("refusal"):
            raise Declined(f"{deployment} declined: {str(message['refusal'])[:200]}")
        if choices[0].get("finish_reason") not in (None, "stop"):
            raise Declined(f"{deployment} stopped early ({choices[0].get('finish_reason')})")
        return _parse(message.get("content") or "", deployment)


def _parse(text: str, label: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError as error:
        raise Declined(f"{label} didn't answer with valid JSON") from error
    if not isinstance(data, dict):
        raise Declined(f"{label} didn't answer with a JSON object")
    return data


def label(spec: str) -> str:
    """How a model is shown in reports: its name, with the family if that isn't obvious."""
    model = name(spec)
    kind = family(spec)
    if kind == "openai" and not model.lower().startswith(("gpt", "o1", "o3", "o4")):
        return f"{model} (OpenAI)"
    return model


def specs(value: Any) -> list[str]:
    """A setting can be one model or a list, tried in order."""
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value or []]
