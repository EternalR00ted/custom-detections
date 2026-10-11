"""Claude through the Anthropic API: one tool call per request, usage counted, refusals detected.

The models never get tools that do anything. Each request offers one or two
"answer" tools whose input schema is the shape we want back, and the model must
call one. Code checks everything it returns before using it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import observability
from .common import Fail, env, settings


class Declined(Exception):
    """The model declined or didn't answer with a tool call."""


@dataclass
class Answer:
    tool: str
    data: dict[str, Any]
    model: str


@dataclass
class Usage:
    calls: dict[str, int] = field(default_factory=dict)
    input_tokens: dict[str, int] = field(default_factory=dict)
    output_tokens: dict[str, int] = field(default_factory=dict)

    def add(self, model: str, usage: Any) -> None:
        self.calls[model] = self.calls.get(model, 0) + 1
        self.input_tokens[model] = self.input_tokens.get(model, 0) + int(getattr(usage, "input_tokens", 0) or 0)
        self.output_tokens[model] = self.output_tokens.get(model, 0) + int(getattr(usage, "output_tokens", 0) or 0)

    def table(self) -> str:
        if not self.calls:
            return "No model calls."
        lines = ["| Model | Calls | Input tokens | Output tokens |", "|---|---|---|---|"]
        for model in sorted(self.calls):
            lines.append(f"| {model} | {self.calls[model]} | {self.input_tokens[model]:,} | "
                         f"{self.output_tokens[model]:,} |")
        return "\n".join(lines)


def anthropic_client():
    from anthropic import Anthropic

    return Anthropic(api_key=env("ANTHROPIC_API_KEY", required=True), max_retries=6, timeout=600)


ANSWER_WITH_A_TOOL = "Answer only by calling exactly one of the tools you were given. Don't reply in plain text."


class Claude:
    def __init__(self, client, usage: Usage | None = None):
        self.client = client
        self.usage = usage or Usage()

    def ask(self, model: str, system: str, prompt: str, tools: list[dict], max_tokens: int | None = None) -> Answer:
        """Ask one model and return its tool call.

        Opus 5.5, Sonnet 5.5, Fable 5.1 and Mythos 5.1 return a 400 when a tool is forced, so this lets the
        model choose, tells it to answer with a tool, and asks once more if it answers in plain text.
        """
        limit = max_tokens or settings()["limits"]["max_output_tokens"]
        system = f"{system}\n\n{ANSWER_WITH_A_TOOL}"
        messages: list[dict] = [{"role": "user", "content": prompt}]
        for attempt in range(2):
            with observability.chat("claude", model, limit) as call:
                try:
                    reply = self.client.messages.create(
                        model=model,
                        max_tokens=limit,
                        system=system,
                        messages=messages,
                        tools=tools,
                        tool_choice={"type": "auto"},
                    )
                except Exception as error:  # the SDK raises many types; the caller decides what a failure means
                    raise Declined(f"{model} failed: {type(error).__name__}: {str(error)[:300]}") from error
                usage = getattr(reply, "usage", None)
                call.tokens(getattr(usage, "input_tokens", 0), getattr(usage, "output_tokens", 0))
                call.finished(getattr(reply, "stop_reason", ""))
            self.usage.add(model, usage)
            stop_reason = getattr(reply, "stop_reason", "")
            if stop_reason == "refusal":
                raise Declined(f"{model} declined this request")
            tool_calls = [block for block in reply.content if getattr(block, "type", "") == "tool_use"]
            if tool_calls:
                if not isinstance(tool_calls[0].input, dict):
                    break
                return Answer(tool_calls[0].name, tool_calls[0].input, model)
            if attempt == 0 and stop_reason == "end_turn":
                messages = [*messages, {"role": "assistant", "content": reply.content},
                            {"role": "user", "content": ANSWER_WITH_A_TOOL}]
                continue
            break
        raise Declined(f"{model} didn't answer in the required format (stop reason: {reply.stop_reason})")

    def ask_with_fallback(self, models: list[str], system: str, prompt: str, tools: list[dict]) -> tuple[Answer, list[str]]:
        """Try each model in order. Returns the answer and the reasons earlier models failed."""
        reasons: list[str] = []
        for model in models:
            try:
                return self.ask(model, system, prompt, tools), reasons
            except Declined as reason:
                reasons.append(str(reason))
        raise Declined("; ".join(reasons) or "no model to ask")


def from_env() -> Claude:
    if not env("ANTHROPIC_API_KEY"):
        raise Fail("Set ANTHROPIC_API_KEY, a secret variable in the 'detections' variable group.")
    return Claude(anthropic_client())
