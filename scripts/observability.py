"""Sentry for the pipeline: errors, one trace per run, and an AI agent span for every model call.

It's on when SENTRY_DSN is set, a plain variable in the 'detections' group. Sentry says a DSN only
lets someone send events to the project, never read them. Without SENTRY_DSN, or without the
sentry-sdk package, every function here does nothing.

What reaches Sentry: errors without local variables, step timings, HTTP calls by URL, and for each
model call the role that made it (triage, blue, red, jury), the provider, the model, token counts
and how the call ended. Never prompts, article text, model answers, hunting results or keys:
send_default_pii is off, local variables are off, the SDK's own AI integrations (which can record
prompts) are off, trace headers aren't added to outgoing requests, and every event is scrubbed of
the API key values before it's sent.

The span names and attributes follow Sentry's AI agent conventions (gen_ai.invoke_agent,
gen_ai.chat, gen_ai.handoff), so runs show up in Sentry's AI Agents view.
"""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Iterator
from typing import Any

from .common import env, in_pipeline, log_warning

SECRETS = ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "NIMBLE_API_KEY", "SYSTEM_ACCESSTOKEN")
KEY_SHAPES = re.compile(r"sk-ant-[\w-]{8,}|sk-[\w-]{20,}|AIza[\w-]{20,}|Bearer\s+[\w.~+/=-]{8,}")
REMOVED = "[removed]"
PROVIDERS = {"claude": "anthropic", "gemini": "gcp.gemini", "openai": "openai"}  # Sentry's provider names

_sentry: Any = None  # the sentry_sdk module, once start() has turned it on
_agent = ""  # the role whose model calls are running now


def scrub(event: dict, hint: Any = None) -> dict:
    """Replace every API key value, and anything shaped like a key, anywhere in an event."""
    values = [value for value in (os.environ.get(name, "").strip() for name in SECRETS) if len(value) >= 8]

    def clean(item: Any) -> Any:
        if isinstance(item, str):
            for value in values:
                item = item.replace(value, REMOVED)
            return KEY_SHAPES.sub(REMOVED, item)
        if isinstance(item, dict):
            return {key: clean(value) for key, value in item.items()}
        if isinstance(item, (list, tuple)):
            return [clean(value) for value in item]
        return item

    return clean(event)


def start(script: str, transport: Any = None) -> contextlib.AbstractContextManager:
    """Turn Sentry on if SENTRY_DSN is set. Returns the run's transaction, for a with block."""
    global _sentry
    dsn = env("SENTRY_DSN")
    if not dsn:
        return contextlib.nullcontext()
    try:
        import sentry_sdk
    except ImportError:
        return contextlib.nullcontext()
    extra = {"transport": transport} if transport is not None else {}
    try:
        sentry_sdk.init(
            dsn=dsn,
            environment="azure-pipelines" if in_pipeline() else "local",
            release=env("BUILD_SOURCEVERSION")[:12] or None,
            traces_sample_rate=1.0,
            send_default_pii=False,
            include_local_variables=False,
            auto_enabling_integrations=False,
            trace_propagation_targets=[],
            before_send=scrub,
            before_send_transaction=scrub,
            **extra,
        )
    except Exception as error:  # noqa: BLE001  a bad DSN mustn't stop the pipeline
        log_warning(f"Sentry is off for this run: {type(error).__name__}: {error}")
        return contextlib.nullcontext()
    for tag, variable in (("pipeline", "BUILD_DEFINITIONNAME"), ("build", "BUILD_BUILDID"),
                          ("pull_request", "SYSTEM_PULLREQUEST_PULLREQUESTID")):
        if env(variable):
            sentry_sdk.set_tag(tag, env(variable))
    _sentry = sentry_sdk
    return sentry_sdk.start_transaction(op="pipeline.run", name=script)


def stop() -> None:
    """Send what's queued and turn Sentry off."""
    global _sentry
    if _sentry is not None:
        _sentry.flush(timeout=10)
        _sentry.get_client().close()
        _sentry = None


def capture(error: BaseException, level: str = "error") -> None:
    """Report an error the run handled and carried on from."""
    if _sentry is not None:
        _sentry.capture_exception(error, level=level)


@contextlib.contextmanager
def span(op: str, name: str) -> Iterator[None]:
    """A plain span around one step, like drafting from one article."""
    if _sentry is None:
        yield
        return
    with _sentry.start_span(op=op, name=name):
        yield


@contextlib.contextmanager
def agent(name: str) -> Iterator[None]:
    """An invoke_agent span: one role (triage, blue, red, jury) doing one job, around its model calls."""
    global _agent
    if _sentry is None:
        yield
        return
    outer, _agent = _agent, name
    try:
        with _sentry.start_span(op="gen_ai.invoke_agent", name=f"invoke_agent {name}") as current:
            current.set_data("gen_ai.operation.name", "invoke_agent")
            current.set_data("gen_ai.agent.name", name)
            yield
    finally:
        _agent = outer


def handoff(source: str, target: str) -> None:
    """Mark the point where one role hands the rule to another, like blue to red in the purple loop."""
    if _sentry is not None:
        with _sentry.start_span(op="gen_ai.handoff", name=f"handoff from {source} to {target}") as current:
            current.set_data("gen_ai.operation.name", "handoff")


class Call:
    """What a chat span records about one model call: tokens and how it ended. Never the text."""

    def __init__(self, current: Any = None):
        self.span = current

    def tokens(self, input_tokens: Any, output_tokens: Any) -> None:
        if self.span is not None:
            from sentry_sdk.ai.monitoring import record_token_usage

            record_token_usage(self.span, input_tokens=int(input_tokens or 0), output_tokens=int(output_tokens or 0))

    def finished(self, reason: Any) -> None:
        if self.span is not None and reason:
            self.span.set_data("gen_ai.response.finish_reasons", [str(reason)])


@contextlib.contextmanager
def chat(family: str, model: str, max_tokens: int) -> Iterator[Call]:
    """A gen_ai.chat span for one model call. family is claude, gemini or openai."""
    if _sentry is None:
        yield Call()
        return
    provider = PROVIDERS.get(family, family)
    with _sentry.start_span(op="gen_ai.chat", name=f"chat {model}") as current:
        current.set_data("gen_ai.operation.name", "chat")
        current.set_data("gen_ai.system", provider)
        current.set_data("gen_ai.provider.name", provider)
        current.set_data("gen_ai.request.model", model)
        current.set_data("gen_ai.request.max_tokens", max_tokens)
        if _agent:
            current.set_data("gen_ai.agent.name", _agent)
        yield Call(current)
