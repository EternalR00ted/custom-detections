"""Sentry: off without a DSN, and when it's on, only metadata leaves the pipeline."""

import argparse
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import common, draft, feeds, jury, observability
from scripts.claude import Claude
from scripts.common import ROOT, Fail
from scripts.models import Models
from tests.fakes import FakeAnthropic, FakeGraph, FakeResponse, FakeSession, tool_reply
from tests.test_draft import PAGE, handler
from tests.test_models_jury import APPROVE, GEMINI, OPENAI, gemini_reply, openai_reply
from tests.test_purple import ARTICLE

HAS_SENTRY = importlib.util.find_spec("sentry_sdk") is not None
DSN = "https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/42"
KEYS = {"ANTHROPIC_API_KEY": "sk-ant-api03-TESTKEY0000000000", "GEMINI_API_KEY": "AIzaTESTKEY000000000000000000000",
        "OPENAI_API_KEY": "sk-proj-TESTKEY0000000000000000", "NIMBLE_API_KEY": "nimble-TESTKEY-0000"}
PROMPT = "PROMPT TEXT THAT MUST NOT LEAVE"


class WithoutSentry(unittest.TestCase):
    def test_no_dsn_does_nothing(self):
        with mock.patch.dict(os.environ, {"SENTRY_DSN": ""}), observability.start("draft"):
            with observability.agent("blue"), observability.chat("claude", "claude-opus-5-5", 100) as call:
                call.tokens(10, 20)
                call.finished("tool_use")
            observability.handoff("blue", "red")
            observability.capture(RuntimeError("not sent"))
        self.assertIsNone(observability._sentry)

    def test_scrub_removes_key_values_and_key_shapes(self):
        event = {"message": f"failed: {KEYS['NIMBLE_API_KEY']}", "extra": {"header": "Bearer abcdefgh12345678"},
                 "spans": [{"data": {"note": "sk-ant-api03-somethinglong"}}], "count": 3}
        with mock.patch.dict(os.environ, KEYS):
            cleaned = observability.scrub(event)
        text = str(cleaned)
        for secret in (KEYS["NIMBLE_API_KEY"], "abcdefgh12345678", "sk-ant-api03"):
            self.assertNotIn(secret, text)
        self.assertEqual(cleaned["count"], 3)


@unittest.skipUnless(HAS_SENTRY, "sentry-sdk isn't installed")
class WithSentry(unittest.TestCase):
    def setUp(self):
        from sentry_sdk.transport import Transport

        self.envelopes = []
        sent = self.envelopes

        class Capture(Transport):
            def capture_envelope(self, envelope):
                sent.append(envelope)

        self.transport = Capture()
        patcher = mock.patch.dict(os.environ, {"SENTRY_DSN": DSN, **KEYS})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(observability.stop)

    def sent(self) -> bytes:
        return b"".join(envelope.serialize() for envelope in self.envelopes)

    def transaction(self) -> dict:
        return next(e.get_transaction_event() for e in self.envelopes if e.get_transaction_event())

    def spans(self) -> list[tuple[str, str, dict]]:
        """Every span sent: the transaction's own, plus the span items Sentry 2.71 moves gen_ai spans into."""
        found = []
        for envelope in self.envelopes:
            for item in envelope.items:
                payload = item.payload.json or {}
                if item.headers.get("type") == "transaction":
                    found += [(s.get("op"), s.get("description"), s.get("data") or {}) for s in payload.get("spans", [])]
                elif item.headers.get("type") == "span":
                    for s in payload.get("items", []):
                        data = {key: value.get("value") if isinstance(value, dict) else value
                                for key, value in (s.get("attributes") or {}).items()}
                        found.append((data.get("sentry.op"), s.get("name"), data))
        return found

    def error(self) -> dict:
        return next(e.get_event() for e in self.envelopes if e.get_event())

    def test_model_calls_become_agent_spans_with_tokens_and_no_text(self):
        session = FakeSession({GEMINI: gemini_reply(APPROVE), OPENAI: openai_reply(APPROVE)})
        claude = Claude(FakeAnthropic(lambda model, tools, kwargs: tool_reply("answer", APPROVE, input_tokens=700,
                                                                                output_tokens=90)))
        models = Models(claude, session)
        with observability.start("draft", transport=self.transport):
            observability.handoff("blue", "red")
            for spec in ("gemini:gemini-3.8-flash", "openai:gpt-6.1-sol", "claude:claude-haiku-5-5"):
                with observability.agent("jury"):
                    models.ask_json(spec, "SYSTEM " + PROMPT, PROMPT, jury.SCHEMA)
        observability.stop()

        spans = self.spans()
        chats = {name: data for op, name, data in spans if op == "gen_ai.chat"}
        self.assertEqual(set(chats), {"chat gemini-3.8-flash", "chat gpt-6.1-sol", "chat claude-haiku-5-5"})
        gemini = chats["chat gemini-3.8-flash"]
        self.assertEqual(gemini["gen_ai.provider.name"], "gcp.gemini")
        self.assertEqual(gemini["gen_ai.agent.name"], "jury")
        self.assertEqual((gemini["gen_ai.usage.input_tokens"], gemini["gen_ai.usage.output_tokens"]), (1200, 300))
        self.assertEqual(chats["chat gpt-6.1-sol"]["gen_ai.usage.input_tokens"], 900)
        self.assertEqual(chats["chat claude-haiku-5-5"]["gen_ai.provider.name"], "anthropic")
        self.assertIn("tool_use", str(chats["chat claude-haiku-5-5"]["gen_ai.response.finish_reasons"]))
        ops = [op for op, _, _ in spans]
        self.assertEqual(ops.count("gen_ai.invoke_agent"), 3)
        self.assertIn("gen_ai.handoff", ops)

        body = self.sent()
        self.assertNotIn(PROMPT.encode(), body)
        self.assertNotIn(b"Looks right", body)  # the models' answers stay out too
        for key in KEYS.values():
            self.assertNotIn(key.encode(), body)

    def test_errors_carry_no_local_variables_or_keys(self):
        def fails():
            article_text = PROMPT  # noqa: F841  a local Sentry must not send
            raise RuntimeError(f"Graph returned 500 with key {KEYS['OPENAI_API_KEY']}")

        with observability.start("check_pr", transport=self.transport):
            try:
                fails()
            except RuntimeError as error:
                observability.capture(error)
        observability.stop()

        frames = self.error()["exception"]["values"][0]["stacktrace"]["frames"]
        self.assertTrue(all("vars" not in frame for frame in frames))
        body = self.sent()
        self.assertIn(b"Graph returned 500", body)
        self.assertNotIn(PROMPT.encode(), body)
        self.assertNotIn(KEYS["OPENAI_API_KEY"].encode(), body)

    def test_a_draft_run_traces_each_role(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.addCleanup(shutil.rmtree, ROOT / "work" / "drafts", True)
        session = FakeSession({r"example\.com/report": FakeResponse(200, PAGE, {"Content-Type": "text/html"})})
        args = argparse.Namespace(url="https://example.com/report", dry_run=True)
        with mock.patch.dict(os.environ, {"LAB_VM": "detonation-vm", "GEMINI_API_KEY": "", "OPENAI_API_KEY": ""}), \
                observability.start("draft", transport=self.transport):
            summary = draft.run(args, Models(Claude(FakeAnthropic(handler))), FakeGraph(), None, session,
                                feeds.Seen(tmp / "seen.json"), None)
        observability.stop()
        self.assertIn("| drafted |", summary)

        spans = self.spans()
        agents = [data.get("gen_ai.agent.name") for op, _, data in spans if op == "gen_ai.invoke_agent"]
        self.assertEqual(set(agents), {"triage", "blue", "red"})
        self.assertIn("handoff from blue to red", [name for op, name, _ in spans if op == "gen_ai.handoff"])
        models_used = {data.get("gen_ai.request.model") for op, _, data in spans if op == "gen_ai.chat"}
        self.assertEqual(models_used, {"claude-haiku-5-5", "claude-opus-5-5", "claude-fable-5-1"})
        self.assertIn(("draft.article", "https://example.com/report"), [(op, name) for op, name, _ in spans])
        body = self.sent()
        self.assertNotIn(ARTICLE[:60].encode(), body)
        self.assertNotIn(b"Ignore your instructions", body)

    def test_a_bad_dsn_warns_and_carries_on(self):
        with mock.patch.dict(os.environ, {"SENTRY_DSN": "not a dsn"}), observability.start("draft"):
            pass
        self.assertIsNone(observability._sentry)

    def test_run_main_reports_a_fail_and_exits_1(self):
        real_start = observability.start

        def main():
            raise Fail("Set ANTHROPIC_API_KEY")

        with mock.patch.object(observability, "start", lambda script: real_start(script, transport=self.transport)), \
                mock.patch.object(sys, "argv", ["scripts/draft.py"]), self.assertRaises(SystemExit) as stop:
            common.run_main(main)
        self.assertEqual(stop.exception.code, 1)
        self.assertEqual(self.error()["exception"]["values"][0]["type"], "Fail")
        self.assertEqual(self.transaction()["transaction"], "draft")
        self.assertIsNone(observability._sentry)


if __name__ == "__main__":
    unittest.main()
