"""Opus 5.5 and Fable 5.1 reject forced tool choice, so Claude.ask must never send it."""

import dataclasses
import re
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.claude import Claude, Declined


class FakeMessages:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.replies.pop(0)


def reply(*blocks, stop="end_turn"):
    return SimpleNamespace(content=list(blocks), stop_reason=stop,
                           usage=SimpleNamespace(input_tokens=10, output_tokens=5))


def tool(name, data):
    return SimpleNamespace(type="tool_use", id="toolu_1", name=name, input=data)


def text(words):
    return SimpleNamespace(type="text", text=words)


def fields(answer):
    return dataclasses.astuple(answer) if dataclasses.is_dataclass(answer) else tuple(answer)


class ToolChoiceTest(unittest.TestCase):
    def ask(self, *replies):
        messages = FakeMessages(replies)
        claude = Claude(SimpleNamespace(messages=messages))
        return claude, messages

    def test_never_forces_a_tool(self):
        claude, messages = self.ask(reply(tool("verdict", {"ok": True})))
        answer = claude.ask("claude-opus-5-5", "system", "prompt", [{"name": "verdict"}], max_tokens=100)
        self.assertIn({"ok": True}, fields(answer))
        self.assertEqual(messages.calls[0]["tool_choice"], {"type": "auto"})

    def test_asks_once_more_after_plain_text(self):
        claude, messages = self.ask(reply(text("Here is my view.")), reply(tool("verdict", {"ok": True})))
        answer = claude.ask("claude-fable-5-1", "system", "prompt", [{"name": "verdict"}], max_tokens=100)
        self.assertIn({"ok": True}, fields(answer))
        self.assertEqual(len(messages.calls), 2)
        self.assertEqual([turn["role"] for turn in messages.calls[1]["messages"]], ["user", "assistant", "user"])
        self.assertTrue(all(call["tool_choice"] == {"type": "auto"} for call in messages.calls))

    def test_gives_up_after_two_plain_text_answers(self):
        claude, messages = self.ask(reply(text("one")), reply(text("two")))
        with self.assertRaises(Declined):
            claude.ask("claude-opus-5-5", "system", "prompt", [{"name": "verdict"}], max_tokens=100)
        self.assertEqual(len(messages.calls), 2)

    def test_refusal_is_not_retried(self):
        claude, messages = self.ask(reply(text("no"), stop="refusal"))
        with self.assertRaises(Declined):
            claude.ask("claude-fable-5-1", "system", "prompt", [{"name": "verdict"}], max_tokens=100)
        self.assertEqual(len(messages.calls), 1)

    def test_no_forced_tool_choice_anywhere_in_scripts(self):
        forced = re.compile(r"tool_choice\s*=\s*\{[^}]*[\"']type[\"']\s*:\s*[\"'](any|tool)[\"']")
        hits = [str(path) for path in Path("scripts").rglob("*.py") if forced.search(path.read_text())]
        self.assertEqual(hits, [], "Opus 5.5 and Fable 5.1 return a 400 for forced tool choice")


if __name__ == "__main__":
    unittest.main()
