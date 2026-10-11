"""The three-family model layer, the model jury, and Nimble research."""

import json
import os
import unittest
from unittest import mock

from scripts import draft, feeds, jury, purple, rules
from scripts.claude import Claude, Declined
from scripts.common import Fail
from scripts.models import Models, strict
from scripts.nimble import Nimble
from tests.fakes import FakeAnthropic, FakeGraph, FakeResponse, FakeSession, tool_reply
from tests.test_purple import ARTICLE, submission

GEMINI = r"generativelanguage\.googleapis\.com/v1beta/models/gemini-3\.8-flash:generateContent"
OPENAI = r"api\.openai\.com/v1/chat/completions"
APPROVE = {"verdict": "approve", "matches_source": True, "kql_issues": [], "false_positive_risk": "low",
           "false_positive_notes": "", "missed_variants": [], "summary": "Looks right."}
REVISE = {"verdict": "revise", "matches_source": True, "kql_issues": ["has won't match the abbreviated -ExclusionP"],
          "false_positive_risk": "medium", "false_positive_notes": "Intune scripts add exclusions.",
          "missed_variants": ["Set-MpPreference instead of Add-MpPreference"], "summary": "Close."}


def gemini_reply(data, finish="STOP", thought=False):
    parts = [{"text": "thinking...", "thought": True}] if thought else []
    parts.append({"text": json.dumps(data)})
    return FakeResponse(200, json.dumps({
        "candidates": [{"content": {"parts": parts}, "finishReason": finish}],
        "usageMetadata": {"promptTokenCount": 1200, "candidatesTokenCount": 300}}))


def openai_reply(data, refusal=None):
    message = {"content": json.dumps(data) if data is not None else None, "refusal": refusal}
    return FakeResponse(200, json.dumps({"choices": [{"message": message, "finish_reason": "stop"}],
                                         "usage": {"prompt_tokens": 900, "completion_tokens": 200}}))


ENV = {"GEMINI_API_KEY": "test-gemini-key", "OPENAI_API_KEY": "test-openai-key", "LAB_VM": "detonation-vm"}


class ModelLayer(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_strict_schema(self):
        schema = strict(jury.SCHEMA)
        self.assertEqual(schema["required"], list(jury.SCHEMA["properties"]))
        self.assertFalse(schema["additionalProperties"])
        nested = strict(purple.TRIAGE_TOOL["input_schema"])
        self.assertIn("behaviors", nested["required"])

    def test_gemini_json(self):
        session = FakeSession({GEMINI: gemini_reply(APPROVE, thought=True)})
        models = Models(None, session)
        answer = models.ask_json("gemini:gemini-3.8-flash", "system", "prompt", jury.SCHEMA)
        self.assertEqual(answer["verdict"], "approve")
        _method, _url, body = session.requests[0]
        self.assertEqual(body["generationConfig"]["responseMimeType"], "application/json")
        self.assertFalse(body["generationConfig"]["responseJsonSchema"]["additionalProperties"])
        self.assertEqual(body["systemInstruction"]["parts"][0]["text"], "system")
        self.assertEqual(models.usage.calls, {"gemini-3.8-flash": 1})
        self.assertEqual(models.usage.input_tokens["gemini-3.8-flash"], 1200)

    def test_gemini_blocks_and_truncation_are_declines(self):
        for response in (FakeResponse(200, json.dumps({"promptFeedback": {"blockReason": "SAFETY"}})),
                         gemini_reply(APPROVE, finish="MAX_TOKENS"),
                         FakeResponse(400, b"bad schema")):
            models = Models(None, FakeSession({GEMINI: response}))
            with self.assertRaises(Declined):
                models.ask_json("gemini:gemini-3.8-flash", "s", "p", jury.SCHEMA)

    def test_openai_api(self):
        session = FakeSession({OPENAI: openai_reply(REVISE)})
        models = Models(None, session)
        answer = models.ask_json("openai:gpt-6.1-sol", "system", "prompt", jury.SCHEMA)
        self.assertEqual(answer["verdict"], "revise")
        _, _url, body = session.requests[0]
        self.assertEqual(body["model"], "gpt-6.1-sol")
        self.assertTrue(body["response_format"]["json_schema"]["strict"])
        self.assertEqual(body["messages"][0], {"role": "system", "content": "system"})
        with self.assertRaises(Declined):
            Models(None, FakeSession({OPENAI: openai_reply(None, refusal="no")})).ask_json(
                "openai:gpt-6.1-sol", "s", "p", jury.SCHEMA)

    def test_first_json_falls_back_to_claude(self):
        claude = Claude(FakeAnthropic(lambda model, tools, kwargs: tool_reply("answer", {"relevant": False,
                                                                                     "reason": "patch notice",
                                                                                     "behaviors": []})))
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            models = Models(claude, FakeSession())
            answer, who, reasons = models.first_json(["gemini:gemini-3.8-flash", "claude:claude-haiku-5-5"], "s", "p",
                                                     purple.TRIAGE_TOOL["input_schema"])
        self.assertEqual(who, "claude:claude-haiku-5-5")
        self.assertIn("isn't set up", reasons[0])
        self.assertFalse(answer["relevant"])


class FakeModels(Models):
    """Answers jury questions from a queue per model."""

    def __init__(self, claude, answers):
        super().__init__(claude, FakeSession())
        self.answers = {spec: list(queue) for spec, queue in answers.items()}

    def available(self, spec):
        return spec in self.answers or spec.startswith("claude")

    def ask_json(self, spec, system, prompt, schema, max_tokens=8000):
        reply = self.answers[spec].pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class Jury(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_votes_consensus_and_table(self):
        models = FakeModels(None, {"gemini:gemini-3.8-flash": [APPROVE], "openai:gpt-6.1-sol": [REVISE]})
        votes = jury.review(models, purple.draft_from(submission()).rule, ARTICLE)
        self.assertEqual([v.verdict for v in votes], ["approve", "revise"])
        self.assertEqual(jury.consensus(votes), "revise")
        self.assertTrue(jury.needs_revision(votes))
        table = jury.table(votes)
        self.assertIn("| gemini-3.8-flash | approve | yes | low | Looks right. |", table)
        self.assertIn("| gpt-6.1-sol | REVISE | yes | medium |", table)
        self.assertIn("gpt-6.1-sol, missed variant: Set-MpPreference", jury.findings(votes))

    def test_missing_juror_and_bad_answer(self):
        models = FakeModels(None, {"openai:gpt-6.1-sol": [{"verdict": "maybe"}]})
        votes = jury.review(models, purple.draft_from(submission()).rule, ARTICLE)
        self.assertEqual(votes[0].verdict, "not set up")
        self.assertEqual(votes[1].verdict, "no answer")
        self.assertEqual(jury.consensus(votes), "no jury")

    def test_jury_revision_round(self):
        revised_query = ('DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n'
                         '| where ProcessCommandLine contains "MpPreference" and ProcessCommandLine contains "Exclusion"\n'
                         "| project Timestamp, DeviceId, DeviceName, ReportId, AccountName, AccountDomain")

        def handler(model, tools, kwargs):
            if "submit_rule" in tools:
                assert "has won't match the abbreviated" in kwargs["messages"][0]["content"]
                return tool_reply("submit_rule", submission(query=revised_query))
            raise AssertionError(model)

        claude = Claude(FakeAnthropic(handler))
        models = FakeModels(claude, {"gemini:gemini-3.8-flash": [REVISE, APPROVE],
                                     "openai:gpt-6.1-sol": [APPROVE, APPROVE]})
        checker = purple.Checker(FakeGraph(), set(rules.all_rules()))
        result = purple.LoopResult(purple.draft_from(submission()), [], ["claude-fable-5-1"], 1, [], "ok")
        record = draft.run_jury(models, checker, result, feeds.Article("https://x", "x", ARTICLE))
        self.assertEqual(len(record.rounds), 2)
        self.assertEqual(record.consensus, "approve")
        self.assertIn('contains "Exclusion"', result.draft.rule["query"])
        text = draft.pr_description(result, feeds.Article("https://x", "x", ARTICLE, feed="Nimble search: q"),
                                    "ai", record)
        self.assertIn("First vote, before the revision:", text)
        self.assertIn("Found by: Nimble search: q", text)
        self.assertIn("### Model jury: approve", text)

    def test_red_vote(self):
        result = purple.LoopResult(purple.draft_from(submission()), [
            purple.Variant("V1", "cosmetic", "alias", "", True, False, False)], ["claude-fable-5-1"], 3, [])
        vote = jury.red_vote(result)
        self.assertEqual((vote.model, vote.verdict), ("claude:claude-fable-5-1", "revise"))


class NimbleResearch(unittest.TestCase):
    def test_search_and_extract(self):
        session = FakeSession({
            r"/v2/search": FakeResponse(200, json.dumps({"request_id": "r", "total_results": 2, "results": [
                {"title": "Intrusion", "url": "https://thedfirreport.com/2026/10/09/x/", "content": "A" * 600,
                 "description": "", "metadata": {}},
                {"title": "Spam", "url": "https://evil.example/thedfirreport.com", "content": "B" * 600,
                 "description": "", "metadata": {}}]})),
            r"/v2/extract": FakeResponse(200, json.dumps({"task_id": "t", "url": "https://redcanary.com/blog/a/",
                                                          "status": "success", "data": {"markdown": "C" * 700},
                                                          "metadata": {}})),
        })
        nimble = Nimble("key", session)
        config = {"queries": ["q1"], "domains": ["thedfirreport.com"], "time_range": "week", "results_per_query": 5}
        with mock.patch.object(feeds, "load_yaml", return_value=config):
            found = feeds.research_articles(nimble)
        self.assertEqual([a.url for a in found], ["https://thedfirreport.com/2026/10/09/x"])
        self.assertEqual(found[0].feed, "Nimble search: q1")
        body = session.requests[0][2]
        self.assertEqual(body["include_domains"], ["thedfirreport.com"])
        self.assertTrue(body["full_content"])
        article = feeds.fetch_article(session, feeds.Article("https://redcanary.com/blog/a", "a",
                                                             domain="redcanary.com"), nimble)
        self.assertEqual(article.text, "C" * 700)
        self.assertEqual(session.requests[-1][2]["markdown_backend"], "main_content")

    def test_extract_redirect_off_domain_and_budget(self):
        session = FakeSession({r"/v2/extract": FakeResponse(200, json.dumps({
            "task_id": "t", "url": "https://evil.example/", "status": "success", "data": {"markdown": "x" * 900},
            "metadata": {}})), r"/v2/search": FakeResponse(402, b"trial expired")})
        nimble = Nimble("key", session)
        with self.assertRaises(Fail):
            feeds.fetch_article(session, feeds.Article("https://redcanary.com/a", "a", domain="redcanary.com"), nimble)
        with self.assertRaises(Fail):
            nimble.search("q", ["redcanary.com"])


if __name__ == "__main__":
    unittest.main()
