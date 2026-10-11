import os
import unittest
from unittest import mock

from scripts import purple, rules
from scripts.claude import Claude, Declined
from tests.fakes import FakeAnthropic, FakeGraph, refusal_reply, tool_reply

ARTICLE = (
    "The operator opened PowerShell and ran Add-MpPreference -ExclusionPath C:\\ProgramData\\svc to stop "
    "Defender from scanning the staging folder. Later the actor used the abbreviated form -ExclusionP to "
    "add a second path, and finally used WMIC to call the MSFT_MpPreference class. " * 3
)

SIGMA = """title: Defender exclusion from PowerShell
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: MpPreference
  condition: selection
level: medium
"""


def submission(**changes):
    data = {
        "id": "defender-exclusion-from-powershell",
        "name": "MDE - Defender exclusion from PowerShell",
        "description": "PowerShell added a Defender exclusion.",
        "severity": "medium",
        "frequency": "PT1H",
        "tactics": [{"tactic": "DefenseEvasion", "techniques": ["T1562.001"]}],
        "query": ('DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n'
                  '| where ProcessCommandLine has "Add-MpPreference" and ProcessCommandLine has "ExclusionPath"\n'
                  "| project Timestamp, DeviceId, DeviceName, ReportId, AccountName, AccountDomain"),
        "hunt_query": 'DeviceProcessEvents\n| where ProcessCommandLine has "MpPreference"',
        "entities": {"hosts": [{"deviceIdColumn": "DeviceId", "nameColumn": "DeviceName"}],
                     "accounts": [{"nameColumn": "AccountName", "ntDomainColumn": "AccountDomain"}], "files": []},
        "recommended_actions": "Check who added the exclusion.",
        "lab_tests": ["0b19f4ee-de90-4059-88cb-63c800c683ed"],
        "sigma": SIGMA,
        "evidence": [
            {"point": "The actor excluded a folder.", "quote": "ran Add-MpPreference -ExclusionPath C:\\ProgramData\\svc"},
            {"point": "Made up.", "quote": "this sentence is not in the article at all"},
        ],
    }
    data.update(changes)
    return data


class Scripted:
    """Answers each call in order from a list of (model, reply) expectations."""

    def __init__(self, script):
        self.script = list(script)

    def __call__(self, model, tools, kwargs):
        expected_model, reply = self.script.pop(0)
        assert model == expected_model, f"expected {expected_model}, got {model}"
        if isinstance(reply, Exception):
            raise reply
        return reply


def red(variants, summary="Narrow rule."):
    return tool_reply("report_variants", {"variants": variants, "summary": summary})


class Evidence(unittest.TestCase):
    def test_quotes_must_be_in_the_article(self):
        kept, dropped = purple.verify_evidence(submission()["evidence"], ARTICLE)
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(dropped), 1)

    def test_whitespace_and_quote_styles_are_normalized(self):
        kept, _ = purple.verify_evidence([{"point": "p", "quote": "used  WMIC to call\nthe MSFT_MpPreference class"}],
                                         ARTICLE)
        self.assertEqual(len(kept), 1)

    def test_short_quotes_are_dropped(self):
        kept, _ = purple.verify_evidence([{"point": "p", "quote": "WMIC"}], ARTICLE)
        self.assertEqual(kept, [])


class Loop(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"LAB_VM": "detonation-vm"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def checker(self):
        return purple.Checker(FakeGraph(), set(rules.all_rules()))

    def test_red_finds_gap_blue_hardens(self):
        hardened_query = ('DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "wmic.exe")\n'
                          '| where ProcessCommandLine contains "MpPreference" and ProcessCommandLine contains "Exclusion"\n'
                          "| project Timestamp, DeviceId, DeviceName, ReportId, AccountName, AccountDomain")
        script = Scripted([
            ("claude-fable-5-1", red([
                {"tier": "baseline", "variant": "Add-MpPreference -ExclusionPath", "visible": True, "caught": True},
                {"tier": "cosmetic", "variant": "Abbreviated -ExclusionP parameter", "visible": True, "caught": False,
                 "evidence": "ProcessCommandLine contains ExclusionP"},
                {"tier": "behavioral", "variant": "Group Policy pushes the exclusion", "visible": False, "caught": False},
            ])),
            ("claude-opus-5-5", tool_reply("submit_rule", submission(query=hardened_query, id="renamed-by-model"))),
            ("claude-fable-5-1", red([
                {"ref": "V1", "tier": "baseline", "variant": "x", "visible": True, "caught": True},
                {"ref": "V2", "tier": "cosmetic", "variant": "x", "visible": True, "caught": True},
                {"ref": "V3", "tier": "behavioral", "variant": "x", "visible": False, "caught": False},
            ], summary="Robust now.")),
        ])
        claude = Claude(FakeAnthropic(script))
        draft = purple.draft_from(submission())
        draft.evidence, _ = purple.verify_evidence(draft.evidence, ARTICLE)
        result = purple.purple_loop(claude, self.checker(), draft)
        self.assertEqual(script.script, [])
        self.assertEqual(result.rounds, 2)
        self.assertEqual(result.red_models, ["claude-fable-5-1", "claude-fable-5-1"])
        self.assertEqual(result.draft.rule["id"], "defender-exclusion-from-powershell")
        self.assertIn('contains "Exclusion"', result.draft.rule["query"])
        by_ref = {v.ref: v for v in result.variants}
        self.assertEqual((by_ref["V2"].caught_first, by_ref["V2"].caught_final), (False, True))
        table = purple.tier_table(result)
        self.assertIn("| V2 | cosmetic | Abbreviated -ExclusionP parameter | yes | NO | yes |", table)
        self.assertIn("| V3 | behavioral | Group Policy pushes the exclusion | no | not visible | not visible |", table)
        self.assertEqual(result.summary, "Robust now.")

    def test_red_declines_falls_back_to_opus(self):
        script = Scripted([
            ("claude-fable-5-1", refusal_reply()),
            ("claude-opus-4-8", red([{"tier": "baseline", "variant": "as described", "visible": True, "caught": True}])),
        ])
        claude = Claude(FakeAnthropic(script))
        result = purple.purple_loop(claude, self.checker(), purple.draft_from(submission()))
        self.assertEqual(result.red_models, ["claude-opus-4-8"])
        self.assertTrue(any("declined" in note and "claude-opus-4-8 answered instead" in note for note in result.notes))

    def test_no_red_side_at_all(self):
        script = Scripted([("claude-fable-5-1", RuntimeError("down")), ("claude-opus-4-8", RuntimeError("down"))])
        result = purple.purple_loop(Claude(FakeAnthropic(script)), self.checker(), purple.draft_from(submission()))
        self.assertEqual(result.rounds, 0)
        self.assertIn("no red-side review", result.notes[0])

    def test_hardened_rule_that_fails_checks_is_not_used(self):
        bad = submission(query="EmailEvents | take 1")
        script = Scripted([
            ("claude-fable-5-1", red([{"tier": "cosmetic", "variant": "v", "visible": True, "caught": False}])),
            ("claude-opus-5-5", tool_reply("submit_rule", bad)),
            ("claude-opus-5-5", tool_reply("submit_rule", bad)),
        ])
        draft = purple.draft_from(submission())
        result = purple.purple_loop(Claude(FakeAnthropic(script)), self.checker(), draft)
        self.assertEqual(result.draft.rule["query"], draft.rule["query"])
        self.assertTrue(any("kept the previous rule" in note for note in result.notes))

    def test_repair_fixes_a_failing_draft(self):
        script = Scripted([("claude-opus-5-5", tool_reply("submit_rule", submission()))])
        broken = purple.draft_from(submission(severity="critical"))
        fixed, found = purple.repair(Claude(FakeAnthropic(script)), self.checker(), "system", "prompt", broken, 2)
        self.assertEqual(found, [])
        self.assertEqual(fixed.rule["severity"], "medium")

    def test_existing_id_is_rejected(self):
        draft = purple.draft_from(submission(id="defender-exclusion-added-from-command-line"))
        found = self.checker().problems(draft)
        self.assertTrue(any("already used" in p for p in found))


class Handoff(unittest.TestCase):
    def test_handoff_lists_clauses_and_known_variants(self):
        rule = purple.draft_from(submission()).rule
        variant = purple.Variant("V1", "cosmetic", "abbreviated parameter", "", True, False, False)
        text = purple.handoff(rule, [variant])
        self.assertIn("1. `DeviceProcessEvents`", text)
        self.assertIn("- V1 (cosmetic): abbreviated parameter", text)

    def test_claude_requires_a_tool_answer(self):
        from types import SimpleNamespace
        reply = SimpleNamespace(content=[SimpleNamespace(type="text", text="hi")], stop_reason="end_turn",
                                usage=SimpleNamespace(input_tokens=1, output_tokens=1))
        claude = Claude(FakeAnthropic(lambda model, tools, kwargs: reply))
        with self.assertRaises(Declined):
            claude.ask("m", "s", "p", [purple.TRIAGE_TOOL])
        self.assertEqual(claude.usage.calls, {"m": 2})  # a plain-text answer, then one retry


if __name__ == "__main__":
    unittest.main()
