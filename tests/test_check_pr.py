import os
import unittest
from unittest import mock

from scripts import check_pr
from scripts.check_pr import Change
from tests.fakes import FakeGraph

LAB = "detections/lab/defender-exclusion-added-from-command-line.yaml"


class GuardRails(unittest.TestCase):
    def test_ai_branch_may_only_add_ai_files(self):
        changes = [Change("A", "detections/ai/new-rule.yaml"), Change("A", "sigma/ai/new-rule.yml")]
        self.assertEqual(check_pr.guard_rails(changes, "refs/heads/ai/new-rule-12", False), [])
        changes.append(Change("M", "config/settings.yaml"))
        found = " | ".join(check_pr.guard_rails(changes, "refs/heads/ai/new-rule-12", False))
        self.assertIn("config/settings.yaml: AI branches may only add files", found)
        self.assertIn("AI branches may only add new files", found)

    def test_rule_delete_and_rename_blocked(self):
        changes = [Change("D", LAB), Change("R", "detections/lab/a.yaml", "detections/lab/b.yaml")]
        found = check_pr.guard_rails(changes, "refs/heads/feature", False)
        self.assertEqual(len(found), 2)
        self.assertIn("Set its status to retired", found[0])

    def test_promotion_branch(self):
        self.assertEqual(check_pr.guard_rails([Change("M", LAB)], "refs/heads/promote/x", False), [])
        found = check_pr.guard_rails([Change("A", "detections/lab/new.yaml")], "refs/heads/promote/x", False)
        self.assertIn("promotion branches may only edit existing rule files", found[0])

    def test_forks_fail(self):
        self.assertIn("forks", check_pr.guard_rails([], "refs/heads/x", True)[0])

    def test_sigma_change_checks_its_rule(self):
        paths = check_pr.changed_rules([Change("M", "sigma/lab/defender-exclusion-added-from-command-line.yml")])
        self.assertEqual(paths, [LAB])


class HuntingChecks(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"LAB_VM": "detonation-vm"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_quiet_rule_passes(self):
        graph = FakeGraph()
        [result] = check_pr.check_rules([LAB], graph, "noise-reviewed-abc1234", [])
        self.assertFalse(result.failed)
        self.assertEqual(result.compiled, "yes")
        self.assertEqual(result.production, "0 hits: PASS")
        production = next(q for q, t in graph.queries if t == "P3D")
        self.assertIn('not(tolower(tostring(column_ifexists("DeviceName", ""))) == "detonation-vm"', production)

    def test_noisy_rule_fails_until_labelled(self):
        graph = FakeGraph(counts=[("summarize Hits", 7)])
        [result] = check_pr.check_rules([LAB], graph, "noise-reviewed-abc1234", [])
        self.assertTrue(result.failed and result.noisy)
        self.assertIn("noise-reviewed-abc1234", result.production)
        [result] = check_pr.check_rules([LAB], graph, "noise-reviewed-abc1234", ["noise-reviewed-abc1234"])
        self.assertFalse(result.failed)
        [result] = check_pr.check_rules([LAB], graph, "noise-reviewed-abc1234", ["noise-reviewed-0000000"])
        self.assertTrue(result.failed)

    def test_compile_error_and_missing_columns(self):
        [result] = check_pr.check_rules([LAB], FakeGraph(compile_error="Syntax error near |"), "x", [])
        self.assertTrue(result.failed)
        self.assertIn("Syntax error", result.compiled)
        [result] = check_pr.check_rules([LAB], FakeGraph(columns=["Timestamp", "DeviceId"]), "x", [])
        self.assertIn("results must include column ReportId", result.compiled)

    def test_report_counts_only(self):
        results = check_pr.check_rules([LAB], FakeGraph(counts=[("summarize Hits", 3)]), "noise-reviewed-abc1234", [])
        text = check_pr.report("abc1234def", [], results, [], True)
        self.assertIn("Guard rails: PASS", text)
        self.assertIn("3 hits: NOISY", text)
        self.assertIn("Commit `abc1234`", text)


if __name__ == "__main__":
    unittest.main()
