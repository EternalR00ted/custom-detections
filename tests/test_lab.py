"""Fire plan, detonation record checks, and the true-positive check."""

import hashlib
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import yaml

from scripts import fire_plan, rules, tp_check
from scripts.check_pr import Change
from scripts.common import Fail
from tests.fakes import FakeGraph, FakeResponse, FakeSession

LAB = "detections/lab/defender-exclusion-added-from-command-line.yaml"
COMMIT = "a" * 40
GUIDS = ["0b19f4ee-de90-4059-88cb-63c800c683ed", "315f4be6-2240-4552-b3e1-d1047f5eecea",
         "a123ce6a-3916-45d6-ba9c-7d4081315c27", "59d386fc-3a4b-41b8-850d-9e3eee24dfe4"]

ATOMIC_FILE = yaml.safe_dump({
    "attack_technique": "T1685",
    "atomic_tests": [
        {"name": "Folder", "auto_generated_guid": GUIDS[0], "supported_platforms": ["windows"],
         "input_arguments": {"excluded_folder": {"type": "path", "default": "C:\\Temp"}},
         "executor": {"name": "powershell", "command": '$p= "#{excluded_folder}"\nAdd-MpPreference -ExclusionPath $p',
                      "cleanup_command": "Remove-MpPreference -ExclusionPath #{excluded_folder}"}},
        {"name": "Extension", "auto_generated_guid": GUIDS[1], "supported_platforms": ["windows"],
         "executor": {"name": "powershell", "command": "Add-MpPreference -ExclusionExtension .exe"}},
        {"name": "Process", "auto_generated_guid": GUIDS[2], "supported_platforms": ["windows"],
         "executor": {"name": "powershell", "command": "Add-MpPreference -ExclusionProcess outlook.exe"}},
        {"name": "WMIC", "auto_generated_guid": GUIDS[3], "supported_platforms": ["windows"],
         "executor": {"name": "command_prompt", "command": "wmic.exe call Add ExclusionPath=x"}},
    ],
}).encode()


def config(sha=None):
    return {"source": {"commit": COMMIT},
            "files": {"atomics/T1685/T1685.yaml": sha or hashlib.sha256(ATOMIC_FILE).hexdigest()},
            "tests": [{"guid": g, "file": "atomics/T1685/T1685.yaml", "name": n, "tier": t}
                      for g, n, t in zip(GUIDS, ["Folder", "Extension", "Process", "WMIC"],
                                         ["baseline", "baseline", "baseline", "structural"], strict=True)]}


class FirePlan(unittest.TestCase):
    def setUp(self):
        for target, value in ((os.environ, {"LAB_VM": "detonation-vm"}),):
            patcher = mock.patch.dict(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.session = FakeSession({"raw.githubusercontent.com": FakeResponse(200, ATOMIC_FILE)})

    def build(self, changes, cfg=None, graph=None):
        with mock.patch.object(fire_plan, "changes_between", return_value=changes), \
             mock.patch.object(rules, "atomics", return_value=cfg or config()):
            return fire_plan.build("HEAD^1", "HEAD", self.session, graph)

    def test_plan_has_every_command_and_a_stable_hash(self):
        device = {"DeviceName": "detonation-vm", "OnboardingStatus": "Onboarded", "SensorHealthState": "Active",
                  "OSPlatform": "WindowsServer2022", "Timestamp": "2026-10-11T15:00:00Z"}
        plan, checks = self.build([Change("M", LAB)], graph=FakeGraph(device=device))
        self.assertTrue(all(ok for ok, _ in checks), checks)
        self.assertEqual([s["guid"] for s in plan["steps"]], GUIDS)
        self.assertEqual(plan["steps"][0]["command"], '$p= "C:\\Temp"\nAdd-MpPreference -ExclusionPath $p')
        self.assertEqual(plan["steps"][0]["cleanup"], "Remove-MpPreference -ExclusionPath C:\\Temp")
        self.assertEqual(plan["steps"][3]["executor"], "command_prompt")
        again, _ = self.build([Change("M", LAB)])
        self.assertEqual(plan["sha256"], again["sha256"])
        text = fire_plan.report(plan, checks)
        self.assertIn("Add-MpPreference -ExclusionPath $p", text)
        self.assertIn("Nothing runs until you approve", text)
        self.assertIn(plan["sha256"], text)

    def test_files_outside_rules_block_the_plan(self):
        _, checks = self.build([Change("M", LAB), Change("M", "scripts/detonate.py")])
        self.assertFalse(checks[0][0])
        self.assertIn("scripts/detonate.py", checks[0][1])

    def test_hash_mismatch_is_refused(self):
        with self.assertRaises(Fail):
            self.build([Change("M", LAB)], cfg=config(sha="0" * 64))

    def test_unsupported_tests_are_refused(self):
        for definition, message in (
            ({"executor": {"name": "bash", "command": "x"}, "supported_platforms": ["windows"]}, "executor"),
            ({"executor": {"name": "powershell", "command": "x"}, "supported_platforms": ["windows"],
              "dependencies": [{"description": "d"}]}, "dependencies"),
            ({"executor": {"name": "powershell", "command": "PathToAtomicsFolder\\x.exe"},
              "supported_platforms": ["windows"]}, "Atomic Red Team folder"),
            ({"executor": {"name": "powershell", "command": "#{missing}"}, "supported_platforms": ["windows"]},
             "no default"),
        ):
            with self.assertRaises(Fail) as raised:
                fire_plan.test_step(definition, {"name": "n", "tier": "baseline", "file": "f"}, "g")
            self.assertIn(message, str(raised.exception))

    def test_missing_lab_device_fails_preflight(self):
        _, checks = self.build([Change("M", LAB)], graph=FakeGraph(device=None))
        self.assertFalse(checks[-1][0])


def record(minutes_ago=30):
    start = datetime(2026, 10, 11, 16, 0, tzinfo=timezone.utc)
    runs = []
    for number, guid in enumerate(GUIDS):
        began = start + timedelta(minutes=3 * number)
        runs.append({"guid": guid, "name": f"Test {number}", "tier": "baseline",
                     "rules": ["defender-exclusion-added-from-command-line"],
                     "started": began.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "finished": (began + timedelta(seconds=40)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "ran": True, "exit_code": 0})
    return {"vm": "detonation-vm", "plan_sha256": "f" * 64, "staging": {"hostname": "DETONATION-VM", "sense": "Running"},
            "runs": runs}


class TruePositives(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"LAB_VM": "detonation-vm"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_all_caught(self):
        graph = FakeGraph(counts=[("summarize Hits", 2)])
        rows, passed = tp_check.check(graph, record(), wait=False)
        self.assertTrue(passed)
        text = tp_check.report(record(), rows, passed)
        self.assertIn("defender-exclusion-added-from-command-line: yes (2)", text)
        self.assertIn("DeviceProcessEvents 12", text)
        window = next(q for q, _ in graph.queries if "between" in q)
        self.assertIn("datetime(2026-10-11T15:59:30Z) .. datetime(2026-10-11T16:01:40Z)", window)

    def test_miss_is_reported_and_waits_and_polls(self):
        sleeps = []
        clock_values = iter([datetime(2026, 10, 11, 16, 15, tzinfo=timezone.utc) + timedelta(minutes=m)
                             for m in range(0, 400, 5)])
        graph = FakeGraph(counts=[(r"datetime\(2026-10-11T16:08:30Z\)", 1)])
        rows, passed = tp_check.check(graph, record(), wait=True, sleep=sleeps.append,
                                      clock=lambda: next(clock_values))
        self.assertFalse(passed)
        self.assertGreater(sleeps[0], 0)
        caught = [next(iter(row["caught"].values())) for row in rows]
        self.assertEqual(caught, [0, 0, 0, 1])
        self.assertIn("**FAIL**", tp_check.report(record(), rows, passed))

    def test_test_that_did_not_run_fails(self):
        data = record()
        data["runs"][0].update(ran=False, error="Run Command failed")
        rows, passed = tp_check.check(FakeGraph(counts=[("summarize Hits", 1)]), data, wait=False)
        self.assertFalse(passed)
        self.assertIn("NO: Run Command failed", tp_check.report(data, rows, passed))


if __name__ == "__main__":
    unittest.main()
