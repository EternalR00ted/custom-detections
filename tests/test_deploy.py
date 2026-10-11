"""Deploy, promote, shadow run, and the Azure DevOps client."""

import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import ado, deploy, promote, rules, shadow
from scripts.common import ROOT, Fail
from tests.fakes import FakeGraph, FakeResponse, FakeSession

LAB = "detections/lab/defender-exclusion-added-from-command-line.yaml"


class Deploy(unittest.TestCase):
    def test_create_then_update(self):
        graph = FakeGraph()
        self.assertEqual(deploy.deploy([LAB], graph, "Contoso"), 0)
        self.assertEqual(graph.created[0]["displayName"], "Contoso - MDE - Defender exclusion added from the command line")
        self.assertEqual(deploy.deploy([LAB], graph, "Contoso"), 0)
        self.assertEqual(graph.updated[0][0], "defender-exclusion-added-from-command-line")

    def test_graph_error_fails_the_run(self):
        graph = FakeGraph()
        graph.create_rule = mock.Mock(side_effect=Fail("Microsoft Graph returned 400: bad tactic"))
        self.assertEqual(deploy.deploy([LAB], graph, "Contoso"), 1)


class Promote(unittest.TestCase):
    def test_promote_and_retire_edit_only_two_lines(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        path = folder / "defender-exclusion-added-from-command-line.yaml"
        shutil.copy(ROOT / LAB, path)
        before = path.read_text()
        self.assertEqual(promote.set_status(path, "production"), "1.1.0")
        after = path.read_text()
        self.assertEqual(rules.load(path)["status"], "production")
        changed = [line for line in after.splitlines() if line not in before.splitlines()]
        self.assertEqual(changed, ["status: production", "version: 1.1.0"])
        self.assertEqual(promote.set_status(path, "retired"), "1.1.1")
        with self.assertRaises(Fail):
            promote.set_status(path, "retired")


class Shadow(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"LAB_VM": "detonation-vm"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_ready_needs_days_and_zero_hits(self):
        with mock.patch.object(shadow, "days_in_testing", return_value=9):
            rows = shadow.shadow(FakeGraph())
            self.assertTrue(all(row["ready"] for row in rows))
            rows = shadow.shadow(FakeGraph(counts=[("summarize Hits", 4)]))
            self.assertFalse(any(row["ready"] for row in rows))
        with mock.patch.object(shadow, "days_in_testing", return_value=2):
            self.assertFalse(any(row["ready"] for row in shadow.shadow(FakeGraph())))

    def test_days_in_testing_reads_git_history(self):
        days = shadow.days_in_testing(ROOT / LAB, datetime.now(timezone.utc))
        self.assertIsNotNone(days)
        self.assertGreaterEqual(days, 0)


class AzureDevOpsClient(unittest.TestCase):
    def client(self, routes):
        session = FakeSession(routes)
        return ado.AzureDevOps("https://dev.azure.com/org/", "My Project", "repo-id", "repo", "token", session), session

    def test_comment_is_a_closed_thread(self):
        client, session = self.client({"threads": FakeResponse(200, b"{}")})
        client.comment(5, "hello")
        method, url, body = session.requests[0]
        self.assertEqual(method, "POST")
        self.assertIn("/My%20Project/_apis/git/repositories/repo-id/pullRequests/5/threads?api-version=7.1", url)
        self.assertEqual(body["status"], 4)
        self.assertEqual(body["comments"][0]["content"], "hello")

    def test_long_description_goes_to_a_comment(self):
        client, session = self.client({
            r"/pullrequests\?": FakeResponse(200, b'{"pullRequestId": 7}'),
            "threads": FakeResponse(200, b"{}"),
            "labels": FakeResponse(200, b"{}"),
        })
        pr = client.create_pr("ai/x-1", "main", "AI draft: x", "y" * 5000, ["ai-draft"])
        self.assertEqual(pr["pullRequestId"], 7)
        create = session.requests[0][2]
        self.assertEqual(create["sourceRefName"], "refs/heads/ai/x-1")
        self.assertLessEqual(len(create["description"]), 4000)
        self.assertEqual(len(session.requests[1][2]["comments"][0]["content"]), 5000)
        self.assertEqual(session.requests[2][2], {"name": "ai-draft"})

    def test_labels_and_list(self):
        client, session = self.client({
            "labels": FakeResponse(200, b'{"value": [{"name": "noise-reviewed-abc1234", "active": true}]}'),
            "pullrequests": FakeResponse(200, b'{"value": [{"pullRequestId": 1}]}'),
        })
        self.assertEqual(client.labels(3), ["noise-reviewed-abc1234"])
        self.assertEqual(client.list_prs(source_branch="promote/x"), [{"pullRequestId": 1}])
        self.assertIn("searchCriteria.sourceRefName=refs%2Fheads%2Fpromote%2Fx", session.requests[1][1])

    def test_errors_are_clear(self):
        client, _ = self.client({"labels": FakeResponse(403, b"denied")})
        with self.assertRaises(Fail) as raised:
            client.labels(3)
        self.assertIn("403", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
