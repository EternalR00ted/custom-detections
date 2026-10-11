"""Offline stand-ins for Microsoft Graph, Azure DevOps, Claude and HTTP, used by the tests."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

from scripts.graph import GraphError


class FakeGraph:
    """Advanced hunting and custom detection rules, in memory.

    counts: list of (regex, number) pairs. The first regex that matches a
    count query decides the number; anything else counts 0.
    """

    def __init__(self, columns=None, counts=None, compile_error=None, device=None, telemetry=None):
        self.columns_result = columns if columns is not None else [
            "Timestamp", "DeviceId", "DeviceName", "ReportId", "AccountName", "AccountDomain", "AccountSid",
            "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "InitiatingProcessCommandLine"]
        self.counts = counts or []
        self.compile_error = compile_error
        self.device = device
        self.telemetry = telemetry or {"DeviceProcessEvents": 12}
        self.rules: dict[str, dict] = {}
        self.queries: list[tuple[str, str | None]] = []
        self.created: list[dict] = []
        self.updated: list[tuple[str, dict]] = []

    def hunt(self, query, timespan=None):
        self.queries.append((query, timespan))
        if query.startswith("DeviceInfo"):
            return {"schema": [], "results": [self.device] if self.device else []}
        if query.startswith("union withsource=Table"):
            return {"schema": [], "results": [{"Table": t, "Events": n} for t, n in self.telemetry.items()]}
        raise AssertionError(f"unexpected hunt: {query[:80]}")

    def count(self, query, timespan=None):
        self.queries.append((query, timespan))
        for pattern, number in self.counts:
            if re.search(pattern, query, re.DOTALL):
                return number
        return 0

    def columns(self, query):
        self.queries.append((query, "columns"))
        if self.compile_error:
            raise GraphError(400, self.compile_error)
        return list(self.columns_result)

    def get_rule(self, rule_id):
        return self.rules.get(rule_id)

    def create_rule(self, body):
        self.created.append(body)
        self.rules[body["id"]] = body
        return body

    def update_rule(self, rule_id, body):
        self.updated.append((rule_id, body))


class FakeADO:
    def __init__(self, labels=None, prs=None):
        self._labels = labels or []
        self.prs = prs or []
        self.comments: list[tuple[str, str]] = []
        self.created: list[dict] = []

    def labels(self, pr_id):
        return list(self._labels)

    def comment(self, pr_id, text):
        self.comments.append((str(pr_id), text))

    def list_prs(self, source_branch=None, status="all", top=500):
        if source_branch:
            ref = source_branch if source_branch.startswith("refs/") else f"refs/heads/{source_branch}"
            return [pr for pr in self.prs if pr.get("sourceRefName") == ref]
        return list(self.prs)

    def create_pr(self, source_branch, target_branch, title, description, labels=None):
        pr = {"pullRequestId": 100 + len(self.created), "sourceRefName": f"refs/heads/{source_branch}",
              "title": title, "description": description, "labels": labels or []}
        self.created.append(pr)
        self.prs.append(pr)
        return pr

    def web_url(self, pr_id):
        return f"https://dev.azure.com/org/project/_git/repo/pullrequest/{pr_id}"

    def file_url(self, path, branch="main"):
        return f"https://dev.azure.com/org/project/_git/repo?path=/{path}&version=GB{branch}"


def tool_reply(name, data, stop_reason="tool_use", input_tokens=100, output_tokens=50):
    block = SimpleNamespace(type="tool_use", name=name, input=data)
    return SimpleNamespace(content=[block], stop_reason=stop_reason,
                           usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens))


def refusal_reply():
    return SimpleNamespace(content=[], stop_reason="refusal", usage=SimpleNamespace(input_tokens=10, output_tokens=0))


class FakeMessages:
    """Answers by calling handler(model, tool_names, kwargs), which returns a reply or raises."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        names = [tool["name"] for tool in kwargs.get("tools", [])]
        return self.handler(kwargs["model"], names, kwargs)


class FakeAnthropic:
    def __init__(self, handler):
        self.messages = FakeMessages(handler)


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None, url=""):
        self.status_code = status
        self._body = body if isinstance(body, bytes) else body.encode("utf-8")
        self.headers = headers or {}
        self.url = url
        self.encoding = "utf-8"
        self._content = self._body
        self.content = self._body
        self.text = self._body.decode("utf-8", errors="replace")

    @property
    def is_redirect(self):
        return self.status_code in (301, 302, 303, 307, 308) and "Location" in self.headers

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, size):
        for start in range(0, len(self._body), size):
            yield self._body[start:start + size]

    def json(self):
        return json.loads(self._body or b"{}")


class FakeSession:
    """requests.Session stand-in. routes: url -> FakeResponse (or a callable taking the url)."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.headers = {}
        self.requests: list[tuple[str, str, dict | None]] = []

    def _answer(self, method, url, body=None):
        self.requests.append((method, url, body))
        for pattern, response in self.routes.items():
            if re.search(pattern, url):
                return response(url) if callable(response) else response
        return FakeResponse(404, b"not found")

    def get(self, url, **kwargs):
        return self._answer("GET", url)

    def post(self, url, json=None, **kwargs):
        return self._answer("POST", url, json)

    def request(self, method, url, json=None, **kwargs):
        return self._answer(method, url, json)
