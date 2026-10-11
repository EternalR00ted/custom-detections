"""Azure DevOps REST calls for pull requests: comments, labels, listing and creating.

Uses the pipeline's own token (System.AccessToken). The project's build service
needs Contribute, Create branch and Contribute to pull requests on the repo;
Step 7 of the setup guide grants exactly those. It can't complete a pull
request past the branch policies, so a person still approves every change.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from urllib.parse import quote

import requests

from .common import Fail, env, run_main

API = "api-version=7.1"
DESCRIPTION_LIMIT = 4000


class AzureDevOps:
    def __init__(self, collection_url: str, project: str, repo_id: str, repo_name: str, token: str,
                 session: requests.Session | None = None):
        self.collection = collection_url.rstrip("/") + "/"
        self.project = project
        self.repo_id = repo_id
        self.repo_name = repo_name
        self._session = session or requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    @classmethod
    def from_env(cls, session: requests.Session | None = None) -> AzureDevOps:
        return cls(
            env("SYSTEM_COLLECTIONURI", required=True),
            env("SYSTEM_TEAMPROJECT", required=True),
            env("BUILD_REPOSITORY_ID", required=True),
            env("BUILD_REPOSITORY_NAME", required=True),
            env("SYSTEM_ACCESSTOKEN", required=True),
            session,
        )

    def _url(self, path: str) -> str:
        repo = f"{self.collection}{quote(self.project)}/_apis/git/repositories/{self.repo_id}"
        joiner = "&" if "?" in path else "?"
        return f"{repo}{path}{joiner}{API}"

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        for attempt in range(5):
            response = self._session.request(method, self._url(path), json=body, timeout=60)
            if response.status_code in (429, 500, 502, 503) and attempt < 4:
                time.sleep(2 ** (attempt + 1))
                continue
            if response.status_code >= 400:
                raise Fail(f"Azure DevOps returned {response.status_code} for {method} {path.split('?')[0]}: "
                           f"{response.text[:300]}")
            return response.json() if response.content else {}
        return {}

    # Pull requests

    def comment(self, pr_id: int | str, markdown: str) -> None:
        """Post a comment thread, marked closed so it never blocks completion."""
        body = {"comments": [{"parentCommentId": 0, "content": markdown, "commentType": 1}], "status": 4}
        self._request("POST", f"/pullRequests/{int(pr_id)}/threads", body)

    def labels(self, pr_id: int | str) -> list[str]:
        data = self._request("GET", f"/pullRequests/{int(pr_id)}/labels")
        return [label["name"] for label in data.get("value", []) if label.get("active", True)]

    def add_label(self, pr_id: int | str, name: str) -> None:
        self._request("POST", f"/pullRequests/{int(pr_id)}/labels", {"name": name})

    def list_prs(self, source_branch: str | None = None, status: str = "all", top: int = 500) -> list[dict]:
        query = f"/pullrequests?searchCriteria.status={status}&$top={top}"
        if source_branch:
            ref = source_branch if source_branch.startswith("refs/") else f"refs/heads/{source_branch}"
            query += f"&searchCriteria.sourceRefName={quote(ref, safe='')}"
        return self._request("GET", query).get("value", [])

    def create_pr(self, source_branch: str, target_branch: str, title: str, description: str,
                  labels: list[str] | None = None) -> dict:
        """Open a pull request. A description over the 4,000-character limit is
        shortened, and the full text goes in the first comment."""
        short = description
        if len(description) > DESCRIPTION_LIMIT:
            note = "\n\n(Shortened. The full description is the first comment.)"
            short = description[: DESCRIPTION_LIMIT - len(note)] + note
        body = {
            "sourceRefName": f"refs/heads/{source_branch}",
            "targetRefName": f"refs/heads/{target_branch}",
            "title": title[:400],
            "description": short,
        }
        pr = self._request("POST", "/pullrequests", body)
        if short != description:
            self.comment(pr["pullRequestId"], description)
        for label in labels or []:
            self.add_label(pr["pullRequestId"], label)
        return pr

    def web_url(self, pr_id: int | str) -> str:
        return f"{self.collection}{quote(self.project)}/_git/{quote(self.repo_name)}/pullrequest/{int(pr_id)}"

    def file_url(self, path: str, branch: str = "main") -> str:
        return (f"{self.collection}{quote(self.project)}/_git/{quote(self.repo_name)}"
                f"?path=/{quote(path)}&version=GB{quote(branch)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Pull request helpers for pipeline steps.")
    sub = parser.add_subparsers(dest="command", required=True)
    post = sub.add_parser("comment", help="Post a Markdown file as a pull request comment")
    post.add_argument("--pr", required=True)
    post.add_argument("--file", required=True)
    has = sub.add_parser("has-label", help="Exit 0 if the pull request has the label, 1 if not")
    has.add_argument("--pr", required=True)
    has.add_argument("--label", required=True)
    args = parser.parse_args()

    if not str(args.pr).isdigit():
        raise Fail("This step only runs for a pull request.")
    client = AzureDevOps.from_env()
    if args.command == "comment":
        client.comment(args.pr, Path(args.file).read_text(encoding="utf-8"))
        return 0
    return 0 if args.label in client.labels(args.pr) else 1


if __name__ == "__main__":
    run_main(main)
