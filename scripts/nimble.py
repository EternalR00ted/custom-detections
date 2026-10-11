"""Nimble: live web search and clean article extraction for the drafter.

Search finds new threat reports on the trusted domains in config/research.yaml
and returns each page's text. Extract turns any article URL into clean
Markdown of its main content, including pages that need JavaScript to render.
The key is NIMBLE_API_KEY, a secret variable in the 'detections' group.
"""

from __future__ import annotations

import time

import requests

from .common import Fail

API = "https://sdk.nimbleway.com/v2"


class Nimble:
    def __init__(self, api_key: str, session: requests.Session | None = None):
        self.api_key = api_key
        self.session = session or requests.Session()

    def _post(self, path: str, body: dict) -> dict:
        for attempt in range(4):
            response = self.session.post(f"{API}{path}", json=body, timeout=180,
                                         headers={"Authorization": f"Bearer {self.api_key}",
                                                  "Content-Type": "application/json"})
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(2 ** (attempt + 2))
                continue
            if response.status_code == 402:
                raise Fail("Nimble says the account is out of budget or the trial has ended (402).")
            if response.status_code >= 400:
                raise Fail(f"Nimble {path} returned {response.status_code}: {response.text[:300]}")
            return response.json()
        raise Fail(f"Nimble {path} kept returning {response.status_code}")

    def search(self, query: str, domains: list[str], time_range: str = "week", max_results: int = 5) -> list[dict]:
        body = {
            "query": query,
            "search_depth": "standard",
            "full_content": True,
            "max_results": max_results,
            "include_domains": domains[:50],
            "time_range": time_range,
            "output_format": "markdown",
            "focus": "general",
        }
        results = self._post("/search", body).get("results") or []
        return [{"url": item.get("url", ""), "title": item.get("title", ""), "content": item.get("content") or ""}
                for item in results if item.get("url")]

    def extract(self, url: str) -> tuple[str, str]:
        """Returns the final URL after redirects and the page's main content as Markdown."""
        body = {"url": url, "formats": ["markdown"], "markdown_backend": "main_content"}
        data = self._post("/extract", body)
        if data.get("status") != "success":
            raise Fail(f"Nimble couldn't extract {url} (status {data.get('status')}, HTTP {data.get('status_code')})")
        markdown = (data.get("data") or {}).get("markdown") or ""
        return data.get("url") or url, markdown
