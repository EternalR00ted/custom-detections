"""Microsoft Graph calls: advanced hunting and custom detection rules.

Advanced hunting results never leave this module as rows in a report. Callers
ask for counts or column lists only, so nothing from your tenant's data ends up
in a pull request comment or a pipeline log.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from .common import Fail

GRAPH = "https://graph.microsoft.com"
SCOPE = "https://graph.microsoft.com/.default"


class GraphError(Fail):
    def __init__(self, status: int, message: str):
        super().__init__(f"Microsoft Graph returned {status}: {message}")
        self.status = status
        self.message = message


class Graph:
    def __init__(self, credential, session: requests.Session | None = None):
        self._credential = credential
        self._session = session or requests.Session()
        self._token = None

    def _bearer(self) -> str:
        if self._token is None or self._token.expires_on - time.time() < 300:
            self._token = self._credential.get_token(SCOPE)
        return self._token.token

    def _call(self, method: str, url: str, body: dict | None = None) -> requests.Response:
        for attempt in range(6):
            response = self._session.request(
                method, url, json=body, timeout=120,
                headers={"Authorization": f"Bearer {self._bearer()}",
                         "Content-Type": "application/json; charset=utf-8"},
            )
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 5:
                wait = response.headers.get("Retry-After", "")
                time.sleep(min(int(wait) if wait.isdigit() else 2 ** (attempt + 2), 120))
                continue
            return response
        return response

    @staticmethod
    def _error(response: requests.Response) -> GraphError:
        try:
            error = response.json().get("error", {})
            message = error.get("message") or error.get("code") or response.text[:300]
        except ValueError:
            message = response.text[:300]
        return GraphError(response.status_code, message)

    # Advanced hunting (v1.0)

    def hunt(self, query: str, timespan: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"Query": query}
        if timespan:
            body["Timespan"] = timespan
        response = self._call("POST", f"{GRAPH}/v1.0/security/runHuntingQuery", body)
        if response.status_code != 200:
            raise self._error(response)
        data = response.json()
        return {"schema": data.get("schema") or [], "results": data.get("results") or []}

    def count(self, query: str, timespan: str | None = None) -> int:
        """Run a query that ends in `summarize Hits = count()` and return the number."""
        results = self.hunt(query, timespan)["results"]
        if not results:
            return 0
        row = results[0]
        value = row.get("Hits", row.get("hits", 0))
        return int(value or 0)

    def columns(self, query: str) -> list[str]:
        """The column names a query returns, without returning any rows.

        Tries `getschema` first. If advanced hunting rejects that, runs the query
        with `take 0` and reads the schema of the empty result. A query that's
        actually broken fails both ways, and the second error is the one raised.
        """
        try:
            result = self.hunt(f"{query}\n| getschema | project ColumnName", "P1D")
            names = [row.get("ColumnName") or row.get("columnName") for row in result["results"]]
            names = [name for name in names if name]
            if names:
                return names
        except GraphError as error:
            if error.status != 400:
                raise
        result = self.hunt(f"{query}\n| take 0", "P1D")
        return [column.get("name") or column.get("Name") for column in result["schema"] if column]

    # Custom detection rules (beta)

    def get_rule(self, rule_id: str) -> dict | None:
        response = self._call("GET", f"{GRAPH}/beta/security/rules/detectionRules/{rule_id}")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise self._error(response)
        return response.json()

    def create_rule(self, body: dict) -> dict:
        response = self._call("POST", f"{GRAPH}/beta/security/rules/detectionRules", body)
        if response.status_code not in (200, 201):
            raise self._error(response)
        return response.json()

    def update_rule(self, rule_id: str, body: dict) -> None:
        patch = {key: value for key, value in body.items() if key not in ("id", "@odata.type")}
        response = self._call("PATCH", f"{GRAPH}/beta/security/rules/detectionRules/{rule_id}", patch)
        if response.status_code not in (200, 204):
            raise self._error(response)
