"""The daily shadow run: what each rule in testing would have caught.

Rules in testing are deployed turned off, because custom detections have no
"alerts but no incidents" mode. Each day this runs every testing rule over the
last few days of data with the lab VM left out and reports the count (counts
only, never rows). With --propose it opens a promotion pull request for each
rule that has spent long enough in testing with no hits: CCCS's last step,
where a person approves the move to production.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from . import observability, rules
from .common import ROOT, git, lab_vm, md, run_main, settings, upload_summary
from .promote import set_status

PIPELINE_AUTHOR = ["-c", "user.name=Detection pipeline", "-c", "user.email=pipeline@detections.invalid"]


def days_in_testing(path: Path, now: datetime) -> int | None:
    """Days since the rule file first appeared on this branch, from git history."""
    dates = git("log", "--diff-filter=A", "--follow", "--format=%cI", "--", rules.relative(path), check=False)
    lines = [line for line in dates.splitlines() if line.strip()]
    if not lines:
        return None
    added = datetime.fromisoformat(lines[-1].strip())
    return (now - added).days


def shadow(graph, now: datetime | None = None) -> list[dict]:
    cfg = settings()["promotion"]
    now = now or datetime.now(timezone.utc)
    lab = lab_vm()
    rows = []
    for path in rules.rule_files():
        rule = rules.load(path)
        if rule.get("status") != "testing" or rules.problems(rule, path):
            continue
        row = {"path": rules.relative(path), "id": rule["id"], "days": days_in_testing(path, now)}
        try:
            row["hits"] = graph.count(rules.production_query(rule, lab), f"P{cfg['shadow_days']}D")
        except Exception as error:  # noqa: BLE001  report it and carry on with the other rules
            observability.capture(error)
            row["hits"] = None
            row["error"] = str(error)[:200]
        row["ready"] = (row["hits"] is not None and row["hits"] <= cfg["max_hits"]
                        and row["days"] is not None and row["days"] >= cfg["min_days_in_testing"])
        rows.append(row)
    return rows


def propose(ado, row: dict, base: str) -> str:
    branch = f"promote/{row['id']}"
    if ado.list_prs(source_branch=branch):
        return "already proposed once (a closed proposal means no)"
    git("switch", "--quiet", "-c", branch, base)
    try:
        version = set_status(ROOT / row["path"], "production")
        git("add", row["path"])
        git(*PIPELINE_AUTHOR, "commit", "--quiet", "-m", f"Promote {row['id']} to production")
        git("push", "--quiet", "--force", "origin", f"HEAD:refs/heads/{branch}")
        cfg = settings()["promotion"]
        body = "\n".join([
            f"## Promote {row['id']} to production",
            "",
            (f"It has been in testing for {row['days']} days, and the shadow run counted {row['hits']} hits over "
             f"the last {cfg['shadow_days']} days with the lab VM left out."),
            "",
            f"Completing this sets status to production (version {version}), and the deploy turns the rule on.",
            "",
            "Before you approve, check what the shadow run can't:",
            "1. True-positive evidence: a passing Lab detonation or a documented manual test.",
            "2. A name, description and entities a Tier 1 analyst can act on without asking you.",
            "",
            "Abandon this pull request to keep the rule in testing. It won't be proposed again.",
        ])
        pr = ado.create_pr(branch, "main", f"Promote {row['id']} to production", body, ["promotion"])
        return ado.web_url(pr["pullRequestId"])
    finally:
        git("switch", "--quiet", "--detach", base, check=False)
        git("branch", "--quiet", "-D", branch, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Count what each testing rule would have caught.")
    parser.add_argument("--propose", action="store_true", help="Open promotion pull requests")
    parser.add_argument("--summary", default="work/shadow.md")
    args = parser.parse_args()

    from .auth import credential
    from .graph import Graph

    cfg = settings()["promotion"]
    rows = shadow(Graph(credential()))
    ado = None
    base = git("rev-parse", "HEAD").strip()
    if args.propose and any(row["ready"] for row in rows):
        from .ado import AzureDevOps
        ado = AzureDevOps.from_env()
    lines = ["# Shadow run", "",
             (f"Each rule in testing over the last {cfg['shadow_days']} days, lab VM left out. Counts only. A count "
              "is an upper bound on alerts, because Defender merges duplicate events into one alert."), "",
             "| Rule | Days in testing | Hits | Promotion |", "|---|---|---|---|"]
    for row in rows:
        if row["hits"] is None:
            status = f"ERROR: {row.get('error', '')}"
        elif row["ready"] and ado:
            status = propose(ado, row, base)
        elif row["ready"]:
            status = "ready (run with --propose to open a pull request)"
        else:
            status = f"not yet (needs {cfg['min_days_in_testing']} days and {cfg['max_hits']} hits)"
        hits = "error" if row["hits"] is None else row["hits"]
        lines.append(f"| {md(row['id'])} | {row['days'] if row['days'] is not None else '?'} | {hits} | {md(status)} |")
    if not rows:
        lines.append("| no rules in testing | | | |")
    text = "\n".join(lines)
    path = ROOT / args.summary
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    upload_summary(path)
    print(text)
    return 1 if any(row["hits"] is None for row in rows) else 0


if __name__ == "__main__":
    run_main(main)
