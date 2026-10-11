"""Did each rule catch each lab test? CCCS step 6, the blue side validates.

Waits for telemetry (10 minutes after the last test, like CCCS), then counts
the rule's hits on the lab VM inside each test's time window. It also counts
what the lab VM recorded in that window, by table, so a miss can be told apart
from missing telemetry. Counts only.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timedelta, timezone

from . import rules
from .common import ROOT, Fail, lab_vm, md, run_main, settings, upload_summary

TELEMETRY_TABLES = ["DeviceProcessEvents", "DeviceEvents", "DeviceRegistryEvents", "DeviceFileEvents",
                    "DeviceNetworkEvents"]


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def window(run: dict) -> tuple[str, str]:
    return (stamp(parse_time(run["started"]) - timedelta(seconds=30)),
            stamp(parse_time(run["finished"]) + timedelta(seconds=60)))


def telemetry(graph, lab: str, start: str, end: str) -> dict[str, int]:
    query = "\n".join([
        f"union withsource=Table {', '.join(TELEMETRY_TABLES)}",
        f"| where Timestamp between (datetime({start}) .. datetime({end}))",
        rules.only_lab(lab),
        "| summarize Events = count() by Table",
    ])
    rows = graph.hunt(query, f"{start}/{end}")["results"]
    return {str(row.get("Table")): int(row.get("Events") or 0) for row in rows}


def check(graph, record: dict, wait: bool = True, sleep=time.sleep, clock=None) -> tuple[list[dict], bool]:
    lab_cfg = settings()["lab"]
    lab = lab_vm() or record["vm"]
    clock = clock or (lambda: datetime.now(timezone.utc))
    ran = [run for run in record["runs"] if run.get("ran")]
    rule_cache = {}
    for path in rules.rule_files():
        rule = rules.load(path)
        if isinstance(rule.get("id"), str):
            rule_cache[rule["id"]] = rule
    if wait and ran:
        last = max(parse_time(run["finished"]) for run in ran)
        remaining = (last + timedelta(minutes=lab_cfg["initial_wait_minutes"]) - clock()).total_seconds()
        if remaining > 0:
            print(f"Waiting {int(remaining)} seconds for telemetry, like CCCS did.")
            sleep(remaining)
    deadline = clock() + timedelta(minutes=lab_cfg["max_wait_minutes"] if wait else 0)
    results: dict[tuple[str, str], int] = {}
    while True:
        for run in ran:
            start, end = window(run)
            for rule_id in run["rules"]:
                if results.get((run["guid"], rule_id), 0) > 0:
                    continue
                rule = rule_cache.get(rule_id)
                if rule is None:
                    raise Fail(f"Rule {rule_id} isn't in this commit.")
                results[(run["guid"], rule_id)] = graph.count(rules.window_query(rule, lab, start, end),
                                                              f"{start}/{end}")
        missing = [key for key, hits in results.items() if hits == 0]
        if not missing or clock() >= deadline:
            break
        print(f"{len(missing)} test and rule pair(s) without hits yet. Checking again in "
              f"{lab_cfg['poll_seconds']} seconds.")
        sleep(lab_cfg["poll_seconds"])
    rows, passed = [], True
    for run in record["runs"]:
        row = {"run": run, "caught": {}, "telemetry": {}}
        if run.get("ran"):
            start, end = window(run)
            row["telemetry"] = telemetry(graph, lab, start, end)
            for rule_id in run["rules"]:
                row["caught"][rule_id] = results.get((run["guid"], rule_id), 0)
                if row["caught"][rule_id] == 0:
                    passed = False
        else:
            passed = False
        rows.append(row)
    return rows, passed


def report(record: dict, rows: list[dict], passed: bool) -> str:
    lines = ["### Lab detonation results", "",
             (f"VM `{record['vm']}`, plan `{record['plan_sha256'][:12]}`. Staging check: hostname "
              f"{md(record.get('staging', {}).get('hostname', '?'))}, Defender sensor "
              f"{md(record.get('staging', {}).get('sense', '?'))}."), "",
             "| # | Test | Tier | Ran | Caught | Lab telemetry in the window |", "|---|---|---|---|---|---|"]
    for number, row in enumerate(rows, 1):
        run = row["run"]
        ran = "yes" if run.get("ran") else f"NO: {run.get('error', 'no exit code')}"
        caught = ", ".join(f"{rule_id}: {'yes' if hits else 'NO'} ({hits})" for rule_id, hits in row["caught"].items())
        events = ", ".join(f"{table} {count}" for table, count in sorted(row["telemetry"].items())) or "none"
        lines.append(f"| {number} | {md(run['name'])} | {run['tier']} | {md(ran)} | {md(caught or '-')} | "
                     f"{md(events)} |")
    lines += ["", "**PASS**: every rule caught every test that ran." if passed else
              "**FAIL**: a rule missed a test, or a test didn't run. If the lab telemetry column shows events "
              "but Caught says NO, the rule missed. If it shows none, the telemetry didn't arrive."]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Count each rule's hits per lab test window.")
    parser.add_argument("--runs", default="work/detonations.json")
    parser.add_argument("--report", default="work/tp-check.md")
    parser.add_argument("--no-wait", action="store_true")
    args = parser.parse_args()

    from .auth import credential
    from .graph import Graph

    record = json.loads((ROOT / args.runs).read_text(encoding="utf-8"))
    rows, passed = check(Graph(credential()), record, wait=not args.no_wait)
    text = report(record, rows, passed)
    path = ROOT / args.report
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    upload_summary(path)
    print(text)
    return 0 if passed else 1


if __name__ == "__main__":
    run_main(main)
