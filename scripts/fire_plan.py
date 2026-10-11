"""The fire plan: exactly what the lab detonation will run, shown before anyone approves it.

For each changed rule that lists lab tests, it reads the test from the pinned
Atomic Red Team file, checks the file's SHA-256, and fills in the test's
default arguments. The plan shows the target VM as Defender sees it, every
command and cleanup command, each test's tier, and pre-flight checks. Its
SHA-256 is checked again right before the VM starts, so what you approved is
what runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re

import requests
import yaml

from . import rules
from .check_pr import changed_rules, changes_between
from .common import ROOT, Fail, lab_vm, md, run_main, set_output, upload_summary

RAW = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{commit}/{path}"
EXECUTORS = {"powershell", "command_prompt"}


def fetch_atomic_file(session: requests.Session, commit: str, path: str, expected_sha256: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Fail("config/atomics.yaml must pin a full 40-character commit")
    if not re.fullmatch(r"atomics/T[0-9.]+/T[0-9.]+\.yaml", path):
        raise Fail(f"{path} isn't an Atomic Red Team test file path")
    response = session.get(RAW.format(commit=commit, path=path), timeout=60)
    response.raise_for_status()
    actual = hashlib.sha256(response.content).hexdigest()
    if actual != expected_sha256:
        raise Fail(f"{path} at {commit[:7]} has SHA-256 {actual}, not the pinned {expected_sha256}")
    return yaml.safe_load(response.content)


def fill_arguments(text: str, arguments: dict) -> str:
    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in arguments:
            raise Fail(f"the test uses #{{{name}}} but has no default for it")
        return str(arguments[name].get("default", ""))
    return re.sub(r"#\{([A-Za-z0-9_]+)\}", replace, text or "")


def test_step(definition: dict, test: dict, guid: str) -> dict:
    executor = definition.get("executor") or {}
    if executor.get("name") not in EXECUTORS:
        raise Fail(f"{guid} uses the {executor.get('name')} executor; only powershell and command_prompt are allowed")
    if definition.get("dependencies"):
        raise Fail(f"{guid} has dependencies, which this lab doesn't install")
    if "windows" not in (definition.get("supported_platforms") or []):
        raise Fail(f"{guid} doesn't support Windows")
    arguments = definition.get("input_arguments") or {}
    command = fill_arguments(executor.get("command", ""), arguments).strip()
    cleanup = fill_arguments(executor.get("cleanup_command", ""), arguments).strip()
    if re.search(r"PathToAtomicsFolder|PathToPayloads", command + cleanup, re.IGNORECASE):
        raise Fail(f"{guid} needs files from the Atomic Red Team folder, which this lab doesn't download")
    return {"guid": guid, "name": test["name"], "tier": test["tier"], "file": test["file"],
            "executor": executor["name"], "command": command, "cleanup": cleanup, "rules": []}


def plan_hash(plan: dict) -> str:
    material = {"commit": plan["commit"], "vm": plan["vm"],
                "steps": [{k: step[k] for k in ("guid", "file", "executor", "command", "cleanup", "rules")}
                          for step in plan["steps"]]}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()


def lab_device(graph, lab: str) -> dict | None:
    query = "\n".join([
        "DeviceInfo",
        "| where Timestamp > ago(30d)",
        rules.only_lab(lab),
        "| summarize arg_max(Timestamp, *)",
        '| project Timestamp, DeviceName, OnboardingStatus = tostring(column_ifexists("OnboardingStatus", "")),',
        '    SensorHealthState = tostring(column_ifexists("SensorHealthState", "")), OSPlatform',
    ])
    results = graph.hunt(query, "P30D")["results"]
    return results[0] if results else None


def build(base: str, head: str, session: requests.Session, graph=None) -> tuple[dict, list[tuple[bool, str]]]:
    lab = lab_vm()
    if not lab:
        raise Fail("Set LAB_VM in the 'detections' variable group.")
    changes = changes_between(base, head)
    checks: list[tuple[bool, str]] = []
    outside = sorted({c.new_path or c.path for c in changes
                      if not (c.new_path or c.path).startswith(("detections/", "sigma/"))})
    checks.append((not outside, "Only rule and Sigma files changed" if not outside else
                   "This pull request changes files outside detections/ and sigma/: " + ", ".join(outside) +
                   ". A detonation runs the branch's own pipeline and scripts, so it won't plan one."))
    config = rules.atomics()
    commit = config["source"]["commit"]
    steps: dict[str, dict] = {}
    files: dict[str, dict] = {}
    for path in changed_rules(changes):
        rule = rules.load(ROOT / path)
        if rule.get("status") == "retired":
            continue
        for guid in rule.get("lab_tests") or []:
            test = rules.atomic(guid)
            if guid not in steps:
                if test["file"] not in files:
                    expected = config["files"].get(test["file"])
                    if not expected:
                        raise Fail(f"{test['file']} has no SHA-256 in config/atomics.yaml")
                    files[test["file"]] = fetch_atomic_file(session, commit, test["file"], expected)
                definition = next((t for t in files[test["file"]].get("atomic_tests", [])
                                   if t.get("auto_generated_guid") == guid), None)
                if definition is None:
                    raise Fail(f"{guid} isn't in {test['file']} at {commit[:7]}")
                steps[guid] = test_step(definition, test, guid)
            steps[guid]["rules"].append(rule["id"])
    plan = {"commit": commit, "vm": lab, "steps": list(steps.values())}
    plan["sha256"] = plan_hash(plan)
    if files:
        checks.append((True, f"Every test is allowlisted and its file matches the pinned SHA-256 at {commit[:7]}"))
    if graph is not None and plan["steps"]:
        device = lab_device(graph, lab)
        if device is None:
            checks.append((False, f"Defender has no DeviceInfo for {lab} in the last 30 days. Is it onboarded?"))
        else:
            onboarded = str(device.get("OnboardingStatus", "")) in ("", "Onboarded")
            plan["device"] = {k: device.get(k) for k in ("DeviceName", "OnboardingStatus", "SensorHealthState",
                                                         "OSPlatform", "Timestamp")}
            checks.append((onboarded, (f"Defender sees {device.get('DeviceName')} as "
                                       f"{device.get('OnboardingStatus') or 'onboarded'}, sensor "
                                       f"{device.get('SensorHealthState') or 'unknown'}, last seen "
                                       f"{device.get('Timestamp')}")))
    return plan, checks


def report(plan: dict, checks: list[tuple[bool, str]]) -> str:
    lines = ["### Fire plan (lab detonation)", ""]
    if not plan["steps"]:
        lines.append("No changed rule lists lab tests, so nothing will run.")
    else:
        lines += [(f"Target: **{md(plan['vm'])}**. Atomic Red Team pinned at `{plan['commit'][:7]}`. "
                   f"Plan SHA-256: `{plan['sha256']}`"), ""]
        for number, step in enumerate(plan["steps"], 1):
            shell = "powershell" if step["executor"] == "powershell" else "bat"
            lines += [(f"**{number}. {md(step['name'])}** ({step['tier']}, {step['executor']}). "
                       f"Checks: {', '.join(md(r) for r in step['rules'])}"), "",
                      f"```{shell}", step["command"], "```"]
            if step["cleanup"]:
                lines += ["Cleanup:", "", f"```{shell}", step["cleanup"], "```"]
            lines.append("")
    lines += ["Pre-flight checks:", ""]
    lines += [f"- {'PASS' if ok else 'FAIL'}: {md(text)}" for ok, text in checks]
    if plan["steps"] and all(ok for ok, _ in checks):
        lines += ["", ("Nothing runs until you approve the waiting stage of this Lab detonation run in Azure "
                       "Pipelines. The run checks this plan's SHA-256 again before it starts the VM.")]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the fire plan for a pull request's lab tests.")
    parser.add_argument("--base", default="HEAD^1")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--out", default="work/fire-plan.json")
    parser.add_argument("--report", default="work/fire-plan.md")
    parser.add_argument("--no-target", action="store_true", help="Skip the Defender check of the lab VM")
    parser.add_argument("--expect-sha256", default="", help="Fail unless the plan has this SHA-256")
    args = parser.parse_args()

    graph = None
    if not args.no_target:
        from .auth import credential
        from .graph import Graph
        graph = Graph(credential())
    plan, checks = build(args.base, args.head, requests.Session(), graph)
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, indent=2, default=str), encoding="utf-8")
    if args.expect_sha256:
        if plan["sha256"] != args.expect_sha256:
            raise Fail(f"The plan changed since it was approved: {plan['sha256']} isn't {args.expect_sha256}.")
        print(f"Plan SHA-256 matches what was approved: {plan['sha256']}")
        return 0
    text = report(plan, checks)
    path = ROOT / args.report
    path.write_text(text, encoding="utf-8")
    upload_summary(path)
    print(text)
    failed = not all(ok for ok, _ in checks)
    set_output("steps", "0" if failed else str(len(plan["steps"])))
    set_output("sha256", plan["sha256"])
    return 1 if failed else 0


if __name__ == "__main__":
    run_main(main)
