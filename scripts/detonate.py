"""Run an approved fire plan on the lab VM through Azure Run Command.

Starts the VM, runs a staging check (the machine that answers is the lab VM
and its Defender sensor service is running), runs each test with a gap
between them so each one has its own time window, records when each ran, and
always deallocates the VM at the end.

Uses the Azure CLI that the AzureCLI@2 step signed in with the detonate
service connection, whose approval check is what held this run for you.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from .common import ROOT, Fail, log_warning, run_main, settings

LAB_SCRIPTS = ROOT / "scripts" / "lab"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def az(*args: str) -> str:
    result = subprocess.run(["az", *args, "--only-show-errors"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise Fail(f"az {args[0]} {args[1]} failed: {result.stderr.strip()[:500]}")
    return result.stdout


def run_command(group: str, vm: str, script: Path, parameters: list[str] | None = None) -> str:
    args = ["vm", "run-command", "invoke", "--resource-group", group, "--name", vm,
            "--command-id", "RunPowerShellScript", "--scripts", f"@{script}", "--output", "json"]
    if parameters:
        args += ["--parameters", *parameters]
    data = json.loads(az(*args) or "{}")
    stdout = [item.get("message", "") for item in data.get("value", []) if "StdOut" in item.get("code", "")]
    return "\n".join(stdout)


def field(output: str, name: str) -> str:
    for line in output.splitlines():
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip()
    return ""


def staged(group: str, vm: str) -> dict:
    """The machine answering Run Command must be the lab VM, with the Defender sensor running."""
    last = {}
    for attempt in range(4):
        output = run_command(group, vm, LAB_SCRIPTS / "staging.ps1")
        last = {"hostname": field(output, "HOSTNAME"), "sense": field(output, "SENSE")}
        if last["hostname"].lower() == vm.lower() and last["sense"] == "Running":
            return last
        time.sleep(30 * (attempt + 1))
    raise Fail(f"Staging check failed: hostname {last.get('hostname')!r}, Defender sensor service "
               f"{last.get('sense')!r}. Expected {vm} with the Sense service Running.")


def detonate(plan: dict, group: str, vm: str, out: Path) -> int:
    if vm.lower() != plan["vm"].lower():
        raise Fail(f"The plan targets {plan['vm']}, not {vm}.")
    lab = settings()["lab"]
    record = {"vm": vm, "plan_sha256": plan["sha256"], "started": now(), "staging": {}, "runs": []}
    failed = False
    try:
        print(f"Starting {vm}")
        az("vm", "start", "--resource-group", group, "--name", vm)
        record["staging"] = staged(group, vm)
        print(f"Staging check passed: {record['staging']}")
        for number, step in enumerate(plan["steps"], 1):
            if number > 1:
                time.sleep(lab["gap_seconds"])
            run = {k: step[k] for k in ("guid", "name", "tier", "rules")}
            run["started"] = now()
            try:
                output = run_command(group, vm, LAB_SCRIPTS / "run_test.ps1", [
                    f"Executor={step['executor']}",
                    f"CommandHex={step['command'].encode('utf-8').hex()}",
                    f"CleanupHex={step['cleanup'].encode('utf-8').hex()}",
                    f"TimeoutSeconds={lab['test_timeout_seconds']}",
                ])
                code = field(output, "EXITCODE")
                run["exit_code"] = int(code) if code.lstrip("-").isdigit() else None
                run["ran"] = run["exit_code"] is not None
                run["output_tail"] = output[-1500:]
            except Fail as error:
                run["ran"] = False
                run["error"] = str(error)
                failed = True
            run["finished"] = now()
            record["runs"].append(run)
            print(f"{number}. {step['name']}: exit code {run.get('exit_code')}")
    finally:
        record["finished"] = now()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, indent=2), encoding="utf-8")
        try:
            az("vm", "deallocate", "--resource-group", group, "--name", vm, "--no-wait")
            print(f"Deallocating {vm}")
        except Fail as error:
            log_warning(f"Couldn't deallocate {vm}: {error}. The nightly auto-shutdown is the backstop.")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an approved fire plan on the lab VM.")
    parser.add_argument("--plan", default="work/fire-plan.json")
    parser.add_argument("--out", default="work/detonations.json")
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--vm", required=True)
    args = parser.parse_args()
    plan = json.loads((ROOT / args.plan).read_text(encoding="utf-8"))
    if not plan.get("steps"):
        print("The plan has no steps.")
        return 0
    return detonate(plan, args.resource_group, args.vm, ROOT / args.out)


if __name__ == "__main__":
    run_main(main)
