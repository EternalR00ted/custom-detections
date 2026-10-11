"""Change a rule's status: testing to production (turns it on), or to retired (turns it off).

Bumps the version: minor for a promotion, patch for a retirement.
Edits the file in place so the change goes through a pull request.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from . import rules
from .common import ROOT, Fail, run_main


def bump(version: str, part: str) -> str:
    major, minor, patch = (int(x) for x in str(version).split("."))
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def set_status(path: Path, status: str) -> str:
    """Rewrite only the status and version lines, so the rest of the file stays as the author wrote it."""
    text = path.read_text(encoding="utf-8")
    rule = rules.load(path)
    if rule.get("status") == status:
        raise Fail(f"{rules.relative(path)} is already {status}.")
    version = bump(rule["version"], "minor" if status == "production" else "patch")
    text, count_status = re.subn(r"(?m)^status:\s*\S+\s*$", f"status: {status}", text, count=1)
    text, count_version = re.subn(r"(?m)^version:\s*\S+\s*$", f"version: {version}", text, count=1)
    if count_status != 1 or count_version != 1:
        raise Fail(f"Couldn't find top-level status and version lines in {rules.relative(path)}.")
    path.write_text(text, encoding="utf-8")
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description="Promote a rule to production, or retire it.")
    parser.add_argument("rule_file")
    parser.add_argument("--retire", action="store_true")
    args = parser.parse_args()
    path = Path(args.rule_file)
    if not path.is_absolute():
        path = ROOT / path
    status = "retired" if args.retire else "production"
    version = set_status(path, status)
    print(f"{rules.relative(path)}: status {status}, version {version}")
    return 0


if __name__ == "__main__":
    run_main(main)
