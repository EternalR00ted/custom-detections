"""Write the red-side handoff for one rule (CCCS's /export-analytic).

The handoff has the rule's KQL, each clause on its own line, the tables it
may use, and the variants found so far. The purple loop sends the same text
to the red-side model.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import purple, rules
from .common import ROOT, run_main


def variants_from(rule: dict) -> list[purple.Variant]:
    loop = (rule.get("metadata") or {}).get("purple_loop") or {}
    found = []
    for item in loop.get("variants") or []:
        found.append(purple.Variant(str(item.get("ref", "")), str(item.get("tier", "")), str(item.get("variant", "")),
                                    "", bool(item.get("visible")), item.get("first_draft"),
                                    bool(item.get("final_rule"))))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Write the red-side handoff for a rule.")
    parser.add_argument("rule_file")
    parser.add_argument("--out", default="", help="File to write. Prints to the screen if left out.")
    args = parser.parse_args()
    path = Path(args.rule_file)
    if not path.is_absolute():
        path = ROOT / path
    rule = rules.load(path)
    text = purple.handoff(rule, variants_from(rule))
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    run_main(main)
