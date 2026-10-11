"""Deploy rule files to Microsoft Defender XDR as custom detection rules.

Run by pipelines/deploy.yml after a pull request is completed into main, with
the files that changed. Rules in testing and retired rules deploy turned off;
rules in production deploy turned on. The rule's id is the custom detection's
id in Defender, so a redeploy updates the same rule.
"""

from __future__ import annotations

import argparse
import json

from . import rules
from .common import ROOT, Fail, env, git, read_list, run_main


def deploy(paths: list[str], graph, company: str, dry_run: bool = False) -> int:
    failures = 0
    for item in paths:
        path = ROOT / item
        rule = rules.load(path)
        found = rules.problems(rule, path)
        if found:
            print(f"SKIP {item}: fails static checks: {'; '.join(found)}")
            failures += 1
            continue
        body = rules.to_graph(rule, company)
        if dry_run:
            print(f"DRY RUN {item}: '{body['displayName']}' status={body['status']}")
            print(json.dumps(body, indent=2))
            continue
        try:
            if graph.get_rule(rule["id"]) is None:
                graph.create_rule(body)
                print(f"CREATED {rule['id']}: '{body['displayName']}' ({body['status']})")
            else:
                graph.update_rule(rule["id"], body)
                print(f"UPDATED {rule['id']}: '{body['displayName']}' ({body['status']})")
        except Fail as error:
            print(f"FAILED {item}: {error}")
            failures += 1
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy rule files as Defender XDR custom detections.")
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--files-from", help="File with one rule path per line")
    parser.add_argument("--all", action="store_true", help="Deploy every rule file")
    parser.add_argument("--changed-since", default="", help="Deploy rule files changed since this commit")
    parser.add_argument("--dry-run", action="store_true", help="Print the request bodies, send nothing")
    args = parser.parse_args()

    paths = list(args.paths) + read_list(args.files_from)
    if args.changed_since:
        if git("rev-parse", "--verify", "--quiet", f"{args.changed_since}^{{commit}}", check=False).strip():
            changed = git("diff", "--name-only", "--diff-filter=AM", args.changed_since, "HEAD", "--", "detections")
            paths += [line for line in changed.splitlines() if line.endswith((".yaml", ".yml"))]
        else:
            print(f"{args.changed_since} doesn't exist (first commit), so every rule is deployed.")
            args.all = True
    if args.all:
        paths = [rules.relative(p) for p in rules.rule_files()]
    paths = [p for p in dict.fromkeys(paths) if p.startswith("detections/")]
    if not paths:
        print("No rule files to deploy.")
        return 0
    company = env("COMPANY_NAME")
    graph = None
    if not args.dry_run:
        from .auth import credential
        from .graph import Graph
        graph = Graph(credential())
    return deploy(paths, graph, company, args.dry_run)


if __name__ == "__main__":
    run_main(main)
