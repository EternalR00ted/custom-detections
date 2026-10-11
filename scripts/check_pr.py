"""Rule checks: the required check on every pull request into main.

1. Guard rails on which files changed.
2. Static checks on each changed rule and its Sigma version.
3. Advanced hunting compiles each rule and returns its columns (no rows).
4. The production check (CCCS's): the rule over the last 3 days of real data,
   lab VM left out, must return zero hits. Only the count is reported. If a
   person checked every hit and they're all true positives, they add the label
   noise-reviewed-<first 7 characters of the commit>.
5. Optional red-side review of each changed rule's logic, by tier.

Posts one comment on the pull request and fails if anything failed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

from . import jury, observability, purple, rules
from . import models as model_layer
from .claude import Declined
from .common import ROOT, env, git, lab_vm, md, run_main, settings, upload_summary

RULE_SUFFIXES = (".yaml", ".yml")


@dataclass
class Change:
    status: str  # A, M, D or R
    path: str
    new_path: str = ""


@dataclass
class RuleResult:
    path: str
    rule_id: str = ""
    static: list[str] = field(default_factory=list)
    compiled: str = "not run"
    production: str = "not run"
    failed: bool = False
    noisy: bool = False


def changes_between(base: str, head: str) -> list[Change]:
    found = []
    for line in git("diff", "--name-status", "--find-renames", base, head).splitlines():
        parts = line.split("\t")
        status = parts[0][:1]
        if status == "R":
            found.append(Change("R", parts[1], parts[2]))
        elif len(parts) >= 2:
            found.append(Change(status, parts[1]))
    return found


def is_rule(path: str) -> bool:
    return path.startswith("detections/") and path.endswith(RULE_SUFFIXES)


def guard_rails(changes: list[Change], source_branch: str, is_fork: bool) -> list[str]:
    branch = source_branch.removeprefix("refs/heads/")
    found = []
    if is_fork:
        found.append("Pull requests from forks can't run the hunting checks. Push the branch to this repo instead.")
    for change in changes:
        paths = [change.path] + ([change.new_path] if change.new_path else [])
        if change.status in ("D", "R") and any(is_rule(p) for p in paths):
            found.append(f"{change.path}: deleting or renaming a rule file leaves the old rule running in "
                         "Defender. Set its status to retired instead.")
        if branch.startswith("ai/"):
            for path in paths:
                if not path.startswith(("detections/ai/", "sigma/ai/")):
                    found.append(f"{path}: AI branches may only add files under detections/ai/ and sigma/ai/.")
            if change.status != "A":
                found.append(f"{change.path}: AI branches may only add new files.")
        if branch.startswith("promote/") and not (change.status == "M" and is_rule(change.path)):
            found.append(f"{change.path}: promotion branches may only edit existing rule files.")
    return found


def changed_rules(changes: list[Change]) -> list[str]:
    paths = []
    for change in changes:
        path = change.new_path or change.path
        if change.status in ("A", "M") and is_rule(path):
            paths.append(path)
        if change.status in ("A", "M") and path.startswith("sigma/") and path.endswith(RULE_SUFFIXES):
            folder, name = Path(path).parent.name, Path(path).stem
            for suffix in RULE_SUFFIXES:
                candidate = f"detections/{folder}/{name}{suffix}"
                if (ROOT / candidate).exists() and candidate not in paths:
                    paths.append(candidate)
    return sorted(set(paths))


def check_rules(paths: list[str], graph, noise_label: str, labels: list[str]) -> list[RuleResult]:
    cfg = settings()
    lab = lab_vm()
    ids = {}
    for path in rules.rule_files():
        rule_id = rules.load(path).get("id")
        ids.setdefault(rule_id, []).append(rules.relative(path))
    results = []
    for path in paths:
        result = RuleResult(path)
        results.append(result)
        rule = rules.load(ROOT / path)
        result.rule_id = str(rule.get("id", ""))
        result.static = rules.problems(rule, ROOT / path)
        if isinstance(rule.get("id"), str):
            result.static += rules.sigma_problems(rules.sigma_path(ROOT / path, rule["id"]), rule["id"])
            if len(ids.get(rule["id"], [])) > 1:
                result.static.append(f"id {rule['id']} is used by {', '.join(ids[rule['id']])}")
        if result.static:
            result.failed = True
            continue
        if graph is None:
            continue
        try:
            columns = graph.columns(rule["query"])
            schema = rules.schema_problems(rule, columns)
            if schema:
                result.compiled = "NO: " + "; ".join(schema)
                result.failed = True
                continue
            result.compiled = "yes" if columns else "yes (no column list came back, columns not verified)"
        except Exception as error:  # noqa: BLE001  Kusto errors come back as Graph 400s; report, don't crash
            result.compiled = f"NO: {error}"
            result.failed = True
            continue
        if rule["status"] == "retired":
            result.production = "skipped (retired)"
            continue
        days = cfg["checks"]["production_days"]
        try:
            hits = graph.count(rules.production_query(rule, lab), f"P{days}D")
        except Exception as error:  # noqa: BLE001  report it on the pull request and fail the check
            observability.capture(error)
            result.production = f"ERROR: {error}"
            result.failed = True
            continue
        if hits <= cfg["checks"]["max_hits"]:
            result.production = f"{hits} hits: PASS"
        elif noise_label in labels:
            result.production = f"{hits} hits: reviewed (label {noise_label})"
        else:
            result.production = (f"{hits} hits: NOISY. Run the query in advanced hunting and check every hit. "
                                 f"If they're all true positives, add the label {noise_label} and queue "
                                 "Rule checks again.")
            result.failed = True
            result.noisy = True
    return results


def red_review(claude, path: str) -> str:
    rule = rules.load(ROOT / path)
    models = settings()["models"]
    try:
        with observability.agent("red"):
            answer, failures = claude.ask_with_fallback(
                [models["red"], models["red_fallback"]], purple._prompt("red", tables=purple.tables_text()),
                purple.handoff(rule, []), [purple.RED_TOOL])
    except Declined as reason:
        return f"### Red-side review: {md(rule.get('id'))}\n\nNo review: {md(reason)}"
    result = purple.LoopResult(purple.Draft(rule, ""), [], [answer.model], 1, [])
    purple._merge(answer.data.get("variants") or [], result.variants, first_round=False)
    lines = [f"### Red-side review: {md(rule.get('id'))} ({answer.model})", "",
             purple.tier_table(result, single=True)]
    if answer.data.get("summary"):
        lines += ["", md(answer.data["summary"])]
    lines += [f"- {md(f)}; {answer.model} answered instead." for f in failures]
    return "\n".join(lines)


def jury_review(models, path: str) -> str:
    """Gemini and OpenAI reviews of one rule. The source isn't fetched here, so they see the drafter's quotes."""
    rule = rules.load(ROOT / path)
    quotes = [item.get("quote", "") for item in (rule.get("metadata") or {}).get("evidence") or []]
    source = ("The source isn't fetched during a pull request check. These are the quotes the drafter took from "
              "it:\n" + "\n".join(f"- {q}" for q in quotes)) if quotes else ""
    votes = jury.review(models, rule, source)
    return "\n".join([f"### Model jury: {md(rule.get('id'))}, {jury.consensus(votes)}", "", jury.table(votes)])


def report(commit: str, guard: list[str], results: list[RuleResult], reviews: list[str], hunted: bool) -> str:
    lines = ["### Rule checks", "", f"Commit `{commit[:7] or 'unknown'}`", ""]
    if guard:
        lines.append("**Guard rails: FAIL**")
        lines += [f"- {md(problem)}" for problem in guard]
    else:
        lines.append("**Guard rails: PASS**")
    lines.append("")
    if not results:
        lines.append("No rule files changed.")
    else:
        days = settings()["checks"]["production_days"]
        lines += [f"| Rule | Static and Sigma | Compiles | Production, last {days} days, lab VM left out |",
                  "|---|---|---|---|"]
        for result in results:
            static = "PASS" if not result.static else "FAIL: " + "; ".join(result.static)
            lines.append(f"| {md(result.rule_id or result.path)} | {md(static)} | {md(result.compiled)} | "
                         f"{md(result.production)} |")
        if not hunted:
            lines += ["", "Hunting checks didn't run (no Azure sign-in in this run)."]
    if reviews:
        lines += [""] + reviews
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Checks for a pull request into main.")
    parser.add_argument("--base", default="HEAD^1", help="Target branch commit (the merge commit's first parent)")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--report", default="work/rule-checks.md")
    parser.add_argument("--no-hunting", action="store_true", help="Static checks only")
    parser.add_argument("--red-review", action="store_true", help="Claude red-side review of each changed rule")
    parser.add_argument("--jury", action="store_true", help="Gemini and OpenAI reviews of each changed rule")
    parser.add_argument("--post", action="store_true", help="Post the report on the pull request")
    args = parser.parse_args()

    pr_id = env("SYSTEM_PULLREQUEST_PULLREQUESTID")
    source = env("SYSTEM_PULLREQUEST_SOURCEBRANCH")
    commit = env("SYSTEM_PULLREQUEST_SOURCECOMMITID", git("rev-parse", args.head).strip())
    is_fork = env("SYSTEM_PULLREQUEST_ISFORK").lower() == "true"
    changes = changes_between(args.base, args.head)
    guard = guard_rails(changes, source, is_fork)
    paths = changed_rules(changes)

    ado = graph = claude = None
    labels: list[str] = []
    if pr_id and (args.post or not args.no_hunting):
        from .ado import AzureDevOps
        ado = AzureDevOps.from_env()
        labels = ado.labels(pr_id) if pr_id else []
    hunting = not args.no_hunting and not is_fork and bool(paths)
    models = None
    if hunting or args.red_review or args.jury:
        from .auth import credential as get_credential
        credential = get_credential()
        if hunting:
            from .graph import Graph
            graph = Graph(credential)
        if (args.red_review or args.jury) and paths:
            from .claude import from_env as claude_from_env
            claude = claude_from_env()
            models = model_layer.Models(claude)

    results = check_rules(paths, graph, f"noise-reviewed-{commit[:7]}", labels)
    reviews = []
    branch = source.removeprefix("refs/heads/")
    if claude and not branch.startswith("promote/"):
        for result in results:
            if result.failed:
                continue
            if args.red_review:
                reviews.append(red_review(claude, result.path))
            if args.jury:
                reviews.append(jury_review(models, result.path))
        reviews.append("Model calls:\n\n" + models.usage.table())
    text = report(commit, guard, results, reviews, graph is not None)
    path = ROOT / args.report
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    upload_summary(path)
    print(text)
    if args.post and pr_id:
        ado.comment(pr_id, text)
    return 1 if guard or any(r.failed for r in results) else 0


if __name__ == "__main__":
    run_main(main)
