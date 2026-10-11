"""Draft rules from threat intel and open one pull request per rule.

Run by pipelines/draft.yml every weekday, or by hand with one article URL.

1. Research: Nimble Search finds new reports on trusted domains, plus the
   allowlisted feeds and the analyst write-ups in inputs/. Nimble Extract
   gets each article's main content.
2. Triage: a Gemini model screens each article (Claude Haiku if Gemini isn't
   set up).
3. CCCS loop: Claude Opus drafts, code checks, Claude Fable attacks, Opus hardens.
4. Model jury: Gemini and an OpenAI model review the rule independently. If
   either asks for changes, Opus revises once and the jury votes again.
5. One pull request per rule. The AI can only add files under detections/ai/
   and sigma/ai/, and a person completes or abandons every pull request.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests
import yaml

from . import feeds, jury, observability, purple, rules
from . import models as model_layer
from .claude import Declined
from .common import ROOT, env, git, log_warning, md, run_main, settings, upload_summary

PIPELINE_AUTHOR = ["-c", "user.name=Detection pipeline", "-c", "user.email=pipeline@detections.invalid"]


class _Dumper(yaml.SafeDumper):
    pass


def _represent_str(dumper: yaml.SafeDumper, value: str):
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_Dumper.add_representer(str, _represent_str)


def dump_yaml(data) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=100)


@dataclass
class JuryRecord:
    rounds: list[list[jury.Vote]] = field(default_factory=list)
    revision_note: str = ""

    @property
    def final(self) -> list[jury.Vote]:
        return self.rounds[-1] if self.rounds else []

    @property
    def consensus(self) -> str:
        return jury.consensus(self.final)


def rule_document(result: purple.LoopResult, article: feeds.Article, record: JuryRecord) -> dict:
    cfg = settings()["models"]
    rule = dict(result.draft.rule)
    if not rule["query"].endswith("\n"):
        rule["query"] += "\n"
    if rule.get("hunt_query") and not rule["hunt_query"].endswith("\n"):
        rule["hunt_query"] += "\n"
    order = ["id", "name", "description", "severity", "frequency", "tactics", "query", "entities",
             "recommended_actions", "status", "version", "hunt_query", "lab_tests"]
    document = {key: rule[key] for key in order if key in rule and rule[key] not in (None, "", [])}
    document["metadata"] = {
        "author": f"AI drafter (blue side {cfg['blue']}, red side {', '.join(sorted(set(result.red_models))) or 'none'})",
        "drafted": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "sources": [article.url],
        "found_by": article.feed,
        "evidence": result.draft.evidence,
        "purple_loop": {
            "rounds": result.rounds,
            "summary": result.summary,
            "variants": [
                {"ref": v.ref, "tier": v.tier, "variant": v.variant, "visible": v.visible,
                 "first_draft": v.caught_first, "final_rule": v.caught_final}
                for v in result.variants
            ],
        },
        "jury": {
            "consensus": record.consensus,
            "rounds": len(record.rounds),
            "votes": [{"model": v.model, "verdict": v.verdict, "matches_source": v.matches_source,
                       "false_positive_risk": v.false_positive_risk} for v in record.final],
        },
    }
    return document


def pr_description(result: purple.LoopResult, article: feeds.Article, folder: str, record: JuryRecord) -> str:
    rule = result.draft.rule
    tests = {test["guid"]: test for test in rules.atomics()["tests"]}
    lines = [
        f"## {md(rule['name'])}",
        "",
        f"Source: {article.url}",
        f"Found by: {md(article.feed or 'an article URL a person picked')}",
        "",
        md(rule["description"]),
        "",
        "### Why this logic (quoted from the source)",
    ]
    lines += [f"- {md(item['point'])} Quote: \"{md(item['quote'])}\"" for item in result.draft.evidence]
    red = ", ".join(sorted(set(result.red_models))) or "none"
    lines += ["", f"### Purple loop ({result.rounds} red review(s), red side: {red})", "",
              purple.tier_table(result), ""]
    if result.summary:
        lines += [f"Red side's summary: {md(result.summary)}", ""]
    lines += [f"- {md(note)}" for note in result.notes]
    lines += ["", f"### Model jury: {record.consensus.upper() if record.consensus != 'approve' else 'approve'}", ""]
    if len(record.rounds) > 1:
        lines += ["First vote, before the revision:", "", jury.table(record.rounds[0]), "",
                  "Claude revised the rule with those findings. Final vote:", ""]
    elif record.revision_note:
        lines += [f"No revision: {md(record.revision_note)}", ""]
    lines += [jury.table(record.final) if record.final else "No jury ran."]
    lines += ["", "### Lab tests the Lab detonation check will run"]
    if rule.get("lab_tests"):
        lines += [f"- {md(tests[g]['name'])} ({tests[g]['tier']})" for g in rule["lab_tests"] if g in tests]
    else:
        lines.append("None fit. Test it by hand, or add a matching Atomic test to config/atomics.yaml in its "
                     "own pull request.")
    lines += [
        "",
        "### Before you approve",
        f"1. **Files**: only `detections/{folder}/{rule['id']}.yaml` and `sigma/{folder}/{rule['id']}.yml`.",
        ("2. **Rule checks** comment: static checks, compile, zero hits over 3 days of production data, and the "
         "jury's view of the current version."),
        "3. Open the source and check each quote supports its point.",
        ("4. Read the tier table and the jury. NO in the final column is a gap the rule still has, and a REVISE "
         "or REJECT vote says what another model family found."),
        ("5. Queue **Lab detonation** from the Checks list if the rule lists lab tests, read the fire plan, "
         "and approve the run."),
        "6. Approve and complete to ship it disabled for the shadow run, or abandon with a lesson.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Draft custom detections from threat intel.")
    parser.add_argument("--url", default="", help="Draft from this one article instead of researching")
    parser.add_argument("--seen", default="work/seen.json", help="File of articles already handled")
    parser.add_argument("--summary", default="work/draft-summary.md")
    parser.add_argument("--dry-run", action="store_true", help="Write drafts to work/drafts, no pull requests")
    args = parser.parse_args()

    from .auth import credential as get_credential
    from .claude import from_env as claude_from_env
    from .graph import Graph

    credential = get_credential()
    session = requests.Session()
    models = model_layer.Models(claude_from_env(), session)
    nimble = None
    if env("NIMBLE_API_KEY"):
        from .nimble import Nimble
        nimble = Nimble(env("NIMBLE_API_KEY"), session)
    ado = None
    if not args.dry_run:
        from .ado import AzureDevOps
        ado = AzureDevOps.from_env()
    seen = feeds.Seen(ROOT / args.seen)
    summary = run(args, models, Graph(credential), ado, session, seen, credential, nimble)
    path = ROOT / args.summary
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(summary, encoding="utf-8")
    upload_summary(path)
    print(summary)
    return 0


def gather(url: str, ado, session, nimble) -> list[feeds.Article]:
    if url:
        return [feeds.Article(feeds.normalize(url), "", feed="Article URL a person picked")]
    file_url = ado.file_url if ado else (lambda path: f"https://example.invalid/{path}")
    articles = feeds.analyst_inputs(file_url)
    if nimble is not None:
        articles += feeds.research_articles(nimble)
    articles += feeds.feed_articles(session)
    unique: dict[str, feeds.Article] = {}
    for article in articles:
        unique.setdefault(feeds.normalize(article.url), article)
    return list(unique.values())


def run(args, models: model_layer.Models, graph, ado, session, seen: feeds.Seen, credential, nimble=None) -> str:
    cfg = settings()
    url = (args.url or "").strip()
    if url.lower() in ("none", "$(articleurl)"):
        url = ""
    articles = gather(url, ado, session, nimble)
    drafted_before = feeds.urls_in_pull_requests(ado.list_prs()) if ado else set()
    checker = purple.Checker(graph, set(rules.all_rules()))
    shield = env("CONTENT_SAFETY_ENDPOINT")
    base = git("rev-parse", "HEAD").strip()
    build = env("BUILD_BUILDID", "local")
    outcomes: list[tuple[str, str, str]] = []
    drafted = triaged = 0
    limit = cfg["limits"]["articles_per_run"]
    triage_models = model_layer.specs(cfg["models"]["triage"])
    triage_system = purple._prompt("triage", tables=purple.tables_text())

    for article in articles:
        if drafted >= limit or triaged >= limit * 3:
            break
        if not url and (article.url in seen or feeds.normalize(article.url) in drafted_before):
            continue
        try:
            with observability.span("draft.article", article.url):
                if not article.text:
                    feeds.fetch_article(session, article, nimble)
                if shield and feeds.shield_attack(session, credential, shield, article.text):
                    outcomes.append((article.url, "SKIPPED", "Prompt Shields flagged hidden instructions"))
                    seen.add(article.url, "prompt shields")
                    continue
                triaged += 1
                with observability.agent("triage"):
                    verdict, who, _ = models.first_json(triage_models, triage_system,
                                                        purple.wrap_article(article.text),
                                                        purple.TRIAGE_TOOL["input_schema"], max_tokens=2000)
                if not verdict.get("relevant"):
                    outcomes.append((article.url, "not relevant",
                                     f"{model_layer.label(who)}: {verdict.get('reason', '')}"))
                    seen.add(article.url, "not relevant")
                    continue
                outcome, detail = draft_one(article, models, checker, ado, base, build, args.dry_run)
                outcomes.append((article.url, outcome, detail))
                seen.add(article.url, outcome)
                if outcome == "drafted":
                    drafted += 1
        except Declined as reason:
            outcomes.append((article.url, "declined", str(reason)))
            seen.add(article.url, "declined")
        except Exception as error:  # noqa: BLE001  one bad article shouldn't stop the run
            outcomes.append((article.url, "FAILED", f"{type(error).__name__}: {str(error)[:300]}"))
            log_warning(f"{article.url}: {error}")
            observability.capture(error)
        finally:
            if not args.dry_run:
                git("switch", "--quiet", "--detach", base, check=False)
    seen.save()

    sources = "Nimble research, feeds and analyst write-ups" if nimble else "feeds and analyst write-ups"
    lines = ["# Draft rules run", "", f"Sources: {sources}." if not url else f"Article: {url}", "",
             "| Article | Outcome | Detail |", "|---|---|---|"]
    lines += [f"| {md(u)} | {md(o)} | {md(d)} |" for u, o, d in outcomes] or ["| none | | |"]
    lines += ["", "## Model calls", "", models.usage.table()]
    if not outcomes:
        lines.insert(4, "No new articles.")
    return "\n".join(lines)


def run_jury(models: model_layer.Models, checker: purple.Checker, result: purple.LoopResult,
             article: feeds.Article) -> JuryRecord:
    record = JuryRecord()
    votes = [jury.red_vote(result)] + jury.review(models, result.draft.rule, article.text)
    record.rounds.append(votes)
    if not jury.needs_revision(votes[1:]):
        return record
    revised, note = jury.revise(models.claude, checker, result.draft, votes[1:])
    if revised is None:
        record.revision_note = note
        result.notes.append(f"Jury revision: {note}; kept the rule the purple loop produced.")
        return record
    result.draft = revised
    stale = jury.red_vote(result)
    stale.note = "red side's view of the version before the jury revision"
    record.rounds.append([stale] + jury.review(models, revised.rule, article.text))
    return record


def draft_one(article: feeds.Article, models: model_layer.Models, checker: purple.Checker, ado, base: str,
              build: str, dry_run: bool) -> tuple[str, str]:
    cfg = settings()
    claude = models.claude
    system = purple.blue_system()
    prompt = "Draft a custom detection rule from this source.\n\n" + purple.wrap_article(article.text)
    with observability.agent("blue"):
        answer = claude.ask(cfg["models"]["blue"], system, prompt, purple.blue_tools())
    if answer.tool == "no_rule":
        return "no rule", str(answer.data.get("reason", ""))
    draft = purple.draft_from(answer.data)
    draft.evidence, dropped = purple.verify_evidence(draft.evidence, article.text)
    if not draft.evidence:
        return "DROPPED", "no evidence quote matched the article word for word"
    with observability.agent("blue"):
        fixed, found = purple.repair(claude, checker, system, prompt, draft, cfg["purple_loop"]["max_repairs"])
    if fixed is None:
        return "FAILED checks", "; ".join(found[:5])
    result = purple.purple_loop(claude, checker, fixed)
    if dropped:
        result.notes.append(f"{len(dropped)} evidence point(s) dropped because the quote isn't in the article.")
    record = run_jury(models, checker, result, article)
    rule = result.draft.rule
    checker.taken_ids.add(rule["id"])
    folder = "ai"
    rule_path = ROOT / "detections" / folder / f"{rule['id']}.yaml"
    sigma_path = ROOT / "sigma" / folder / f"{rule['id']}.yml"
    document = dump_yaml(rule_document(result, article, record))
    sigma = purple.sigma_with_name(result.draft.sigma, rule["id"])
    description = pr_description(result, article, folder, record)
    labels = ["ai-draft"] + (["jury-concerns"] if record.consensus in ("revise", "reject") else [])
    if dry_run:
        out = ROOT / "work" / "drafts"
        out.mkdir(parents=True, exist_ok=True)
        (out / rule_path.name).write_text(document, encoding="utf-8")
        (out / sigma_path.name).write_text(sigma, encoding="utf-8")
        (out / f"{rule['id']}.pr.md").write_text(description, encoding="utf-8")
        return "drafted", f"dry run: work/drafts/{rule_path.name}, jury {record.consensus}, labels {labels}"
    branch = f"ai/{rule['id']}-{build}"
    git("switch", "--quiet", "-c", branch, base)
    try:
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        sigma_path.parent.mkdir(parents=True, exist_ok=True)
        rule_path.write_text(document, encoding="utf-8")
        sigma_path.write_text(sigma, encoding="utf-8")
        git("add", str(rule_path.relative_to(ROOT)), str(sigma_path.relative_to(ROOT)))
        git(*PIPELINE_AUTHOR, "commit", "--quiet", "-m", f"AI draft: {rule['name']}")
        git("push", "--quiet", "origin", f"HEAD:refs/heads/{branch}")
        pr = ado.create_pr(branch, "main", f"AI draft: {rule['name']}", description, labels)
    finally:
        git("switch", "--quiet", "--detach", base, check=False)
        git("branch", "--quiet", "-D", branch, check=False)
    return "drafted", f"{ado.web_url(pr['pullRequestId'])} (jury {record.consensus})"


if __name__ == "__main__":
    run_main(main)
