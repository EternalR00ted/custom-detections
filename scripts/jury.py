"""The model jury: independent reviews of a rule by other model families.

Claude writes the rule and Claude Fable attacks it (the CCCS loop). Then a
Gemini model and an OpenAI model review the finished rule on their own: does
it match the source, is the KQL correct, how noisy will it be, what does it
miss. If either asks for changes, the blue side gets one revision with their
findings (it may reject findings that are wrong), the revision goes through
the same checks, and the jury votes again. The pull request shows every vote.
A person still makes the call.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import models as model_layer
from . import observability, purple
from .claude import Claude, Declined
from .common import md, settings

VERDICTS = ("approve", "revise", "reject")

SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "matches_source": {"type": "boolean"},
        "kql_issues": {"type": "array", "items": {"type": "string"}},
        "false_positive_risk": {"type": "string", "enum": ["low", "medium", "high"]},
        "false_positive_notes": {"type": "string"},
        "missed_variants": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
    },
}


@dataclass
class Vote:
    model: str
    verdict: str
    matches_source: bool | None = None
    kql_issues: list[str] = field(default_factory=list)
    false_positive_risk: str = ""
    false_positive_notes: str = ""
    missed_variants: list[str] = field(default_factory=list)
    summary: str = ""
    note: str = ""

    @property
    def answered(self) -> bool:
        return self.verdict in VERDICTS


def _strings(value) -> list[str]:
    return [str(item).strip() for item in value or [] if str(item).strip()][:8]


def vote_from(spec: str, data: dict) -> Vote:
    verdict = str(data.get("verdict", "")).lower()
    if verdict not in VERDICTS:
        raise Declined(f"{spec} gave no valid verdict")
    risk = str(data.get("false_positive_risk", "")).lower()
    return Vote(spec, verdict, bool(data.get("matches_source")), _strings(data.get("kql_issues")),
                risk if risk in ("low", "medium", "high") else "", str(data.get("false_positive_notes", "")).strip(),
                _strings(data.get("missed_variants")), str(data.get("summary", "")).strip())


def review_prompt(rule: dict, source_text: str) -> str:
    shown = {key: rule.get(key) for key in ("name", "description", "severity", "frequency", "tactics", "query",
                                            "entities")}
    source = purple.wrap_article(source_text[:30000]) if source_text else "<article>\n(No source text.)\n</article>"
    return f"The rule:\n```json\n{json.dumps(shown, indent=1)}\n```\n\nThe source it was written from:\n{source}"


def jurors() -> list[str]:
    return model_layer.specs(settings()["models"].get("jury"))


def review(models: model_layer.Models, rule: dict, source_text: str, specs: list[str] | None = None) -> list[Vote]:
    system = purple._prompt("jury", tables=purple.tables_text())
    prompt = review_prompt(rule, source_text)
    votes = []
    for spec in specs if specs is not None else jurors():
        if not models.available(spec):
            votes.append(Vote(spec, "not set up", note=_setup_hint(spec)))
            continue
        try:
            with observability.agent("jury"):
                votes.append(vote_from(spec, models.ask_json(spec, system, prompt, SCHEMA, max_tokens=8000)))
        except Declined as reason:
            votes.append(Vote(spec, "no answer", note=str(reason)))
    return votes


def _setup_hint(spec: str) -> str:
    return {"gemini": "GEMINI_API_KEY isn't set", "openai": "OPENAI_API_KEY isn't set"}.get(
        model_layer.family(spec), "ANTHROPIC_API_KEY isn't set")


def red_vote(result: purple.LoopResult) -> Vote:
    """The Claude red side's last assessment, counted as Anthropic's vote."""
    if not result.red_models:
        return Vote("claude", "no answer", note="no red-side review")
    gaps = [v for v in result.variants if v.visible and not v.caught_final]
    verdict = "approve" if not gaps else "revise"
    return Vote(f"claude:{result.red_models[-1]}", verdict, None, [],
                "", "", [f"{v.ref} ({v.tier}): {v.variant}" for v in gaps], result.summary,
                note="red side: visible variants the final rule misses")


def consensus(votes: list[Vote]) -> str:
    answered = [vote for vote in votes if vote.answered]
    if not answered:
        return "no jury"
    if any(vote.verdict == "reject" for vote in answered):
        return "reject"
    if all(vote.verdict == "approve" for vote in answered):
        return "approve"
    return "revise"


def needs_revision(votes: list[Vote]) -> bool:
    return any(vote.verdict in ("revise", "reject") and (vote.kql_issues or vote.missed_variants)
               for vote in votes if vote.answered)


def findings(votes: list[Vote]) -> str:
    lines = []
    for vote in votes:
        if not vote.answered or vote.verdict == "approve":
            continue
        who = model_layer.label(vote.model)
        lines += [f"- {who}: {issue}" for issue in vote.kql_issues]
        lines += [f"- {who}, missed variant: {variant}" for variant in vote.missed_variants]
        if vote.false_positive_risk == "high" and vote.false_positive_notes:
            lines.append(f"- {who}, false positives: {vote.false_positive_notes}")
    return "\n".join(lines)


def revise(claude: Claude, checker: purple.Checker, draft: purple.Draft, votes: list[Vote]) -> tuple[purple.Draft | None, str]:
    """One blue-side revision with the jury's findings. Returns the revised draft, or None and why not."""
    prompt = (f"Your current rule:\n```json\n{purple._submission(draft)}\n```\n\n"
              "Independent reviewers from other model families checked it and found:\n"
              f"{findings(votes)}\n\n"
              "Fix the findings that are real. Some may be wrong: if a reviewer names a column that doesn't exist "
              "or misreads the KQL, leave that part as it is. Keep the same id and name. "
              "Call submit_rule with the complete revised rule.")
    system = purple.blue_system()
    try:
        with observability.agent("blue"):
            answer = claude.ask(settings()["models"]["blue"], system, prompt, purple.blue_tools())
    except Declined as reason:
        return None, f"the blue side didn't revise ({reason})"
    if answer.tool != "submit_rule":
        return None, "the blue side didn't submit a revision"
    revised = purple.draft_from(answer.data)
    revised.evidence = draft.evidence
    revised.rule["id"], revised.rule["name"] = draft.rule["id"], draft.rule["name"]
    with observability.agent("blue"):
        fixed, found = purple.repair(claude, checker, system, prompt, revised, 1)
    if fixed is None:
        return None, "the revision failed checks (" + "; ".join(found[:3]) + ")"
    return fixed, ""


def table(votes: list[Vote]) -> str:
    lines = ["| Model | Verdict | Matches the source | False positive risk | What it found |", "|---|---|---|---|---|"]
    for vote in votes:
        found = vote.kql_issues + [f"Misses: {v}" for v in vote.missed_variants]
        detail = "; ".join(found) or vote.summary or vote.note or "-"
        source = {True: "yes", False: "NO", None: "-"}[vote.matches_source]
        verdict = vote.verdict.upper() if vote.verdict in ("revise", "reject") else vote.verdict
        lines.append(f"| {md(model_layer.label(vote.model))} | {verdict} | {source} | "
                     f"{md(vote.false_positive_risk or '-')} | {md(detail[:600])} |")
    return "\n".join(lines)
