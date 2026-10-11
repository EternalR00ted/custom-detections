"""The CCCS-style loop for one article: blue drafts, code checks, red attacks, blue hardens.

1. The blue side (Opus) drafts a rule, a hunt query, a Sigma version and quoted evidence.
2. Code checks the quotes against the article, runs the static checks, and has
   advanced hunting compile the query. Failures go back to the blue side for repair.
3. The red side (Fable 5.1, Opus if Fable declines) gets a handoff with the
   rule's clauses and lists variants by tier: baseline, cosmetic, structural,
   behavioral. It says which ones the tables can see and which the rule catches.
4. The blue side hardens the rule for every visible gap, code checks it again,
   and the red side re-assesses. Up to purple_loop.max_rounds red reviews.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

import yaml

from . import observability, rules
from .claude import Claude, Declined
from .common import PROMPTS_DIR, ROOT, md, settings

TIERS = ["baseline", "cosmetic", "structural", "behavioral"]


# Tools the models answer with

def _mapping_items(fields: set[str]) -> dict:
    return {"type": "array", "items": {"type": "object", "properties": {f: {"type": "string"} for f in sorted(fields)}}}


def blue_tools() -> list[dict]:
    cfg = settings()
    guids = [test["guid"] for test in rules.atomics()["tests"]]
    lab_item = {"type": "string", "enum": guids} if guids else {"type": "string"}
    submit = {
        "name": "submit_rule",
        "description": "Submit the complete detection rule.",
        "input_schema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "The title in lowercase words joined by hyphens"},
                "name": {"type": "string", "description": "MDE - <plain English title>"},
                "description": {"type": "string"},
                "severity": {"type": "string", "enum": cfg["severities"]},
                "frequency": {"type": "string", "enum": cfg["frequencies"]},
                "tactics": {"type": "array", "items": {"type": "object", "properties": {
                    "tactic": {"type": "string", "enum": cfg["tactics"]},
                    "techniques": {"type": "array", "items": {"type": "string"}}},
                    "required": ["tactic", "techniques"]}},
                "query": {"type": "string", "description": "The KQL rule"},
                "hunt_query": {"type": "string", "description": "Broader KQL for analysts to run by hand"},
                "entities": {"type": "object", "properties": {
                    kind: _mapping_items(fields) for kind, fields in rules.ENTITY_FIELDS.items()}},
                "recommended_actions": {"type": "string"},
                "lab_tests": {"type": "array", "items": lab_item},
                "sigma": {"type": "string", "description": "The Sigma rule as YAML"},
                "evidence": {"type": "array", "items": {"type": "object", "properties": {
                    "point": {"type": "string"},
                    "quote": {"type": "string", "description": "Copied word for word from the article"}},
                    "required": ["point", "quote"]}},
            },
            "required": ["id", "name", "description", "severity", "frequency", "tactics", "query", "hunt_query",
                         "entities", "recommended_actions", "lab_tests", "sigma", "evidence"],
        },
    }
    no_rule = {
        "name": "no_rule",
        "description": "Use when the article doesn't describe endpoint behavior the allowed tables record.",
        "input_schema": {"type": "object", "properties": {"reason": {"type": "string"}}, "required": ["reason"]},
    }
    return [submit, no_rule]


TRIAGE_TOOL = {
    "name": "triage",
    "description": "Report whether the article is worth drafting a rule from.",
    "input_schema": {"type": "object", "properties": {
        "relevant": {"type": "boolean"},
        "reason": {"type": "string"},
        "behaviors": {"type": "array", "items": {"type": "string"}}},
        "required": ["relevant", "reason"]},
}

RED_TOOL = {
    "name": "report_variants",
    "description": "Report the variants of the technique and whether the rule catches each one.",
    "input_schema": {"type": "object", "properties": {
        "variants": {"type": "array", "items": {"type": "object", "properties": {
            "ref": {"type": "string", "description": "The known variant's ref, like V1. Empty for a new variant."},
            "tier": {"type": "string", "enum": TIERS},
            "variant": {"type": "string", "description": "What the attacker does differently, in words"},
            "evidence": {"type": "string", "description": "The column and value that would show it"},
            "visible": {"type": "boolean"},
            "caught": {"type": "boolean"}},
            "required": ["tier", "variant", "visible", "caught"]}},
        "summary": {"type": "string"}},
        "required": ["variants", "summary"]},
}


# Prompts

def _prompt(name: str, **values: str) -> str:
    text = (PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{" + key + "}", value)
    return text


def tables_text() -> str:
    return ", ".join(settings()["tables"])


def atomics_text() -> str:
    lines = ["Allowed lab tests (GUID, tier, what it does):"]
    for test in rules.atomics()["tests"]:
        lines.append(f"- {test['guid']} ({test['tier']}): {test['name']}. {test.get('what_it_does', '')}".rstrip())
    return "\n".join(lines)


def lessons_text(limit: int = 40) -> str:
    path = ROOT / "feedback" / "lessons.md"
    if not path.exists():
        return "(none yet)"
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("- ")]
    return "\n".join(lines[-limit:]) or "(none yet)"


def wrap_article(text: str) -> str:
    safe = re.sub(r"</?\s*article\b[^>]*>", "[article tag removed]", text, flags=re.IGNORECASE)
    return f"<article>\n{safe}\n</article>"


def blue_system() -> str:
    return _prompt("blue", tables=tables_text(), atomics=atomics_text(), lessons=lessons_text())


# Evidence

def _norm(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    text = text.replace("–", "-").replace("—", "-")
    return re.sub(r"\s+", " ", text).strip().casefold()


def verify_evidence(evidence: list[dict], article_text: str) -> tuple[list[dict], list[dict]]:
    haystack = _norm(article_text)
    kept, dropped = [], []
    for item in evidence or []:
        quote = str(item.get("quote", ""))
        if len(_norm(quote)) >= 12 and _norm(quote) in haystack:
            kept.append({"point": str(item.get("point", "")).strip(), "quote": quote.strip()})
        else:
            dropped.append(item)
    return kept, dropped


# Drafts

@dataclass
class Draft:
    rule: dict[str, Any]
    sigma: str
    evidence: list[dict] = field(default_factory=list)


def draft_from(data: dict[str, Any]) -> Draft:
    rule = {key: data.get(key) for key in ("id", "name", "description", "severity", "frequency", "tactics",
                                            "query", "entities", "recommended_actions")}
    rule["status"] = "testing"
    rule["version"] = "1.0.0"
    if data.get("hunt_query"):
        rule["hunt_query"] = data["hunt_query"]
    rule["lab_tests"] = [str(t) for t in data.get("lab_tests") or []]
    entities = rule.get("entities") or {}
    rule["entities"] = {kind: maps for kind, maps in entities.items() if maps}
    return Draft(rule, str(data.get("sigma") or ""), list(data.get("evidence") or []))


def sigma_with_name(sigma: str, rule_id: str) -> str:
    try:
        data = yaml.safe_load(sigma)
    except yaml.YAMLError:
        return sigma
    if not isinstance(data, dict):
        return sigma
    data["name"] = rule_id
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=1000)


class Checker:
    """Static checks plus an advanced hunting compile, shared by drafting and hardening."""

    def __init__(self, graph, taken_ids: set[str]):
        self.graph = graph
        self.taken_ids = taken_ids

    def problems(self, draft: Draft) -> list[str]:
        found = rules.problems(draft.rule)
        if draft.rule.get("id") in self.taken_ids:
            found.append(f"id {draft.rule['id']} is already used by another rule; pick a different id")
        found += rules.sigma_text_problems(draft.sigma, str(draft.rule.get("id")))
        if found or self.graph is None:
            return found
        try:
            columns = self.graph.columns(draft.rule["query"])
        except Exception as error:  # noqa: BLE001  a compile error comes back as a Graph 400 with Kusto's message
            return [f"advanced hunting couldn't run the query: {error}"]
        if not columns:
            return []
        return rules.schema_problems(draft.rule, columns)


def _submission(draft: Draft) -> str:
    data = dict(draft.rule)
    data["sigma"] = draft.sigma
    data["evidence"] = draft.evidence
    return json.dumps(data, indent=1)


def repair(claude: Claude, checker: Checker, system: str, base_prompt: str, draft: Draft,
           max_repairs: int) -> tuple[Draft | None, list[str]]:
    found = checker.problems(draft)
    tries = 0
    while found and tries < max_repairs:
        tries += 1
        prompt = (f"{base_prompt}\n\nYour last submission:\n```json\n{_submission(draft)}\n```\n\n"
                  "It failed these checks:\n" + "\n".join(f"- {p}" for p in found) +
                  "\n\nFix every problem and call submit_rule again with the complete rule.")
        answer = claude.ask(settings()["models"]["blue"], system, prompt, blue_tools())
        if answer.tool != "submit_rule":
            return None, found
        evidence = draft.evidence
        draft = draft_from(answer.data)
        draft.evidence = evidence
        found = checker.problems(draft)
    return (None, found) if found else (draft, [])


# The red side

@dataclass
class Variant:
    ref: str
    tier: str
    variant: str
    evidence: str
    visible: bool
    caught_first: bool | None
    caught_final: bool


def handoff(rule: dict, variants: list[Variant]) -> str:
    """The red-side handoff file (CCCS's /export-analytic)."""
    clauses = [line.strip() for line in rules.strip_query(rule["query"]).splitlines() if line.strip()]
    lines = [
        f"# Red-side handoff: {rule['name']}",
        "",
        f"Rule id: {rule['id']}",
        f"Description: {rule['description']}",
        f"Tactics: {', '.join(t['tactic'] + ' ' + ' '.join(t.get('techniques') or []) for t in rule['tactics'])}",
        f"Tables the rule may query: {tables_text()}",
        "",
        "## The rule's KQL",
        "```kusto",
        rules.strip_query(rule["query"]),
        "```",
        "",
        "## Clauses, one per line",
    ]
    lines += [f"{n}. `{clause}`" for n, clause in enumerate(clauses, 1)]
    lines += ["", "## Variants found in earlier rounds"]
    if variants:
        lines += [f"- {v.ref} ({v.tier}): {v.variant}" for v in variants]
    else:
        lines.append("None yet.")
    return "\n".join(lines)


@dataclass
class LoopResult:
    draft: Draft
    variants: list[Variant]
    red_models: list[str]
    rounds: int
    notes: list[str]
    summary: str = ""


def _merge(report: list[dict], variants: list[Variant], first_round: bool) -> None:
    by_ref = {v.ref: v for v in variants}
    for item in report[:12]:
        tier = item.get("tier") if item.get("tier") in TIERS else "behavioral"
        caught = bool(item.get("caught"))
        known = by_ref.get(str(item.get("ref") or "").strip().upper())
        if known:
            known.caught_final = caught
            known.visible = bool(item.get("visible"))
            continue
        ref = f"V{len(variants) + 1}"
        variant = Variant(ref, tier, str(item.get("variant", "")).strip(), str(item.get("evidence", "")).strip(),
                          bool(item.get("visible")), caught if first_round else None, caught)
        variants.append(variant)
        by_ref[ref] = variant


def purple_loop(claude: Claude, checker: Checker, draft: Draft) -> LoopResult:
    cfg = settings()
    models = cfg["models"]
    red_system = _prompt("red", tables=tables_text())
    system = blue_system()
    variants: list[Variant] = []
    red_models: list[str] = []
    notes: list[str] = []
    summary = ""
    rounds = 0
    for round_number in range(1, cfg["purple_loop"]["max_rounds"] + 1):
        observability.handoff("blue", "red")
        try:
            with observability.agent("red"):
                answer, failures = claude.ask_with_fallback(
                    [models["red"], models["red_fallback"]], red_system, handoff(draft.rule, variants), [RED_TOOL])
        except Declined as reason:
            notes.append(f"Round {round_number}: no red-side review ({reason}).")
            break
        rounds = round_number
        red_models.append(answer.model)
        for failure in failures:
            notes.append(f"Round {round_number}: {failure}; {answer.model} answered instead.")
        _merge(answer.data.get("variants") or [], variants, first_round=round_number == 1)
        summary = str(answer.data.get("summary", "")).strip()
        gaps = [v for v in variants if v.visible and not v.caught_final]
        if not gaps or round_number == cfg["purple_loop"]["max_rounds"]:
            break
        gap_text = "\n".join(f"- {v.ref} ({v.tier}): {v.variant} Telemetry: {v.evidence or 'not given'}"
                             for v in gaps)
        prompt = (f"Your current rule:\n```json\n{_submission(draft)}\n```\n\n"
                  f"The red side found these gaps that the tables can see:\n{gap_text}\n\n"
                  "Revise the rule so it catches them without matching normal administration. "
                  "Keep the same id and name. Call submit_rule with the complete revised rule.")
        observability.handoff("red", "blue")
        try:
            with observability.agent("blue"):
                answer = claude.ask(models["blue"], system, prompt, blue_tools())
        except Declined as reason:
            notes.append(f"Round {round_number}: hardening failed ({reason}); kept the previous rule.")
            break
        if answer.tool != "submit_rule":
            notes.append(f"Round {round_number}: the blue side didn't submit a hardened rule; kept the previous rule.")
            break
        hardened = draft_from(answer.data)
        hardened.evidence = draft.evidence
        hardened.rule["id"], hardened.rule["name"] = draft.rule["id"], draft.rule["name"]
        with observability.agent("blue"):
            fixed, found = repair(claude, checker, system, prompt, hardened, 1)
        if fixed is None:
            notes.append(f"Round {round_number}: the hardened rule failed checks ({'; '.join(found[:3])}); "
                         "kept the previous rule.")
            break
        draft = fixed
    return LoopResult(draft, variants, red_models, rounds, notes, summary)


def tier_table(result: LoopResult, single: bool = False) -> str:
    """The tier table. single=True shows one 'caught' column, for a review of one rule version."""
    if not result.variants:
        return "No red-side review."
    yes_no = {True: "yes", False: "NO", None: "-"}
    if single:
        lines = ["| Ref | Tier | Variant | Tables see it | Caught by this rule |", "|---|---|---|---|---|"]
    else:
        lines = ["| Ref | Tier | Variant | Tables see it | First draft | Final rule |", "|---|---|---|---|---|---|"]
    order = {tier: n for n, tier in enumerate(TIERS)}
    for v in sorted(result.variants, key=lambda item: (order.get(item.tier, 9), int(item.ref[1:] or 0))):
        caught_first = yes_no[v.caught_first] if v.visible else "not visible"
        caught_final = yes_no[v.caught_final] if v.visible else "not visible"
        cells = [v.ref, v.tier, md(v.variant), "yes" if v.visible else "no"]
        cells += [caught_final] if single else [caught_first, caught_final]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)
