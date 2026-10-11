"""The rule format: loading, static checks, KQL guard rails, and the Graph body.

One YAML file per rule under detections/<folder>/<id>.yaml. Optional Sigma
version at sigma/<folder>/<id>.yml. See the README for every field.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml

from .common import ROOT, RULES_DIR, SIGMA_DIR, Fail, run_main, settings

RULE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
COLUMN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NAME = re.compile(r"^(?P<source>[A-Za-z0-9]+) - (?P<title>\S.*)$")
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Advanced hunting table names end in one of these words. Column names don't.
TABLE_WORD = re.compile(r"\b([A-Z][A-Za-z]*(?:Events|Info|Evidence|EventsBeta|Inventory|Nodes|Edges|Beta))\b")
LAB_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*$")

STATUS_TO_GRAPH = {"testing": "disabled", "production": "enabled", "retired": "disabled"}
ENTITY_FIELDS = {
    "hosts": {"deviceIdColumn", "dnsDomainColumn", "nameColumn", "netBiosNameColumn", "ntDomainColumn"},
    "accounts": {"aadUserIdColumn", "dnsDomainColumn", "nameColumn", "ntDomainColumn", "sidColumn",
                 "upnColumn", "upnSuffixColumn"},
    "files": {"nameColumn", "sha1Column", "sha256Column"},
}
REQUIRED = ["id", "name", "description", "severity", "frequency", "tactics", "query", "entities",
            "recommended_actions", "status", "version"]
OPTIONAL = ["hunt_query", "lab_tests", "metadata"]


# Loading

def load(path: Path) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as error:
        raise Fail(f"{relative(path)} isn't valid YAML: {error}") from error
    if not isinstance(data, dict):
        raise Fail(f"{relative(path)} must be a YAML mapping.")
    return data


def relative(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def rule_files() -> list[Path]:
    return sorted(p for p in RULES_DIR.rglob("*") if p.suffix in (".yaml", ".yml") and p.is_file())


def all_rules() -> dict[str, Path]:
    found: dict[str, Path] = {}
    for path in rule_files():
        rule_id = load(path).get("id")
        if isinstance(rule_id, str):
            found.setdefault(rule_id, path)
    return found


def sigma_path(rule_path: Path, rule_id: str) -> Path:
    folder = Path(rule_path).resolve().parent.name
    return SIGMA_DIR / folder / f"{rule_id}.yml"


# KQL

def strip_query(query: str) -> str:
    return query.strip().rstrip(";").rstrip()


def code_only(query: str) -> str:
    """The query with comments removed and every string literal replaced by "".

    Checks run on this, so a rule that looks for "Invoke-Expression" in a command
    line isn't mistaken for one that uses the invoke operator.
    """
    out: list[str] = []
    i, n = 0, len(query)
    while i < n:
        if query.startswith("//", i):
            end = query.find("\n", i)
            i = n if end < 0 else end
            continue
        if query.startswith("```", i):
            end = query.find("```", i + 3)
            i = n if end < 0 else end + 3
            out.append('""')
            continue
        char = query[i]
        if char in "@" and i + 1 < n and query[i + 1] in "\"'":
            quote_char, i = query[i + 1], i + 2
            while i < n:
                if query[i] == quote_char:
                    if i + 1 < n and query[i + 1] == quote_char:
                        i += 2
                        continue
                    break
                i += 1
            i += 1
            out.append('""')
            continue
        if char in "\"'":
            i += 1
            while i < n and query[i] != char:
                i += 2 if query[i] == "\\" else 1
            i += 1
            out.append('""')
            continue
        out.append(char)
        i += 1
    return "".join(out)


def tables_in(query: str) -> set[str]:
    return set(TABLE_WORD.findall(code_only(query)))


def kql_problems(query: str, label: str = "query") -> list[str]:
    problems = []
    cfg = settings()
    if not isinstance(query, str) or not query.strip():
        return [f"{label} is empty"]
    lowered = code_only(query).lower()
    for word in cfg["blocked_kql"]:
        word = word.lower()
        pattern = re.escape(word) if not word[-1].isalnum() else rf"\b{re.escape(word)}\b"
        if re.search(pattern, lowered):
            problems.append(f"{label} uses blocked KQL: {word}")
    tables = tables_in(query)
    allowed = set(cfg["tables"])
    if not tables & allowed:
        problems.append(f"{label} doesn't query any allowed table ({', '.join(sorted(allowed))})")
    for table in sorted(tables - allowed):
        problems.append(f"{label} uses a table that isn't allowed: {table}")
    if re.search(r"\bunion\b[^|]*\*", lowered):
        problems.append(f"{label} uses a wildcard union")
    return problems


def lab_literal(lab_vm: str) -> str:
    lab = lab_vm.lower().strip()
    if not LAB_NAME.match(lab):
        raise Fail(f"LAB_VM {lab_vm!r} isn't a valid computer name.")
    return f'"{lab}"'


def device_name_expr() -> str:
    return 'tolower(tostring(column_ifexists("DeviceName", "")))'


def without_lab(lab_vm: str) -> str:
    """KQL that drops the lab VM's rows. Defender may show the name with a domain suffix."""
    if not lab_vm:
        return ""
    lab = lab_literal(lab_vm)
    return f"| where not({device_name_expr()} == {lab} or {device_name_expr()} startswith strcat({lab}, \".\"))"


def only_lab(lab_vm: str) -> str:
    lab = lab_literal(lab_vm)
    return f"| where {device_name_expr()} == {lab} or {device_name_expr()} startswith strcat({lab}, \".\")"


def production_query(rule: dict, lab_vm: str) -> str:
    parts = [strip_query(rule["query"]), without_lab(lab_vm), "| summarize Hits = count()"]
    return "\n".join(part for part in parts if part)


def window_query(rule: dict, lab_vm: str, start: str, end: str) -> str:
    return "\n".join([
        strip_query(rule["query"]),
        f"| where Timestamp between (datetime({start}) .. datetime({end}))",
        only_lab(lab_vm),
        "| summarize Hits = count()",
    ])


# Static checks

def problems(rule: dict, path: Path | None = None) -> list[str]:
    cfg = settings()
    found: list[str] = []
    for key in REQUIRED:
        if rule.get(key) in (None, "", [], {}):
            found.append(f"missing {key}")
    for key in rule:
        if key not in REQUIRED and key not in OPTIONAL:
            found.append(f"unknown field {key} (response actions and other settings belong in the portal)")
    if found:
        return found

    rule_id = rule["id"]
    if not isinstance(rule_id, str) or not RULE_ID.match(rule_id) or len(rule_id) > 80:
        found.append("id must be lowercase words joined by hyphens, 80 characters or fewer")
    elif path is not None and Path(path).stem != rule_id:
        found.append(f"file name must be {rule_id}.yaml")

    match = NAME.match(str(rule["name"]))
    if not match:
        found.append("name must look like '<Source> - <Title>', for example 'MDE - Defender exclusion added'")
    elif match.group("source") not in cfg["sources"]:
        found.append(f"name source {match.group('source')} isn't one of {', '.join(cfg['sources'])}")
    if len(str(rule["name"])) > 200:
        found.append("name is longer than 200 characters")

    if rule["severity"] not in cfg["severities"]:
        found.append(f"severity must be one of {', '.join(cfg['severities'])}")
    if rule["frequency"] not in cfg["frequencies"]:
        found.append(f"frequency must be one of {', '.join(cfg['frequencies'])}")
    if rule["status"] not in STATUS_TO_GRAPH:
        found.append(f"status must be one of {', '.join(STATUS_TO_GRAPH)}")
    if not VERSION.match(str(rule["version"])):
        found.append("version must look like 1.0.0")
    for key in ("description", "recommended_actions"):
        if not isinstance(rule[key], str) or len(rule[key]) > 4000:
            found.append(f"{key} must be text of 4,000 characters or fewer")

    tactics = rule["tactics"]
    if not isinstance(tactics, list):
        found.append("tactics must be a list")
    else:
        for item in tactics:
            if not isinstance(item, dict) or item.get("tactic") not in cfg["tactics"]:
                found.append(f"tactic must be one of {', '.join(cfg['tactics'])}")
                continue
            for technique in item.get("techniques") or []:
                if not TECHNIQUE.match(str(technique)):
                    found.append(f"technique {technique} must look like T1059 or T1059.001")

    found += kql_problems(rule["query"])
    if rule.get("hunt_query"):
        found += kql_problems(rule["hunt_query"], "hunt_query")

    entities = rule["entities"]
    if not isinstance(entities, dict):
        found.append("entities must be a mapping of hosts, accounts or files")
    else:
        for kind, mappings in entities.items():
            if kind not in ENTITY_FIELDS:
                found.append(f"entity type {kind} isn't supported (use {', '.join(ENTITY_FIELDS)})")
                continue
            for mapping in mappings or []:
                if not isinstance(mapping, dict) or not mapping:
                    found.append(f"each {kind} entity must map settings to columns")
                    continue
                for field, column in mapping.items():
                    if field not in ENTITY_FIELDS[kind]:
                        found.append(f"{kind} entity has no setting {field}")
                    elif not isinstance(column, str) or not COLUMN.match(column):
                        found.append(f"{kind}.{field} must be a column name")

    lab_tests = rule.get("lab_tests") or []
    if not isinstance(lab_tests, list) or not all(isinstance(t, str) and GUID.match(t) for t in lab_tests):
        found.append("lab_tests must be a list of Atomic test GUIDs from config/atomics.yaml")
    else:
        allowed = {test["guid"] for test in atomics()["tests"]}
        for guid in lab_tests:
            if guid not in allowed:
                found.append(f"lab test {guid} isn't in config/atomics.yaml")
    if "metadata" in rule and not isinstance(rule["metadata"], dict):
        found.append("metadata must be a mapping")
    return found


def sigma_problems(path: Path, rule_id: str) -> list[str]:
    if not path.exists():
        return []
    return sigma_text_problems(path.read_text(encoding="utf-8"), rule_id, check_name=True)


def sigma_text_problems(text: str, rule_id: str, check_name: bool = False) -> list[str]:
    if not text or not text.strip():
        return ["Sigma version is empty"]
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        return [f"Sigma isn't valid YAML: {error}"]
    if not isinstance(data, dict):
        return ["Sigma must be a YAML mapping"]
    found = []
    if check_name and data.get("name") != rule_id:
        found.append(f"Sigma name must be the rule id {rule_id}")
    if not isinstance(data.get("title"), str) or not data["title"].strip():
        found.append("Sigma needs a title")
    logsource = data.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        found.append("Sigma needs a logsource")
    detection = data.get("detection")
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), (str, list)):
        found.append("Sigma needs detection with a condition")
    elif len(detection) < 2:
        found.append("Sigma detection needs at least one selection besides the condition")
    if data.get("level") and data["level"] not in ("informational", "low", "medium", "high", "critical"):
        found.append("Sigma level must be informational, low, medium, high or critical")
    return found


# Schema checks, after advanced hunting compiles the query

def required_columns(rule: dict) -> set[str]:
    needed: set[str] = set()
    tables = settings()["tables"]
    for table in tables_in(rule["query"]):
        needed.update(tables.get(table, []))
    return needed


def entity_columns(rule: dict) -> set[str]:
    columns = set()
    for mappings in (rule.get("entities") or {}).values():
        for mapping in mappings or []:
            columns.update(value for value in mapping.values() if isinstance(value, str))
    return columns


def schema_problems(rule: dict, columns: list[str]) -> list[str]:
    have = set(columns)
    found = [f"results must include column {name}" for name in sorted(required_columns(rule) - have)]
    found += [f"entity mapping uses column {name}, which the query doesn't return"
              for name in sorted(entity_columns(rule) - have)]
    return found


# Microsoft Graph

def to_graph(rule: dict, company: str) -> dict[str, Any]:
    display = f"{company} - {rule['name']}" if company else rule["name"]
    tactics = [
        {"tactic": item["tactic"], "techniques": [{"technique": str(t)} for t in item.get("techniques") or []]}
        for item in rule["tactics"]
    ]
    mappings = {kind: [dict(m) for m in maps] for kind, maps in rule["entities"].items() if maps}
    return {
        "@odata.type": "#microsoft.graph.security.detectionRule",
        "id": rule["id"],
        "displayName": display,
        "description": rule["description"].strip(),
        "status": STATUS_TO_GRAPH[rule["status"]],
        "queryCondition": {"queryText": strip_query(rule["query"])},
        "schedule": {"frequency": rule["frequency"]},
        "detectionAction": {
            "alertTemplate": {
                "title": display,
                "description": rule["description"].strip(),
                "severity": rule["severity"],
                "recommendedActions": rule["recommended_actions"].strip(),
                "entityMappings": mappings,
                "tactics": tactics,
            },
        },
    }


# Atomic Red Team allowlist

def atomics() -> dict[str, Any]:
    with open(ROOT / "config" / "atomics.yaml", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def atomic(guid: str) -> dict[str, Any]:
    for test in atomics()["tests"]:
        if test["guid"] == guid:
            return test
    raise Fail(f"Atomic test {guid} isn't in config/atomics.yaml")


# Command line: static checks for files or folders

def check_paths(paths: list[str]) -> int:
    failed = 0
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if not path.is_absolute():
            path = ROOT / path
        if path.is_dir():
            files += sorted(p for p in path.rglob("*") if p.suffix in (".yaml", ".yml"))
        elif path.exists():
            files.append(path)
    seen: dict[str, Path] = {}
    for path in files:
        if SIGMA_DIR in path.resolve().parents:
            continue
        rule = load(path)
        found = problems(rule, path)
        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            found += sigma_problems(sigma_path(path, rule_id), rule_id)
            if rule_id in seen:
                found.append(f"id {rule_id} is also used by {relative(seen[rule_id])}")
            seen[rule_id] = path
        if found:
            failed += 1
            print(f"FAIL {relative(path)}")
            for problem in found:
                print(f"  - {problem}")
        else:
            print(f"PASS {relative(path)}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Static checks for rule files.")
    parser.add_argument("paths", nargs="*", default=["detections"])
    return check_paths(parser.parse_args().paths)


if __name__ == "__main__":
    run_main(main)
