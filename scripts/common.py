"""Shared helpers: repo paths, settings, environment, Markdown and pipeline output."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from functools import cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections"
SIGMA_DIR = ROOT / "sigma"
CONFIG_DIR = ROOT / "config"
PROMPTS_DIR = ROOT / "prompts"


class Fail(Exception):
    """A problem the person running the pipeline can fix. Printed without a traceback."""


@cache
def settings() -> dict[str, Any]:
    return load_yaml(CONFIG_DIR / "settings.yaml")


def load_yaml(path: Path) -> Any:
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def env(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, "").strip()
    # Azure Pipelines leaves "$(NAME)" in place when a variable isn't defined.
    if value.startswith("$(") and value.endswith(")"):
        value = ""
    if not value:
        if required:
            raise Fail(f"Set {name}. In Azure Pipelines it comes from the 'detections' variable group.")
        return default or ""
    return value


def lab_vm() -> str:
    return env("LAB_VM").lower()


def md(text: Any) -> str:
    """Make text safe inside a Markdown table cell or line."""
    value = str(text if text is not None else "")
    value = value.replace("\r", " ").replace("\n", " ")
    value = re.sub(r"([\\`*_{}\[\]<>|#])", r"\\\1", value)
    return value.strip()


def code(text: str) -> str:
    """Show text as inline code, safe for Markdown tables."""
    value = str(text).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    if "`" in value:
        return f"`` {value} ``"
    return f"`{value}`"


def git(*args: str, check: bool = True) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise Fail(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def in_pipeline() -> bool:
    return os.environ.get("TF_BUILD", "").lower() == "true"


def set_output(name: str, value: str, is_output: bool = True) -> None:
    """Set an Azure Pipelines variable for later steps and stages."""
    if in_pipeline():
        flag = ";isoutput=true" if is_output else ""
        print(f"##vso[task.setvariable variable={name}{flag}]{value}")


def upload_summary(path: Path) -> None:
    if in_pipeline():
        print(f"##vso[task.uploadsummary]{path.resolve()}")


def log_error(message: str) -> None:
    if in_pipeline():
        print(f"##vso[task.logissue type=error]{message}")
    else:
        print(f"ERROR: {message}", file=sys.stderr)


def log_warning(message: str) -> None:
    if in_pipeline():
        print(f"##vso[task.logissue type=warning]{message}")
    else:
        print(f"WARNING: {message}", file=sys.stderr)


def read_list(path: str | Path | None) -> list[str]:
    if not path:
        return []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip()]


def run_main(main) -> None:
    """Run a script's main() and turn Fail into a clean error and exit code 1.

    With SENTRY_DSN set, the run is one Sentry transaction and its errors are reported (scripts/observability.py).
    """
    from . import observability

    try:
        with observability.start(Path(sys.argv[0]).stem):
            try:
                code_ = main()
            except Fail as problem:
                observability.capture(problem)
                log_error(str(problem))
                code_ = 1
            except Exception as error:
                observability.capture(error)
                raise
    finally:
        observability.stop()
    sys.exit(code_ or 0)
