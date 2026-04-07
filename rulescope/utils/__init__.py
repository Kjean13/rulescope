from __future__ import annotations

"""Utility functions — file discovery, text normalization, time helpers."""

import fnmatch
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── File discovery ──────────────────────────────────────────────

def find_rule_files(root: str, exclude_patterns: list[str] | None = None) -> list[Path]:
    base = Path(root)
    if not base.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")
    if base.is_file():
        return [base]

    exclude = []
    for pattern in exclude_patterns or []:
        exclude.append(pattern if any(ch in pattern for ch in "*?[]") else f"*{pattern}*")
    results = []
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".yml", ".yaml"}:
            continue
        rel = str(p.relative_to(base))
        if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
            continue
        results.append(p)
    return results


# ── Text helpers ────────────────────────────────────────────────

def normalize_text(value: str) -> str:
    value = value or ""
    value = value.lower().strip()
    value = re.sub(r"\s+", " ", value)
    return value


def flatten_structure(data: Any) -> str:
    try:
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return str(data)


# ── Time helpers ────────────────────────────────────────────────

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
