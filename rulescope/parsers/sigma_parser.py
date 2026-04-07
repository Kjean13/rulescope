from __future__ import annotations

"""Sigma YAML parser with broad format support.

Handles single-doc, multi-doc YAML (global + rule pattern with recursive
merge), list-of-maps selectors, keyword lists, correlation rules
(type: correlation), filter rules (type: filter), boolean/null/int
values, and latin-1 fallback for non-UTF8 files.
"""

from pathlib import Path
from typing import Any

import yaml

from rulescope.models.rule import DetectionRule


class SigmaParserError(Exception):
    pass


# Known Sigma modifiers — used for validation hints, not blocking
KNOWN_MODIFIERS = {
    "contains", "endswith", "startswith", "all", "base64", "base64offset",
    "utf16le", "utf16be", "utf16", "wide", "windash", "re", "cidr",
    "gt", "gte", "lt", "lte", "expand", "exists", "fieldref",
}

# Sigma correlation types
CORRELATION_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *overlay* into a copy of *base*.

    Lists are concatenated; dicts are merged recursively; scalars from
    *overlay* win.  This implements the Sigma multi-document global-merge
    pattern where the first YAML document carries shared metadata that
    applies to all subsequent documents.
    """
    merged = dict(base)
    for key, value in overlay.items():
        if key in merged:
            existing = merged[key]
            if isinstance(existing, dict) and isinstance(value, dict):
                merged[key] = _deep_merge(existing, value)
            elif isinstance(existing, list) and isinstance(value, list):
                merged[key] = existing + value
            else:
                merged[key] = value
        else:
            merged[key] = value
    return merged


class SigmaParser:
    """Parse Sigma YAML rule files into DetectionRule objects.

    Handles:
    - Standard single-document rules
    - Multi-document YAML with recursive global merge (global + rule)
    - Sigma v2 correlation rules (type: correlation)
    - Sigma v2 filter rules (type: filter)
    - List-of-maps selectors (normalizes for downstream analysis)
    - Keyword-list selectors (preserved as-is)
    - Mixed value types in selectors (int, bool, null coerced safely)
    - Graceful handling of unknown/advanced modifiers
    - Latin-1 fallback for non-UTF8 files
    """

    def parse_file(self, path: Path) -> DetectionRule:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                text = path.read_text(encoding="latin-1")
            except Exception as exc:
                raise SigmaParserError(f"Cannot read file: {path}: {exc}") from exc
        except Exception as exc:
            raise SigmaParserError(f"Cannot read file: {path}: {exc}") from exc

        try:
            documents = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            raise SigmaParserError(f"Invalid YAML: {path}: {exc}") from exc

        content = self._select_rule_document(documents, path)
        return self._build_rule(path, content)

    def parse_string(self, text: str, name: str = "<string>") -> DetectionRule:
        try:
            documents = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            raise SigmaParserError(f"Invalid YAML in {name}: {exc}") from exc
        content = self._select_rule_document(documents, Path(name))
        return self._build_rule(Path(name), content)

    def _select_rule_document(self, documents: list, path: Path) -> dict[str, Any]:
        """From potentially multiple YAML documents, select and merge.

        Implements the Sigma multi-document pattern:
        - If there are 2+ mapping documents and the first one has no
          ``detection`` key, treat it as a **global** document whose
          fields merge into every subsequent document.
        - Among the remaining documents, pick the best candidate using
          the standard priority: detection+logsource > correlation >
          filter > title/detection > first mapping.
        """
        candidates = [doc for doc in documents if isinstance(doc, dict)]
        if not candidates:
            raise SigmaParserError(f"Rule content is not a YAML mapping: {path}")

        # Multi-doc global merge: first doc is "global" if it lacks detection
        if len(candidates) >= 2 and "detection" not in candidates[0]:
            global_doc = candidates[0]
            rest = candidates[1:]
            candidates = [_deep_merge(global_doc, doc) for doc in rest]

        return self._pick_best_candidate(candidates)

    @staticmethod
    def _pick_best_candidate(candidates: list[dict[str, Any]]) -> dict[str, Any]:
        """Pick the best Sigma rule candidate from a list of merged docs."""
        for doc in candidates:
            if "detection" in doc and "logsource" in doc:
                return doc
        for doc in candidates:
            if doc.get("type") == "correlation" or "correlation" in doc:
                return doc
        for doc in candidates:
            if doc.get("type") == "filter":
                return doc
        for doc in candidates:
            if "detection" in doc or "title" in doc:
                return doc
        return candidates[0]

    def _detect_rule_type(self, content: dict[str, Any]) -> str:
        """Detect whether this is a standard, correlation, or filter rule."""
        explicit_type = str(content.get("type", "")).lower()
        if explicit_type == "correlation" or "correlation" in content:
            return "correlation"
        if explicit_type == "filter":
            return "filter"
        return "standard"

    def _build_rule(self, path: Path, content: dict[str, Any]) -> DetectionRule:
        def as_list(value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, list):
                return [str(v) for v in value]
            return [str(value)]

        rule_type = self._detect_rule_type(content)

        detection = content.get("detection") or {}
        if isinstance(detection, dict):
            detection = self._normalize_detection(detection)
        else:
            detection = {}

        correlation = {}
        if rule_type == "correlation":
            correlation = content.get("correlation", {})
            if not isinstance(correlation, dict):
                correlation = {}
            for ckey in ("group-by", "timespan", "rules", "generate"):
                if ckey in content and ckey not in correlation:
                    correlation[ckey] = content[ckey]
            if "type" not in correlation:
                cond = correlation.get("condition", content.get("condition", {}))
                if isinstance(cond, dict):
                    if "gte" in cond or "lte" in cond or "gt" in cond or "lt" in cond:
                        correlation["type"] = "event_count"
                    elif "field" in cond:
                        correlation["type"] = "value_count"

        logsource = content.get("logsource") or {}
        if not isinstance(logsource, dict):
            logsource = {}

        rule = DetectionRule(
            path=str(path),
            source_name=path.name,
            raw=content,
            title=str(content.get("title") or ""),
            rule_id=str(content.get("id") or ""),
            description=str(content.get("description") or ""),
            status=str(content.get("status") or ""),
            level=str(content.get("level") or ""),
            author=str(content.get("author") or ""),
            date=str(content.get("date") or ""),
            modified=str(content.get("modified") or ""),
            tags=as_list(content.get("tags")),
            falsepositives=as_list(content.get("falsepositives")),
            references=as_list(content.get("references")),
            logsource=logsource,
            detection=detection,
            rule_type=rule_type,
            correlation=correlation,
        )
        rule.extract_attack_tags()
        return rule

    def _normalize_detection(self, detection: dict[str, Any]) -> dict[str, Any]:
        """Normalize detection section for consistent downstream analysis.

        List-of-maps selectors are merged into a single dict.  When
        multiple maps define the same field, values are accumulated
        into a list so no information is lost.
        """
        normalized = {}
        for key, value in detection.items():
            if key == "condition":
                normalized[key] = value
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                merged: dict[str, Any] = {}
                for item in value:
                    if isinstance(item, dict):
                        for field, val in item.items():
                            if field in merged:
                                existing = merged[field]
                                if not isinstance(existing, list):
                                    existing = [existing]
                                if isinstance(val, list):
                                    existing.extend(val)
                                else:
                                    existing.append(val)
                                merged[field] = existing
                            else:
                                merged[field] = val
                normalized[key] = merged
            else:
                normalized[key] = value
        return normalized
