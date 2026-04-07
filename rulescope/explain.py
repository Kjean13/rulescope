from __future__ import annotations
"""Explain weak rules in analyst-friendly language with prioritized remediation guidance."""
from collections import Counter
from rulescope.i18n import localize_finding, translate_text
from rulescope.models.finding import SEVERITY_RANK
from rulescope.models.report import RuleReport
CODE_SUGGESTIONS: dict[str, str] = {
    "PARSE-001": "Fix the YAML syntax or unsupported structure so the rule can be parsed and analyzed.",
    "ATK-001": "Add at least one ATT&CK tactic and one technique tag so the rule contributes to coverage governance.",
    "ATK-002": "Align ATT&CK tactic tags with the existing technique mapping.",
    "ATK-003": "Map to at least one ATT&CK technique ID (e.g. attack.t1059.001).",
    "ATK-004": "Reduce ATT&CK mapping breadth to the tactics truly supported by the logic.",
    "ATK-005": "Review ATT&CK mapping for specificity and avoid broad parent-technique-only coverage.",
    "ATK-006": "Map to sub-techniques where applicable for precise coverage.",
    "META-001": "Populate the missing metadata to improve maintainability and portability.",
    "META-002": "Use a valid UUID for the rule identifier.",
    "META-003": "Normalize the rule status to a standard Sigma lifecycle value.",
    "META-004": "Align severity to a supported value and justify it in the description or references.",
    "META-005": "Write a clearer description with context and expected behavior.",
    "META-006": "Add tags for ATT&CK mapping, product, or data source context.",
    "META-007": "Add a date field for lifecycle tracking.",
    "DOC-001": "Use title case to improve readability in review dashboards.",
    "DOC-002": "Replace the generic title with a behavior-specific title.",
    "DOC-003": "Describe what the rule detects, why it matters, and expected sources.",
    "DOC-004": "Add analyst-facing context about the threat behavior and expected telemetry.",
    "DOC-005": "Replace placeholder false positives with realistic benign scenarios.",
    "DOC-006": "Fix or replace invalid references with valid URLs.",
    "NOISE-001": "Tighten matching values or add exclusions to reduce noise.",
    "NOISE-002": "Validate the regex-like patterns against benign telemetry and document expected noise.",
    "NOISE-003": "Document realistic benign scenarios for analyst triage.",
    "NOISE-004": "Add contextual constraints or downgrade severity until validated.",
    "NOISE-005": "Either harden the detection or downgrade the severity until it becomes selective enough.",
    "NOISE-006": "Prefer exact values, startswith, or endswith in at least part of the selection set.",
    "NOISE-007": "Replace leading wildcard patterns with endswith modifiers or exact matches to avoid full-table scans.",
    "NOISE-008": "Replace very short substrings with longer unique patterns, or combine with a parent process / image anchor.",
    "NOISE-009": "Split the large CommandLine IOC list into focused rules or use a lookup table to reduce FP surface.",
    "NOISE-010": "Consider splitting OR-storm branches into separate rules with tuned severity, or require ≥2 branches to match.",
    "WEAK-001": "Add one or more discriminating selectors to improve selectivity.",
    "WEAK-002": "Replace broad wildcards with more specific values or supporting filters.",
    "WEAK-003": "Prefer endswith, startswith, exact values, or contextual parent/process filters.",
    "WEAK-004": "Mix process, parent, command line, user, or image path fields for stronger intent.",
    "WEAK-005": "Revisit severity — the rule currently looks weaker than its declared impact.",
    "WEAK-006": "Add a positive selector before the negation so the condition does not match almost everything.",
    "WEAK-007": "Add a positive selector block so the rule defines a suspicious pattern, not only exclusions.",
    "WEAK-008": "Replace vague values with concrete binaries, paths, hashes, registry keys, or strongly discriminating command fragments.",
    "WEAK-009": "Increase semantic precision by combining better fields, stronger modifiers, and more specific values.",
    "MAINT-001": "Split the rule or simplify the detection structure if it keeps growing.",
    "MAINT-002": "Reduce condition branching to keep the logic reviewable and portable.",
    "MAINT-003": "Flatten or simplify nested field composition in selectors to make updates safer.",
    "MAINT-004": "Refactor the rule so naming and structure remain readable over time.",
    "MAINT-005": "Add an explicit condition to avoid ambiguous parser or reviewer behavior.",
    "MAINT-006": "Reduce structural complexity before promoting the rule.",
    "STRUCT-001": "Complete logsource information so the event source is unambiguous.",
    "STRUCT-002": "Add product or category to logsource for better routing and quality checks.",
    "STRUCT-003": "Complete the detection section; a rule without valid detections should not be merged.",
    "STRUCT-004": "Add a condition clause so the detection logic is explicit.",
    "STRUCT-005": "Repair malformed detection structure before any quality review.",
    "STRUCT-006": "Fix invalid structure first; other findings are secondary until parsing is stable.",
    "STRUCT-007": "Fix the condition to reference only defined selection block names.",
    "STRUCT-008": "Reference unused selections in the condition or remove dead code.",
    "CORR-001": "Add a correlation type (event_count, value_count, temporal) and reference base rules.",
    "CORR-002": "Add group-by fields to scope the correlation (e.g. source IP, user, hostname).",
    "CORR-003": "Add a timespan to bound the correlation window and limit resource usage.",
    "CORR-004": "Reference base detection rules by ID or name so the correlation has inputs.",
    "DUP-001": "Review duplicated logic and consider merging or refactoring to reduce redundant detections.",
    "OVL-001": "Review overlapping rules on the same logsource for merge candidates or document their differentiation.",
}
CATEGORY_PLAYBOOKS: dict[str, str] = {
    "metadata": "Metadata debt hurts reviewability, ownership, and lifecycle tracking.",
    "documentation": "Documentation debt slows triage and makes reviewer intent harder to preserve.",
    "noise": "Noise issues raise false-positive risk and erode analyst trust.",
    "weakness": "Weakness issues reduce selectivity and can make the rule hard to operate at scale.",
    "attack": "Coverage issues reduce ATT&CK reporting quality and content governance value.",
    "maintainability": "Maintainability issues increase rule debt and future change risk.",
    "structural": "Structural issues can invalidate the rule or make later findings unreliable.",
    "duplicate": "Duplicate rules waste analyst attention and inflate coverage metrics.",
    "overlap": "Overlapping rules generate redundant alerts on the same events.",
    "correlation": "Incomplete correlation rules cannot be compiled by any backend.",
}
CATEGORY_PRIORITY: dict[str, int] = {
    "structural": 100,
    "correlation": 95,
    "noise": 80,
    "weakness": 75,
    "duplicate": 65,
    "overlap": 63,
    "metadata": 55,
    "documentation": 50,
    "attack": 45,
    "maintainability": 40,
}
BLOCKING_CODES = {
    "PARSE-001",
    "STRUCT-003",
    "STRUCT-004",
    "STRUCT-005",
    "STRUCT-007",
    "CORR-001",
    "CORR-002",
    "CORR-003",
    "CORR-004",
}
class RuleExplainer:
    def explain(self, rule: RuleReport) -> str:
        grouped = Counter((finding.category or "general") for finding in rule.findings)
        highest_severity = self._highest_severity(rule)
        focus_order = sorted(grouped.items(), key=lambda item: (-item[1], -CATEGORY_PRIORITY.get(item[0], 0), item[0]))
        immediate, followup = self._prioritized_suggestions(rule)
        lines = [
            f"{translate_text('Rule: ')}{rule.title or rule.path}",
            f"{translate_text('Path: ')}{rule.path}",
            f"{translate_text('Overall score: ')}{rule.scores.overall}/100",
            f"{translate_text('Severity focus: ')}{highest_severity.upper() if highest_severity else 'NONE'}",
            "",
            translate_text("Findings:"),
        ]
        if rule.findings:
            for finding in self._ordered_findings(rule):
                lf = localize_finding(finding)
                lines.append(f"- {lf.code} [{lf.severity}] {lf.message}")
        else:
            lines.append(f"- {translate_text('No findings.')}")
        if focus_order:
            lines.extend(["", translate_text("Review focus:")])
            for category, count in focus_order[:4]:
                rationale = translate_text(CATEGORY_PLAYBOOKS.get(category, "This area deserves targeted cleanup before merge."))
                lines.append(f"- {category}: {count} finding(s). {rationale}")
        profile = rule.semantic_profile
        lines.extend(["", translate_text("Semantic profile:")])
        lines.append(
            f"- selectors={profile.selector_count}, fields={profile.field_count}, wildcards={profile.wildcard_count}, contains={profile.contains_modifiers}, condition_complexity={profile.condition_complexity}"
        )
        lines.extend(["", translate_text("Recommended improvements:")])
        if immediate:
            lines.append(translate_text("Immediate next steps:"))
            for suggestion in immediate[:7]:
                lines.append(f"- {suggestion}")
        if followup:
            lines.append(translate_text("Then harden the rule:" if immediate else "Next hardening steps:"))
            for suggestion in followup[:7]:
                lines.append(f"- {suggestion}")
        if not immediate and not followup:
            lines.append(f"- {translate_text('This rule already looks production-ready. Keep validating it against real telemetry before promoting severity.')}")
        return "\n".join(lines)
    def _ordered_findings(self, rule: RuleReport):
        return sorted(
            rule.findings,
            key=lambda f: (self._severity_rank(f.severity), CATEGORY_PRIORITY.get(f.category or "", 0), self._code_priority(f.code), f.code),
            reverse=True,
        )
    def _prioritized_suggestions(self, rule: RuleReport) -> tuple[list[str], list[str]]:
        immediate: list[str] = []
        followup: list[str] = []
        seen: set[str] = set()
        blocked = self._is_blocked(rule)
        def add(bucket: list[str], text: str) -> None:
            localized = translate_text(text)
            if localized and localized not in seen:
                bucket.append(localized)
                seen.add(localized)
        for finding in self._ordered_findings(rule):
            localized = localize_finding(finding)
            suggestion = localized.recommendation or translate_text(CODE_SUGGESTIONS.get(finding.code, ""))
            if finding.code == "NOISE-003":
                suggestion = translate_text("Document 2-3 concrete benign scenarios in falsepositives, such as admin scripts, software deployment, or IT troubleshooting.")
            elif finding.code in {"META-005", "DOC-003"}:
                suggestion = translate_text("Expand the description with intent, expected trigger path, and what a reviewer should verify first during triage.")
            if not suggestion:
                continue
            if blocked and finding.code not in BLOCKING_CODES and (finding.category or "") not in {"structural", "correlation"}:
                add(followup, suggestion)
            else:
                add(immediate, suggestion)
        profile = rule.semantic_profile
        if blocked:
            add(immediate, "Re-run the scan after the rule parses cleanly so downstream findings reflect the real logic.")
        if profile.selector_count <= 1:
            add(followup if blocked else immediate, "Add a second selector around parent process, user, or command line so the rule is not driven by a single block.")
        if profile.wildcard_count >= 3:
            add(immediate, f"Replace at least {min(2, profile.wildcard_count)} wildcard-heavy values with bounded patterns or exact switches to reduce broad matches.")
        if profile.contains_modifiers >= 1:
            add(immediate, "Where possible, replace contains modifiers with startswith, endswith, or exact tokens tied to known attacker tradecraft.")
        if profile.field_count <= 1:
            add(followup if blocked else immediate, "Increase field diversity by combining image, command line, parent image, or user context in the same rule.")
        if not rule.attack_techniques and not rule.attack_tactics:
            add(followup if blocked else immediate, "Add at least one ATT&CK tactic and one technique tag so the rule contributes to coverage governance.")
        if any(f.code == "NOISE-003" for f in rule.findings):
            add(immediate, "Document 2-3 concrete benign scenarios in falsepositives, such as admin scripts, software deployment, or IT troubleshooting.")
        if any(f.code == "META-005" for f in rule.findings) or any(f.code == "DOC-003" for f in rule.findings):
            add(immediate, "Expand the description with intent, expected trigger path, and what a reviewer should verify first during triage.")
        if rule.duplicate_candidates:
            add(immediate, f"Merge or retire duplicate logic found in {len(rule.duplicate_candidates)} nearby rule(s) to reduce redundant alerts.")
        if rule.overlap_candidates:
            add(immediate, f"Document or refactor {len(rule.overlap_candidates)} overlap relationship(s) so alert ownership stays clear.")
        if not immediate and not followup:
            add(immediate, "This rule already looks production-ready. Keep validating it against real telemetry before promoting severity.")
        return immediate, followup
    def _is_blocked(self, rule: RuleReport) -> bool:
        return any(f.code in BLOCKING_CODES or (f.category or "") in {"structural", "correlation"} and self._severity_rank(f.severity) >= 2 for f in rule.findings)
    @staticmethod
    def _severity_rank(severity: str) -> int:
        return SEVERITY_RANK.get(severity, 0)
    @staticmethod
    def _code_priority(code: str) -> int:
        if code in BLOCKING_CODES:
            return 100
        prefix = code.split("-", 1)[0]
        return {
            "PARSE": 100,
            "STRUCT": 95,
            "CORR": 90,
            "NOISE": 80,
            "WEAK": 75,
            "DUP": 65,
            "OVL": 63,
            "META": 55,
            "DOC": 50,
            "ATK": 45,
            "MAINT": 40,
        }.get(prefix, 0)
    def _highest_severity(self, rule: RuleReport) -> str | None:
        if not rule.findings:
            return None
        ranked = sorted(rule.findings, key=lambda f: self._severity_rank(f.severity), reverse=True)
        return ranked[0].severity
