from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations
import re
from typing import Any, Iterable


ANCHORED_MODIFIERS = frozenset({"endswith", "startswith", "base64", "base64offset", "windash"})
UNANCHORED_MODIFIERS = frozenset({"contains", "contains_any", "contains_all", "re", "regex"})
HIGH_PRECISION_FIELDS = {
    "image",
    "originalfilename",
    "parentimage",
    "parentoriginalfilename",
    "hashes",
    "sha256",
    "sha1",
    "md5",
    "eventid",
    "integritylevel",
    "logonid",
    "processguid",
    "parentprocessguid",
}
MEDIUM_PRECISION_FIELDS = {
    "commandline",
    "parentcommandline",
    "targetfilename",
    "sourcename",
    "providername",
    "scriptblocktext",
    "queryname",
    "destinationhostname",
    "registrypath",
    "targetobject",
    "pipe",
    "servicename",
}
LOW_PRECISION_FIELDS = {"description", "details", "message", "keywords", "payload", "data"}
FIELD_FAMILIES = (
    {"image", "originalfilename"},
    {"parentimage", "parentoriginalfilename"},
    {"targetfilename", "image"},
    {"registrypath", "targetobject"},
)


@dataclass(frozen=True)
class DetectionAtom:
    selector: str
    field: str
    modifiers: tuple[str, ...]
    values: tuple[str, ...]

    @property
    def modifier_class(self) -> str:
        mods = set(self.modifiers)
        if not mods:
            return "exact"
        if mods & ANCHORED_MODIFIERS:
            return "anchored"
        if mods & UNANCHORED_MODIFIERS:
            return "unanchored"
        return "other"


@dataclass(frozen=True)
class DetectionSemantics:
    logsource_key: str
    condition: str
    atoms: tuple[DetectionAtom, ...]

    @property
    def fields(self) -> set[str]:
        return {atom.field for atom in self.atoms}

    @property
    def field_families(self) -> set[str]:
        return {field_family(atom.field) for atom in self.atoms}

    @property
    def selector_count(self) -> int:
        return len({atom.selector for atom in self.atoms})

    @property
    def total_atom_weight(self) -> float:
        return sum(atom_weight(atom) for atom in self.atoms)

    @property
    def family_weight_map(self) -> dict[str, float]:
        weights: dict[str, float] = {}
        for atom in self.atoms:
            family = field_family(atom.field)
            weights[family] = weights.get(family, 0.0) + atom_weight(atom)
        return weights


def normalize_condition(condition: str) -> str:
    return " ".join((condition or "").lower().split())


def iter_detection_atoms(detection: dict[str, Any]) -> Iterable[DetectionAtom]:
    for selector_name, selector in (detection or {}).items():
        if selector_name == "condition":
            continue
        if isinstance(selector, dict):
            yield from _atoms_from_selector(selector_name, selector)
        elif isinstance(selector, list):
            for item in selector:
                if isinstance(item, dict):
                    yield from _atoms_from_selector(selector_name, item)


def build_detection_semantics(logsource_key: str, detection: dict[str, Any]) -> DetectionSemantics:
    atoms = tuple(sorted(iter_detection_atoms(detection), key=lambda a: (a.selector, a.field, a.modifiers, a.values)))
    return DetectionSemantics(
        logsource_key=logsource_key or "(unknown)",
        condition=normalize_condition(str((detection or {}).get("condition") or "")),
        atoms=atoms,
    )


def event_surface_similarity(left: DetectionSemantics, right: DetectionSemantics) -> int:
    if not left.atoms or not right.atoms:
        return 0

    logsource_factor = 1.0 if left.logsource_key == right.logsource_key else 0.92
    field_overlap = _jaccard(left.fields, right.fields)
    condition_similarity = _condition_similarity(left.condition, right.condition)
    coverage = (_coverage(left.atoms, right.atoms) + _coverage(right.atoms, left.atoms)) / 2
    score = (coverage * 0.72 + field_overlap * 0.18 + condition_similarity * 0.10) * logsource_factor
    return int(round(score * 100))


def event_surface_similarity_upper_bound(left: DetectionSemantics, right: DetectionSemantics) -> int:
    """Deterministic upper bound used for exact pruning before expensive scoring.

    The bound is conservative: it may keep extra pairs, but it must never discard
    a pair that could reach the exact semantic score threshold.
    """
    if not left.atoms or not right.atoms:
        return 0
    logsource_factor = 1.0 if left.logsource_key == right.logsource_key else 0.92
    field_overlap = _jaccard(left.fields, right.fields)
    condition_similarity = _condition_similarity(left.condition, right.condition)
    coverage_upper = (_coverage_upper_bound(left, right) + _coverage_upper_bound(right, left)) / 2
    score = (coverage_upper * 0.72 + field_overlap * 0.18 + condition_similarity * 0.10) * logsource_factor
    return int(score * 100)


def candidate_rule_pairs_by_logsource(rule_paths: list[str], semantics_by_path: dict[str, DetectionSemantics]) -> list[tuple[str, str]]:
    """Generate deterministic candidate pairs that share at least one field family.

    This is an exact pruning stage: any pair with non-zero atom-level similarity must
    share at least one field family because cross-family atom similarity is zero.
    """
    family_index: dict[str, list[str]] = {}
    for path in rule_paths:
        semantics = semantics_by_path[path]
        for family in sorted(semantics.field_families):
            family_index.setdefault(family, []).append(path)

    seen: set[tuple[str, str]] = set()
    ordered_pairs: list[tuple[str, str]] = []
    for _family, members in sorted(family_index.items(), key=lambda item: (len(item[1]), item[0])):
        if len(members) < 2:
            continue
        for left, right in combinations(sorted(members), 2):
            pair = (left, right)
            if pair in seen:
                continue
            seen.add(pair)
            ordered_pairs.append(pair)
    return ordered_pairs


def semantic_strength(rule_or_detection: Any) -> float:
    if hasattr(rule_or_detection, "detection"):
        detection = rule_or_detection.detection or {}
    else:
        detection = rule_or_detection or {}

    atoms = list(iter_detection_atoms(detection))
    if not atoms:
        return 0.0
    strengths = [atom_strength(atom) for atom in atoms]
    diversity_bonus = min(len({atom.field for atom in atoms}) * 0.08, 0.24)
    selector_bonus = min(len({atom.selector for atom in atoms}) * 0.05, 0.20)
    avg_strength = sum(strengths) / len(strengths)
    return min(avg_strength + diversity_bonus + selector_bonus, 1.0)


def atom_strength(atom: DetectionAtom) -> float:
    field_component = field_precision(atom.field)
    modifier_component = modifier_strength(atom.modifiers)
    value_component = value_specificity(atom.values)
    return min(field_component * modifier_component * value_component, 1.0)


def atom_weight(atom: DetectionAtom) -> float:
    return max(atom_strength(atom), 0.15)


def field_precision(field: str) -> float:
    if field in HIGH_PRECISION_FIELDS:
        return 1.0
    if field in MEDIUM_PRECISION_FIELDS:
        return 0.72
    if field in LOW_PRECISION_FIELDS:
        return 0.38
    return 0.58


def modifier_strength(modifiers: tuple[str, ...]) -> float:
    if not modifiers:
        return 1.0
    mods = set(modifiers)
    if mods & ANCHORED_MODIFIERS:
        return 0.88
    if mods & {"all"}:
        return 0.82
    if mods & {"re", "regex"}:
        return 0.60
    if mods & UNANCHORED_MODIFIERS:
        return 0.42
    return 0.68


def value_specificity(values: tuple[str, ...]) -> float:
    if not values:
        return 0.20
    best = max(_single_value_specificity(v) for v in values)
    if len(values) > 8:
        best *= 0.82
    return max(min(best, 1.0), 0.10)


def _single_value_specificity(value: str) -> float:
    v = str(value or "").strip().lower()
    if not v:
        return 0.12
    if len(v) <= 3:
        return 0.12
    if v.startswith("imphash=") or len(v) >= 24 and all(ch in "0123456789abcdef=-_{}" for ch in v):
        return 1.0
    if v.endswith(".exe") or v.endswith(".dll") or "\\" in v or "/" in v:
        return 0.95
    if "*" in v:
        return 0.30 if v.count("*") >= 2 else 0.42
    if " " in v and len(v) >= 18:
        return 0.78
    if len(v) >= 12:
        return 0.74
    if len(v) >= 8:
        return 0.60
    return 0.36


def has_anchored_atom(detection: dict[str, Any]) -> bool:
    return any(atom.modifier_class in {"exact", "anchored"} or atom.field in HIGH_PRECISION_FIELDS for atom in iter_detection_atoms(detection))


def weakest_atoms(detection: dict[str, Any], limit: int = 3) -> list[DetectionAtom]:
    atoms = sorted(iter_detection_atoms(detection), key=atom_strength)
    return atoms[:limit]


def _atoms_from_selector(selector_name: str, selector: dict[str, Any]) -> Iterable[DetectionAtom]:
    for raw_field, value in selector.items():
        parts = [part.strip().lower() for part in str(raw_field).split("|") if part.strip()]
        if not parts:
            continue
        field = parts[0]
        modifiers = tuple(parts[1:])
        values = tuple(_normalize_value_list(value))
        yield DetectionAtom(selector=selector_name, field=field, modifiers=modifiers, values=values)


def _normalize_value_list(value: Any) -> list[str]:
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_normalize_value_list(item))
        return out
    if isinstance(value, dict):
        return [f"{k}:{v}" for k, v in sorted(value.items())]
    if value is None:
        return []
    return [" ".join(str(value).strip().lower().split())]


def _coverage(left: tuple[DetectionAtom, ...], right: tuple[DetectionAtom, ...]) -> float:
    total = 0.0
    weights = 0.0
    for atom in left:
        weight = atom_weight(atom)
        best = max((_atom_similarity(atom, candidate) for candidate in right), default=0.0)
        total += best * weight
        weights += weight
    return total / weights if weights else 0.0


def _coverage_upper_bound(left: DetectionSemantics, right: DetectionSemantics) -> float:
    """Cheap exact upper bound on directional coverage.

    An atom can only score above zero against atoms in the same field family, so the
    total weight mass of families absent from the other rule is guaranteed to score 0.
    """
    if not left.atoms or not right.atoms:
        return 0.0
    right_families = right.field_families
    total = left.total_atom_weight
    if total <= 0:
        return 0.0
    matched_weight = sum(weight for family, weight in left.family_weight_map.items() if family in right_families)
    return min(matched_weight / total, 1.0)


def _atom_similarity(left: DetectionAtom, right: DetectionAtom) -> float:
    field_score = _field_similarity(left.field, right.field)
    if field_score == 0.0:
        return 0.0
    modifier_score = 1.0 if left.modifiers == right.modifiers else _modifier_family_similarity(left, right)
    value_score = _value_set_similarity(left.values, right.values)
    return (modifier_score * 0.30 + value_score * 0.50 + field_score * 0.20)


def _modifier_family_similarity(left: DetectionAtom, right: DetectionAtom) -> float:
    if left.modifier_class == right.modifier_class:
        return 0.82
    if {left.modifier_class, right.modifier_class} <= {"exact", "anchored", "other"}:
        return 0.58
    return 0.22


def _value_set_similarity(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    if not left or not right:
        return 0.0
    scores = []
    for lv in left:
        scores.append(max((_value_similarity(lv, rv) for rv in right), default=0.0))
    return sum(scores) / len(scores)


@lru_cache(maxsize=65536)
def _value_similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0

    left_kind = _value_kind(left)
    right_kind = _value_kind(right)
    if left_kind != right_kind and not ({left_kind, right_kind} <= {"path", "word", "text"}):
        return 0.0

    left_tokens = _value_tokens(left)
    right_tokens = _value_tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0

    left_set = frozenset(left_tokens)
    right_set = frozenset(right_tokens)
    token_jaccard = _jaccard(left_set, right_set)
    shared = len(left_set & right_set)
    containment = shared / min(len(left_set), len(right_set)) if shared else 0.0

    left_tail = _tail_token(left_tokens)
    right_tail = _tail_token(right_tokens)
    tail_score = 0.92 if left_tail and left_tail == right_tail else 0.0

    substring_score = 0.0
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    if len(shorter) >= 6 and shorter in longer:
        substring_score = 0.88

    anchored_prefix = _shared_prefix_chars(left, right)
    anchored_suffix = _shared_suffix_chars(left, right)
    anchored_score = 0.0
    if anchored_prefix >= 8 or anchored_suffix >= 8:
        anchored_score = min(max(anchored_prefix, anchored_suffix) / max(len(left), len(right)), 1.0) * 0.85

    return max(token_jaccard, containment * 0.9, tail_score, substring_score, anchored_score)


def _field_similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    for family in FIELD_FAMILIES:
        if left in family and right in family:
            return 0.84
    return 0.0


def field_family(field: str) -> str:
    field = (field or "").lower()
    for family in FIELD_FAMILIES:
        if field in family:
            return "/".join(sorted(family))
    return field


def semantic_bucket_keys(semantics: DetectionSemantics) -> set[str]:
    """Build coarse candidate buckets to reduce pairwise explosion.

    Buckets intentionally over-approximate similarity: rules sharing a logsource,
    condition shape, and at least one high-signal field family become candidates
    for exact semantic scoring.
    """
    condition = semantics.condition or "(none)"
    atoms = semantics.atoms
    if not atoms:
        return {f"ls:{semantics.logsource_key}|cond:{condition}"}

    families = {field_family(atom.field) for atom in atoms}
    anchored = {field_family(atom.field) for atom in atoms if atom.modifier_class in {"exact", "anchored"} or atom.field in HIGH_PRECISION_FIELDS}
    value_tokens: set[str] = set()
    for atom in atoms:
        for value in atom.values[:2]:
            for token in value.replace('\\', ' ').replace('/', ' ').replace('=', ' ').split():
                if len(token) >= 5:
                    value_tokens.add(token[:24])
                    if len(value_tokens) >= 8:
                        break
            if len(value_tokens) >= 8:
                break
        if len(value_tokens) >= 8:
            break

    buckets: set[str] = set()
    for fam in sorted(anchored or families):
        buckets.add(f"ls:{semantics.logsource_key}|field:{fam}")
        buckets.add(f"cond:{condition}|field:{fam}")
        for token in sorted(value_tokens):
            buckets.add(f"ls:{semantics.logsource_key}|field:{fam}|tok:{token}")
    if not buckets:
        buckets.add(f"ls:{semantics.logsource_key}|cond:{condition}")
    return buckets


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


@lru_cache(maxsize=4096)
def _condition_similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    left_tokens = frozenset(_simple_tokens(left))
    right_tokens = frozenset(_simple_tokens(right))
    if not left_tokens or not right_tokens:
        return 0.0
    jaccard = _jaccard(left_tokens, right_tokens)
    shared = len(left_tokens & right_tokens)
    containment = shared / min(len(left_tokens), len(right_tokens)) if shared else 0.0
    return max(jaccard, containment * 0.9)


@lru_cache(maxsize=65536)
def _value_tokens(value: str) -> tuple[str, ...]:
    return tuple(tok for tok in _simple_tokens(value) if tok)


@lru_cache(maxsize=65536)
def _value_kind(value: str) -> str:
    value = (value or '').lower()
    if not value:
        return 'empty'
    compact = value.replace('-', '')
    if value.startswith('imphash=') or re.fullmatch(r'[0-9a-f]{24,64}', compact):
        return 'hash'
    if '\\' in value or '/' in value or value.endswith(('.exe', '.dll', '.sys', '.ps1', '.vbs', '.js', '.bat', '.cmd', '.tmp', '.dmp', '.plist')):
        return 'path'
    if value.isdigit():
        return 'number'
    if len(value.split()) <= 2:
        return 'word'
    return 'text'


@lru_cache(maxsize=131072)
def _simple_tokens(value: str) -> tuple[str, ...]:
    value = (value or '').lower()
    return tuple(tok for tok in re.split(r'[^a-z0-9_.$:-]+', value) if tok)


def _tail_token(tokens: tuple[str, ...]) -> str:
    return tokens[-1] if tokens else ''


def _shared_prefix_chars(left: str, right: str) -> int:
    count = 0
    for lch, rch in zip(left, right):
        if lch != rch:
            break
        count += 1
    return count


def _shared_suffix_chars(left: str, right: str) -> int:
    count = 0
    for lch, rch in zip(reversed(left), reversed(right)):
        if lch != rch:
            break
        count += 1
    return count
