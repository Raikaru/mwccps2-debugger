"""Immutable, conservative source transformation primitives."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Callable, Iterable, Mapping, Sequence

from .c_ast import Node, TranslationUnit, lex_c


class TransformError(ValueError): pass
class TransformRejected(TransformError): pass


@dataclass(frozen=True, slots=True)
class SemanticGuard:
    id: str
    description: str
    requirement: str  # proven, assumption_required, rejected


@dataclass(frozen=True, slots=True)
class TransformSpec:
    id: str
    title: str
    node_kinds: tuple[str, ...]
    semantic_risk: str
    guards: tuple[SemanticGuard, ...]
    evidence: Mapping[str, object]
    reachability: str
    default_search: bool
    operators: tuple[str, ...] = ()
    cfg_change: bool = False

    def manifest(self) -> dict[str, object]:
        return {"cfg_change": self.cfg_change, "default_search": self.default_search, "evidence": dict(self.evidence), "guards": [{"description": g.description, "id": g.id, "requirement": g.requirement} for g in self.guards], "id": self.id, "node_kinds": list(self.node_kinds), "operators": list(self.operators), "reachability": self.reachability, "semantic_risk": self.semantic_risk, "title": self.title}


@dataclass(frozen=True, slots=True)
class TransformApplication:
    spec_id: str
    node_id: str
    start: int
    end: int
    replacement: str
    assumptions: tuple[str, ...] = ()
    status: str = "applicable"  # applicable, assumption_required, rejected
    rejection: str | None = None

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start: raise TransformError("invalid source span")
        if self.status not in {"applicable", "assumption_required", "rejected"}: raise TransformError("invalid application status")
        if self.status == "rejected" and not self.rejection: raise TransformError("rejected application requires reason")
        if self.status == "applicable" and self.assumptions: raise TransformError("applicable application cannot have assumptions")


@dataclass(frozen=True, slots=True)
class TransformResult:
    source: str
    applications: tuple[TransformApplication, ...]
    rejected: tuple[TransformApplication, ...] = ()

    def manifest(self) -> dict[str, object]:
        return {"applications": [_application_json(a) for a in self.applications], "rejected": [_application_json(a) for a in self.rejected], "schema": {"name": "mwccps2-source-transform-result", "version": 1}}


def _application_json(a: TransformApplication) -> dict[str, object]:
    return {"assumptions": list(a.assumptions), "end": a.end, "node_id": a.node_id, "rejection": a.rejection, "replacement": a.replacement, "spec_id": a.spec_id, "start": a.start, "status": a.status}


def canonical_json(value: object) -> str:
    """Serialize only JSON-compatible manifest values deterministically."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _has_unsafe_tokens(text: str) -> str | None:
    tokens = lex_c(text)
    significant = [t.text for t in tokens if t.kind not in {"whitespace", "comment"}]
    if any(t.kind == "directive" for t in tokens): return "macro or preprocessor directive intersects target"
    if "volatile" in significant: return "volatile access cannot be proven safe"
    if "(" in significant: return "call or cast expression requires semantic proof"
    if any(x in significant for x in ("++", "--", "=", "+=", "-=", "*=", "/=", "%=")): return "side effect cannot be proven safe"
    return None


def guarded_application(spec: TransformSpec, unit: TranslationUnit, node_id: str, replacement: str, *, require_pure: bool = True, assumptions: Sequence[str] = ()) -> TransformApplication:
    """Build an application only if its source-local safety requirements hold."""
    node = unit.node(node_id)
    if node.kind not in spec.node_kinds:
        return TransformApplication(spec.id, node_id, node.start, node.end, replacement, status="rejected", rejection="unsupported node kind")
    unsafe = _has_unsafe_tokens(unit.source[node.start:node.end]) if require_pure else None
    if unsafe:
        return TransformApplication(spec.id, node_id, node.start, node.end, replacement, status="rejected", rejection=unsafe)
    all_assumptions = tuple(sorted(set(assumptions)))
    return TransformApplication(spec.id, node_id, node.start, node.end, replacement, all_assumptions, "assumption_required" if all_assumptions else "applicable")


def apply_applications(unit: TranslationUnit, applications: Iterable[TransformApplication], *, allow_assumptions: bool = False) -> TransformResult:
    """Apply non-overlapping node-anchored edits without changing other bytes."""
    requested = tuple(applications); accepted: list[TransformApplication] = []; rejected: list[TransformApplication] = []
    known = {node.id: node for node in unit.nodes}
    for app in requested:
        node = known.get(app.node_id)
        if app.status == "rejected": rejected.append(app); continue
        if app.status == "assumption_required" and not allow_assumptions:
            rejected.append(TransformApplication(app.spec_id, app.node_id, app.start, app.end, app.replacement, app.assumptions, "rejected", "semantic assumptions were not authorized")); continue
        if node is None or (node.start, node.end) != (app.start, app.end):
            rejected.append(TransformApplication(app.spec_id, app.node_id, app.start, app.end, app.replacement, app.assumptions, "rejected", "node identity or span does not belong to this translation unit")); continue
        accepted.append(app)
    accepted.sort(key=lambda a: (a.start, a.end, a.spec_id, a.node_id))
    prior_end = -1
    for app in accepted:
        if app.start < prior_end: raise TransformRejected("overlapping transformation spans")
        prior_end = app.end
    parts: list[str] = []; cursor = 0
    for app in accepted:
        parts.extend((unit.source[cursor:app.start], app.replacement)); cursor = app.end
    parts.append(unit.source[cursor:])
    return TransformResult("".join(parts), tuple(accepted), tuple(rejected))


def enumerate_applications(unit: TranslationUnit, spec: TransformSpec, builder: Callable[[Node], TransformApplication | None]) -> tuple[TransformApplication, ...]:
    """Enumerate in source order, independent of hash iteration or host state."""
    result = [candidate for node in unit.nodes if node.kind in spec.node_kinds for candidate in (builder(node),) if candidate is not None]
    return tuple(sorted(result, key=lambda a: (a.start, a.end, a.spec_id, a.node_id)))
