"""Durable, portable evidence artifacts for MWCCPS2 solver attempts.

This module deliberately treats absent evidence as unknown.  In particular, a
capture-gap request is not a claim that two compiler runs are equivalent; it is
only a bounded request to collect the evidence needed to explain an object
mismatch.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Sequence

SCHEMA_NAME = "mwccps2-solver-evidence"
SCHEMA_VERSION = 1

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]*\Z")
_ADDRESS = re.compile(r"(?:0x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9_.:-]*)\Z")
_SAFE_REASON = re.compile(r"[a-z][a-z0-9_:-]*\Z")
_CAPTURE_COMPLETE = frozenset({"complete", "completed"})
_LIFECYCLE = frozenset({"candidate_generated", "compiled", "failed", "rejected", "not_run"})


class EvidenceError(ValueError):
    """Raised when durable solver evidence is malformed or unsafe."""


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceError(f"{context} must be an object")
    return value


def _keys(value: Mapping[str, Any], allowed: frozenset[str], context: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise EvidenceError(f"{context} has unknown keys: {', '.join(sorted(unknown))}")
    missing = {key for key in allowed if key not in value}
    # Callers with optional fields pass a reduced allowed set below; this helper
    # intentionally only rejects unknown keys.


def _string(value: Any, context: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{context} must be a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EvidenceError(f"{context} has an invalid value")
    return value


def _sha(value: Any, context: str) -> str:
    return _string(value, context, _SHA256)


def _optional_sha(value: Any, context: str) -> str | None:
    return None if value is None else _sha(value, context)


def _bool_or_none(value: Any, context: str) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise EvidenceError(f"{context} must be true, false, or null")
    return value


def _integer(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EvidenceError(f"{context} must be a non-negative integer")
    return value


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                           allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as exc:
        raise EvidenceError(f"value cannot be represented as canonical JSON: {exc}") from exc


def canonical_json(value: Any) -> str:
    """Return canonical, deterministic JSON suitable for durable artifacts."""
    return _canonical_bytes(value).decode("ascii")


def canonical_sha256(value: Any) -> str:
    return sha256(_canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class PortableEvidenceRef:
    """A content-addressed reference with no host filesystem location."""

    kind: str
    sha256: str
    identifier: str | None = None

    def __post_init__(self) -> None:
        _string(self.kind, "evidence ref kind", _IDENTIFIER)
        _sha(self.sha256, "evidence ref sha256")
        if self.identifier is not None:
            _string(self.identifier, "evidence ref identifier", _IDENTIFIER)

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind, "sha256": self.sha256}
        if self.identifier is not None:
            result["identifier"] = self.identifier
        return result

    @classmethod
    def from_json(cls, value: Any) -> "PortableEvidenceRef":
        raw = _mapping(value, "evidence ref")
        _keys(raw, frozenset({"kind", "sha256", "identifier"}), "evidence ref")
        if "kind" not in raw or "sha256" not in raw:
            raise EvidenceError("evidence ref requires kind and sha256")
        return cls(raw["kind"], raw["sha256"], raw.get("identifier"))


@dataclass(frozen=True)
class StageEvidence:
    """Only values actually observed for one captured stage occurrence."""

    stage: str
    occurrence: int
    capture_status: str
    normalized_stage_sha256: str | None = None
    graph_sha256: str | None = None
    pcode_text_sha256: str | None = None

    def __post_init__(self) -> None:
        _string(self.stage, "stage", _IDENTIFIER)
        _integer(self.occurrence, "stage occurrence")
        _string(self.capture_status, "capture status", _SAFE_REASON)
        _optional_sha(self.normalized_stage_sha256, "normalized stage sha256")
        _optional_sha(self.graph_sha256, "graph sha256")
        _optional_sha(self.pcode_text_sha256, "PCode text sha256")

    def to_json(self) -> dict[str, Any]:
        return {
            "stage": self.stage, "occurrence": self.occurrence,
            "capture_status": self.capture_status,
            "normalized_stage_sha256": self.normalized_stage_sha256,
            "graph_sha256": self.graph_sha256,
            "pcode_text_sha256": self.pcode_text_sha256,
        }

    @classmethod
    def from_json(cls, value: Any) -> "StageEvidence":
        raw = _mapping(value, "stage evidence")
        expected = frozenset({"stage", "occurrence", "capture_status", "normalized_stage_sha256", "graph_sha256", "pcode_text_sha256"})
        _keys(raw, expected, "stage evidence")
        if set(raw) != set(expected):
            raise EvidenceError("stage evidence has missing keys")
        return cls(**dict(raw))


@dataclass(frozen=True)
class FailureRecord:
    candidate_sha256: str
    source_sha256: str
    transform_chain: tuple[str, ...]
    lifecycle_status: str
    reason: str
    error_kind: str | None
    direct_object_equal: bool | None
    instrumented_object_equal: bool | None
    stages: tuple[StageEvidence, ...] = ()
    evidence_refs: tuple[PortableEvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        _sha(self.candidate_sha256, "candidate sha256")
        _sha(self.source_sha256, "source sha256")
        if not isinstance(self.transform_chain, tuple):
            raise EvidenceError("transform chain must be a tuple")
        for index, transform in enumerate(self.transform_chain):
            _string(transform, f"transform chain[{index}]", _IDENTIFIER)
        _string(self.lifecycle_status, "lifecycle status", _SAFE_REASON)
        if self.lifecycle_status not in _LIFECYCLE:
            raise EvidenceError("lifecycle status is not recognized")
        _string(self.reason, "failure reason", _SAFE_REASON)
        if self.error_kind is not None:
            _string(self.error_kind, "error kind", _SAFE_REASON)
        _bool_or_none(self.direct_object_equal, "direct object equality")
        _bool_or_none(self.instrumented_object_equal, "instrumented object equality")
        if not isinstance(self.stages, tuple) or not isinstance(self.evidence_refs, tuple):
            raise EvidenceError("stages and evidence refs must be tuples")
        for stage in self.stages:
            if not isinstance(stage, StageEvidence):
                raise EvidenceError("stages must contain StageEvidence")
        for ref in self.evidence_refs:
            if not isinstance(ref, PortableEvidenceRef):
                raise EvidenceError("evidence refs must contain PortableEvidenceRef")

    def to_json(self) -> dict[str, Any]:
        return {"candidate_sha256": self.candidate_sha256, "source_sha256": self.source_sha256,
                "transform_chain": list(self.transform_chain), "lifecycle_status": self.lifecycle_status,
                "reason": self.reason, "error_kind": self.error_kind,
                "direct_object_equal": self.direct_object_equal,
                "instrumented_object_equal": self.instrumented_object_equal,
                "stages": [stage.to_json() for stage in self.stages],
                "evidence_refs": [ref.to_json() for ref in self.evidence_refs]}

    @classmethod
    def from_json(cls, value: Any) -> "FailureRecord":
        raw = _mapping(value, "failure record")
        expected = frozenset({"candidate_sha256", "source_sha256", "transform_chain", "lifecycle_status", "reason", "error_kind", "direct_object_equal", "instrumented_object_equal", "stages", "evidence_refs"})
        _keys(raw, expected, "failure record")
        if set(raw) != set(expected):
            raise EvidenceError("failure record has missing keys")
        chain = raw["transform_chain"]
        stages = raw["stages"]
        refs = raw["evidence_refs"]
        if not isinstance(chain, list) or not isinstance(stages, list) or not isinstance(refs, list):
            raise EvidenceError("failure record arrays must be arrays")
        return cls(raw["candidate_sha256"], raw["source_sha256"], tuple(chain), raw["lifecycle_status"],
                   raw["reason"], raw["error_kind"], raw["direct_object_equal"], raw["instrumented_object_equal"],
                   tuple(StageEvidence.from_json(item) for item in stages),
                   tuple(PortableEvidenceRef.from_json(item) for item in refs))


@dataclass(frozen=True)
class CaptureGapRequest:
    comparison_sha256: str
    profile_name: str
    profile_sha256: str
    stage: str
    address: str
    reason: str
    status: str = "pending"
    run_status: str = "not_run"
    baseline_capture_count: int = 0
    variant_capture_count: int = 0
    baseline_statuses: tuple[str, ...] = ()
    variant_statuses: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _sha(self.comparison_sha256, "comparison sha256")
        _string(self.profile_name, "profile name", _IDENTIFIER)
        _sha(self.profile_sha256, "profile sha256")
        _string(self.stage, "request stage", _IDENTIFIER)
        _string(self.address, "request address", _ADDRESS)
        _string(self.reason, "request reason", _SAFE_REASON)
        if self.status != "pending" or self.run_status != "not_run":
            raise EvidenceError("new capture-gap requests must be pending and not_run")
        _integer(self.baseline_capture_count, "baseline capture count")
        _integer(self.variant_capture_count, "variant capture count")
        for label, statuses in (("baseline", self.baseline_statuses), ("variant", self.variant_statuses)):
            if not isinstance(statuses, tuple):
                raise EvidenceError(f"{label} statuses must be a tuple")
            for status in statuses:
                _string(status, f"{label} capture status", _SAFE_REASON)

    def to_json(self) -> dict[str, Any]:
        return {"comparison_sha256": self.comparison_sha256, "profile_name": self.profile_name,
                "profile_sha256": self.profile_sha256, "stage": self.stage, "address": self.address,
                "reason": self.reason, "status": self.status, "run_status": self.run_status,
                "baseline_capture_count": self.baseline_capture_count,
                "variant_capture_count": self.variant_capture_count,
                "baseline_statuses": list(self.baseline_statuses), "variant_statuses": list(self.variant_statuses)}

    @classmethod
    def from_json(cls, value: Any) -> "CaptureGapRequest":
        raw = _mapping(value, "capture gap request")
        expected = frozenset({"comparison_sha256", "profile_name", "profile_sha256", "stage", "address", "reason", "status", "run_status", "baseline_capture_count", "variant_capture_count", "baseline_statuses", "variant_statuses"})
        _keys(raw, expected, "capture gap request")
        if set(raw) != set(expected):
            raise EvidenceError("capture gap request has missing keys")
        if not isinstance(raw["baseline_statuses"], list) or not isinstance(raw["variant_statuses"], list):
            raise EvidenceError("capture statuses must be arrays")
        cooked = dict(raw)
        cooked["baseline_statuses"] = tuple(cooked["baseline_statuses"])
        cooked["variant_statuses"] = tuple(cooked["variant_statuses"])
        return cls(**cooked)


@dataclass(frozen=True)
class CaptureGapRejection:
    comparison_sha256: str
    stage: str | None
    reason: str
    baseline_capture_count: int | None
    variant_capture_count: int | None
    baseline_statuses: tuple[str, ...] = ()
    variant_statuses: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _sha(self.comparison_sha256, "comparison sha256")
        if self.stage is not None:
            _string(self.stage, "rejection stage", _IDENTIFIER)
        _string(self.reason, "rejection reason", _SAFE_REASON)
        if self.baseline_capture_count is not None:
            _integer(self.baseline_capture_count, "baseline capture count")
        if self.variant_capture_count is not None:
            _integer(self.variant_capture_count, "variant capture count")
        for statuses in (self.baseline_statuses, self.variant_statuses):
            if not isinstance(statuses, tuple):
                raise EvidenceError("capture statuses must be tuples")
            for status in statuses:
                _string(status, "capture status", _SAFE_REASON)

    def to_json(self) -> dict[str, Any]:
        return {"comparison_sha256": self.comparison_sha256, "stage": self.stage, "reason": self.reason,
                "baseline_capture_count": self.baseline_capture_count,
                "variant_capture_count": self.variant_capture_count,
                "baseline_statuses": list(self.baseline_statuses), "variant_statuses": list(self.variant_statuses)}

    @classmethod
    def from_json(cls, value: Any) -> "CaptureGapRejection":
        raw = _mapping(value, "capture gap rejection")
        expected = frozenset({"comparison_sha256", "stage", "reason", "baseline_capture_count", "variant_capture_count", "baseline_statuses", "variant_statuses"})
        _keys(raw, expected, "capture gap rejection")
        if set(raw) != set(expected) or not isinstance(raw["baseline_statuses"], list) or not isinstance(raw["variant_statuses"], list):
            raise EvidenceError("capture gap rejection has invalid keys or statuses")
        cooked = dict(raw)
        cooked["baseline_statuses"] = tuple(cooked["baseline_statuses"])
        cooked["variant_statuses"] = tuple(cooked["variant_statuses"])
        return cls(**cooked)


@dataclass(frozen=True)
class SolverEvidence:
    failures: tuple[FailureRecord, ...] = ()
    capture_gap_requests: tuple[CaptureGapRequest, ...] = ()
    capture_gap_rejections: tuple[CaptureGapRejection, ...] = ()

    def __post_init__(self) -> None:
        for records, kind in ((self.failures, FailureRecord), (self.capture_gap_requests, CaptureGapRequest), (self.capture_gap_rejections, CaptureGapRejection)):
            if not isinstance(records, tuple) or any(not isinstance(record, kind) for record in records):
                raise EvidenceError(f"solver evidence must contain {kind.__name__} tuples")

    def to_json(self) -> dict[str, Any]:
        return {"schema": {"name": SCHEMA_NAME, "version": SCHEMA_VERSION},
                "failures": [record.to_json() for record in self.failures],
                "capture_gap_requests": [record.to_json() for record in self.capture_gap_requests],
                "capture_gap_rejections": [record.to_json() for record in self.capture_gap_rejections]}

    @classmethod
    def from_json(cls, value: Any) -> "SolverEvidence":
        raw = _mapping(value, "solver evidence")
        expected = frozenset({"schema", "failures", "capture_gap_requests", "capture_gap_rejections"})
        _keys(raw, expected, "solver evidence")
        if set(raw) != set(expected):
            raise EvidenceError("solver evidence has missing keys")
        schema = _mapping(raw["schema"], "solver evidence schema")
        if set(schema) != {"name", "version"} or schema.get("name") != SCHEMA_NAME or schema.get("version") != SCHEMA_VERSION:
            raise EvidenceError("solver evidence must use mwccps2-solver-evidence schema v1")
        arrays = (raw["failures"], raw["capture_gap_requests"], raw["capture_gap_rejections"])
        if any(not isinstance(item, list) for item in arrays):
            raise EvidenceError("solver evidence records must be arrays")
        return cls(tuple(FailureRecord.from_json(item) for item in arrays[0]),
                   tuple(CaptureGapRequest.from_json(item) for item in arrays[1]),
                   tuple(CaptureGapRejection.from_json(item) for item in arrays[2]))


def _summary_variants(summary: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    variants = summary.get("variants")
    if not isinstance(variants, list):
        raise EvidenceError("experiment summary variants must be an array")
    result: dict[str, Mapping[str, Any]] = {}
    for raw in variants:
        variant = _mapping(raw, "experiment summary variant")
        name = _string(variant.get("name"), "experiment summary variant name", _IDENTIFIER)
        if name in result:
            raise EvidenceError(f"duplicate experiment summary variant {name}")
        result[name] = variant
    return result


def _stage_observations(variant: Mapping[str, Any], stage: str) -> tuple[int, tuple[str, ...]]:
    snapshot = variant.get("snapshot_compile")
    if not isinstance(snapshot, Mapping) or not isinstance(snapshot.get("stages"), list):
        return 0, ()
    statuses: list[str] = []
    for raw in snapshot["stages"]:
        if isinstance(raw, Mapping) and raw.get("stage") == stage and isinstance(raw.get("capture_status"), str):
            statuses.append(raw["capture_status"])
    return len(statuses), tuple(statuses)


def _invariant_proven(variant: Mapping[str, Any]) -> bool:
    snapshot = variant.get("snapshot_compile")
    return isinstance(snapshot, Mapping) and snapshot.get("matches_direct_object") is True


def _first_stage_sequence(variant: Mapping[str, Any], stage: str) -> int | None:
    snapshot = variant.get("snapshot_compile")
    if not isinstance(snapshot, Mapping) or not isinstance(snapshot.get("stages"), list):
        return None
    sequences = [
        raw["sequence"] for raw in snapshot["stages"]
        if isinstance(raw, Mapping) and raw.get("stage") == stage
        and isinstance(raw.get("sequence"), int) and not isinstance(raw["sequence"], bool)
    ]
    return min(sequences) if sequences else None


def _semantic_divergence_localizes(
    comparison: Mapping[str, Any], baseline: Mapping[str, Any], variant: Mapping[str, Any], stage: str,
) -> bool:
    divergence = comparison.get("earliest_pcode_divergence")
    if divergence is None:
        return False
    if not isinstance(divergence, Mapping) or not isinstance(divergence.get("stage"), str):
        # A malformed/non-specific divergence cannot establish that a stage is
        # still unlocalized, so do not issue a collection request from it.
        return True
    divergent_stage = divergence["stage"]
    if divergent_stage == stage:
        return True
    candidate_sequences = [
        sequence for sequence in (_first_stage_sequence(baseline, stage), _first_stage_sequence(variant, stage))
        if sequence is not None
    ]
    divergent_sequences = [
        sequence for sequence in (
            _first_stage_sequence(baseline, divergent_stage),
            _first_stage_sequence(variant, divergent_stage),
        ) if sequence is not None
    ]
    # Without observed ordering, an existing semantic divergence blocks an
    # otherwise speculative request.  Missing values remain unknown, never
    # evidence that the candidate stage came first.
    return not candidate_sequences or not divergent_sequences or min(divergent_sequences) < min(candidate_sequences)


def _candidate_gaps(comparison: Mapping[str, Any], variants: Mapping[str, Mapping[str, Any]]) -> list[tuple[str, str, int, tuple[str, ...], int, tuple[str, ...]]]:
    baseline_name = _string(comparison.get("baseline_variant"), "comparison baseline variant", _IDENTIFIER)
    variant_name = _string(comparison.get("variant"), "comparison variant", _IDENTIFIER)
    baseline = variants.get(baseline_name)
    variant = variants.get(variant_name)
    if baseline is None or variant is None:
        raise EvidenceError("comparison refers to an unknown variant")
    candidates: dict[str, str] = {}
    for raw in comparison.get("missing_stages", []):
        item = _mapping(raw, "missing stage")
        stage = _string(item.get("stage"), "missing stage name", _IDENTIFIER)
        candidates.setdefault(stage, "missing_stage")
    for raw in comparison.get("capture_count_differences", []):
        item = _mapping(raw, "capture count difference")
        stage = _string(item.get("stage"), "count-difference stage name", _IDENTIFIER)
        candidates.setdefault(stage, "capture_count_difference")
    for side in (baseline, variant):
        snapshot = side.get("snapshot_compile")
        if isinstance(snapshot, Mapping) and isinstance(snapshot.get("stages"), list):
            for raw in snapshot["stages"]:
                if isinstance(raw, Mapping) and isinstance(raw.get("stage"), str) and isinstance(raw.get("capture_status"), str):
                    if raw["capture_status"] not in _CAPTURE_COMPLETE:
                        reason = "handler_failure" if raw["capture_status"] == "instrumentation_error" else "partial_capture"
                        candidates.setdefault(raw["stage"], reason)
    return [(stage, reason, *_stage_observations(baseline, stage), *_stage_observations(variant, stage))
            for stage, reason in sorted(candidates.items())]


def derive_capture_gap_requests(
    experiment_summary: Mapping[str, Any], *, profile_name: str, profile_sha256: str,
    stage_addresses: Mapping[str, str],
) -> tuple[tuple[CaptureGapRequest, ...], tuple[CaptureGapRejection, ...]]:
    """Derive bounded gap requests without claiming equality from incomplete evidence."""
    summary = _mapping(experiment_summary, "experiment summary")
    schema = _mapping(summary.get("schema"), "experiment summary schema")
    if schema.get("name") != "mwccps2-experiment-summary" or schema.get("version") != 1:
        raise EvidenceError("capture gaps require experiment-summary-v1")
    _string(profile_name, "profile name", _IDENTIFIER)
    _sha(profile_sha256, "profile sha256")
    checked_addresses: dict[str, str] = {}
    for stage, address in stage_addresses.items():
        checked_addresses[_string(stage, "profile stage", _IDENTIFIER)] = _string(address, "profile stage address", _ADDRESS)
    variants = _summary_variants(summary)
    comparisons = summary.get("comparisons")
    if not isinstance(comparisons, list):
        raise EvidenceError("experiment summary comparisons must be an array")
    requests: list[CaptureGapRequest] = []
    rejections: list[CaptureGapRejection] = []
    for raw in comparisons:
        comparison = _mapping(raw, "comparison")
        digest = canonical_sha256(comparison)
        candidates = _candidate_gaps(comparison, variants)
        if not candidates:
            continue
        baseline = variants[_string(comparison.get("baseline_variant"), "comparison baseline variant", _IDENTIFIER)]
        variant = variants[_string(comparison.get("variant"), "comparison variant", _IDENTIFIER)]
        if comparison.get("final_object_equal") is True:
            gate = "final_object_equal"
        elif comparison.get("final_object_equal") is not False:
            gate = "final_object_equality_unknown"
        elif not (_invariant_proven(baseline) and _invariant_proven(variant)):
            gate = "object_invariant_unproven"
        elif comparison.get("earliest_pcode_divergence") is not None:
            gate = "semantic_pcode_divergence_localized"
        else:
            gate = None
        for stage, reason, base_count, base_statuses, variant_count, variant_statuses in candidates:
            localized = gate == "semantic_pcode_divergence_localized" and _semantic_divergence_localizes(
                comparison, baseline, variant, stage
            )
            if gate is not None and (gate != "semantic_pcode_divergence_localized" or localized):
                rejections.append(CaptureGapRejection(digest, stage, gate, base_count, variant_count, base_statuses, variant_statuses))
            elif stage not in checked_addresses:
                rejections.append(CaptureGapRejection(digest, stage, "unknown_stage", base_count, variant_count, base_statuses, variant_statuses))
            else:
                requests.append(CaptureGapRequest(
                    digest, profile_name, profile_sha256, stage, checked_addresses[stage], reason,
                    baseline_capture_count=base_count, variant_capture_count=variant_count,
                    baseline_statuses=base_statuses, variant_statuses=variant_statuses,
                ))
    return tuple(requests), tuple(rejections)


def write_solver_evidence(path: str | Path, evidence: SolverEvidence) -> None:
    """Atomically write canonical evidence JSON; parents must already exist."""
    if not isinstance(evidence, SolverEvidence):
        raise EvidenceError("evidence must be SolverEvidence")
    destination = Path(path)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False) as output:
            temporary = Path(output.name)
            output.write(_canonical_bytes(evidence.to_json()))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise EvidenceError(f"cannot write solver evidence: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_solver_evidence(path: str | Path) -> SolverEvidence:
    try:
        with Path(path).open("r", encoding="utf-8", newline=None) as source:
            raw = json.load(source, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot load solver evidence: {exc}") from exc
    return SolverEvidence.from_json(raw)
