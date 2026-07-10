"""Pure, deterministic bounded search over transformed C source text.

This module deliberately has no compiler, verifier, or subprocess dependency.  Callers
supply transformation enumeration/application and evidence evaluation callbacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence, Tuple

_RETAIL_STATUSES = frozenset(("MATCH", "MISMATCH", "NON_MATCH", "UNKNOWN"))
STATE_SCHEMA = "mwccps2-guided-search-state"
STATE_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HOST_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/]|(?:\\\\|//)[^\\/\s]+[\\/][^\\/\s]+|"
    r"(?:^|[\s\"'=])/(?:[^\\/\s]+/)+[^\\/\s]+|"
    r"(?:^|[\s\"'=])/(?:Users|home|tmp|var|opt|mnt|etc|private|workspace|root|usr|srv|run|Volumes|nix|proc|sys|dev|media|data|app)(?:/|$))"
)
_STAGE_STATUSES = frozenset(("complete", "partial", "missing", "unknown"))

JSONValue = Any
EnumerateCallback = Callable[..., Iterable[JSONValue]]
ApplyCallback = Callable[..., str]
EvaluateCallback = Callable[..., "CandidateEvaluation"]


class SearchStateError(ValueError):
    """A checkpoint is malformed, corrupt, or incompatible with this search."""


def canonical_json(value: JSONValue) -> str:
    """Return the repository's canonical JSON representation for JSON-shaped data."""
    _validate_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_json(value: JSONValue) -> str:
    return sha256(canonical_json(value).encode("ascii")).hexdigest()


def _source_sha256(source: str) -> str:
    if not isinstance(source, str):
        raise TypeError("source must be text")
    _reject_host_paths(source)
    return sha256(source.encode("utf-8")).hexdigest()


def _reject_host_paths(text: str) -> None:
    if _HOST_PATH.search(text):
        raise ValueError("durable search artifacts must not contain raw host paths")

def _reject_artifact_host_paths(value: JSONValue) -> None:
    """Reject a host path anywhere in a durable artifact's JSON tree."""
    if isinstance(value, str):
        _reject_host_paths(value)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_artifact_host_paths(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                _reject_host_paths(key)
            _reject_artifact_host_paths(item)


def _validate_json(value: JSONValue) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str):
            _reject_host_paths(value)
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("JSON values must be finite")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_json(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            _reject_host_paths(key)
            _validate_json(item)
        return
    raise TypeError("value is not JSON-shaped")


def _require_sha256(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class StageObservation:
    """One observed compiler stage; only complete observations can support pruning."""

    stage: str
    status: str
    digest: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.stage, str) or not self.stage:
            raise ValueError("stage must be a non-empty string")
        if self.status not in _STAGE_STATUSES:
            raise ValueError("invalid stage observation status")
        if self.digest is not None:
            _require_sha256(self.digest, "stage digest")
        if self.status == "complete" and self.digest is None:
            raise ValueError("a complete stage observation requires a digest")
        if self.status != "complete" and self.digest is not None:
            raise ValueError("only complete stage observations may carry a digest")

    @property
    def complete(self) -> bool:
        return self.status == "complete"

    def to_json(self) -> dict[str, JSONValue]:
        return {"digest": self.digest, "stage": self.stage, "status": self.status}

    @classmethod
    def from_json(cls, value: JSONValue) -> "StageObservation":
        data = _strict_object(value, {"stage", "status", "digest"})
        return cls(stage=data["stage"], status=data["status"], digest=data.get("digest"))


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    """Evidence returned by an injected evaluator, never inferred by the engine."""

    stages: Tuple[StageObservation, ...] = ()
    retail_status: str = "UNKNOWN"
    retail_verifier: Optional[str] = None
    retail_authoritative: bool = False
    retail_diff: Optional[int] = None
    blocked_reason: Optional[str] = None

    def __post_init__(self) -> None:
        stages = tuple(self.stages)
        if any(not isinstance(stage, StageObservation) for stage in stages):
            raise TypeError("stages must contain StageObservation values")
        if len({stage.stage for stage in stages}) != len(stages):
            raise ValueError("stage observations must be unique by stage")
        object.__setattr__(self, "stages", stages)
        if self.retail_status not in _RETAIL_STATUSES:
            raise ValueError("invalid retail verifier status")
        if self.retail_verifier is not None and (not isinstance(self.retail_verifier, str) or not self.retail_verifier):
            raise ValueError("retail_verifier must be a non-empty string or null")
        if not isinstance(self.retail_authoritative, bool):
            raise TypeError("retail_authoritative must be bool")
        if self.retail_status == "MATCH" and not (self.retail_authoritative and self.retail_verifier == "p3"):
            raise ValueError("MATCH is valid only from the authoritative P3 verifier")
        if self.retail_diff is not None and (isinstance(self.retail_diff, bool) or not isinstance(self.retail_diff, int) or self.retail_diff < 0):
            raise ValueError("retail_diff must be a non-negative integer or null")
        if self.blocked_reason is not None:
            if not isinstance(self.blocked_reason, str) or not self.blocked_reason:
                raise ValueError("blocked_reason must be a non-empty string or null")
            _reject_host_paths(self.blocked_reason)

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "blocked_reason": self.blocked_reason,
            "retail_authoritative": self.retail_authoritative,
            "retail_status": self.retail_status,
            "retail_verifier": self.retail_verifier,
            "retail_diff": self.retail_diff,
            "stages": [stage.to_json() for stage in self.stages],
        }

    @classmethod
    def from_json(cls, value: JSONValue) -> "CandidateEvaluation":
        data = _strict_object(value, {"stages", "retail_status", "retail_verifier", "retail_authoritative", "retail_diff", "blocked_reason"})
        if not isinstance(data["stages"], list):
            raise SearchStateError("evaluation stages must be an array")
        return cls(
            stages=tuple(StageObservation.from_json(item) for item in data["stages"]),
            retail_status=data["retail_status"],
            retail_verifier=data["retail_verifier"],
            retail_authoritative=data["retail_authoritative"],
            retail_diff=data["retail_diff"],
            blocked_reason=data["blocked_reason"],
        )


@dataclass(frozen=True, slots=True)
class StageObjective:
    stage: str
    digest: Optional[str] = None
    complete: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.stage, str) or not self.stage:
            raise ValueError("objective stage must be a non-empty string")
        if self.digest is not None:
            _require_sha256(self.digest, "objective digest")
        if self.complete and self.digest is None:
            raise ValueError("a complete stage objective requires a digest")
        if not self.complete and self.digest is not None:
            raise ValueError("an incomplete stage objective cannot carry a digest")

    def to_json(self) -> dict[str, JSONValue]:
        return {"complete": self.complete, "digest": self.digest, "stage": self.stage}

    @classmethod
    def from_json(cls, value: JSONValue) -> "StageObjective":
        data = _strict_object(value, {"stage", "digest", "complete"})
        return cls(data["stage"], data["digest"], data["complete"])


@dataclass(frozen=True, slots=True)
class Objective:
    stages: Tuple[StageObjective, ...] = ()

    def __post_init__(self) -> None:
        stages = tuple(self.stages)
        if any(not isinstance(stage, StageObjective) for stage in stages):
            raise TypeError("stages must contain StageObjective values")
        if len({stage.stage for stage in stages}) != len(stages):
            raise ValueError("stage objectives must be unique by stage")
        object.__setattr__(self, "stages", tuple(sorted(stages, key=lambda item: item.stage)))

    def to_json(self) -> dict[str, JSONValue]:
        return {"stages": [stage.to_json() for stage in self.stages]}

    @classmethod
    def from_json(cls, value: JSONValue) -> "Objective":
        data = _strict_object(value, {"stages"})
        if not isinstance(data["stages"], list):
            raise SearchStateError("objective stages must be an array")
        return cls(tuple(StageObjective.from_json(item) for item in data["stages"]))


@dataclass(frozen=True, slots=True)
class SearchConfig:
    max_depth: int = 1
    max_candidates: int = 100
    terminal_authoritative_retail_non_match: bool = False
    required_stages: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int) or self.max_depth < 0:
            raise ValueError("max_depth must be a non-negative integer")
        if isinstance(self.max_candidates, bool) or not isinstance(self.max_candidates, int) or self.max_candidates < 1:
            raise ValueError("max_candidates must be a positive integer")
        if not isinstance(self.terminal_authoritative_retail_non_match, bool):
            raise TypeError("terminal_authoritative_retail_non_match must be bool")
        required_stages = tuple(self.required_stages)
        if (any(not isinstance(stage, str) or not stage for stage in required_stages)
                or len(set(required_stages)) != len(required_stages)):
            raise ValueError("required_stages must be unique non-empty strings")
        object.__setattr__(self, "required_stages", tuple(sorted(required_stages)))

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "max_candidates": self.max_candidates,
            "max_depth": self.max_depth,
            "required_stages": list(self.required_stages),
            "terminal_authoritative_retail_non_match": self.terminal_authoritative_retail_non_match,
        }

    @classmethod
    def from_json(cls, value: JSONValue) -> "SearchConfig":
        data = _strict_object(value, {"max_depth", "max_candidates", "terminal_authoritative_retail_non_match", "required_stages"})
        if not isinstance(data["required_stages"], list):
            raise SearchStateError("required_stages must be an array")
        return cls(
            max_depth=data["max_depth"],
            max_candidates=data["max_candidates"],
            terminal_authoritative_retail_non_match=data["terminal_authoritative_retail_non_match"],
            required_stages=tuple(data["required_stages"]),
        )


@dataclass(frozen=True, slots=True)
class Candidate:
    source: str
    source_sha256: str
    transforms: Tuple[JSONValue, ...] = ()
    parent_source_sha256: Optional[str] = None
    evaluation: Optional[CandidateEvaluation] = None
    rejections: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if _source_sha256(self.source) != self.source_sha256:
            raise ValueError("candidate source_sha256 does not match source")
        if self.parent_source_sha256 is not None:
            _require_sha256(self.parent_source_sha256, "parent source_sha256")
        transforms = tuple(self.transforms)
        for transform in transforms:
            _validate_json(transform)
        if self.evaluation is not None and not isinstance(self.evaluation, CandidateEvaluation):
            raise TypeError("candidate evaluation must be CandidateEvaluation or null")
        object.__setattr__(self, "transforms", transforms)
        rejections = tuple(self.rejections)
        if any(not isinstance(reason, str) or not reason for reason in rejections):
            raise ValueError("candidate rejections must be non-empty strings")
        object.__setattr__(self, "rejections", rejections)

    @property
    def depth(self) -> int:
        return len(self.transforms)

    @property
    def candidate_id(self) -> str:
        return self.source_sha256

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "evaluation": None if self.evaluation is None else self.evaluation.to_json(),
            "parent_source_sha256": self.parent_source_sha256,
            "rejections": list(self.rejections),
            "source": self.source,
            "source_sha256": self.source_sha256,
            "transforms": list(self.transforms),
        }

    @classmethod
    def from_json(cls, value: JSONValue) -> "Candidate":
        data = _strict_object(value, {"source", "source_sha256", "transforms", "parent_source_sha256", "evaluation", "rejections"})
        if not isinstance(data["transforms"], list) or not isinstance(data["rejections"], list):
            raise SearchStateError("candidate transforms and rejections must be arrays")
        evaluation = data["evaluation"]
        return cls(data["source"], data["source_sha256"], tuple(data["transforms"]), data["parent_source_sha256"], None if evaluation is None else CandidateEvaluation.from_json(evaluation), tuple(data["rejections"]))


@dataclass(frozen=True, slots=True)
class SearchResult:
    status: str
    candidates: Tuple[Candidate, ...]
    attempts: Tuple[Mapping[str, JSONValue], ...]
    best_candidate: Optional[Candidate]
    checkpoint: Optional[dict[str, JSONValue]] = None

    def __post_init__(self) -> None:
        if self.status not in {"matched", "exhausted", "limit_reached", "blocked"}:
            raise ValueError("invalid search result status")
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "attempts", tuple(self.attempts))


def _strict_object(value: JSONValue, keys: set[str]) -> dict[str, JSONValue]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise SearchStateError("checkpoint object has missing or unknown fields")
    result = dict(value)
    _validate_json(result)
    return result


def _transform_key(transform: JSONValue) -> str:
    return sha256_json(transform)

def _canonical_catalog(transform_catalog: Sequence[JSONValue]) -> tuple[JSONValue, ...]:
    by_id: dict[str, JSONValue] = {}
    for transform in transform_catalog:
        _validate_json(transform)
        if not isinstance(transform, Mapping):
            raise TypeError("transform catalog entries must be JSON objects")
        spec_id = transform.get("id")
        if not isinstance(spec_id, str) or not spec_id:
            raise ValueError("transform catalog entries require a non-empty id")
        if spec_id in by_id:
            raise ValueError("transform catalog contains duplicate ids")
        by_id[spec_id] = transform
    return tuple(by_id[key] for key in sorted(by_id))

def _application_identity(application: JSONValue) -> tuple[str, str]:
    _validate_json(application)
    if not isinstance(application, Mapping):
        raise TypeError("transform applications must be JSON objects")
    spec_id = application.get("spec_id")
    node_id = application.get("node_id")
    if not isinstance(spec_id, str) or not spec_id or not isinstance(node_id, str) or not node_id:
        raise ValueError("transform applications require non-empty spec_id and node_id")
    return spec_id, node_id


def _call(callback: Callable[..., Any], args: tuple[Any, ...]) -> Any:
    """Call injected callbacks with their declared supported positional arity."""
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        return callback(*args)
    for size in range(len(args), -1, -1):
        try:
            signature.bind(*args[:size])
        except TypeError:
            continue
        return callback(*args[:size])
    raise TypeError("callback cannot accept its required search arguments")


def _prune_reasons(evaluation: CandidateEvaluation, objective: Objective, config: SearchConfig) -> tuple[str, ...]:
    observed = {item.stage: item for item in evaluation.stages}
    reasons: list[str] = []
    for target in objective.stages:
        actual = observed.get(target.stage)
        if target.complete and target.digest is not None and actual is not None and actual.complete and actual.digest != target.digest:
            reasons.append("complete_stage_digest_mismatch:" + target.stage)
    if (config.terminal_authoritative_retail_non_match and evaluation.retail_verifier == "p3"
            and evaluation.retail_authoritative and evaluation.retail_status in {"MISMATCH", "NON_MATCH"}):
        reasons.append("authoritative_p3_retail_non_match")
    return tuple(reasons)


def _required_stages_complete(candidate: Candidate, config: SearchConfig) -> bool:
    if candidate.evaluation is None:
        return False
    observed = {item.stage: item for item in candidate.evaluation.stages}
    return all((stage := observed.get(name)) is not None and stage.complete for name in config.required_stages)

def _is_authoritative_p3_match(candidate: Candidate) -> bool:
    evaluation = candidate.evaluation
    return bool(
        evaluation is not None
        and evaluation.retail_status == "MATCH"
        and evaluation.retail_verifier == "p3"
        and evaluation.retail_authoritative
    )


def _rank(candidate: Candidate, objective: Objective, config: SearchConfig) -> tuple[Any, ...]:
    evaluation = candidate.evaluation
    if evaluation is None:
        return (4, 0, 0, 0, 0, 0, 0, candidate.depth, candidate.source_sha256, tuple(_transform_key(t) for t in candidate.transforms))
    observed = {item.stage: item for item in evaluation.stages}
    complete_matches = sum(1 for target in objective.stages if target.complete and (actual := observed.get(target.stage)) is not None and actual.complete and actual.digest == target.digest)
    complete_targets = sum(1 for target in objective.stages if target.complete)
    return (
        0 if evaluation.retail_status == "MATCH" and evaluation.retail_verifier == "p3" and evaluation.retail_authoritative else 1,
        1 if not _required_stages_complete(candidate, config) else 0,
        1 if candidate.rejections else 0,
        -complete_matches,
        -(complete_targets - complete_matches),
        0 if evaluation.retail_status == "MATCH" else (1 if evaluation.retail_diff is None else 0),
        0 if evaluation.retail_diff is None else evaluation.retail_diff,
        candidate.depth,
        candidate.source_sha256,
        tuple(_transform_key(t) for t in candidate.transforms),
    )


def _state_artifact(baseline_source: str, catalog: tuple[JSONValue, ...], objective: Objective, config: SearchConfig, candidates: Mapping[str, Candidate], frontier: Sequence[str], attempts: Sequence[Mapping[str, JSONValue]], status: Optional[str]) -> dict[str, JSONValue]:
    artifact: dict[str, JSONValue] = {
        "baseline_source_sha256": _source_sha256(baseline_source),
        "candidates": [candidates[key].to_json() for key in sorted(candidates)],
        "config_sha256": sha256_json(config.to_json()),
        "frontier": list(frontier),
        "objective_sha256": sha256_json(objective.to_json()),
        "schema": STATE_SCHEMA,
        "status": status,
        "transform_catalog_sha256": sha256_json(list(catalog)),
        "transform_catalog": list(catalog),
        "attempts": [dict(item) for item in attempts],
        "version": STATE_VERSION,
    }
    _validate_json(artifact)
    return artifact


def save_checkpoint(path: os.PathLike[str] | str, artifact: Mapping[str, JSONValue]) -> None:
    """Atomically write a validated state artifact without timestamps or host paths."""
    _reject_artifact_host_paths(artifact)
    _validate_state(artifact)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_json(dict(artifact)).encode("ascii") + b"\n"
    with NamedTemporaryFile(mode="wb", dir=destination.parent, prefix=".mwccps2-guided-search-", suffix=".tmp", delete=False) as handle:
        temporary = handle.name
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_checkpoint(path: os.PathLike[str] | str, baseline_source: str, transform_catalog: Sequence[JSONValue], objective: Objective, config: SearchConfig) -> dict[str, JSONValue]:
    try:
        with open(path, "rb") as handle:
            decoded = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SearchStateError("checkpoint is unreadable or corrupt") from exc
    _reject_artifact_host_paths(decoded)
    artifact = _validate_state(decoded)
    catalog = _canonical_catalog(transform_catalog)
    expected = _state_artifact(baseline_source, catalog, objective, config, {}, (), (), None)
    for key in ("baseline_source_sha256", "transform_catalog_sha256", "objective_sha256", "config_sha256"):
        if artifact[key] != expected[key]:
            raise SearchStateError("checkpoint is incompatible with this search")
    if artifact["transform_catalog"] != list(catalog):
        raise SearchStateError("checkpoint transform catalog differs")
    return artifact


def _validate_state(value: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    keys = {"schema", "version", "baseline_source_sha256", "transform_catalog", "transform_catalog_sha256", "objective_sha256", "config_sha256", "candidates", "frontier", "attempts", "status"}
    data = _strict_object(value, keys)
    if data["schema"] != STATE_SCHEMA or data["version"] != STATE_VERSION:
        raise SearchStateError("unsupported search checkpoint schema")
    for name in ("baseline_source_sha256", "transform_catalog_sha256", "objective_sha256", "config_sha256"):
        _require_sha256(data[name], name)
    if not isinstance(data["transform_catalog"], list) or not isinstance(data["candidates"], list) or not isinstance(data["frontier"], list) or not isinstance(data["attempts"], list):
        raise SearchStateError("checkpoint collections must be arrays")
    if data["status"] is not None and data["status"] not in {"matched", "exhausted", "limit_reached", "blocked"}:
        raise SearchStateError("invalid checkpoint status")
    candidates = [Candidate.from_json(item) for item in data["candidates"]]
    if len({item.source_sha256 for item in candidates}) != len(candidates):
        raise SearchStateError("checkpoint has duplicate candidate source digests")
    for candidate in candidates:
        application_pairs = tuple(_application_identity(application) for application in candidate.transforms)
        if len(set(application_pairs)) != len(application_pairs):
            raise SearchStateError("checkpoint candidate repeats a transform application")
    known = {item.source_sha256 for item in candidates}
    if any(not isinstance(item, str) or item not in known for item in data["frontier"]):
        raise SearchStateError("checkpoint frontier references unknown candidates")
    for attempt in data["attempts"]:
        _strict_object(attempt, {"outcome", "parent_source_sha256", "transform_sha256"})
        if attempt["outcome"] not in {"accepted", "duplicate_source", "duplicate_application", "application_failed", "not_in_catalog", "candidate_limit"}:
            raise SearchStateError("invalid transformation attempt outcome")
        _require_sha256(attempt["parent_source_sha256"], "attempt parent source_sha256")
        _require_sha256(attempt["transform_sha256"], "attempt transform_sha256")
    return data


def apply_checkpoint(*args: Any, **kwargs: Any) -> dict[str, JSONValue]:
    """Compatibility spelling for loading a checkpoint into a run."""
    return load_checkpoint(*args, **kwargs)


def run_search(
    baseline_source: str,
    transform_catalog: Sequence[JSONValue],
    enumerate_transforms: EnumerateCallback,
    apply_transform: ApplyCallback,
    evaluate_candidate: EvaluateCallback,
    objective: Objective = Objective(),
    config: SearchConfig = SearchConfig(),
    *,
    checkpoint_path: Optional[os.PathLike[str] | str] = None,
    resume: bool = False,
) -> SearchResult:
    """Run or resume a breadth-first, source-deduplicated bounded search.

    Enumeration receives ``(source, catalog)`` (or any prefix it declares), application
    receives ``(source, transform)``, and evaluation receives a ``Candidate``.  Callback
    return data is validated before it is retained in a checkpoint.
    """
    if not isinstance(objective, Objective) or not isinstance(config, SearchConfig):
        raise TypeError("objective and config must be their solver model types")
    catalog = _canonical_catalog(transform_catalog)
    catalog_by_id = {str(transform["id"]): transform for transform in catalog}

    if resume:
        if checkpoint_path is None:
            raise ValueError("resume requires checkpoint_path")
        artifact = load_checkpoint(checkpoint_path, baseline_source, catalog, objective, config)
        candidates = {item.source_sha256: item for item in (Candidate.from_json(raw) for raw in artifact["candidates"])}
        frontier = list(artifact["frontier"])
        attempts: list[Mapping[str, JSONValue]] = [dict(item) for item in artifact["attempts"]]
        prior_status = artifact["status"]
        if prior_status in {"matched", "exhausted"}:
            ranked = tuple(sorted(candidates.values(), key=lambda item: _rank(item, objective, config)))
            best = (next((item for item in ranked if _is_authoritative_p3_match(item)), None)
                    if prior_status == "matched"
                    else next((item for item in ranked if _required_stages_complete(item, config)), None))
            return SearchResult(prior_status, ranked, tuple(attempts), best, artifact)
    else:
        baseline = Candidate(baseline_source, _source_sha256(baseline_source))
        candidates = {baseline.source_sha256: baseline}
        frontier = [baseline.source_sha256]
        attempts = []

    status: Optional[str] = None
    processed_pairs = {(str(item["parent_source_sha256"]), str(item["transform_sha256"])) for item in attempts}
    while frontier:
        current_sha = frontier.pop(0)
        current = candidates[current_sha]
        if current.evaluation is None:
            try:
                evaluation = _call(evaluate_candidate, (current, current.source))
            except Exception:
                status = "blocked"
                break
            if not isinstance(evaluation, CandidateEvaluation):
                raise TypeError("evaluate_candidate must return CandidateEvaluation")
            reasons = _prune_reasons(evaluation, objective, config)
            current = Candidate(current.source, current.source_sha256, current.transforms, current.parent_source_sha256, evaluation, reasons)
            candidates[current_sha] = current
            if evaluation.retail_status == "MATCH" and evaluation.retail_verifier == "p3" and evaluation.retail_authoritative:
                status = "matched"
                break
            if evaluation.blocked_reason is not None:
                status = "blocked"
                break
            if reasons:
                if checkpoint_path is not None:
                    save_checkpoint(checkpoint_path, _state_artifact(baseline_source, catalog, objective, config, candidates, frontier, attempts, None))
                continue
        if current.depth >= config.max_depth:
            continue
        enumerated = _call(enumerate_transforms, (current.source, catalog, current))
        try:
            transform_items = tuple(enumerated)
        except TypeError as exc:
            raise TypeError("enumerate_transforms must return an iterable") from exc
        for application in sorted(transform_items, key=_transform_key):
            spec_id, node_id = _application_identity(application)
            application_sha = _transform_key(application)
            pair = (current.source_sha256, application_sha)
            if pair in processed_pairs:
                continue
            processed_pairs.add(pair)
            attempt = {"parent_source_sha256": current.source_sha256, "transform_sha256": application_sha}
            chain_pairs = {
                _application_identity(previous)
                for previous in current.transforms
            }
            if (spec_id, node_id) in chain_pairs:
                attempts.append({**attempt, "outcome": "duplicate_application"})
                continue
            if spec_id not in catalog_by_id:
                attempts.append({**attempt, "outcome": "not_in_catalog"})
                continue
            try:
                child_source = _call(apply_transform, (current.source, application, current))
                if not isinstance(child_source, str):
                    raise TypeError("apply_transform must return source text")
                child_sha = _source_sha256(child_source)
            except Exception:
                attempts.append({**attempt, "outcome": "application_failed"})
                continue
            if child_sha in candidates:
                attempts.append({**attempt, "outcome": "duplicate_source"})
                continue
            if len(candidates) >= config.max_candidates:
                attempts.append({**attempt, "outcome": "candidate_limit"})
                status = "limit_reached"
                break
            child = Candidate(child_source, child_sha, current.transforms + (application,), current.source_sha256)
            candidates[child_sha] = child
            frontier.append(child_sha)
            attempts.append({**attempt, "outcome": "accepted"})
        if checkpoint_path is not None:
            save_checkpoint(checkpoint_path, _state_artifact(baseline_source, catalog, objective, config, candidates, frontier, attempts, status))
        if status == "limit_reached":
            break

    if status is None:
        status = "exhausted" if not frontier else "limit_reached"
    artifact = _state_artifact(baseline_source, catalog, objective, config, candidates, frontier, attempts, status)
    if checkpoint_path is not None:
        save_checkpoint(checkpoint_path, artifact)
    ranked = tuple(sorted(candidates.values(), key=lambda item: _rank(item, objective, config)))
    if status == "exhausted" and config.required_stages and not any(_required_stages_complete(item, config) for item in ranked):
        status = "blocked"
        artifact = _state_artifact(baseline_source, catalog, objective, config, candidates, frontier, attempts, status)
        if checkpoint_path is not None:
            save_checkpoint(checkpoint_path, artifact)
    best = (next((item for item in ranked if _is_authoritative_p3_match(item)), None)
            if status == "matched"
            else next((item for item in ranked if _required_stages_complete(item, config)), None))
    return SearchResult(status, ranked, tuple(attempts), best, artifact)
