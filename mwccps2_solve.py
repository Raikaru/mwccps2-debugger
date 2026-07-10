"""Bounded, evidence-guided MWCCPS2 source mismatch solver.

This is deliberately an orchestration boundary: source rewrites and search are pure,
while compiler capture and retail verification remain optional evidence providers.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
from typing import Any, Mapping, Sequence

from decomp.c_ast import CParseError, parse_c
from decomp import mwccps2_transforms as transforms
from decomp.source_transforms import TransformApplication, apply_applications
from solver.search import (Candidate, CandidateEvaluation, Objective, SearchConfig,
                           SearchResult, StageObjective, StageObservation, run_search,
                           sha256_json)
from solver.evidence import (CaptureGapRejection, EvidenceError, FailureRecord, SolverEvidence,
                             StageEvidence, canonical_json, derive_capture_gap_requests,
                             write_solver_evidence)
from solver.p3_verify import P3VerifierConfigurationError, verify_candidate
try:
    from solver.b210_evaluator import (B210CandidateEvaluator, B210CandidateResult, StageResult,
                                       compare as compare_captures)
except ImportError:  # Allows offline import on hosts without the optional runner.
    B210CandidateEvaluator = None  # type: ignore[assignment,misc]
    B210CandidateResult = Any  # type: ignore[misc,assignment]
    StageResult = Any  # type: ignore[misc,assignment]
    compare_captures = None  # type: ignore[assignment]

SUMMARY_NAME = "solve-summary-v1.json"
EVIDENCE_NAME = "solver-evidence-v1.json"
CHECKPOINT_NAME = "search-checkpoint-v1.json"
RUN_IDENTITY_NAME = "run-identity-v1.json"

_BUILD_ROOT = Path(__file__).resolve().parent / "build"


class SolveError(ValueError):
    """A deterministic user/configuration error (never a false solver result)."""


@dataclass(frozen=True)
class SolveConfig:
    source: Path
    function: str
    max_depth: int = 1
    max_candidates: int = 100
    transforms: tuple[str, ...] = ()
    include_disabled: bool = False
    allow_assumptions: bool = False
    integer_type: str | None = None
    required_stages: tuple[str, ...] = ()
    stage_objectives: tuple[str, ...] = ()
    output: Path | None = None
    resume: bool = False
    p3_root: Path | None = None
    address: str | None = None
    python: str = sys.executable
    verifier: str = "tools/verify.py"
    verifier_timeout: float = 60.0
    compiler: Path | None = None
    gdb: Path | None = None
    profile: Path | None = None
    capture_timeout: int = 60
    compiler_flags: tuple[str, ...] = ()
    source_root: Path | None = None


def _digest_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _under(child: Path, parent: Path, label: str) -> Path:
    try:
        resolved = child.resolve()
        resolved.relative_to(parent.resolve())
    except (OSError, ValueError) as exc:
        raise SolveError(f"{label} must be contained by {parent}") from exc
    return resolved


def _config_from(value: SolveConfig | argparse.Namespace | Mapping[str, Any]) -> SolveConfig:
    if isinstance(value, SolveConfig):
        return value
    raw = vars(value) if isinstance(value, argparse.Namespace) else dict(value)
    # argparse uses singular repeatable option destinations.
    aliases = {"transform": "transforms", "stage_objective": "stage_objectives",
               "compiler_flag": "compiler_flags"}
    cooked = {aliases.get(key, key): item for key, item in raw.items()}
    path_fields = {"source", "output", "p3_root", "compiler", "gdb", "profile", "source_root"}
    for key in path_fields:
        if key in cooked and cooked[key] is not None and not isinstance(cooked[key], Path):
            cooked[key] = Path(cooked[key])
    for key in ("transforms", "required_stages", "stage_objectives", "compiler_flags"):
        if key in cooked and cooked[key] is not None:
            cooked[key] = tuple(cooked[key])
    known = set(SolveConfig.__dataclass_fields__)
    return SolveConfig(**{key: item for key, item in cooked.items() if key in known})


def _application_json(app: TransformApplication) -> dict[str, Any]:
    return {"assumptions": list(app.assumptions), "end": app.end, "node_id": app.node_id,
            "rejection": app.rejection, "replacement": app.replacement, "spec_id": app.spec_id,
            "start": app.start, "status": app.status}


def _application_from(raw: Mapping[str, Any]) -> TransformApplication:
    expected = {"assumptions", "end", "node_id", "rejection", "replacement", "spec_id", "start", "status"}
    if set(raw) != expected or not isinstance(raw["assumptions"], list):
        raise SolveError("invalid serialized transform application")
    try:
        return TransformApplication(raw["spec_id"], raw["node_id"], raw["start"], raw["end"],
                                    raw["replacement"], tuple(raw["assumptions"]), raw["status"], raw["rejection"])
    except (TypeError, ValueError) as exc:
        raise SolveError("invalid serialized transform application") from exc


def _objectives(entries: Sequence[str]) -> Objective:
    items: list[StageObjective] = []
    for entry in entries:
        if not isinstance(entry, str) or entry.count("=") != 1:
            raise SolveError("--stage-objective must be STAGE=SHA256")
        stage, digest = entry.split("=", 1)
        try:
            items.append(StageObjective(stage, digest, True))
        except ValueError as exc:
            raise SolveError("--stage-objective must be STAGE=SHA256") from exc
    try:
        return Objective(tuple(items))
    except ValueError as exc:
        raise SolveError(str(exc)) from exc


def _catalog(config: SolveConfig) -> tuple[dict[str, Any], ...]:
    available = {spec.id: spec for spec in transforms.catalog()}
    requested = config.transforms or tuple(spec.id for spec in transforms.catalog())
    if len(set(requested)) != len(requested):
        raise SolveError("transform IDs must be unique")
    unknown = sorted(set(requested) - set(available))
    if unknown:
        raise SolveError("unknown transform ID: " + ", ".join(unknown))
    selected = [available[identifier] for identifier in requested]
    if not config.include_disabled:
        selected = [spec for spec in selected if spec.default_search]
    return tuple(sorted((spec.manifest() for spec in selected), key=lambda item: str(item["id"])))


def _prepare_output(config: SolveConfig, source_sha: str) -> Path:
    root = _BUILD_ROOT.resolve()
    output = config.output
    if output is None:
        output = root / ("solve-" + source_sha[:16])
    elif not output.is_absolute():
        # ``--output build/<run>`` is relative to this debugger, irrespective of
        # the invoking shell's current directory.
        output = ((root.parent / output) if output.parts and output.parts[0] == "build" else (root / output))
    output = output.resolve()
    _under(output, root, "output")
    if config.resume:
        if not output.is_dir() or not (output / CHECKPOINT_NAME).is_file():
            raise SolveError("--resume requires an existing solver output with a checkpoint")
    else:
        if output.exists():
            raise SolveError("output already exists; use --resume to continue it")
        output.mkdir(parents=True, exist_ok=False)
    return output



def _file_sha256(path: Path) -> str | None:
    try:
        return sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    except OSError:
        return None


def _command_sha256(command: Path | str) -> str:
    candidate = Path(command)
    if candidate.is_file():
        digest = _file_sha256(candidate.resolve())
        if digest is not None:
            return digest
    located = shutil.which(str(command))
    if located:
        digest = _file_sha256(Path(located))
        if digest is not None:
            return digest
    # A content digest is preferred, but an opaque command digest still detects
    # a configured interpreter/command change without retaining its path.
    return _digest_text(str(command))




def _run_identity(baseline: str, catalog: Sequence[Mapping[str, Any]], objective: Objective,
                  search_config: SearchConfig, config: SolveConfig, p3_requested: bool,
                  capture_requested: bool, evaluator: Any, compiler_flags: Sequence[str]) -> dict[str, Any]:
    """Bind every authority/configuration input without retaining host paths."""
    identity: dict[str, Any] = {
        "schema": {"name": "mwccps2-solver-run-identity", "version": 1},
        "baseline_sha256": _digest_text(baseline), "catalog_sha256": sha256_json(list(catalog)),
        "search_config_sha256": sha256_json(search_config.to_json()),
        "objective_sha256": sha256_json(objective.to_json()), "function": config.function,
        "allow_assumptions": config.allow_assumptions, "include_disabled": config.include_disabled,
        "integer_type": config.integer_type, "p3_enabled": p3_requested,
        "capture_enabled": capture_requested,
    }
    if p3_requested:
        root = config.p3_root.resolve()
        verifier = Path(config.verifier)
        verifier = (root / verifier if not verifier.is_absolute() else verifier).resolve()
        files = [*sorted(root.rglob("verify_config*.json")), root / "tools" / "slus21621_functions.json"]
        env_keys = sorted({"P3_MWCC", "P3_RETAIL_ELF", *(
            key for key in os.environ if "VERIFIER" in key.upper())})
        env_values = {key: os.environ.get(key, "") for key in env_keys}
        identity["p3"] = {
            "address": config.address.lower().removeprefix("0x"),
            "verifier": verifier.relative_to(root).as_posix(),
            "verifier_sha256": _file_sha256(verifier),
            "python_sha256": _command_sha256(config.python),
            "authority_files": sorted(filter(None, (_file_sha256(item) for item in files))),
            "environment_value_sha256": {key: _digest_text(value) for key, value in env_values.items()},
            "environment_file_sha256": {
                key: digest for key, value in env_values.items()
                for digest in (_file_sha256(Path(value)),) if digest is not None
            },
        }
    if capture_requested:
        identity["capture"] = {
            "configuration_sha256": getattr(evaluator, "configuration_sha256", None),
            "compiler_flags_sha256": _digest_text("\0".join(compiler_flags)),
            "timeout": config.capture_timeout,
            "gdb_sha256": _command_sha256(config.gdb),
        }
    return identity


def _json_text(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False) + "\n"


def _check_or_write_identity(output: Path, resume: bool, identity: Mapping[str, Any]) -> None:
    path = output / RUN_IDENTITY_NAME
    payload = _json_text(identity)
    if resume:
        try:
            existing = path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise SolveError("resume identity is missing or unreadable") from exc
        if existing != payload:
            raise SolveError("resume configuration differs from the original run")
    else:
        path.write_text(payload, encoding="ascii", newline="")


def _stage_digest(stage: StageResult) -> str:
    # Ordered occurrences are the actual observation identity; do not infer equality
    # from individual digest coincidences.
    return sha256_json([[sequence, normalized, graph, pcode] for sequence, normalized, graph, pcode in stage.occurrences])


def _stage_observations(result: B210CandidateResult | None) -> tuple[StageObservation, ...]:
    if result is None:
        return ()
    observed: list[StageObservation] = []
    for stage in sorted(result.stages, key=lambda item: item.stage):
        if stage.status == "complete":
            observed.append(StageObservation(stage.stage, "complete", _stage_digest(stage)))
        elif stage.status in {"partial", "missing"}:
            observed.append(StageObservation(stage.stage, stage.status))
        else:
            observed.append(StageObservation(stage.stage, "unknown"))
    return tuple(observed)


def _stage_evidence(result: B210CandidateResult | None) -> tuple[StageEvidence, ...]:
    if result is None:
        return ()
    records: list[StageEvidence] = []
    for stage in result.stages:
        # Partial/handler stages are retained as observations but never admitted
        # with a digest as complete evidence.
        if stage.status != "complete":
            records.append(StageEvidence(stage.stage, 0, stage.status, None, None, None))
            continue
        for sequence, normalized, graph, pcode in stage.occurrences:
            records.append(StageEvidence(stage.stage, sequence, "complete", normalized, graph, pcode))
    return tuple(sorted(records, key=lambda item: (item.stage, item.occurrence)))


def _safe_reason(value: str | None, fallback: str) -> str:
    text = (value or fallback).lower().replace("-", "_").replace(" ", "_")
    return "".join(char for char in text if char.isalnum() or char in "_:") or fallback


def solve(args: SolveConfig | argparse.Namespace | Mapping[str, Any]) -> dict[str, Any]:
    """Run the bounded solver and write portable summary/evidence artifacts.

    Returns the parsed summary document so callers need not parse a host artifact.
    """
    config = _config_from(args)
    source = config.source.resolve()
    if not source.is_file() or source.suffix.lower() != ".c":
        raise SolveError("source must be an existing C source file")
    if not config.function:
        raise SolveError("function must be non-empty")
    if config.max_depth < 0 or config.max_candidates < 1:
        raise SolveError("max depth and candidates must be positive bounds")
    capture_requested = any(item is not None for item in (config.compiler, config.gdb, config.profile))
    if capture_requested and not all(item is not None for item in (config.compiler, config.gdb, config.profile)):
        raise SolveError("capture mode requires --compiler, --gdb, and --profile")
    p3_requested = config.p3_root is not None or config.address is not None
    if p3_requested and (config.p3_root is None or config.address is None):
        raise SolveError("P3 mode requires both --p3-root and --address")
    if not capture_requested and not p3_requested:
        raise SolveError("select at least one evaluation mode: P3 verification or b210 capture")
    if p3_requested:
        _under(source, config.p3_root.resolve(), "source")
    source_root = (config.source_root or config.p3_root)
    if capture_requested:
        if source_root is None:
            raise SolveError("capture mode requires --source-root or --p3-root")
        _under(source, source_root.resolve(), "source")

    try:
        baseline = source.read_text(encoding="utf-8")
        unit = parse_c(baseline)
    except (OSError, UnicodeError, CParseError) as exc:
        raise SolveError(f"cannot parse source: {exc}") from exc
    if sum(function.name == config.function for function in unit.functions) != 1:
        raise SolveError("function name must identify exactly one parsed function")
    function = next(function for function in unit.functions if function.name == config.function)
    catalog = _catalog(config)
    objective = _objectives(config.stage_objectives)
    try:
        search_config = SearchConfig(config.max_depth, config.max_candidates, False, tuple(config.required_stages))
    except (TypeError, ValueError) as exc:
        raise SolveError(str(exc)) from exc
    output = _prepare_output(config, _digest_text(baseline))
    evaluator = None
    baseline_capture = None
    if capture_requested:
        if B210CandidateEvaluator is None:
            raise SolveError("b210 evaluator is unavailable")
        flags = tuple(config.compiler_flags) or ("-O2",)
        # Root paths are runtime-only evaluator input and never serialized.
        if config.p3_root is not None:
            flags += ("-I" + str(config.p3_root.resolve() / "include"),)
        try:
            evaluator = B210CandidateEvaluator(config.compiler, config.gdb, config.profile, flags,
                                               output / "b210", config.capture_timeout,
                                               source_root.resolve(), source)
            baseline_capture = evaluator.evaluate(baseline, "c" + _digest_text(baseline)[:24])
        except Exception as exc:
            # Preserve an operational failure as a blocked search outcome, rather
            # than allowing a missing baseline to become fake evidence.
            baseline_capture = None
            evaluator_error = _safe_reason(str(exc), "capture_initialization")
        else:
            evaluator_error = None
    else:
        evaluator_error = None

    selected_ids = {item["id"] for item in catalog}
    observed_captures: dict[str, B210CandidateResult | None] = {}
    _check_or_write_identity(output, config.resume,
                             _run_identity(baseline, catalog, objective, search_config, config,
                                           p3_requested, capture_requested, evaluator,
                                           flags if capture_requested else ()))

    if baseline_capture is not None:
        observed_captures[_digest_text(baseline)] = baseline_capture
    p3_results: dict[str, Any] = {}

    def enumerate_transforms(candidate_source: str, _catalog_data: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
        candidate_unit = parse_c(candidate_source)
        current_function = [item for item in candidate_unit.functions if item.name == config.function]
        if len(current_function) != 1:
            return ()
        scope = current_function[0]
        apps = transforms.enumerate_candidates(candidate_unit, include_disabled=config.include_disabled,
                                               integer_type=config.integer_type)
        return tuple(_application_json(app) for app in apps
                     if app.spec_id in selected_ids and app.status != "rejected"
                     and (app.status != "assumption_required" or config.allow_assumptions)
                     and scope.body_start <= app.start and app.end <= scope.body_end)

    def apply_transform(candidate_source: str, raw: Mapping[str, Any]) -> str:
        application = _application_from(raw)
        candidate_unit = parse_c(candidate_source)
        result = apply_applications(candidate_unit, (application,), allow_assumptions=config.allow_assumptions)
        if result.rejected or len(result.applications) != 1:
            raise SolveError("transform application was rejected")
        return result.source

    def evaluate(candidate: Candidate) -> CandidateEvaluation:
        capture = None
        blocked = evaluator_error
        if evaluator is not None and blocked is None:
            capture = observed_captures.get(candidate.source_sha256)
            if capture is None:
                try:
                    capture = evaluator.evaluate(candidate.source, "c" + candidate.source_sha256[:24])
                    observed_captures[candidate.source_sha256] = capture
                except Exception as exc:
                    blocked = _safe_reason(str(exc), "capture_failure")
                    observed_captures[candidate.source_sha256] = None
            if capture is not None and capture.outcome != "success":
                blocked = _safe_reason(capture.error_kind or capture.outcome, "capture_failure")
        retail_status, retail_diff, verifier, authoritative = "UNKNOWN", None, None, False
        if p3_requested:
            try:
                result = verify_candidate(config.p3_root, source, candidate.source, config.function,
                                          config.address, config.python, config.verifier_timeout, config.verifier)
                p3_results[candidate.source_sha256] = result
                verifier, authoritative, retail_diff = "p3", True, result.normalized_diff
                retail_status = "MATCH" if result.row_status == "MATCH" else (
                    "NON_MATCH" if result.row_status is not None else "UNKNOWN")
                capture_policy = bool(search_config.required_stages or objective.stages)
                if result.row_status == "MATCH":
                    blocked = None
                elif blocked is not None and not capture_policy and result.row_status is not None:
                    blocked = None
                elif result.error is not None and result.row_status is None:
                    blocked = _safe_reason(result.error, "p3_failure")
            except (P3VerifierConfigurationError, OSError, ValueError) as exc:
                blocked = _safe_reason(str(exc), "p3_failure")
        return CandidateEvaluation(_stage_observations(capture), retail_status, verifier,
                                   authoritative, retail_diff, blocked)

    result = run_search(baseline, catalog, enumerate_transforms, apply_transform, evaluate,
                        objective, search_config, checkpoint_path=output / CHECKPOINT_NAME,
                        resume=config.resume)
    summary = _write_artifacts(output, baseline, catalog, objective, search_config, result,
                               observed_captures, baseline_capture, p3_results, evaluator)
    return summary



def _capture_summary_variant(name: str, result: B210CandidateResult) -> dict[str, Any]:
    snapshots = result._snapshots
    if not isinstance(snapshots, Mapping):
        raise SolveError("successful capture has no in-memory snapshots")
    return {"name": name, "snapshot_compile": {
        "matches_direct_object": result.direct_object_sha256 == result.instrumented_object_sha256,
        "stages": list(snapshots.get("stages", ())),
    }}


def _profile_stage_addresses(profile: Mapping[str, Any]) -> dict[str, str]:
    """Return only addresses explicitly configured by the b210 profile."""
    addresses: dict[str, str] = {}
    functions = profile.get("functions")
    if isinstance(functions, Mapping):
        codegen = functions.get("CodeGen_Generator")
        if isinstance(codegen, Mapping) and isinstance(codegen.get("address"), str):
            addresses["codegen_entry"] = codegen["address"]
    breakpoints = profile.get("pcode_breakpoints")
    if isinstance(breakpoints, Mapping):
        for stage, point in breakpoints.items():
            address = point.get("address") if isinstance(point, Mapping) else point
            if isinstance(stage, str) and isinstance(address, str):
                addresses[stage] = address
    return addresses


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    encoded = _json_text(value).encode("ascii")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass

def _write_artifacts(output: Path, baseline: str, catalog: Sequence[Mapping[str, Any]], objective: Objective,
                     config: SearchConfig, result: SearchResult,
                     captures: Mapping[str, B210CandidateResult | None], baseline_capture: B210CandidateResult | None,
                     p3_results: Mapping[str, Any], evaluator: Any) -> dict[str, Any]:
    best = result.best_candidate
    certified = bool(best and best.evaluation and best.evaluation.retail_status == "MATCH"
                     and best.evaluation.retail_verifier == "p3" and best.evaluation.retail_authoritative)
    artifact = "solution.c" if certified else ("best-candidate.c" if best is not None else None)
    if best is not None:
        (output / artifact).write_text(best.source, encoding="utf-8", newline="")
    failures: list[FailureRecord] = []
    requests = []
    rejections: list[CaptureGapRejection] = []
    for candidate in result.candidates:
        evaluation = candidate.evaluation
        if evaluation is None:
            continue
        capture = captures.get(candidate.source_sha256)
        p3_result = p3_results.get(candidate.source_sha256)
        capture_failed = capture is not None and capture.outcome != "success"
        p3_non_match = (evaluation.retail_verifier == "p3" and evaluation.retail_authoritative
                        and evaluation.retail_status == "NON_MATCH")
        rejected = bool(candidate.rejections)
        if not (evaluation.blocked_reason or capture_failed or p3_non_match or rejected):
            continue
        reason = (evaluation.blocked_reason or ("capture_failure" if capture_failed else
                  ("search_rejected" if rejected else "retail_unmatched")))
        error_kind = getattr(capture, "error_kind", None) or getattr(p3_result, "error", None)
        failures.append(FailureRecord(
            candidate.source_sha256, candidate.source_sha256,
            tuple(str(item["spec_id"]) for item in candidate.transforms), "failed",
            _safe_reason(reason, "retail_unmatched"),
            None if error_kind is None else _safe_reason(error_kind, "operational"),
            None if capture is None or baseline_capture is None else (
                capture.direct_object_sha256 == baseline_capture.direct_object_sha256),
            None if capture is None or baseline_capture is None else (
                capture.instrumented_object_sha256 == baseline_capture.instrumented_object_sha256),
            _stage_evidence(capture)))
    if baseline_capture is not None and baseline_capture.outcome == "success" and evaluator is not None:
        profile = getattr(evaluator, "profile", {})
        executable = getattr(evaluator, "executable", {})
        profile_name = profile.get("name") if isinstance(profile, Mapping) else None
        profile_sha = executable.get("sha256") if isinstance(executable, Mapping) else None
        if not isinstance(profile_name, str) or not profile_name:
            profile_name = "b210"
        if not isinstance(profile_sha, str) or len(profile_sha) != 64:
            profile_sha = sha256_json(profile if isinstance(profile, Mapping) else {})
        for candidate in result.candidates:
            capture = captures.get(candidate.source_sha256)
            if (candidate.source_sha256 == baseline_capture.candidate_source_sha256 or capture is None
                    or capture.outcome != "success" or capture._snapshots is None
                    or compare_captures is None):
                continue
            experiment_summary = {
                "schema": {"name": "mwccps2-experiment-summary", "version": 1},
                "variants": [_capture_summary_variant(baseline_capture.candidate_id, baseline_capture),
                             _capture_summary_variant(capture.candidate_id, capture)],
                "comparisons": [compare_captures(baseline_capture, capture)],
            }
            try:
                derived_requests, derived_rejections = derive_capture_gap_requests(
                    experiment_summary, profile_name=profile_name, profile_sha256=profile_sha,
                    stage_addresses=_profile_stage_addresses(profile if isinstance(profile, Mapping) else {}))
            except EvidenceError as exc:
                raise SolveError(f"cannot derive capture-gap evidence: {exc}") from exc
            requests.extend(derived_requests)
            rejections.extend(derived_rejections)
    evidence = SolverEvidence(
        tuple(sorted(failures, key=lambda item: item.candidate_sha256)),
        tuple(sorted(set(requests), key=lambda item: (item.comparison_sha256, item.stage))),
        tuple(sorted(set(rejections), key=lambda item: (item.comparison_sha256, item.stage or "", item.reason))),
    )
    write_solver_evidence(output / EVIDENCE_NAME, evidence)
    _atomic_json(output / EVIDENCE_NAME, evidence.to_json())
    summary = {"schema": {"name": "mwccps2-solver-summary", "version": 1}, "termination": result.status,
               "baseline_sha256": _digest_text(baseline), "catalog_sha256": sha256_json(list(catalog)),
               "config_sha256": sha256_json(config.to_json()), "objective_sha256": sha256_json(objective.to_json()),
               "candidate_counts": {"candidates": len(result.candidates), "attempts": len(result.attempts)},
               "best_source_sha256": None if best is None else best.source_sha256,
               "best_retail_status": None if best is None or best.evaluation is None else best.evaluation.retail_status,
               "best_retail_diff": None if best is None or best.evaluation is None else best.evaluation.retail_diff,
               "matched": certified, "artifacts": {"checkpoint": CHECKPOINT_NAME, "evidence": EVIDENCE_NAME, "source": artifact}}
    _atomic_json(output / SUMMARY_NAME, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("function")
    parser.add_argument("--max-depth", type=int, default=1)
    parser.add_argument("--max-candidates", type=int, default=100)
    parser.add_argument("--transform", action="append", default=[])
    parser.add_argument("--include-disabled", action="store_true")
    parser.add_argument("--allow-assumptions", action="store_true")
    parser.add_argument("--integer-type")
    parser.add_argument("--required-stage", action="append", default=[])
    parser.add_argument("--stage-objective", action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--p3-root", type=Path)
    parser.add_argument("--address")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--verifier", default="tools/verify.py")
    parser.add_argument("--verifier-timeout", type=float, default=60.0)
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--gdb", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--capture-timeout", type=int, default=60)
    parser.add_argument("--compiler-flag", action="append", default=[])
    parser.add_argument("--source-root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        summary = solve(build_parser().parse_args(argv))
    except (SolveError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: operational failure: {exc}", file=sys.stderr)
        return 1
    print(canonical_json(summary))
    return 0 if summary["termination"] in {"matched", "exhausted", "limit_reached"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
