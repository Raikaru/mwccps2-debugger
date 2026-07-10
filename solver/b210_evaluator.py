"""Native b210 candidate evaluation boundary for the solver.

This module deliberately records only portable digests in its durable result.  The
objects and GDB snapshots used to derive those digests remain in a fresh build
subdirectory and are never evidence unless the direct and instrumented objects
are byte-identical.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Sequence
import uuid

import mwccps2_experiment as _experiment


SCHEMA_NAME = "mwccps2-b210-candidate-evaluation"
SCHEMA_VERSION = 1
RESULT_FILENAME = f"candidate-evaluation-v{SCHEMA_VERSION}.json"
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class B210EvaluatorError(RuntimeError):
    """Raised when an evaluator request or its durable artifact is unsafe."""


@dataclass(frozen=True)
class StageResult:
    """Portable digest summary for one configured snapshot stage.

    ``occurrences`` is ordered by the snapshot capture sequence.  Each entry is
    ``(sequence, normalized_stage_sha256, graph_sha256, pcode_text_sha256)``.
    """

    stage: str
    status: str
    occurrences: tuple[tuple[int, str, str, str], ...]


@dataclass(frozen=True)
class B210CandidateResult:
    """The portable outcome of a single candidate compilation."""

    candidate_id: str
    candidate_source_sha256: str
    configuration_sha256: str
    outcome: str
    direct_object_sha256: str | None
    instrumented_object_sha256: str | None
    stages: tuple[StageResult, ...]
    error_kind: str | None = None
    _snapshots: Mapping[str, Any] | None = field(default=None, repr=False, compare=False)


def compare(baseline: B210CandidateResult, candidate: B210CandidateResult) -> dict[str, Any]:
    """Compare two successful in-memory evaluations using the existing comparator."""
    if baseline._snapshots is None or candidate._snapshots is None:
        raise B210EvaluatorError("comparison requires in-memory snapshot data")
    if baseline.direct_object_sha256 is None or candidate.direct_object_sha256 is None:
        raise B210EvaluatorError("comparison requires direct object digests")
    return _experiment.compare_variant_to_baseline(
        baseline.candidate_id,
        baseline._snapshots,
        candidate.candidate_id,
        candidate._snapshots,
        {"object_sha256": baseline.direct_object_sha256},
        {"object_sha256": candidate.direct_object_sha256},
    )


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                           allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as exc:
        raise B210EvaluatorError(f"cannot canonicalize evaluator data: {exc}") from exc


def _digest(value: Any) -> str:
    return sha256(_canonical_bytes(value)).hexdigest()


def _is_absolute_host_path(value: str) -> bool:
    # PurePath is intentionally not used here: a Windows artifact can be read on
    # another host, where ``C:\\...`` would not be considered absolute.
    return value.startswith(("/", "\\")) or bool(re.match(r"[A-Za-z]:[\\/]", value))


def _portable(value: Any) -> Any:
    """Drop known volatile location/time fields and reject path-like values."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise B210EvaluatorError("fingerprint contains a non-string key")
            lowered = key.lower()
            # Probe reports the inspected executable as ``file``.  It is runtime
            # location data, not fingerprint evidence, and must never be durable.
            if lowered in {"path", "file", "captured_at", "created_at", "timestamp", "pe_timestamp"}:
                continue
            result[key] = _portable(child)
        return result
    if isinstance(value, (list, tuple)):
        return [_portable(child) for child in value]
    if isinstance(value, str) and _is_absolute_host_path(value):
        raise B210EvaluatorError("fingerprint contains a host absolute path")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise B210EvaluatorError("fingerprint contains a non-JSON value")


def _under(child: Path, parent: Path, what: str) -> Path:
    try:
        resolved = child.resolve()
        resolved.relative_to(parent.resolve())
    except (OSError, ValueError) as exc:
        raise B210EvaluatorError(f"{what} must be contained by its configured root") from exc
    return resolved


class B210CandidateEvaluator:
    """Evaluate full translation-unit candidate source under native b210 + GDB."""

    def __init__(
        self,
        compiler: Path,
        gdb: Path,
        profile_path: Path,
        compiler_flags: Sequence[str],
        output_root: Path,
        timeout_seconds: int,
        source_root: Path,
        original_source: Path,
    ) -> None:
        self._validate_platform()
        if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
            raise B210EvaluatorError("timeout_seconds must be a positive integer")
        self.compiler = Path(compiler)
        self.gdb = Path(gdb)
        self.profile_path = Path(profile_path)
        self.compiler_flags = tuple(str(flag) for flag in compiler_flags)
        self.timeout_seconds = timeout_seconds
        self.source_root = Path(source_root).resolve()
        self.original_source = _under(Path(original_source), self.source_root, "original source")
        if self.original_source.suffix.lower() != ".c" or not self.original_source.is_file():
            raise B210EvaluatorError("original_source must be an existing C source file")
        self.output_root = _under(Path(output_root), _experiment.BUILD_DIRECTORY, "output root")
        if self.output_root == _experiment.BUILD_DIRECTORY.resolve():
            raise B210EvaluatorError("output_root must be a fresh subdirectory of build")
        try:
            self.output_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise B210EvaluatorError(f"cannot create output root: {exc}") from exc
        self.profile, self.executable, self.probe = self._fingerprint()
        # Flags participate in the exact configuration identity, but may contain
        # include locations and therefore must not be serialized durably.
        self._configuration = _portable({
            "profile": self.profile,
            "executable": self.executable,
            "probe": self.probe,
            "compiler_flags_sha256": _digest(list(self.compiler_flags)),
        })
        self.configuration_sha256 = _digest(self._configuration)

    def _validate_platform(self) -> None:
        if os.name != "nt":
            raise B210EvaluatorError("B210CandidateEvaluator is available only on native Windows")

    def _fingerprint(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        try:
            return _experiment.fingerprint_b210(self.compiler, self.profile_path)
        except _experiment.ExperimentError as exc:
            raise B210EvaluatorError(f"exact b210 fingerprint rejected: {exc}") from exc

    def _compile_direct(self, source: Path, object_path: Path, work: Path) -> dict[str, Any]:
        return _experiment._compile_direct(self.compiler, self.compiler_flags, source, object_path, work, self.timeout_seconds)

    def _compile_with_snapshots(self, source: Path, object_path: Path, work: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        return _experiment._compile_with_snapshots(
            self.gdb, self.compiler, self.compiler_flags, source, object_path,
            self.profile_path, work, self.timeout_seconds, self.executable,
        )

    def evaluate(self, candidate_source: str, candidate_id: str) -> B210CandidateResult:
        if not isinstance(candidate_source, str):
            raise B210EvaluatorError("candidate_source must be text")
        try:
            source_bytes = candidate_source.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise B210EvaluatorError("candidate_source is not valid UTF-8") from exc
        if not isinstance(candidate_id, str) or _ID.fullmatch(candidate_id) is None:
            raise B210EvaluatorError("candidate_id must be a portable identifier")
        source_sha256 = sha256(source_bytes).hexdigest()
        # GDB command files and snapshot names extend this directory further on
        # Windows.  The complete hashes remain in the strictly validated result.
        candidate_directory = self.output_root / (
            f"{source_sha256[:16]}-{self.configuration_sha256[:16]}"
        )
        if candidate_directory.exists():
            return self._load_existing(candidate_directory, candidate_id, source_sha256)
        try:
            candidate_directory.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            raise B210EvaluatorError(f"cannot create candidate artifact directory: {exc}") from exc

        staged = self.original_source.with_name(
            f".permute_mwccsolve_snapshot_{uuid.uuid4().hex}.c"
        )
        direct: dict[str, Any] | None = None
        instrumented: dict[str, Any] | None = None
        snapshots: dict[str, Any] | None = None
        outcome = "compile_error"
        error_kind: str | None = None
        try:
            try:
                staged.write_bytes(source_bytes)
                direct = self._compile_direct(staged, candidate_directory / "direct.o", candidate_directory)
            except Exception as exc:  # runner seam errors must become durable outcomes
                outcome, error_kind = self._failure_outcome(exc, "compile")
            else:
                try:
                    instrumented, snapshots = self._compile_with_snapshots(
                        staged, candidate_directory / "instrumented.o", candidate_directory
                    )
                except Exception as exc:
                    outcome, error_kind = self._failure_outcome(exc, "snapshot")
                else:
                    if direct.get("object_sha256") != instrumented.get("object_sha256"):
                        outcome, error_kind = "object_mismatch", "object_invariant"
                    else:
                        stages = self._stage_results(snapshots)
                        # A configured stage can legitimately be absent at a given
                        # optimization level.  It is explicit unknown evidence,
                        # while incomplete/handler observations are inadmissible.
                        outcome = "partial" if any(
                            stage.status in {"partial", "handler"} for stage in stages
                        ) else "success"
                        error_kind = None if outcome == "success" else "partial_capture"
        finally:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise B210EvaluatorError(f"cannot remove staged candidate source: {exc}") from exc

        stages = self._stage_results(snapshots) if snapshots is not None and outcome in {"success", "partial"} else ()
        result = B210CandidateResult(
            candidate_id, source_sha256, self.configuration_sha256, outcome,
            self._object_sha(direct), self._object_sha(instrumented), stages, error_kind,
            snapshots if outcome == "success" else None,
        )
        self._write_result(candidate_directory / RESULT_FILENAME, result)
        return result

    @staticmethod
    def _object_sha(value: Mapping[str, Any] | None) -> str | None:
        digest = None if value is None else value.get("object_sha256")
        return digest if isinstance(digest, str) and _SHA256.fullmatch(digest) else None

    @staticmethod
    def _failure_outcome(exc: Exception, phase: str) -> tuple[str, str]:
        message = str(exc).lower()
        if isinstance(exc, TimeoutError) or "timeout" in message or "exceeded" in message:
            return "timeout", f"{phase}_timeout"
        if phase == "snapshot" and ("gdb" in message or "transport" in message):
            return "gdb_error", "gdb"
        if phase == "snapshot" and "instrumentation" in message:
            return "instrumentation_error", "instrumentation"
        return ("compile_error" if phase == "compile" else "snapshot_error"), phase

    @staticmethod
    def _stage_results(snapshots: Mapping[str, Any] | None) -> tuple[StageResult, ...]:
        if snapshots is None:
            return ()
        order = snapshots.get("stage_order")
        captures = snapshots.get("stages")
        if not isinstance(order, list) or not isinstance(captures, list):
            raise B210EvaluatorError("snapshot runner returned an invalid snapshot structure")
        grouped: dict[str, list[Mapping[str, Any]]] = {str(name): [] for name in order}
        for capture in captures:
            if not isinstance(capture, Mapping) or not isinstance(capture.get("stage"), str):
                raise B210EvaluatorError("snapshot runner returned an invalid stage")
            grouped.setdefault(capture["stage"], []).append(capture)
        results: list[StageResult] = []
        for name in [*map(str, order), *(key for key in grouped if key not in order)]:
            entries = sorted(grouped[name], key=lambda entry: int(entry.get("sequence", 0)))
            if not entries:
                results.append(StageResult(name, "missing", ()))
                continue
            statuses = [str(entry.get("capture_status", "")) for entry in entries]
            status = "complete" if all(item in {"complete", "completed"} for item in statuses) else (
                "handler" if any("handler" in item for item in statuses) else "partial"
            )
            digests: list[tuple[int, str, str, str]] = []
            for entry in entries:
                try:
                    occurrence = (int(entry["sequence"]), str(entry["normalized_stage_sha256"]),
                                  str(entry["graph_sha256"]), str(entry["pcode_text_sha256"]))
                except (KeyError, TypeError, ValueError) as exc:
                    raise B210EvaluatorError("snapshot runner omitted normalized stage digests") from exc
                if any(_SHA256.fullmatch(digest) is None for digest in occurrence[1:]):
                    raise B210EvaluatorError("snapshot runner returned malformed stage digests")
                digests.append(occurrence)
            results.append(StageResult(name, status, tuple(digests)))
        return tuple(results)

    def _result_document(self, result: B210CandidateResult) -> dict[str, Any]:
        return {
            "schema": {"name": SCHEMA_NAME, "version": SCHEMA_VERSION},
            "candidate": {"id": result.candidate_id, "source_sha256": result.candidate_source_sha256},
            "configuration": {"sha256": result.configuration_sha256, "fingerprint": self._configuration},
            "outcome": result.outcome,
            "error_kind": result.error_kind,
            "objects": {"direct_sha256": result.direct_object_sha256,
                        "instrumented_sha256": result.instrumented_object_sha256},
            "stages": [
                {"stage": stage.stage, "status": stage.status,
                 "occurrences": [list(item) for item in stage.occurrences]}
                for stage in result.stages
            ],
        }

    def _write_result(self, path: Path, result: B210CandidateResult) -> None:
        payload = _canonical_bytes(self._result_document(result))
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
                                             delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(payload)
            temporary.replace(path)
        except OSError as exc:
            raise B210EvaluatorError(f"cannot atomically write candidate result: {exc}") from exc
        finally:
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

    def _load_existing(self, directory: Path, candidate_id: str, source_sha256: str) -> B210CandidateResult:
        result_path = directory / RESULT_FILENAME
        if not result_path.is_file() or any(child.name != RESULT_FILENAME for child in directory.iterdir()
                                            if child.is_file() and child.suffix == ".json"):
            raise B210EvaluatorError("candidate artifact directory is partial or does not contain exactly one result")

        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise B210EvaluatorError("existing candidate result has duplicate JSON keys")
                result[key] = value
            return result

        def exact(value: Any, keys: set[str], context: str) -> dict[str, Any]:
            if not isinstance(value, dict) or set(value) != keys:
                raise B210EvaluatorError(f"{context} has an invalid field set")
            return value

        def digest(value: Any, context: str, nullable: bool = False) -> str | None:
            if value is None and nullable:
                return None
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise B210EvaluatorError(f"{context} must be a lowercase SHA-256 digest")
            return value

        try:
            raw_bytes = result_path.read_bytes()
            raw = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=no_duplicates)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise B210EvaluatorError("existing candidate result is unreadable") from exc
        if _canonical_bytes(raw) != raw_bytes:
            raise B210EvaluatorError("existing candidate result is not strict canonical JSON")
        root = exact(raw, {"schema", "candidate", "configuration", "outcome", "error_kind", "objects", "stages"},
                     "existing candidate result")
        if exact(root["schema"], {"name", "version"}, "schema") != {"name": SCHEMA_NAME, "version": SCHEMA_VERSION}:
            raise B210EvaluatorError("existing candidate result has the wrong schema")
        if exact(root["candidate"], {"id", "source_sha256"}, "candidate") != {
            "id": candidate_id, "source_sha256": source_sha256,
        }:
            raise B210EvaluatorError("existing candidate result has mismatched candidate hashes")
        if exact(root["configuration"], {"sha256", "fingerprint"}, "configuration") != {
            "sha256": self.configuration_sha256, "fingerprint": self._configuration,
        }:
            raise B210EvaluatorError("existing candidate result has mismatched configuration hashes")
        outcome = root["outcome"]
        error_kind = root["error_kind"]
        outcomes = {"success", "partial", "compile_error", "timeout", "gdb_error",
                    "instrumentation_error", "snapshot_error", "object_mismatch"}
        if outcome not in outcomes or (error_kind is not None and (
                not isinstance(error_kind, str) or not re.fullmatch(r"[a-z][a-z0-9_:-]*", error_kind))):
            raise B210EvaluatorError("existing candidate result has an invalid outcome")
        objects = exact(root["objects"], {"direct_sha256", "instrumented_sha256"}, "objects")
        direct = digest(objects["direct_sha256"], "direct object", True)
        instrumented = digest(objects["instrumented_sha256"], "instrumented object", True)
        if not isinstance(root["stages"], list):
            raise B210EvaluatorError("existing candidate result stages must be an array")
        stages_list: list[StageResult] = []
        stage_names: set[str] = set()
        for index, item in enumerate(root["stages"]):
            entry = exact(item, {"stage", "status", "occurrences"}, f"stages[{index}]")
            name, status, occurrences = entry["stage"], entry["status"], entry["occurrences"]
            if not isinstance(name, str) or not name or name in stage_names:
                raise B210EvaluatorError("existing candidate result has invalid or repeated stages")
            if status not in {"complete", "missing", "partial", "handler"} or not isinstance(occurrences, list):
                raise B210EvaluatorError("existing candidate result has invalid stage status")
            parsed_occurrences: list[tuple[int, str, str, str]] = []
            previous = 0
            for occurrence in occurrences:
                if not isinstance(occurrence, list) or len(occurrence) != 4:
                    raise B210EvaluatorError("existing candidate result has invalid stage occurrence")
                sequence = occurrence[0]
                if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1 or sequence <= previous:
                    raise B210EvaluatorError("existing candidate result has unordered stage occurrences")
                parsed = (sequence, digest(occurrence[1], "normalized stage"), digest(occurrence[2], "graph"),
                          digest(occurrence[3], "PCode text"))
                parsed_occurrences.append((parsed[0], parsed[1], parsed[2], parsed[3]))  # type: ignore[arg-type]
                previous = sequence
            if (status == "missing") != (not parsed_occurrences):
                raise B210EvaluatorError("existing candidate result has inconsistent missing stage")
            stage_names.add(name)
            stages_list.append(StageResult(name, status, tuple(parsed_occurrences)))
        stages = tuple(stages_list)
        if outcome == "success":
            if error_kind is not None or direct is None or direct != instrumented or any(
                    stage.status in {"partial", "handler"} for stage in stages):
                raise B210EvaluatorError("existing successful candidate result violates object or stage invariants")
            try:
                snapshots: Mapping[str, Any] | None = _experiment.parse_snapshot_run(
                    directory / "snapshots", self.executable
                )
            except _experiment.ExperimentError as exc:
                raise B210EvaluatorError("existing successful candidate snapshots are invalid") from exc
            if self._stage_results(snapshots) != stages:
                raise B210EvaluatorError("existing successful candidate result disagrees with retained snapshots")
        elif outcome == "partial":
            if error_kind != "partial_capture" or not any(
                    stage.status in {"partial", "handler"} for stage in stages):
                raise B210EvaluatorError("existing partial candidate result violates stage invariants")
            snapshots = None
        else:
            expected_errors = {
                "compile_error": {"compile"},
                "timeout": {"compile_timeout", "snapshot_timeout"},
                "gdb_error": {"gdb"},
                "instrumentation_error": {"instrumentation"},
                "snapshot_error": {"snapshot"},
                "object_mismatch": {"object_invariant"},
            }
            if error_kind not in expected_errors[outcome] or stages:
                raise B210EvaluatorError("existing failure result contains inadmissible evidence")
            snapshots = None
        return B210CandidateResult(candidate_id, source_sha256, self.configuration_sha256, outcome,
                                   direct, instrumented, stages, error_kind, snapshots)
