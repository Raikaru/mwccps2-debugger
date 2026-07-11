"""Optional exact-b210 capture attachment for function dossiers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from solver.b210_evaluator import B210CandidateEvaluator, B210EvaluatorError


class CompilerCaptureError(ValueError):
    """A user-facing compiler capture configuration or execution failure."""


def capture_candidate(
    *,
    source_root: Path | str,
    source: Path | str,
    candidate_source: str,
    compiler: Path | str,
    gdb: Path | str,
    profile: Path | str,
    output_root: Path | str,
    timeout_seconds: int,
) -> dict[str, Any]:
    root = Path(source_root).resolve()
    source_path = Path(source)
    if not source_path.is_absolute():
        source_path = root / source_path
    try:
        evaluator = B210CandidateEvaluator(
            compiler=Path(compiler),
            gdb=Path(gdb),
            profile_path=Path(profile),
            compiler_flags=("-O2", f"-I{(root / 'include').resolve()}"),
            output_root=Path(output_root),
            timeout_seconds=timeout_seconds,
            source_root=root,
            original_source=source_path,
        )
        result = evaluator.evaluate(candidate_source, "dossier-candidate")
    except (B210EvaluatorError, OSError, UnicodeError, ValueError) as exc:
        raise CompilerCaptureError(str(exc)) from exc
    return {
        "schema": {"name": "mwccps2-b210-capture-attachment", "version": 1},
        "candidate_source_sha256": result.candidate_source_sha256,
        "configuration_sha256": result.configuration_sha256,
        "outcome": result.outcome,
        "error_kind": result.error_kind,
        "direct_object_sha256": result.direct_object_sha256,
        "instrumented_object_sha256": result.instrumented_object_sha256,
        "instrumentation_neutral": (
            result.direct_object_sha256 is not None
            and result.direct_object_sha256 == result.instrumented_object_sha256
        ),
        "stages": [
            {
                "stage": stage.stage,
                "status": stage.status,
                "occurrences": [list(item) for item in stage.occurrences],
            }
            for stage in result.stages
        ],
    }
