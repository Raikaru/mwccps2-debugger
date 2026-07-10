"""Deterministic evidence-guided source search primitives."""

from .search import (
    Candidate,
    CandidateEvaluation,
    Objective,
    SearchConfig,
    SearchResult,
    SearchStateError,
    STATE_SCHEMA,
    STATE_VERSION,
    StageObjective,
    StageObservation,
    apply_checkpoint,
    canonical_json,
    load_checkpoint,
    run_search,
    save_checkpoint,
    sha256_json,
)

__all__ = [
    "Candidate",
    "CandidateEvaluation",
    "Objective",
    "SearchConfig",
    "SearchStateError",
    "STATE_SCHEMA",
    "STATE_VERSION",
    "SearchResult",
    "StageObjective",
    "StageObservation",
    "apply_checkpoint",
    "canonical_json",
    "load_checkpoint",
    "run_search",
    "save_checkpoint",
    "sha256_json",
]
