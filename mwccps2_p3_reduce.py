#!/usr/bin/env python3
"""Create deterministic, manual-only MWCCPS2 reduction bundles for P3 mismatches.

This command is deliberately owned by the independent debugger repository.  It reads an
optional configuration kept in the Persona 3 repository but neither imports nor modifies
any Persona 3 build tool.  A bundle is evidence for reducing one verifier-reported function:
it captures the selected mismatch, a source fingerprint, and classification evidence from
existing MWCCPS2 experiments.  It does not compile the P3 project.

When an experiment summary is supplied, its normal and GDB-instrumented object SHA-256
values must agree for *every* variant before it can be used as evidence.  This keeps the
snapshot workflow's object-byte validation intact rather than treating instrumentation as a
best-effort observation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import sys
from typing import Any, Iterable, Mapping, Sequence


CONFIG_SCHEMA_NAME = "persona3-fes-mwccps2-debugger"
CONFIG_SCHEMA_VERSION = 1
ANALYSIS_SCHEMA_NAME = "persona3-fes-mwccps2-local-analysis"
ANALYSIS_SCHEMA_VERSION = 1
CLASSIFICATION_SCHEMA_NAME = "persona3-fes-mismatch-classification"
CLASSIFICATION_SCHEMA_VERSION = 1
BUNDLE_SCHEMA_NAME = "persona3-fes-mwccps2-reduction-bundle"
BUNDLE_SCHEMA_VERSION = 1
EXPERIMENT_SUMMARY_SCHEMA_NAME = "mwccps2-experiment-summary"
EXPERIMENT_SUMMARY_SCHEMA_VERSION = 1

_ANALYSIS_FILENAME = f"analysis-v{ANALYSIS_SCHEMA_VERSION}.json"
_CLASSIFICATION_FILENAME = f"mismatch-classification-v{CLASSIFICATION_SCHEMA_VERSION}.json"
_BUNDLE_FILENAME = f"bundle-manifest-v{BUNDLE_SCHEMA_VERSION}.json"
_HEX_ADDRESS = re.compile(r"(?:0[xX])?([0-9A-Fa-f]{1,8})\Z")
_SHA256 = re.compile(r"[0-9A-Fa-f]{64}\Z")
_ALLOWED_EXPERIMENT_STAGES = frozenset(
    {
        "codegen_entry",
        "before_scheduling",
        "after_scheduling",
        "before_register_allocation",
        "after_register_allocation",
        "after_colorgraph_assignment",
    }
)


class P3IntegrationError(Exception):
    """Raised when P3 integration input cannot produce trustworthy evidence."""


def _is_exact_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_mapping(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise P3IntegrationError(f"{location} must be an object")
    return value


def _require_string(value: object, location: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise P3IntegrationError(f"{location} must be a string")
    if nonempty and not value:
        raise P3IntegrationError(f"{location} must not be empty")
    if "\0" in value:
        raise P3IntegrationError(f"{location} must not contain a NUL byte")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: Iterable[str], location: str
) -> None:
    expected_set = set(expected)
    unknown = sorted(set(value) - expected_set)
    missing = sorted(expected_set - set(value))
    if unknown:
        raise P3IntegrationError(f"{location} contains unknown field(s): {', '.join(unknown)}")
    if missing:
        raise P3IntegrationError(f"{location} is missing required field(s): {', '.join(missing)}")


def _no_duplicate_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise P3IntegrationError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _load_json(path: Path, description: str) -> tuple[Any, bytes]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise P3IntegrationError(f"cannot read {description} {path}: {exc}") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise P3IntegrationError(f"{description} {path} is not UTF-8 JSON") from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_json_object), data
    except P3IntegrationError:
        raise
    except json.JSONDecodeError as exc:
        raise P3IntegrationError(f"{description} {path} is not valid JSON: {exc}") from exc


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise P3IntegrationError(f"value is not canonical JSON: {exc}") from exc


def _pretty_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise P3IntegrationError(f"value is not JSON serializable: {exc}") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path, description: str) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise P3IntegrationError(f"cannot hash {description} {path}: {exc}") from exc
    return digest.hexdigest()


def _validate_relative_path(value: object, location: str, *, permit_parent: bool) -> str:
    text = _require_string(value, location)
    windows = PureWindowsPath(text)
    posix = PurePosixPath(text.replace("\\", "/"))
    if windows.is_absolute() or windows.drive or posix.is_absolute():
        raise P3IntegrationError(f"{location} must be a relative path")
    if not permit_parent and ".." in posix.parts:
        raise P3IntegrationError(f"{location} must not escape its declared root")
    if not posix.parts or posix == PurePosixPath("."):
        raise P3IntegrationError(f"{location} must name a path")
    return posix.as_posix()


def _resolve_existing(path: Path, description: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise P3IntegrationError(f"cannot resolve {description} {path}: {exc}") from exc
    return resolved


def _parse_hex_address(value: object, location: str) -> str:
    if _is_exact_int(value):
        parsed = int(value)
    elif isinstance(value, str):
        match = _HEX_ADDRESS.fullmatch(value)
        if match is None:
            raise P3IntegrationError(f"{location} must be a hexadecimal 32-bit address")
        parsed = int(match.group(1), 16)
    else:
        raise P3IntegrationError(f"{location} must be a hexadecimal 32-bit address")
    if not 0 <= parsed <= 0xFFFFFFFF:
        raise P3IntegrationError(f"{location} is outside the 32-bit address range")
    return f"0x{parsed:08x}"


def _parse_sha256(value: object, location: str) -> str:
    text = _require_string(value, location)
    if _SHA256.fullmatch(text) is None:
        raise P3IntegrationError(f"{location} must be a SHA-256 hexadecimal digest")
    return text.lower()


def _validate_nonnegative_int(value: object, location: str) -> int:
    if not _is_exact_int(value) or int(value) < 0:
        raise P3IntegrationError(f"{location} must be a non-negative integer")
    return int(value)


def _normalize_relative_source(value: object, location: str) -> str:
    source = _validate_relative_path(value, location, permit_parent=False)
    if not source.startswith("src/"):
        raise P3IntegrationError(f"{location} must be beneath the P3 src/ directory")
    return source


def _ensure_contained(path: Path, root: Path, location: str) -> Path:
    resolved = _resolve_existing(path, location)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise P3IntegrationError(f"{location} escapes P3 root {root}") from exc
    return resolved


def load_config(config_path: Path) -> dict[str, Any]:
    """Load strict schema-v1 external configuration without probing the debugger sibling."""

    resolved_config = _resolve_existing(config_path, "P3 debugger config")
    raw, _ = _load_json(resolved_config, "P3 debugger config")
    config = _require_mapping(raw, "P3 debugger config")
    _require_exact_keys(config, {"schema", "integration", "reports", "reduction"}, "P3 debugger config")

    schema = _require_mapping(config["schema"], "P3 debugger config.schema")
    _require_exact_keys(schema, {"name", "version"}, "P3 debugger config.schema")
    if schema["name"] != CONFIG_SCHEMA_NAME:
        raise P3IntegrationError(
            f"P3 debugger config.schema.name must be {CONFIG_SCHEMA_NAME!r}"
        )
    if not _is_exact_int(schema["version"]) or schema["version"] != CONFIG_SCHEMA_VERSION:
        raise P3IntegrationError(
            f"P3 debugger config.schema.version must be {CONFIG_SCHEMA_VERSION}"
        )

    integration = _require_mapping(config["integration"], "P3 debugger config.integration")
    _require_exact_keys(
        integration, {"mode", "p3_root", "debugger"}, "P3 debugger config.integration"
    )
    if integration["mode"] != "external-optional":
        raise P3IntegrationError(
            "P3 debugger config.integration.mode must be 'external-optional'"
        )
    p3_root_path = _validate_relative_path(
        integration["p3_root"], "P3 debugger config.integration.p3_root", permit_parent=True
    )
    p3_root = _resolve_existing(resolved_config.parent / p3_root_path, "P3 root")
    if not p3_root.is_dir():
        raise P3IntegrationError(f"P3 root is not a directory: {p3_root}")

    debugger = _require_mapping(integration["debugger"], "P3 debugger config.integration.debugger")
    _require_exact_keys(
        debugger,
        {"repository", "compiler", "profile"},
        "P3 debugger config.integration.debugger",
    )
    debugger_repository = _validate_relative_path(
        debugger["repository"],
        "P3 debugger config.integration.debugger.repository",
        permit_parent=True,
    )
    compiler = _require_string(
        debugger["compiler"], "P3 debugger config.integration.debugger.compiler"
    )
    profile = _validate_relative_path(
        debugger["profile"], "P3 debugger config.integration.debugger.profile", permit_parent=False
    )

    reports = _require_mapping(config["reports"], "P3 debugger config.reports")
    _require_exact_keys(
        reports,
        {"default_paths", "accepted_statuses", "analysis_evidence_paths"},
        "P3 debugger config.reports",
    )
    default_paths_value = reports["default_paths"]
    if not isinstance(default_paths_value, list) or not default_paths_value:
        raise P3IntegrationError("P3 debugger config.reports.default_paths must be a non-empty array")
    default_paths = [
        _validate_relative_path(
            item,
            f"P3 debugger config.reports.default_paths[{index}]",
            permit_parent=False,
        )
        for index, item in enumerate(default_paths_value)
    ]
    if len(set(default_paths)) != len(default_paths):
        raise P3IntegrationError("P3 debugger config.reports.default_paths must not contain duplicates")

    statuses_value = reports["accepted_statuses"]
    if not isinstance(statuses_value, list) or not statuses_value:
        raise P3IntegrationError("P3 debugger config.reports.accepted_statuses must be a non-empty array")
    statuses = [
        _require_string(item, f"P3 debugger config.reports.accepted_statuses[{index}]")
        for index, item in enumerate(statuses_value)
    ]
    if len(set(statuses)) != len(statuses):
        raise P3IntegrationError("P3 debugger config.reports.accepted_statuses must not contain duplicates")

    evidence_value = reports["analysis_evidence_paths"]
    if not isinstance(evidence_value, list):
        raise P3IntegrationError("P3 debugger config.reports.analysis_evidence_paths must be an array")
    evidence_paths = [
        _validate_relative_path(
            item,
            f"P3 debugger config.reports.analysis_evidence_paths[{index}]",
            permit_parent=True,
        )
        for index, item in enumerate(evidence_value)
    ]
    if len(set(evidence_paths)) != len(evidence_paths):
        raise P3IntegrationError(
            "P3 debugger config.reports.analysis_evidence_paths must not contain duplicates"
        )

    reduction = _require_mapping(config["reduction"], "P3 debugger config.reduction")
    _require_exact_keys(reduction, {"output_root"}, "P3 debugger config.reduction")
    output_root = _validate_relative_path(
        reduction["output_root"], "P3 debugger config.reduction.output_root", permit_parent=True
    )

    return {
        "config_path": resolved_config,
        "p3_root": p3_root,
        "schema": {"name": CONFIG_SCHEMA_NAME, "version": CONFIG_SCHEMA_VERSION},
        "integration": {
            "mode": "external-optional",
            "debugger": {
                "repository": debugger_repository,
                "compiler": compiler,
                "profile": profile,
            },
        },
        "reports": {
            "default_paths": default_paths,
            "accepted_statuses": sorted(statuses),
            "analysis_evidence_paths": sorted(evidence_paths),
        },
        "reduction": {"output_root": output_root},
    }


def _normalize_relocations(value: object, location: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise P3IntegrationError(f"{location} must be an array")
    relocations: list[dict[str, Any]] = []
    for index, raw_relocation in enumerate(value):
        relocation = _require_mapping(raw_relocation, f"{location}[{index}]")
        normalized: dict[str, Any] = {}
        for key, child in relocation.items():
            if not isinstance(key, str):
                raise P3IntegrationError(f"{location}[{index}] contains a non-string key")
            if isinstance(child, bool) or child is None or isinstance(child, (str, int)):
                normalized[key] = child
            else:
                raise P3IntegrationError(
                    f"{location}[{index}].{key} must be a scalar verifier field"
                )
        if "offset" in normalized:
            normalized["offset"] = _validate_nonnegative_int(
                normalized["offset"], f"{location}[{index}].offset"
            )
        if "retail_target" in normalized:
            normalized["retail_target"] = _parse_hex_address(
                normalized["retail_target"], f"{location}[{index}].retail_target"
            )
        relocations.append(normalized)
    return sorted(relocations, key=_canonical_json_bytes)


def _normalize_report_record(
    value: object,
    location: str,
    *,
    p3_root: Path,
) -> dict[str, Any]:
    record = _require_mapping(value, location)
    required = {"file", "addr", "name", "line", "status"}
    missing = sorted(required - set(record))
    if missing:
        raise P3IntegrationError(f"{location} is missing required field(s): {', '.join(missing)}")

    source = _normalize_relative_source(record["file"], f"{location}.file")
    source_path = _ensure_contained(p3_root / source, p3_root, f"{location}.file")
    if not source_path.is_file():
        raise P3IntegrationError(f"{location}.file is not a source file: {source_path}")
    status = _require_string(record["status"], f"{location}.status")
    if status == "COMPILE_ERROR":
        first_diffs: list[int] = []
        normalized_diff: int | None = None
        object_size: int | None = None
        relocations: list[dict[str, Any]] = []
        window: int | None = None
    else:
        measurement_fields = {"object_size", "window", "normalized_diff"}
        missing_measurements = sorted(measurement_fields - set(record))
        if missing_measurements:
            raise P3IntegrationError(
                f"{location} is missing required comparison field(s): {', '.join(missing_measurements)}"
            )
        first_diffs_value = record.get("first_diffs", [])
        if not isinstance(first_diffs_value, list):
            raise P3IntegrationError(f"{location}.first_diffs must be an array when present")
        first_diffs = sorted(
            {
                _validate_nonnegative_int(item, f"{location}.first_diffs[{index}]")
                for index, item in enumerate(first_diffs_value)
            }
        )
        normalized_diff = _validate_nonnegative_int(
            record["normalized_diff"], f"{location}.normalized_diff"
        )
        object_size = _validate_nonnegative_int(record["object_size"], f"{location}.object_size")
        relocations = _normalize_relocations(record.get("relocations", []), f"{location}.relocations")
        window = _validate_nonnegative_int(record["window"], f"{location}.window")
    return {
        "address": _parse_hex_address(record["addr"], f"{location}.addr"),
        "first_diffs": first_diffs,
        "line": _validate_nonnegative_int(record["line"], f"{location}.line"),
        "name": _require_string(record["name"], f"{location}.name"),
        "normalized_diff": normalized_diff,
        "object_size": object_size,
        "relocations": relocations,
        "source": source,
        "source_sha256": _hash_file(source_path, f"P3 source for {location}"),
        "status": status,
        "window": window,
    }


def load_p3_report(
    report_path: Path, *, accepted_statuses: frozenset[str], p3_root: Path
) -> dict[str, Any]:
    """Normalize configured mismatch statuses while ignoring incomplete non-target verifier rows."""

    resolved = _resolve_existing(report_path, "P3 verifier report")
    raw, raw_bytes = _load_json(resolved, "P3 verifier report")
    report = _require_mapping(raw, "P3 verifier report")
    results = report.get("results")
    if not isinstance(results, list) or not results:
        raise P3IntegrationError("P3 verifier report.results must be a non-empty array")
    records: list[dict[str, Any]] = []
    for index, value in enumerate(results):
        record = _require_mapping(value, f"P3 verifier report.results[{index}]")
        status = _require_string(record.get("status"), f"P3 verifier report.results[{index}].status")
        if status not in accepted_statuses:
            continue
        records.append(
            _normalize_report_record(
                record,
                f"P3 verifier report.results[{index}]",
                p3_root=p3_root,
            )
        )
    return {
        "filename": resolved.name,
        "sha256": _sha256(raw_bytes),
        "records": sorted(records, key=lambda item: (item["name"], item["address"], item["source"])),
    }


def _validate_experiment_stage(value: object, location: str) -> str | None:
    if value is None:
        return None
    difference = _require_mapping(value, location)
    stage = _require_string(difference.get("stage"), f"{location}.stage")
    if stage not in _ALLOWED_EXPERIMENT_STAGES:
        raise P3IntegrationError(f"{location}.stage is not a known MWCCPS2 snapshot stage: {stage}")
    return stage


def load_experiment_report(report_path: Path) -> dict[str, Any]:
    """Validate experiment object equivalence before accepting it as classification evidence."""

    resolved = _resolve_existing(report_path, "MWCCPS2 experiment summary")
    raw, raw_bytes = _load_json(resolved, "MWCCPS2 experiment summary")
    report = _require_mapping(raw, "MWCCPS2 experiment summary")
    schema = _require_mapping(report.get("schema"), "MWCCPS2 experiment summary.schema")
    if schema.get("name") != EXPERIMENT_SUMMARY_SCHEMA_NAME:
        raise P3IntegrationError(
            f"MWCCPS2 experiment summary.schema.name must be {EXPERIMENT_SUMMARY_SCHEMA_NAME!r}"
        )
    if schema.get("version") != EXPERIMENT_SUMMARY_SCHEMA_VERSION:
        raise P3IntegrationError(
            f"MWCCPS2 experiment summary.schema.version must be {EXPERIMENT_SUMMARY_SCHEMA_VERSION}"
        )
    experiment = _require_mapping(report.get("experiment"), "MWCCPS2 experiment summary.experiment")
    experiment_name = _require_string(experiment.get("name"), "MWCCPS2 experiment summary.experiment.name")
    variants_value = report.get("variants")
    if not isinstance(variants_value, list) or not variants_value:
        raise P3IntegrationError("MWCCPS2 experiment summary.variants must be a non-empty array")
    variants: list[str] = []
    for index, raw_variant in enumerate(variants_value):
        variant = _require_mapping(raw_variant, f"MWCCPS2 experiment summary.variants[{index}]")
        name = _require_string(variant.get("name"), f"MWCCPS2 experiment summary.variants[{index}].name")
        direct = _require_mapping(
            variant.get("direct_compile"), f"MWCCPS2 experiment summary.variants[{index}].direct_compile"
        )
        snapshot = _require_mapping(
            variant.get("snapshot_compile"),
            f"MWCCPS2 experiment summary.variants[{index}].snapshot_compile",
        )
        direct_sha = _parse_sha256(
            direct.get("object_sha256"),
            f"MWCCPS2 experiment summary.variants[{index}].direct_compile.object_sha256",
        )
        snapshot_sha = _parse_sha256(
            snapshot.get("object_sha256"),
            f"MWCCPS2 experiment summary.variants[{index}].snapshot_compile.object_sha256",
        )
        if snapshot.get("matches_direct_object") is not True or direct_sha != snapshot_sha:
            raise P3IntegrationError(
                "MWCCPS2 experiment summary rejects direct-vs-instrumented object SHA verification "
                f"for variant {name!r}"
            )
        variants.append(name)
    if len(set(variants)) != len(variants):
        raise P3IntegrationError("MWCCPS2 experiment summary.variants contains duplicate names")

    comparisons_value = report.get("comparisons")
    if not isinstance(comparisons_value, list):
        raise P3IntegrationError("MWCCPS2 experiment summary.comparisons must be an array")
    comparisons: list[dict[str, Any]] = []
    for index, raw_comparison in enumerate(comparisons_value):
        comparison = _require_mapping(raw_comparison, f"MWCCPS2 experiment summary.comparisons[{index}]")
        baseline = _require_string(
            comparison.get("baseline_variant"),
            f"MWCCPS2 experiment summary.comparisons[{index}].baseline_variant",
        )
        variant = _require_string(
            comparison.get("variant"), f"MWCCPS2 experiment summary.comparisons[{index}].variant"
        )
        final_equal = comparison.get("final_object_equal")
        if not isinstance(final_equal, bool):
            raise P3IntegrationError(
                f"MWCCPS2 experiment summary.comparisons[{index}].final_object_equal must be boolean"
            )
        comparisons.append(
            {
                "baseline_variant": baseline,
                "variant": variant,
                "final_object_equal": final_equal,
                "pcode_stage": _validate_experiment_stage(
                    comparison.get("earliest_pcode_divergence"),
                    f"MWCCPS2 experiment summary.comparisons[{index}].earliest_pcode_divergence",
                ),
                "raw_graph_stage": _validate_experiment_stage(
                    comparison.get("earliest_raw_graph_difference"),
                    f"MWCCPS2 experiment summary.comparisons[{index}].earliest_raw_graph_difference",
                ),
            }
        )
    return {
        "experiment": experiment_name,
        "filename": resolved.name,
        "sha256": _sha256(raw_bytes),
        "variants": sorted(variants),
        "comparisons": sorted(
            comparisons,
            key=lambda item: (item["baseline_variant"], item["variant"]),
        ),
    }


def _reachability_metadata(report: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the authoritative three-class reachability framework when present."""

    schema = report.get("schema")
    if not isinstance(schema, dict) or schema.get("name") != "mwccps2-p3-retail-reachability":
        return {}
    class_order_value = report.get("class_order")
    classes_value = report.get("classes")
    if not isinstance(class_order_value, list) or not isinstance(classes_value, list):
        raise P3IntegrationError("retail reachability evidence must contain class_order and classes arrays")
    class_order = [
        _require_string(item, f"retail reachability evidence.class_order[{index}]")
        for index, item in enumerate(class_order_value)
    ]
    if len(class_order) != 3 or len(set(class_order)) != len(class_order):
        raise P3IntegrationError("retail reachability evidence must define exactly three distinct classes")
    experiment_classes: dict[str, str] = {}
    classes: list[str] = []
    for index, raw_class in enumerate(classes_value):
        reachability_class = _require_mapping(raw_class, f"retail reachability evidence.classes[{index}]")
        class_id = _require_string(reachability_class.get("id"), f"retail reachability evidence.classes[{index}].id")
        observed = _require_mapping(
            reachability_class.get("observed"), f"retail reachability evidence.classes[{index}].observed"
        )
        experiment_ids = observed.get("experiment_ids")
        if not isinstance(experiment_ids, list):
            raise P3IntegrationError(
                f"retail reachability evidence.classes[{index}].observed.experiment_ids must be an array"
            )
        for experiment_index, experiment_id in enumerate(experiment_ids):
            name = _require_string(
                experiment_id,
                f"retail reachability evidence.classes[{index}].observed.experiment_ids[{experiment_index}]",
            )
            if name in experiment_classes:
                raise P3IntegrationError(
                    f"retail reachability evidence assigns experiment {name!r} to multiple classes"
                )
            experiment_classes[name] = class_id
        classes.append(class_id)
    if class_order != classes:
        raise P3IntegrationError("retail reachability evidence.class_order must match classes[].id order")
    return {
        "reachability_class_order": class_order,
        "reachability_experiment_classes": dict(sorted(experiment_classes.items())),
    }


def _load_analysis_evidence(path: Path, *, required: bool) -> dict[str, Any]:
    """Record optional sibling artifacts by fingerprint without inventing their semantics."""

    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        if not required:
            return {"path": path.as_posix(), "state": "not_available"}
        raise P3IntegrationError(f"cannot resolve analysis evidence {path}: {exc}") from exc
    raw, raw_bytes = _load_json(resolved, "analysis evidence")
    report = _require_mapping(raw, "analysis evidence")
    if report.get("schema_version") != 1:
        raise P3IntegrationError(f"analysis evidence {resolved} must declare schema_version 1")
    schema_name = report.get("schema_name")
    if schema_name is not None:
        schema_name = _require_string(schema_name, "analysis evidence.schema_name")
    else:
        schema = report.get("schema")
        if isinstance(schema, dict) and "name" in schema:
            schema_name = _require_string(schema["name"], "analysis evidence.schema.name")
    return {
        "filename": resolved.name,
        "schema_name": schema_name,
        "schema_version": 1,
        "sha256": _sha256(raw_bytes),
        "state": "available",
        **_reachability_metadata(report),
    }


def _classify_selected_mismatch(selected: Mapping[str, Any]) -> dict[str, Any]:
    status = str(selected["status"])
    if status == "COMPILE_ERROR":
        normalized_diff: int | None = None
        classification = "compile_blocked"
        reason = "P3 verifier could not produce a candidate object for comparison."
    else:
        raw_normalized_diff = selected["normalized_diff"]
        if not _is_exact_int(raw_normalized_diff):
            raise P3IntegrationError("selected verifier record has no normalized byte-difference count")
        normalized_diff = int(raw_normalized_diff)
        if status == "MISMATCH" and normalized_diff > 0:
            classification = "retail_object_mismatch"
            reason = "P3 verifier reported MISMATCH with non-zero normalized_diff."
        elif status in {"NONMATCHING", "STALE_NONMATCHING"}:
            classification = "retail_nonmatching"
            reason = "P3 verifier reported a nonmatching function outside the byte-equal set."
        else:
            raise P3IntegrationError(
                f"selected function has unsupported mismatch status {status!r}; config admitted it unexpectedly"
            )
    return {
        "class": classification,
        "evidence": {
            "address": selected["address"],
            "normalized_diff": normalized_diff,
            "status": status,
        },
        "function": selected["name"],
        "reason": reason,
        "source_kind": "p3_verifier_report",
    }


def _classify_experiments(
    experiments: Sequence[Mapping[str, Any]], experiment_classes: Mapping[str, str]
) -> list[dict[str, Any]]:
    classifications: list[dict[str, Any]] = []
    for experiment in experiments:
        for comparison in experiment["comparisons"]:
            if comparison["baseline_variant"] == comparison["variant"]:
                continue
            pcode_stage = comparison["pcode_stage"]
            raw_stage = comparison["raw_graph_stage"]
            final_equal = comparison["final_object_equal"]
            if pcode_stage is not None and not final_equal:
                classifications.append(
                    {
                        "class": "semantic_pcode_divergence",
                        "evidence": {
                            "baseline_variant": comparison["baseline_variant"],
                            "experiment": experiment["experiment"],
                            "final_object_equal": False,
                            "stage": pcode_stage,
                            "variant": comparison["variant"],
                            "reachability_class": experiment_classes.get(experiment["experiment"]),
                        },
                        "reason": "Existing experiment diverged in PCode before object generation and its final objects differ.",
                        "source_kind": "mwccps2_experiment",
                    }
                )
            elif pcode_stage is None and raw_stage is not None and final_equal:
                classifications.append(
                    {
                        "class": "normalized_graph_only_equivalence",
                        "evidence": {
                            "baseline_variant": comparison["baseline_variant"],
                            "experiment": experiment["experiment"],
                            "final_object_equal": True,
                            "stage": raw_stage,
                            "variant": comparison["variant"],
                            "reachability_class": experiment_classes.get(experiment["experiment"]),
                        },
                        "reason": "Existing experiment changed normalized graph structure while semantic PCode and final object bytes remained equal.",
                        "source_kind": "mwccps2_experiment",
                    }
                )
    return classifications


def _select_function(
    reports: Sequence[Mapping[str, Any]], function_name: str, accepted_statuses: frozenset[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for report in reports:
        for record in report["records"]:
            if record["name"] == function_name:
                matches.append((dict(report), dict(record)))
    if not matches:
        raise P3IntegrationError(f"function {function_name!r} was not found in supplied P3 reports")
    if len(matches) != 1:
        locations = ", ".join(
            f"{report['filename']}:{record['address']}" for report, record in matches
        )
        raise P3IntegrationError(
            f"function {function_name!r} is ambiguous across supplied P3 reports: {locations}"
        )
    selected_report, selected_record = matches[0]
    if selected_record["status"] not in accepted_statuses:
        raise P3IntegrationError(
            f"function {function_name!r} has status {selected_record['status']!r}, which is not an accepted reduction status"
        )
    return selected_report, selected_record


def _prepare_output_directory(output_directory: Path) -> Path:
    try:
        resolved = output_directory.resolve()
    except OSError as exc:
        raise P3IntegrationError(f"cannot resolve output directory {output_directory}: {exc}") from exc
    if resolved.exists():
        raise P3IntegrationError(f"output directory already exists: {resolved}")
    try:
        resolved.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise P3IntegrationError(f"cannot create output directory {resolved}: {exc}") from exc
    return resolved


def _write_bundle_file(path: Path, value: Mapping[str, Any]) -> str:
    data = _pretty_json_bytes(value)
    try:
        path.write_bytes(data)
    except OSError as exc:
        raise P3IntegrationError(f"cannot write bundle file {path}: {exc}") from exc
    return _sha256(data)


def create_bundle(
    config_path: Path,
    report_paths: Sequence[Path],
    function_name: str,
    output_directory: Path,
    experiment_report_paths: Sequence[Path] = (),
    analysis_report_paths: Sequence[Path] = (),
) -> Path:
    """Create a fresh deterministic local bundle for exactly one P3 verifier function."""

    config = load_config(config_path)
    supplied_reports = list(report_paths)
    if not supplied_reports:
        supplied_reports = [config["p3_root"] / path for path in config["reports"]["default_paths"]]
    reports = [
        load_p3_report(
            report_path,
            accepted_statuses=frozenset(config["reports"]["accepted_statuses"]),
            p3_root=config["p3_root"],
        )
        for report_path in supplied_reports
    ]
    selected_report, selected = _select_function(
        reports, function_name, frozenset(config["reports"]["accepted_statuses"])
    )
    experiments = [load_experiment_report(path) for path in experiment_report_paths]

    optional_evidence = [
        _load_analysis_evidence(config["config_path"].parent / path, required=False)
        for path in config["reports"]["analysis_evidence_paths"]
    ]
    required_evidence = [
        _load_analysis_evidence(path, required=True) for path in analysis_report_paths
    ]
    analysis_evidence = sorted(
        [*optional_evidence, *required_evidence],
        key=lambda item: (item.get("state", ""), item.get("filename", item.get("path", ""))),
    )
    reachability_evidence = [
        item for item in analysis_evidence if "reachability_class_order" in item
    ]
    reachability_fingerprints = {
        item["sha256"] for item in reachability_evidence if item.get("state") == "available"
    }
    if len(reachability_fingerprints) > 1:
        raise P3IntegrationError("multiple conflicting retail reachability evidence reports were supplied")
    reachability = reachability_evidence[0] if reachability_evidence else {}
    reachability_classes = [
        {
            "evidence_report": reachability["filename"],
            "evidence_sha256": reachability["sha256"],
            "id": class_id,
        }
        for class_id in reachability.get("reachability_class_order", [])
    ]

    analysis = {
        "schema": {"name": ANALYSIS_SCHEMA_NAME, "version": ANALYSIS_SCHEMA_VERSION},
        "config": {
            "schema": config["schema"],
            "integration": config["integration"],
            "reduction": config["reduction"],
        },
        "function": {
            "address": selected["address"],
            "line": selected["line"],
            "name": selected["name"],
            "object_size": selected["object_size"],
            "source": selected["source"],
            "source_sha256": selected["source_sha256"],
            "window": selected["window"],
        },
        "mismatch": {
            "first_diffs": selected["first_diffs"],
            "normalized_diff": selected["normalized_diff"],
            "relocation_count": len(selected["relocations"]),
            "relocations": selected["relocations"],
            "status": selected["status"],
        },
        "evidence": {
            "analysis_reports": analysis_evidence,
            "p3_verifier_report": {
                "filename": selected_report["filename"],
                "record_sha256": _sha256(_canonical_json_bytes(selected)),
                "sha256": selected_report["sha256"],
            },
            "source_file": "P3 source digest is recorded from the selected report's relative src/ path.",
        },
        "reduction_workflow": {
            "direct_object_requirement": "Record direct compile object SHA-256 before reduction candidates are compared.",
            "instrumented_object_requirement": "An instrumented capture is admissible only when its object SHA-256 equals the direct compile SHA-256.",
            "selector": {
                "address": selected["address"],
                "function": selected["name"],
                "source": selected["source"],
            },
            "stages": [
                "codegen_entry",
                "before_scheduling",
                "after_scheduling",
                "before_register_allocation",
                "after_register_allocation",
            ],
        },
    }

    classifications = [
        _classify_selected_mismatch(selected),
        *_classify_experiments(experiments, reachability.get("reachability_experiment_classes", {})),
    ]
    classifications = sorted(
        classifications,
        key=lambda item: (
            item["class"],
            item["source_kind"],
            _canonical_json_bytes(item["evidence"]),
        ),
    )
    classification = {
        "schema": {
            "name": CLASSIFICATION_SCHEMA_NAME,
            "version": CLASSIFICATION_SCHEMA_VERSION,
        },
        "classes": classifications,
        "reachability_classes": reachability_classes,
        "evidence": {
            "experiment_reports": [
                {
                    "experiment": experiment["experiment"],
                    "filename": experiment["filename"],
                    "sha256": experiment["sha256"],
                    "verification": "direct_and_instrumented_object_sha256_equal",
                }
                for experiment in sorted(experiments, key=lambda item: (item["experiment"], item["filename"]))
            ],
            "p3_verifier_report": {
                "filename": selected_report["filename"],
                "sha256": selected_report["sha256"],
            },
        },
        "selected_function": {
            "address": selected["address"],
            "name": selected["name"],
            "status": selected["status"],
        },
    }

    output = _prepare_output_directory(output_directory)
    try:
        analysis_sha = _write_bundle_file(output / _ANALYSIS_FILENAME, analysis)
        classification_sha = _write_bundle_file(output / _CLASSIFICATION_FILENAME, classification)
        manifest = {
            "schema": {"name": BUNDLE_SCHEMA_NAME, "version": BUNDLE_SCHEMA_VERSION},
            "files": [
                {"filename": _ANALYSIS_FILENAME, "sha256": analysis_sha},
                {"filename": _CLASSIFICATION_FILENAME, "sha256": classification_sha},
            ],
            "function": {"address": selected["address"], "name": selected["name"]},
        }
        _write_bundle_file(output / _BUNDLE_FILENAME, manifest)
    except P3IntegrationError:
        # A partially written bundle is not valid evidence; keep failure loud and local.
        raise
    return output / _BUNDLE_FILENAME


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a deterministic local MWCCPS2 reduction bundle from P3 verifier reports."
    )
    parser.add_argument("--config", required=True, type=Path, help="optional P3 debugger config JSON")
    parser.add_argument(
        "--report",
        action="append",
        type=Path,
        default=[],
        help="P3 verifier JSON report (repeatable; defaults to config report paths)",
    )
    parser.add_argument("--function", required=True, help="exact verifier function name to reduce")
    parser.add_argument("--output", required=True, type=Path, help="fresh local output directory")
    parser.add_argument(
        "--experiment-report",
        action="append",
        type=Path,
        default=[],
        help="existing mwccps2 experiment-summary-v1 JSON used as verified classification evidence",
    )
    parser.add_argument(
        "--analysis-report",
        action="append",
        type=Path,
        default=[],
        help="required schema-v1 sibling analysis JSON recorded as supplemental evidence",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        manifest_path = create_bundle(
            args.config,
            args.report,
            args.function,
            args.output,
            args.experiment_report,
            args.analysis_report,
        )
    except P3IntegrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"bundle manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
