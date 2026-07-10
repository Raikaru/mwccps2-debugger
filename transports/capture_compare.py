"""Path-independent normalization and comparison for GDB capture directories.

This module understands only a capture directory's manifest references and JSON/text
artifacts. It purposely does not import b210 schemas or decoders, so a capture made
on another host can be compared through the same normalization boundary.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePath
import tempfile
from typing import Any, Mapping

from .capabilities import canonical_json
from .process import TransportError


CAPTURE_COMPARISON_SCHEMA_NAME = "mwccps2-cross-host-capture-comparison"
CAPTURE_COMPARISON_SCHEMA_VERSION = 1
_MANIFEST_FILENAME = "snapshot-manifest.json"
_HOST_PATH_KEYS = frozenset(
    {
        "command_directory",
        "cwd",
        "host_path",
        "path",
        "snapshot_directory",
        "source_path",
        "working_directory",
    }
)


def _require_mapping(value: object, location: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise TransportError(f"{location} must be a JSON object")
    return value


def _load_json(path: Path, location: str) -> Mapping[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            payload = json.load(source)
    except FileNotFoundError as exc:
        raise TransportError(f"{location} does not exist: {path}") from exc
    except UnicodeDecodeError as exc:
        raise TransportError(f"{location} is not UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TransportError(f"{location} is invalid JSON: {path}: {exc}") from exc
    except OSError as exc:
        raise TransportError(f"cannot read {location} {path}: {exc}") from exc
    return _require_mapping(payload, location)


def _capture_member(capture_directory: Path, filename: object, location: str) -> Path:
    if not isinstance(filename, str) or not filename:
        raise TransportError(f"{location} must be a non-empty filename")
    member = PurePath(filename)
    if member.is_absolute() or len(member.parts) != 1 or member.name != filename or ".." in member.parts:
        raise TransportError(f"{location} must name a file directly inside the capture directory")
    candidate = capture_directory / filename
    if not candidate.is_file():
        raise TransportError(f"{location} does not exist: {candidate}")
    return candidate


def _normalize_value(value: Any) -> Any:
    """Remove host-local path fields recursively while retaining all capture semantics."""

    if isinstance(value, dict):
        return {
            key: _normalize_value(value[key])
            for key in sorted(value)
            if key not in _HOST_PATH_KEYS
        }
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    raise TransportError(f"capture JSON contains unsupported value type {type(value).__name__}")


def _read_normalized_text(path: Path, location: str) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise TransportError(f"{location} is not UTF-8: {path}") from exc
    except OSError as exc:
        raise TransportError(f"cannot read {location} {path}: {exc}") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n")


def normalize_capture_directory(capture_directory: Path) -> dict[str, Any]:
    """Collect one manifest and its declared stage/text documents in stable order.

    Only manifest-referenced members are admitted. The resulting value has no host
    path values and can be canonically hashed or compared on any host.
    """

    try:
        root = capture_directory.resolve(strict=True)
    except OSError as exc:
        raise TransportError(f"cannot resolve capture directory {capture_directory}: {exc}") from exc
    if not root.is_dir():
        raise TransportError(f"capture directory is not a directory: {root}")
    manifest = _load_json(root / _MANIFEST_FILENAME, "capture manifest")
    stage_entries = manifest.get("stages")
    if not isinstance(stage_entries, list):
        raise TransportError("capture manifest.stages must be an array")

    documents: dict[str, Any] = {_MANIFEST_FILENAME: _normalize_value(dict(manifest))}
    for index, raw_entry in enumerate(stage_entries):
        entry = _require_mapping(raw_entry, f"capture manifest.stages[{index}]")
        stage_filename = entry.get("file")
        stage_path = _capture_member(root, stage_filename, f"capture manifest.stages[{index}].file")
        stage_payload = _load_json(stage_path, f"stage snapshot {stage_filename}")
        documents[str(stage_filename)] = _normalize_value(dict(stage_payload))
        text_filename = stage_payload.get("pcode_text_file")
        text_path = _capture_member(
            root,
            text_filename,
            f"stage snapshot {stage_filename}.pcode_text_file",
        )
        documents[str(text_filename)] = _read_normalized_text(
            text_path, f"PCode text {text_filename}"
        )

    return {
        "documents": {name: documents[name] for name in sorted(documents)},
        "normalization": {
            "host_path_keys_removed": sorted(_HOST_PATH_KEYS),
            "line_endings": "CRLF and CR are normalized to LF in PCode text",
            "selection": "snapshot-manifest.json and its declared stage/PCode text members",
        },
    }


def _digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
            "utf-8"
        )
    ).hexdigest()


def _first_difference(left: Any, right: Any, pointer: str = "$") -> str | None:
    if type(left) is not type(right):
        return pointer
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                return f"{pointer}.{key}"
            difference = _first_difference(left[key], right[key], f"{pointer}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return pointer
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            difference = _first_difference(left_item, right_item, f"{pointer}[{index}]")
            if difference is not None:
                return difference
        return None
    return None if left == right else pointer


def compare_capture_directories(baseline_directory: Path, candidate_directory: Path) -> dict[str, Any]:
    """Compare two normalized capture bundles without exposing their host paths."""

    baseline = normalize_capture_directory(baseline_directory)
    candidate = normalize_capture_directory(candidate_directory)
    baseline_sha256 = _digest(baseline)
    candidate_sha256 = _digest(candidate)
    return {
        "baseline": {
            "document_count": len(baseline["documents"]),
            "normalized_capture_sha256": baseline_sha256,
        },
        "candidate": {
            "document_count": len(candidate["documents"]),
            "normalized_capture_sha256": candidate_sha256,
        },
        "equal": baseline_sha256 == candidate_sha256,
        "evidence": {
            "first_difference": _first_difference(baseline, candidate),
            "normalization": baseline["normalization"],
        },
        "schema": {
            "name": CAPTURE_COMPARISON_SCHEMA_NAME,
            "version": CAPTURE_COMPARISON_SCHEMA_VERSION,
        },
    }


def write_comparison(path: Path, comparison: Mapping[str, Any]) -> None:
    """Atomically write the versioned comparison artifact."""

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            output.write(canonical_json(comparison))
        temporary_path.replace(path)
    except OSError as exc:
        raise TransportError(f"cannot write capture comparison {path}: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
