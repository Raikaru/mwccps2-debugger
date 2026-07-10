#!/usr/bin/env python3
"""Discover, fingerprint, and compare local MWCCPS2 build profiles.

This tool is deliberately independent of the b210 GDB command.  It validates a b210
image by its complete binary fingerprint and a string/xref anchor signature, not by
its filename, then emits a common direct-object capture shape for every requested
compiler revision.  The existing b210 experiment runner remains the authority for
instrumented direct-versus-GDB object verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence

import mwccps2_probe as probe
from gdb.b210_snapshot_model import SnapshotModelError, load_b210_profile


RUNNER_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_POLICY = RUNNER_DIRECTORY / "profiles" / "mwccps2-version-portability-policy-v1.json"
DEFAULT_PROFILES_DIRECTORY = RUNNER_DIRECTORY / "profiles"
DEFAULT_EXPERIMENTS_DIRECTORY = RUNNER_DIRECTORY / "experiments"
DEFAULT_BUILD_DIRECTORY = RUNNER_DIRECTORY / "build"
WORKSPACE_DIRECTORY = (
    RUNNER_DIRECTORY.parent.parent
    if RUNNER_DIRECTORY.parent.name.casefold() == "source"
    else RUNNER_DIRECTORY.parent
)
HOME_DIRECTORY = Path.home().resolve()

INDEX_SCHEMA_NAME = "mwccps2-version-portability-index"
BUILD_PROFILE_SCHEMA_NAME = "mwccps2-portable-build-profile"
DIRECT_CAPTURE_SCHEMA_NAME = "mwccps2-portable-direct-capture"
SCHEMA_VERSION = 1
INDEX_FILENAME = f"mwccps2-version-portability-v{SCHEMA_VERSION}.json"


class PortabilityError(Exception):
    """Raised for invalid policy data, unsupported binaries, or failed experiments."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        raise PortabilityError(f"cannot serialize canonical JSON: {exc}") from exc


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PortabilityError(f"cannot serialize canonical JSON: {exc}") from exc


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PortabilityError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _load_json(path: Path, description: str) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PortabilityError(f"cannot read {description} {path}: {exc}") from exc
    try:
        return json.loads(text, object_pairs_hook=_duplicate_rejecting_object)
    except PortabilityError:
        raise
    except json.JSONDecodeError as exc:
        raise PortabilityError(f"{description} {path} is not valid JSON: {exc}") from exc


def _require_mapping(value: object, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PortabilityError(f"{location} must be an object")
    return value


def _require_list(value: object, location: str) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        raise PortabilityError(f"{location} must be an array")
    return list(value)


def _require_string(value: object, location: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise PortabilityError(f"{location} must be a non-empty string without NUL")
    return value


def _require_int(value: object, location: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise PortabilityError(f"{location} must be an integer >= {minimum}")
    return value


def _parse_hex32(value: object, location: str) -> int:
    raw = _require_string(value, location)
    if not raw.startswith("0x"):
        raise PortabilityError(f"{location} must be a lower-case 0x hexadecimal address")
    try:
        parsed = int(raw, 16)
    except ValueError as exc:
        raise PortabilityError(f"{location} must be hexadecimal") from exc
    if not 0 <= parsed <= 0xFFFFFFFF:
        raise PortabilityError(f"{location} is outside the unsigned 32-bit range")
    if raw != _hex32(parsed):
        raise PortabilityError(f"{location} must be normalized as {_hex32(parsed)!r}")
    return parsed


def _hex32(value: int) -> str:
    return f"0x{value & 0xFFFFFFFF:08x}"


def _resolved_path_string(path: Path) -> str:
    return path.resolve().as_posix()


def _public_path_string(path: Path) -> str:
    """Normalize a host path while redacting workspace/home prefixes."""

    resolved = path.resolve()
    for label, root in (
        ("<workspace>", WORKSPACE_DIRECTORY),
        ("<home>", HOME_DIRECTORY),
    ):
        try:
            relative = resolved.relative_to(root)
        except ValueError:
            continue
        suffix = relative.as_posix()
        return label if not suffix or suffix == "." else f"{label}/{suffix}"
    return resolved.as_posix()


def _is_absolute_path_string(value: str) -> bool:
    return Path(value).is_absolute() or (len(value) >= 3 and value[1:3] == ":/")


def _policy_path(value: str) -> Path:
    candidate = Path(value)
    return candidate if _is_absolute_path_string(value) else RUNNER_DIRECTORY / candidate


def _validate_binary_spec(value: object, location: str) -> dict[str, Any]:
    binary = _require_mapping(value, location)
    expected = {"sha256", "size", "pe_timestamp", "image_base"}
    actual = set(binary)
    if actual != expected:
        raise PortabilityError(
            f"{location} fields must be {sorted(expected)!r}, not {sorted(actual)!r}"
        )
    digest = _require_string(binary["sha256"], f"{location}.sha256").lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise PortabilityError(f"{location}.sha256 must be a lower-case SHA-256 digest")
    size = _require_int(binary["size"], f"{location}.size", minimum=1)
    timestamp = _parse_hex32(binary["pe_timestamp"], f"{location}.pe_timestamp")
    image_base = _parse_hex32(binary["image_base"], f"{location}.image_base")
    return {
        "sha256": digest,
        "size": size,
        "pe_timestamp": _hex32(timestamp),
        "image_base": _hex32(image_base),
    }


def _validate_anchor_signature(value: object, location: str) -> dict[str, Any]:
    signature = _require_mapping(value, location)
    if set(signature) != {"required"}:
        raise PortabilityError(f"{location} must contain only required")
    required = _require_list(signature["required"], f"{location}.required")
    if not required:
        raise PortabilityError(f"{location}.required must not be empty")
    normalized: list[dict[str, str]] = []
    identities: set[tuple[str, str]] = set()
    for index, raw in enumerate(required):
        item_location = f"{location}.required[{index}]"
        item = _require_mapping(raw, item_location)
        allowed = {"category", "text", "address", "absolute_operand_site"}
        if not {"category", "text", "address"} <= set(item) <= allowed:
            raise PortabilityError(f"{item_location} has invalid fields")
        category = _require_string(item["category"], f"{item_location}.category")
        text = _require_string(item["text"], f"{item_location}.text")
        address = _hex32(_parse_hex32(item["address"], f"{item_location}.address"))
        identity = (category, text)
        if identity in identities:
            raise PortabilityError(f"{location}.required repeats {identity!r}")
        identities.add(identity)
        normalized_item = {"category": category, "text": text, "address": address}
        if "absolute_operand_site" in item:
            normalized_item["absolute_operand_site"] = _hex32(
                _parse_hex32(item["absolute_operand_site"], f"{item_location}.absolute_operand_site")
            )
        normalized.append(normalized_item)
    normalized.sort(key=lambda item: (item["category"], item["text"]))
    return {"required": normalized}


def load_policy(path: Path) -> dict[str, Any]:
    """Load and strictly validate portability-policy schema v1."""

    raw = _require_mapping(_load_json(path, "portability policy"), "portability policy")
    expected_root = {"schema", "capture_schema", "search_roots", "requested_builds"}
    if set(raw) != expected_root:
        raise PortabilityError(
            f"portability policy fields must be {sorted(expected_root)!r}, not {sorted(raw)!r}"
        )
    schema = _require_mapping(raw["schema"], "portability policy.schema")
    if schema != {"name": "mwccps2-version-portability-policy", "version": 1}:
        raise PortabilityError("portability policy.schema must name version 1")
    capture_schema = _require_mapping(raw["capture_schema"], "portability policy.capture_schema")
    if set(capture_schema) != {"name", "version", "stage_order"}:
        raise PortabilityError("portability policy.capture_schema has invalid fields")
    if capture_schema["name"] != DIRECT_CAPTURE_SCHEMA_NAME or capture_schema["version"] != SCHEMA_VERSION:
        raise PortabilityError("portability policy.capture_schema has an unsupported schema")
    stages = _require_list(capture_schema["stage_order"], "portability policy.capture_schema.stage_order")
    if stages != [
        "codegen_entry",
        "before_scheduling",
        "after_scheduling",
        "before_register_allocation",
        "after_register_allocation",
    ]:
        raise PortabilityError("portability policy capture stage_order does not match the normalized stage order")
    roots = _require_list(raw["search_roots"], "portability policy.search_roots")
    normalized_roots: list[str] = []
    for index, root in enumerate(roots):
        root_text = _require_string(root, f"portability policy.search_roots[{index}]")
        if root_text not in normalized_roots:
            normalized_roots.append(root_text)
    builds = _require_list(raw["requested_builds"], "portability policy.requested_builds")
    if not builds:
        raise PortabilityError("portability policy.requested_builds must not be empty")
    normalized_builds: list[dict[str, Any]] = []
    keys: set[str] = set()
    for index, raw_build in enumerate(builds):
        location = f"portability policy.requested_builds[{index}]"
        build = _require_mapping(raw_build, location)
        allowed = {"key", "release", "candidate_paths", "binary", "profile", "anchor_signature"}
        required = {"key", "release", "candidate_paths", "binary"}
        if not required <= set(build) <= allowed:
            raise PortabilityError(f"{location} has invalid fields")
        key = _require_string(build["key"], f"{location}.key")
        if key in keys:
            raise PortabilityError(f"portability policy repeats requested build {key!r}")
        keys.add(key)
        release = _require_string(build["release"], f"{location}.release")
        candidate_paths = _require_list(build["candidate_paths"], f"{location}.candidate_paths")
        if not candidate_paths:
            raise PortabilityError(f"{location}.candidate_paths must not be empty")
        normalized_paths: list[str] = []
        for path_index, candidate in enumerate(candidate_paths):
            candidate_text = _require_string(candidate, f"{location}.candidate_paths[{path_index}]")
            if candidate_text not in normalized_paths:
                normalized_paths.append(candidate_text)
        normalized = {
            "key": key,
            "release": release,
            "candidate_paths": normalized_paths,
            "binary": _validate_binary_spec(build["binary"], f"{location}.binary"),
        }
        has_profile = "profile" in build
        has_signature = "anchor_signature" in build
        if has_profile != has_signature:
            raise PortabilityError(f"{location} must supply both profile and anchor_signature or neither")
        if has_profile:
            normalized["profile"] = _require_string(build["profile"], f"{location}.profile")
            normalized["anchor_signature"] = _validate_anchor_signature(
                build["anchor_signature"], f"{location}.anchor_signature"
            )
        normalized_builds.append(normalized)
    normalized_builds.sort(key=lambda build: build["key"])
    return {
        "schema": {"name": "mwccps2-version-portability-policy", "version": 1},
        "capture_schema": {
            "name": DIRECT_CAPTURE_SCHEMA_NAME,
            "version": SCHEMA_VERSION,
            "stage_order": stages,
        },
        "search_roots": normalized_roots,
        "requested_builds": normalized_builds,
    }


def _iter_compiler_paths(roots: Sequence[Path]) -> tuple[list[Path], list[dict[str, Any]]]:
    """Scan supplied roots once, with sorted traversal and recorded inaccessible roots."""

    candidates: dict[str, Path] = {}
    evidence: list[dict[str, Any]] = []
    for root in roots:
        root_text = _public_path_string(root)
        if not root.exists():
            evidence.append({"path": root_text, "status": "missing"})
            continue
        if root.is_file():
            if root.name.casefold() == "mwccps2.exe":
                candidates[_resolved_path_string(root)] = root.resolve()
                evidence.append({"path": root_text, "status": "matched_file"})
            else:
                evidence.append({"path": root_text, "status": "not_compiler_file"})
            continue
        error_count = 0
        for directory, directory_names, filenames in os.walk(root, topdown=True, followlinks=False):
            directory_names.sort(key=str.casefold)
            for filename in sorted(filenames, key=str.casefold):
                if filename.casefold() != "mwccps2.exe":
                    continue
                candidate = Path(directory) / filename
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError:
                    error_count += 1
                    continue
                candidates[_resolved_path_string(resolved)] = resolved
        entry: dict[str, Any] = {"path": root_text, "status": "scanned"}
        if error_count:
            entry["unreadable_entry_count"] = error_count
        evidence.append(entry)
    return [candidates[key] for key in sorted(candidates, key=str.casefold)], evidence


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as binary:
            for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise PortabilityError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest(), size


def _normalized_anchor_inventory(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_anchors = _require_list(report.get("anchors"), "probe report.anchors")
    normalized: list[dict[str, Any]] = []
    for index, raw_anchor in enumerate(raw_anchors):
        anchor = _require_mapping(raw_anchor, f"probe report.anchors[{index}]")
        category = _require_string(anchor.get("category"), f"probe report.anchors[{index}].category")
        text = _require_string(anchor.get("text"), f"probe report.anchors[{index}].text")
        raw_locations = _require_list(anchor.get("locations"), f"probe report.anchors[{index}].locations")
        locations: list[dict[str, Any]] = []
        for location_index, raw_location in enumerate(raw_locations):
            location = _require_mapping(raw_location, f"probe report.anchors[{index}].locations[{location_index}]")
            locations.append(
                {
                    "file_offset": _hex32(_require_int(location.get("file_offset"), "anchor file_offset")),
                    "rva": _hex32(_require_int(location.get("rva"), "anchor rva")),
                    "address": _hex32(_require_int(location.get("va"), "anchor va")),
                    "absolute_operand_sites": sorted(
                        [_hex32(_require_int(site, "anchor absolute operand site")) for site in _require_list(location.get("absolute_operand_sites"), "anchor absolute_operand_sites")]
                    ),
                    "rva_operand_sites": sorted(
                        [_hex32(_require_int(site, "anchor rva operand site")) for site in _require_list(location.get("rva_operand_sites"), "anchor rva_operand_sites")]
                    ),
                }
            )
        locations.sort(key=lambda item: (item["address"], item["file_offset"]))
        normalized.append({"category": category, "text": text, "locations": locations})
    normalized.sort(key=lambda item: (item["category"], item["text"]))
    return normalized


def _normalized_probe(path: Path) -> dict[str, Any]:
    try:
        image = probe.PEImage.load(path)
        report = probe.build_report(image)
    except probe.ProbeError as exc:
        raise PortabilityError(f"cannot probe {path}: {exc}") from exc
    if not report.get("is_i386"):
        raise PortabilityError(f"compiler candidate {path} is not an i386 PE")
    if not report.get("is_mwccps2"):
        raise PortabilityError(f"compiler candidate {path} lacks the MWCCPS2 identity anchor")
    pe = _require_mapping(report.get("pe"), "probe report.pe")
    return {
        "sha256": _require_string(report.get("sha256"), "probe report.sha256").lower(),
        "size": _require_int(report.get("size"), "probe report.size", minimum=1),
        "pe": {
            "machine": _hex32(_require_int(pe.get("machine"), "probe report.pe.machine")),
            "timestamp": _hex32(_require_int(pe.get("timestamp"), "probe report.pe.timestamp")),
            "characteristics": _hex32(_require_int(pe.get("characteristics"), "probe report.pe.characteristics")),
            "image_base": _hex32(_require_int(pe.get("image_base"), "probe report.pe.image_base")),
            "entry_point_rva": _hex32(_require_int(pe.get("entry_point_rva"), "probe report.pe.entry_point_rva")),
            "sections": [
                {
                    "characteristics": _hex32(_require_int(section["characteristics"], "section characteristics")),
                    "name": _require_string(section["name"], "section name"),
                    "raw_offset": _hex32(_require_int(section["raw_offset"], "section raw_offset")),
                    "raw_size": _hex32(_require_int(section["raw_size"], "section raw_size")),
                    "virtual_address": _hex32(_require_int(section["virtual_address"], "section virtual_address")),
                    "virtual_size": _hex32(_require_int(section["virtual_size"], "section virtual_size")),
                }
                for section in sorted(
                    _require_list(pe.get("sections"), "probe report.pe.sections"), key=lambda value: str(value["name"])
                )
            ],
        },
        "identity": {
            "mwccps2_identity_present": True,
            "source_inventory": {
                "counts_by_suffix": dict(
                    sorted(
                        _require_mapping(report["source_inventory"], "probe report.source_inventory")["counts_by_suffix"].items()
                    )
                ),
                "files": list(_require_mapping(report["source_inventory"], "probe report.source_inventory")["files"]),
            },
        },
        "anchor_inventory": _normalized_anchor_inventory(report),
    }


def _matches_binary_spec(fingerprint: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return (
        fingerprint["sha256"] == expected["sha256"]
        and fingerprint["size"] == expected["size"]
        and fingerprint["pe"]["timestamp"] == expected["pe_timestamp"]
        and fingerprint["pe"]["image_base"] == expected["image_base"]
    )


def _anchor_index(anchor_inventory: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str], list[Mapping[str, Any]]]:
    result: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for anchor in anchor_inventory:
        result[(str(anchor["category"]), str(anchor["text"]))] = list(anchor["locations"])
    return result


def _validate_b210_signature(build: Mapping[str, Any], fingerprint: Mapping[str, Any], profiles_directory: Path) -> dict[str, Any]:
    """Validate the schema profile and independently rediscover every required anchor."""

    profile_filename = str(build["profile"])
    profile_path = profiles_directory / profile_filename
    try:
        b210_profile = load_b210_profile(profile_path)
    except SnapshotModelError as exc:
        raise PortabilityError(f"b210 profile {profile_path} failed schema validation: {exc}") from exc
    profile_binary_mapping = _require_mapping(b210_profile.get("binary"), "b210 profile.binary")
    if profile_binary_mapping.get("filename") != "mwccps2.exe":
        raise PortabilityError("b210 profile.binary.filename must identify mwccps2.exe")
    profile_binary = _validate_binary_spec(
        {key: profile_binary_mapping.get(key) for key in ("sha256", "size", "pe_timestamp", "image_base")},
        "b210 profile.binary",
    )
    if profile_binary != build["binary"]:
        raise PortabilityError("b210 profile binary fingerprint does not match portability policy")
    if not _matches_binary_spec(fingerprint, profile_binary):
        raise PortabilityError("b210 compiler fingerprint does not match the validated b210 profile")
    profile_string_anchors = _require_mapping(b210_profile.get("string_anchors"), "b210 profile.string_anchors")
    signature_by_text = {
        item["text"]: item for item in build["anchor_signature"]["required"]
    }
    profile_anchor_consistency: list[dict[str, str]] = []
    for source_anchor in ("CodeGen.c", "Coloring.c", "Scheduler.c"):
        expected_address = signature_by_text[source_anchor]["address"]
        actual_address = _hex32(
            _parse_hex32(profile_string_anchors.get(source_anchor), f"b210 profile.string_anchors.{source_anchor}")
        )
        if actual_address != expected_address:
            raise PortabilityError(
                f"b210 profile anchor {source_anchor} is {actual_address}, expected {expected_address}"
            )
        profile_anchor_consistency.append(
            {"profile_field": source_anchor, "address": actual_address, "status": "matched"}
        )
    for profile_field, signature_text in (
        ("post_coloring", "After peepholeoptimizepcode [POST COLORING]"),
        ("post_schedule", "After peepholeoptimizepcode [POST SCHEDULE]"),
    ):
        expected = signature_by_text[signature_text]
        profile_anchor = _require_mapping(
            profile_string_anchors.get(profile_field), f"b210 profile.string_anchors.{profile_field}"
        )
        actual_address = _hex32(
            _parse_hex32(profile_anchor.get("string_address"), f"b210 profile.string_anchors.{profile_field}.string_address")
        )
        expected_reference = _hex32(int(expected["absolute_operand_site"], 16) - 1)
        actual_reference = _hex32(
            _parse_hex32(profile_anchor.get("reference_address"), f"b210 profile.string_anchors.{profile_field}.reference_address")
        )
        if actual_address != expected["address"] or actual_reference != expected_reference:
            raise PortabilityError(
                f"b210 profile anchor {profile_field} does not match the required string/xref signature"
            )
        profile_anchor_consistency.append(
            {
                "profile_field": profile_field,
                "address": actual_address,
                "reference_address": actual_reference,
                "status": "matched",
            }
        )
    found = _anchor_index(fingerprint["anchor_inventory"])
    checked: list[dict[str, Any]] = []
    for required in build["anchor_signature"]["required"]:
        category = required["category"]
        text = required["text"]
        expected_address = required["address"]
        locations = found.get((category, text), [])
        matching_locations = [location for location in locations if location["address"] == expected_address]
        if not matching_locations:
            raise PortabilityError(
                f"b210 anchor signature did not find {category}/{text!r} at {expected_address}"
            )
        expected_operand = required.get("absolute_operand_site")
        if expected_operand is not None and not any(
            expected_operand in location["absolute_operand_sites"] for location in matching_locations
        ):
            raise PortabilityError(
                f"b210 anchor signature did not find xref {expected_operand} for {text!r}"
            )
        checked_item = {
            "category": category,
            "text": text,
            "address": expected_address,
            "status": "matched",
        }
        if expected_operand is not None:
            checked_item["absolute_operand_site"] = expected_operand
        checked.append(checked_item)
    return {
        "status": "validated",
        "profile": profile_filename,
        "filename_validation": "not_used_for_loaded_executable_identity",
        "binary_fingerprint": {
            "sha256": fingerprint["sha256"],
            "size": fingerprint["size"],
            "pe_timestamp": fingerprint["pe"]["timestamp"],
            "image_base": fingerprint["pe"]["image_base"],
        },
        "anchor_signature": checked,
        "profile_anchor_consistency": profile_anchor_consistency,
    }


def _find_preferred_location(build: Mapping[str, Any], locations: Sequence[Path]) -> Path:
    candidates = {_resolved_path_string(path): path for path in locations}
    for raw_path in build["candidate_paths"]:
        candidate = _policy_path(raw_path)
        if candidate.exists():
            resolved = _resolved_path_string(candidate)
            if resolved in candidates:
                return candidates[resolved]
    return sorted(locations, key=lambda path: _resolved_path_string(path).casefold())[0]


def discover_builds(policy: Mapping[str, Any], extra_search_roots: Sequence[Path], profiles_directory: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    roots = [_policy_path(root) for root in policy["search_roots"]]
    roots.extend(extra_search_roots)
    deduplicated_roots: list[Path] = []
    seen_roots: set[str] = set()
    for root in roots:
        identity = root.as_posix().casefold()
        if identity not in seen_roots:
            seen_roots.add(identity)
            deduplicated_roots.append(root)
    discovered_paths, root_evidence = _iter_compiler_paths(deduplicated_roots)
    fingerprints_by_path: dict[str, dict[str, Any]] = {}
    for path in discovered_paths:
        fingerprints_by_path[_resolved_path_string(path)] = _normalized_probe(path)
    results: list[dict[str, Any]] = []
    for build in policy["requested_builds"]:
        matching_locations = [
            path
            for path in discovered_paths
            if _matches_binary_spec(fingerprints_by_path[_resolved_path_string(path)], build["binary"])
        ]
        configured_candidates = [_policy_path(value) for value in build["candidate_paths"]]
        missing_candidates = [
            path for path in configured_candidates if not path.is_file()
        ]
        if not matching_locations:
            results.append(
                {
                    "schema": {"name": BUILD_PROFILE_SCHEMA_NAME, "version": SCHEMA_VERSION},
                    "build": {"key": build["key"], "release": build["release"]},
                    "availability": {
                        "status": "unavailable_on_scanned_roots",
                        "candidate_paths_checked": [_public_path_string(path) for path in configured_candidates],
                        "missing_candidate_paths": sorted(
                            [_public_path_string(path) for path in missing_candidates],
                            key=str.casefold,
                        ),
                        "search_root_evidence": root_evidence,
                    },
                    "binary": build["binary"],
                    "capture": {
                        "schema": policy["capture_schema"],
                        "status": "not_run",
                        "instrumented_object_verification": {
                            "status": "not_run",
                            "reason": "no executable matching the evidence-backed requested fingerprint was found",
                        },
                    },
                }
            )
            continue
        selected = _find_preferred_location(build, matching_locations)
        fingerprint = fingerprints_by_path[_resolved_path_string(selected)]
        validation: dict[str, Any]
        if "profile" in build:
            validation = _validate_b210_signature(build, fingerprint, profiles_directory)
        else:
            validation = {
                "status": "fingerprinted",
                "evidence": "exact SHA-256, size, PE timestamp, image base, MWCCPS2 identity string, and backend anchor inventory",
            }
        results.append(
            {
                "schema": {"name": BUILD_PROFILE_SCHEMA_NAME, "version": SCHEMA_VERSION},
                "build": {"key": build["key"], "release": build["release"]},
                "_runtime": {
                    "selected_path": _resolved_path_string(selected),
                },
                "availability": {
                    "status": "available",
                    "selected_path": _public_path_string(selected),
                    "matching_paths": sorted(
                        [_public_path_string(path) for path in matching_locations], key=str.casefold
                    ),
                    "candidate_paths_checked": [_public_path_string(path) for path in configured_candidates],
                    "missing_candidate_paths": sorted(
                        [_public_path_string(path) for path in missing_candidates],
                        key=str.casefold,
                    ),
                    "search_root_evidence": root_evidence,
                },
                "binary": {
                    "filename": selected.name,
                    **fingerprint,
                },
                "profile_validation": validation,
                "capture": {
                    "schema": policy["capture_schema"],
                    "status": "not_run",
                    "instrumented_object_verification": {
                        "status": "not_run",
                        "reason": (
                            "the existing b210 experiment runner remains required for direct-versus-instrumented object SHA verification"
                            if build["key"] == "b210"
                            else "the b210 GDB decoder is intentionally not applied to a non-b210 build"
                        ),
                    },
                },
            }
        )
    return results, root_evidence


def _load_experiment_manifest(directory: Path) -> dict[str, Any]:
    """Use the existing schema-v1 experiment loader without invoking GDB instrumentation."""

    try:
        from mwccps2_experiment import ExperimentError, load_experiment
    except ImportError as exc:
        raise PortabilityError(f"cannot load experiment schema helper: {exc}") from exc
    try:
        experiment = load_experiment(directory)
    except ExperimentError as exc:
        raise PortabilityError(f"invalid experiment corpus entry {directory}: {exc}") from exc
    return experiment


def _experiment_directories(experiments_directory: Path) -> list[Path]:
    try:
        directories = [path for path in experiments_directory.iterdir() if path.is_dir()]
    except OSError as exc:
        raise PortabilityError(f"cannot enumerate experiment corpus {experiments_directory}: {exc}") from exc
    result: list[Path] = []
    for directory in sorted(directories, key=lambda path: path.name.casefold()):
        if not (directory / "experiment.json").is_file():
            raise PortabilityError(f"experiment corpus directory lacks experiment.json: {directory}")
        result.append(directory)
    if not result:
        raise PortabilityError(f"experiment corpus is empty: {experiments_directory}")
    return result


def _run_direct_compile(
    compiler: Path,
    flags: Sequence[str],
    source: Path,
    object_path: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    command = [str(compiler), *[str(flag) for flag in flags], "-c", str(source), "-o", str(object_path)]
    try:
        completed = subprocess.run(
            command,
            cwd=str(object_path.parent),
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=timeout_seconds,
        )
    except OSError as exc:
        raise PortabilityError(f"cannot start direct compilation of {source.name}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PortabilityError(
            f"direct compilation of {source.name} exceeded {timeout_seconds} seconds: {exc}"
        ) from exc
    if completed.returncode:
        output = "\n".join(part for part in (completed.stdout.strip(), completed.stderr.strip()) if part)
        raise PortabilityError(
            f"direct compilation of {source.name} failed with exit code {completed.returncode}: {output or '(no compiler output)'}"
        )
    if not object_path.is_file():
        raise PortabilityError(f"direct compilation of {source.name} did not create {object_path}")
    sha256, size = _sha256_file(object_path)
    return {"object_sha256": sha256, "object_size": size}


def _run_corpus_for_build(
    profile: Mapping[str, Any],
    experiment_directories: Sequence[Path],
    temporary_root: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    runtime = _require_mapping(profile.get("_runtime"), "profile._runtime")
    compiler = Path(_require_string(runtime.get("selected_path"), "profile._runtime.selected_path"))
    build_directory = temporary_root / str(profile["build"]["key"])
    build_directory.mkdir(parents=True, exist_ok=False)
    experiments: list[dict[str, Any]] = []
    for experiment_directory in experiment_directories:
        experiment = _load_experiment_manifest(experiment_directory)
        per_experiment = build_directory / str(experiment["name"])
        per_experiment.mkdir(parents=True, exist_ok=False)
        variants: list[dict[str, Any]] = []
        for variant in experiment["variants"]:
            object_path = per_experiment / f"{variant['name']}.o"
            object_fingerprint = _run_direct_compile(
                compiler,
                experiment["compiler_flags"],
                variant["source_path"],
                object_path,
                timeout_seconds,
            )
            variants.append(
                {
                    "name": variant["name"],
                    "source": variant["source"],
                    "function": variant["function"],
                    "intent": variant["intent"],
                    **object_fingerprint,
                }
            )
        baseline = variants[0]
        experiments.append(
            {
                "name": experiment["name"],
                "question": experiment["question"],
                "compiler_flags": list(experiment["compiler_flags"]),
                "baseline_variant": baseline["name"],
                "variants": variants,
                "variant_object_equal_to_baseline": [
                    {
                        "variant": variant["name"],
                        "equal": variant["object_sha256"] == baseline["object_sha256"],
                    }
                    for variant in variants
                ],
            }
        )
    return {
        "schema": {"name": DIRECT_CAPTURE_SCHEMA_NAME, "version": SCHEMA_VERSION},
        "status": "completed",
        "method": "direct_object",
        "experiment_count": len(experiments),
        "experiments": experiments,
    }


def _behavior_comparison(b210: Mapping[str, Any], alternate: Mapping[str, Any]) -> dict[str, Any]:
    b210_capture = b210["capture"]["direct_object_corpus"]
    alternate_capture = alternate["capture"]["direct_object_corpus"]
    b210_experiments = {entry["name"]: entry for entry in b210_capture["experiments"]}
    alternate_experiments = {entry["name"]: entry for entry in alternate_capture["experiments"]}
    comparisons: list[dict[str, Any]] = []
    behavior_localization: dict[str, Any] | None = None
    for name in sorted(set(b210_experiments) | set(alternate_experiments), key=str.casefold):
        baseline_entry = b210_experiments.get(name)
        alternate_entry = alternate_experiments.get(name)
        if baseline_entry is None or alternate_entry is None:
            comparisons.append(
                {
                    "experiment": name,
                    "status": "missing_from_b210" if baseline_entry is None else "missing_from_alternate",
                }
            )
            continue
        b210_variants = {entry["name"]: entry for entry in baseline_entry["variants"]}
        alternate_variants = {entry["name"]: entry for entry in alternate_entry["variants"]}
        variants: list[dict[str, Any]] = []
        b210_relation = {
            entry["variant"]: entry["equal"] for entry in baseline_entry["variant_object_equal_to_baseline"]
        }
        alternate_relation = {
            entry["variant"]: entry["equal"] for entry in alternate_entry["variant_object_equal_to_baseline"]
        }
        for variant_name in sorted(set(b210_variants) | set(alternate_variants), key=str.casefold):
            baseline_variant = b210_variants.get(variant_name)
            alternate_variant = alternate_variants.get(variant_name)
            if baseline_variant is None or alternate_variant is None:
                variants.append(
                    {
                        "variant": variant_name,
                        "status": "missing_from_b210" if baseline_variant is None else "missing_from_alternate",
                    }
                )
                continue
            object_equal = baseline_variant["object_sha256"] == alternate_variant["object_sha256"]
            relation_equal = b210_relation[variant_name] == alternate_relation[variant_name]
            variant_record = {
                "variant": variant_name,
                "object_sha256_equal": object_equal,
                "baseline_relation_equal": relation_equal,
            }
            variants.append(variant_record)
            if behavior_localization is None and not relation_equal:
                behavior_localization = {
                    "kind": "variant_to_baseline_object_relation_changed",
                    "experiment": name,
                    "variant": variant_name,
                    "b210_equal_to_baseline": b210_relation[variant_name],
                    "alternate_equal_to_baseline": alternate_relation[variant_name],
                    "evidence": "Direct object SHA-256 equality relation differs for the same schema-v1 experiment variant.",
                }
            elif behavior_localization is None and not object_equal:
                behavior_localization = {
                    "kind": "direct_object_sha256_changed",
                    "experiment": name,
                    "variant": variant_name,
                    "b210_object_sha256": baseline_variant["object_sha256"],
                    "alternate_object_sha256": alternate_variant["object_sha256"],
                    "evidence": "The same source and compiler flags produced different direct object SHA-256 values.",
                }
        comparisons.append({"experiment": name, "variants": variants})
    return {
        "baseline_build": b210["build"]["key"],
        "alternate_build": alternate["build"]["key"],
        "comparison_method": "direct_object_sha256_and_variant_to_baseline_relation",
        "experiments": comparisons,
        "behavior_localization": behavior_localization,
    }


def _add_corpus(
    profiles: list[dict[str, Any]],
    experiments_directory: Path,
    work_directory: Path,
    timeout_seconds: int,
) -> list[dict[str, Any]]:
    directories = _experiment_directories(experiments_directory)
    available = [profile for profile in profiles if profile["availability"]["status"] == "available"]
    if not available:
        return profiles
    work_directory = work_directory.resolve()
    work_directory.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="version-portability-", dir=work_directory) as temporary:
            temporary_root = Path(temporary)
            for profile in available:
                corpus = _run_corpus_for_build(profile, directories, temporary_root, timeout_seconds)
                profile["capture"] = {
                    "schema": profile["capture"]["schema"],
                    "status": "completed",
                    "direct_object_corpus": corpus,
                    "instrumented_object_verification": profile["capture"]["instrumented_object_verification"],
                }
    except OSError as exc:
        raise PortabilityError(f"cannot create portability corpus work directory {work_directory}: {exc}") from exc
    by_key = {profile["build"]["key"]: profile for profile in profiles}
    b210 = by_key.get("b210")
    if b210 is not None and b210["availability"]["status"] == "available":
        alternates = [profile for profile in profiles if profile["build"]["key"] != "b210" and profile["availability"]["status"] == "available"]
        for alternate in alternates:
            alternate["behavior_comparison_to_b210"] = _behavior_comparison(b210, alternate)
    return profiles


def build_index(policy: Mapping[str, Any], profiles: Sequence[Mapping[str, Any]], root_evidence: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    index_profiles: list[dict[str, Any]] = []
    for profile in profiles:
        key = str(profile["build"]["key"])
        entry = {
            "key": key,
            "release": profile["build"]["release"],
            "availability": profile["availability"]["status"],
            "profile_file": f"mwcps2-{profile['build']['release'].removeprefix('mwcps2-')}.portability.json",
        }
        if profile["availability"]["status"] == "available":
            entry["sha256"] = profile["binary"]["sha256"]
            entry["pe_timestamp"] = profile["binary"]["pe"]["timestamp"]
        index_profiles.append(entry)
    index_profiles.sort(key=lambda entry: entry["key"])
    return {
        "schema": {"name": INDEX_SCHEMA_NAME, "version": SCHEMA_VERSION},
        "policy_schema": policy["schema"],
        "capture_schema": policy["capture_schema"],
        "search_root_evidence": list(root_evidence),
        "builds": index_profiles,
    }


def _profile_filename(profile: Mapping[str, Any]) -> str:
    release = str(profile["build"]["release"])
    return f"{release}.portability.json"


def _write_atomically(path: Path, value: Any) -> None:
    temporary_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(_canonical_json(value))
        temporary_path.replace(path)
    except OSError as exc:
        raise PortabilityError(f"cannot write {path}: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _public_artifact(value: Any) -> Any:
    """Remove runtime-only fields before writing a shareable artifact."""

    if isinstance(value, Mapping):
        return {
            str(key): _public_artifact(item)
            for key, item in value.items()
            if not str(key).startswith("_")
        }
    if isinstance(value, (list, tuple)):
        return [_public_artifact(item) for item in value]
    return value


def write_profiles(profiles_directory: Path, profiles: Sequence[Mapping[str, Any]], index: Mapping[str, Any]) -> list[Path]:
    written: list[Path] = []
    for profile in profiles:
        path = profiles_directory / _profile_filename(profile)
        _write_atomically(path, _public_artifact(profile))
        written.append(path)
    index_path = profiles_directory / INDEX_FILENAME
    _write_atomically(index_path, _public_artifact(index))
    written.append(index_path)
    return written


def _print_summary(profiles: Sequence[Mapping[str, Any]], wrote: Sequence[Path]) -> None:
    for profile in profiles:
        build = profile["build"]
        availability = profile["availability"]
        if availability["status"] == "available":
            binary = profile["binary"]
            validation = profile.get("profile_validation", {}).get("status", "not_applicable")
            corpus = profile["capture"]["status"]
            print(
                f"{build['key']}: available sha256={binary['sha256']} timestamp={binary['pe']['timestamp']} "
                f"profile_validation={validation} corpus={corpus}"
            )
        else:
            print(f"{build['key']}: {availability['status']}")
    for path in wrote:
        print(f"wrote: {path}")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover and compare local MWCCPS2 b151/b198/b205/b210 portable profiles."
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="schema-v1 portability policy JSON")
    parser.add_argument(
        "--profiles-dir", type=Path, default=DEFAULT_PROFILES_DIRECTORY, help="directory containing b210 and generated profile JSON"
    )
    parser.add_argument(
        "--search-root", action="append", type=Path, default=[], help="additional directory or mwccps2.exe to scan (repeatable)"
    )
    parser.add_argument(
        "--run-corpus", action="store_true", help="directly compile every schema-v1 experiment for every available requested build"
    )
    parser.add_argument(
        "--experiments-dir", type=Path, default=DEFAULT_EXPERIMENTS_DIRECTORY, help="schema-v1 experiment corpus directory"
    )
    parser.add_argument(
        "--work-dir", type=Path, default=DEFAULT_BUILD_DIRECTORY, help="ignored temporary build parent for --run-corpus"
    )
    parser.add_argument(
        "--timeout-seconds", type=int, default=120, help="per direct compilation timeout (default: 120)"
    )
    parser.add_argument("--write-profiles", action="store_true", help="atomically write normalized profile JSON and index to --profiles-dir")
    parser.add_argument("--json", type=Path, help="atomically write the complete portability index to this path")
    args = parser.parse_args(argv)
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    if args.run_corpus and not args.experiments_dir.is_dir():
        parser.error("--experiments-dir must be an existing directory when --run-corpus is used")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        policy = load_policy(args.policy)
        profiles, root_evidence = discover_builds(policy, args.search_root, args.profiles_dir)
        if args.run_corpus:
            profiles = _add_corpus(profiles, args.experiments_dir, args.work_dir, args.timeout_seconds)
        index = build_index(policy, profiles, root_evidence)
        wrote: list[Path] = []
        if args.write_profiles:
            wrote.extend(write_profiles(args.profiles_dir, profiles, index))
        if args.json is not None:
            _write_atomically(args.json, index)
            wrote.append(args.json)
    except PortabilityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_summary(profiles, wrote)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
