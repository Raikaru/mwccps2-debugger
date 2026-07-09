#!/usr/bin/env python3
"""Compile b210 experiment variants and compare their PCode snapshots.

An experiment directory contains an ``experiment.json`` manifest and self-contained C
sources.  This runner deliberately keeps every generated artifact beneath a fresh
subdirectory of this tool's ignored ``build/`` directory.  It performs two compilations
per variant: a normal object build and an equivalent build launched under GDB with the
b210 auto-continuing snapshot command armed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePath
import re
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence

import mwccps2_probe as probe
from gdb.b210_snapshot_model import (
    MANIFEST_SCHEMA_NAME,
    MANIFEST_SCHEMA_VERSION,
    SNAPSHOT_SCHEMA_NAME,
    SNAPSHOT_SCHEMA_VERSION,
    SnapshotModelError,
    fingerprint_executable,
    format_pcode_text,
    load_b210_profile,
)


RUNNER_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_COMPILER = Path("D:/mwcps2-3.0.1b210-060308/mwccps2.exe")
DEFAULT_PROFILE = RUNNER_DIRECTORY / "profiles" / "mwcps2-3.0.1-b210.json"
SNAPSHOT_COMMAND = RUNNER_DIRECTORY / "gdb" / "mwccps2_b210_snapshot.py"
BUILD_DIRECTORY = RUNNER_DIRECTORY / "build"

SUMMARY_SCHEMA_NAME = "mwccps2-experiment-summary"
SUMMARY_SCHEMA_VERSION = 1
SUMMARY_FILENAME = f"experiment-summary-v{SUMMARY_SCHEMA_VERSION}.json"

_VOLATILE_SNAPSHOT_KEYS = frozenset({"captured_at", "created_at", "path"})
_SAFE_VARIANT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class ExperimentError(Exception):
    """Raised when an experiment cannot be safely compiled or compared."""


def _is_exact_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_mapping(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExperimentError(f"{location} must be an object")
    return value


def _require_string(value: object, location: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise ExperimentError(f"{location} must be a string")
    if nonempty and not value:
        raise ExperimentError(f"{location} must not be empty")
    if "\0" in value:
        raise ExperimentError(f"{location} must not contain a NUL byte")
    return value


def _reject_unknown_keys(mapping: Mapping[str, Any], expected: Iterable[str], location: str) -> None:
    unknown = sorted(set(mapping) - set(expected))
    if unknown:
        raise ExperimentError(f"{location} contains unknown field(s): {', '.join(unknown)}")
    missing = sorted(set(expected) - set(mapping))
    if missing:
        raise ExperimentError(f"{location} is missing required field(s): {', '.join(missing)}")


def _no_duplicate_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExperimentError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _load_json(path: Path, description: str) -> Any:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExperimentError(f"cannot read {description} {path}: {exc}") from exc
    try:
        return json.loads(content, object_pairs_hook=_no_duplicate_json_object)
    except ExperimentError:
        raise
    except json.JSONDecodeError as exc:
        raise ExperimentError(f"{description} {path} is not valid JSON: {exc}") from exc


def _read_sha256(path: Path, description: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as input_file:
            for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise ExperimentError(f"cannot hash {description} {path}: {exc}") from exc
    return digest.hexdigest(), size


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExperimentError(f"snapshot contains non-canonical JSON data: {exc}") from exc


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _normalize_volatile_snapshot_value(value: Any) -> Any:
    """Drop host-specific snapshot metadata without changing graph semantics."""

    if isinstance(value, dict):
        return {
            key: _normalize_volatile_snapshot_value(child)
            for key, child in value.items()
            if key not in _VOLATILE_SNAPSHOT_KEYS and not key.endswith("_path")
        }
    if isinstance(value, list):
        return [_normalize_volatile_snapshot_value(child) for child in value]
    return value


def _path_in_directory(path: Path, directory: Path, location: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError(f"cannot resolve {location} {path}: {exc}") from exc
    try:
        resolved.relative_to(directory)
    except ValueError as exc:
        raise ExperimentError(f"{location} {path} escapes experiment directory {directory}") from exc
    return resolved


def _strip_c_comments_and_literals(source: str) -> str:
    """Preserve C token layout while hiding comments and literals from structural checks."""

    output = list(source)
    index = 0
    length = len(source)
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end < 0:
                end = length
            for cursor in range(index, end):
                output[cursor] = " "
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise ExperimentError("C source contains an unterminated block comment")
            end += 2
            for cursor in range(index, end):
                if output[cursor] != "\n":
                    output[cursor] = " "
            index = end
            continue
        if source[index] in {'"', "'"}:
            quote = source[index]
            output[index] = " "
            index += 1
            while index < length:
                if source[index] == "\\":
                    output[index] = " "
                    index += 1
                    if index < length:
                        if output[index] != "\n":
                            output[index] = " "
                        index += 1
                    continue
                if source[index] == quote:
                    output[index] = " "
                    index += 1
                    break
                if output[index] != "\n":
                    output[index] = " "
                index += 1
            else:
                raise ExperimentError("C source contains an unterminated string or character literal")
            continue
        index += 1
    return "".join(output)


def _exported_function_signature(source: str, function: str, source_label: str) -> str:
    """Return a normalized global definition signature for the manifest function."""

    code = _strip_c_comments_and_literals(source)
    if re.search(r"(?m)^\s*#\s*include\b", code):
        raise ExperimentError(f"{source_label} includes a header; experiment sources must be header-free")

    definitions: list[str] = []
    token = re.compile(rf"\b{re.escape(function)}\s*\(")
    for candidate in token.finditer(code):
        # Standard C has no nested function definitions.  Restricting this to file scope
        # avoids accepting a call used as an if/while condition as a definition.
        prefix = code[: candidate.start()]
        if prefix.count("{") != prefix.count("}"):
            continue
        opening_parenthesis = code.find("(", candidate.start(), candidate.end())
        assert opening_parenthesis >= 0
        depth = 1
        cursor = opening_parenthesis + 1
        while cursor < len(code) and depth:
            if code[cursor] == "(":
                depth += 1
            elif code[cursor] == ")":
                depth -= 1
            cursor += 1
        if depth:
            raise ExperimentError(f"{source_label} has an unterminated parameter list for {function}")
        after_parameters = cursor
        while after_parameters < len(code) and code[after_parameters].isspace():
            after_parameters += 1
        if after_parameters == len(code) or code[after_parameters] != "{":
            continue
        declaration_start = max(
            code.rfind(";", 0, candidate.start()), code.rfind("}", 0, candidate.start())
        ) + 1
        return_specifiers = code[declaration_start : candidate.start()]
        if not return_specifiers.strip():
            raise ExperimentError(f"{source_label} has no return type for exported function {function}")
        if re.search(r"\bstatic\b", return_specifiers):
            raise ExperimentError(f"{source_label} defines {function} as static, not exported")
        definition = code[declaration_start:cursor]
        definitions.append(" ".join(definition.split()))

    if not definitions:
        raise ExperimentError(f"{source_label} does not define exported function {function}")
    if len(definitions) != 1:
        raise ExperimentError(f"{source_label} defines exported function {function} more than once")
    return definitions[0]


def _validate_compiler_flags(value: object) -> list[str]:
    if not isinstance(value, list):
        raise ExperimentError("experiment.json.compiler_flags must be an array")
    flags: list[str] = []
    for index, raw_flag in enumerate(value):
        flag = _require_string(raw_flag, f"experiment.json.compiler_flags[{index}]")
        if flag in {"-c", "/c", "-o", "/o"} or flag.startswith("-o=") or (
            flag.startswith("-o") and len(flag) > 2
        ):
            raise ExperimentError(
                "experiment.json.compiler_flags must not select compilation inputs or outputs; "
                f"runner owns {flag!r}"
            )
        flags.append(flag)
    return flags


def _validate_source_path(experiment_directory: Path, source: str, location: str) -> Path:
    raw_path = PurePath(source)
    if raw_path.is_absolute() or ".." in raw_path.parts:
        raise ExperimentError(f"{location} must be a relative path contained in the experiment directory")
    candidate = experiment_directory / source
    if not candidate.is_file():
        raise ExperimentError(f"{location} does not name a readable source file: {candidate}")
    return _path_in_directory(candidate, experiment_directory, location)


def load_experiment(experiment_directory: Path) -> dict[str, Any]:
    """Load schema v1 and validate the cross-variant source contract."""

    try:
        resolved_directory = experiment_directory.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError(f"cannot resolve experiment directory {experiment_directory}: {exc}") from exc
    if not resolved_directory.is_dir():
        raise ExperimentError(f"experiment directory is not a directory: {resolved_directory}")

    manifest_path = resolved_directory / "experiment.json"
    raw_manifest = _require_mapping(_load_json(manifest_path, "experiment manifest"), "experiment manifest")
    _reject_unknown_keys(
        raw_manifest,
        {"schema_version", "name", "question", "compiler_flags", "variants"},
        "experiment manifest",
    )
    if not _is_exact_int(raw_manifest["schema_version"]) or raw_manifest["schema_version"] != 1:
        raise ExperimentError("experiment.json.schema_version must be integer 1")
    name = _require_string(raw_manifest["name"], "experiment.json.name")
    question = _require_string(raw_manifest["question"], "experiment.json.question")
    compiler_flags = _validate_compiler_flags(raw_manifest["compiler_flags"])
    variants_value = raw_manifest["variants"]
    if not isinstance(variants_value, list) or not variants_value:
        raise ExperimentError("experiment.json.variants must be a non-empty array")

    variants: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    expected_function: str | None = None
    expected_signature: str | None = None
    for index, raw_variant in enumerate(variants_value):
        location = f"experiment.json.variants[{index}]"
        variant = _require_mapping(raw_variant, location)
        _reject_unknown_keys(variant, {"name", "source", "function", "intent"}, location)
        variant_name = _require_string(variant["name"], f"{location}.name")
        if not _SAFE_VARIANT_NAME.fullmatch(variant_name):
            raise ExperimentError(
                f"{location}.name must begin with a letter and contain only letters, digits, _ or -"
            )
        if variant_name in seen_names:
            raise ExperimentError(f"{location}.name duplicates variant {variant_name!r}")
        seen_names.add(variant_name)
        source = _require_string(variant["source"], f"{location}.source")
        function = _require_string(variant["function"], f"{location}.function")
        if not _C_IDENTIFIER.fullmatch(function):
            raise ExperimentError(f"{location}.function must be a C identifier")
        intent = _require_string(variant["intent"], f"{location}.intent")
        source_path = _validate_source_path(resolved_directory, source, f"{location}.source")
        try:
            source_text = source_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ExperimentError(f"{location}.source is not UTF-8 text: {source_path}") from exc
        except OSError as exc:
            raise ExperimentError(f"cannot read {location}.source {source_path}: {exc}") from exc
        signature = _exported_function_signature(source_text, function, source)
        if expected_function is None:
            expected_function = function
            expected_signature = signature
        elif function != expected_function:
            raise ExperimentError(
                f"{location}.function must match first variant function {expected_function!r}"
            )
        elif signature != expected_signature:
            raise ExperimentError(
                f"{location}.source function signature {signature!r} does not match first variant "
                f"signature {expected_signature!r}"
            )
        variants.append(
            {
                "name": variant_name,
                "source": source,
                "source_path": source_path,
                "function": function,
                "intent": intent,
                "signature": signature,
            }
        )

    return {
        "directory": resolved_directory,
        "name": name,
        "question": question,
        "compiler_flags": compiler_flags,
        "variants": variants,
    }


def fingerprint_b210(compiler: Path, profile_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate b210 with both the PE probe and snapshot profile validator."""

    try:
        resolved_compiler = compiler.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError(f"cannot resolve compiler {compiler}: {exc}") from exc
    if not resolved_compiler.is_file():
        raise ExperimentError(f"compiler is not a file: {resolved_compiler}")

    try:
        profile = load_b210_profile(profile_path)
        executable = fingerprint_executable(resolved_compiler, profile)
    except SnapshotModelError as exc:
        raise ExperimentError(f"b210 profile fingerprint failed: {exc}") from exc
    try:
        probe_report = probe.build_report(probe.PEImage.load(resolved_compiler))
    except probe.ProbeError as exc:
        raise ExperimentError(f"compiler PE probe failed: {exc}") from exc
    if not probe_report["is_i386"]:
        raise ExperimentError("compiler PE probe rejected the compiler: it is not an i386 image")
    if not probe_report["is_mwccps2"]:
        raise ExperimentError("compiler PE probe rejected the compiler: MWCCPS2 identity was not found")
    return profile, executable, probe_report


def _format_command(command: Sequence[str]) -> str:
    return subprocess.list2cmdline([str(argument) for argument in command])


def _format_process_output(completed: subprocess.CompletedProcess[str]) -> str:
    pieces = []
    if completed.stdout:
        pieces.append("stdout:\n" + completed.stdout.rstrip())
    if completed.stderr:
        pieces.append("stderr:\n" + completed.stderr.rstrip())
    return "\n".join(pieces) if pieces else "(no process output)"


def _run_process(command: Sequence[str], cwd: Path, timeout_seconds: int, description: str) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            [str(argument) for argument in command],
            cwd=str(cwd),
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise ExperimentError(f"cannot start {description}: executable not found: {command[0]}") from exc
    except OSError as exc:
        raise ExperimentError(f"cannot start {description}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        raise ExperimentError(
            f"{description} exceeded {timeout_seconds} seconds\n"
            f"command: {_format_command(command)}\n{output.rstrip()}"
        ) from exc
    if completed.returncode:
        raise ExperimentError(
            f"{description} failed with exit code {completed.returncode}\n"
            f"command: {_format_command(command)}\n{_format_process_output(completed)}"
        )
    return completed


def _compile_command(compiler: Path, compiler_flags: Sequence[str], source: Path, object_path: Path) -> list[str]:
    return [str(compiler), *compiler_flags, "-c", str(source), "-o", str(object_path)]


def _compile_direct(
    compiler: Path,
    compiler_flags: Sequence[str],
    source: Path,
    object_path: Path,
    working_directory: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    command = _compile_command(compiler, compiler_flags, source, object_path)
    _run_process(command, working_directory, timeout_seconds, f"direct compilation of {source.name}")
    if not object_path.is_file():
        raise ExperimentError(
            f"direct compilation of {source.name} completed without creating expected object {object_path}"
        )
    sha256, size = _read_sha256(object_path, "direct object")
    return {"object_sha256": sha256, "object_size": size}


def _gdb_quote(value: str) -> str:
    """Quote exactly one GDB command argument using its shell-like lexer rules."""

    if "\0" in value or "\n" in value or "\r" in value:
        raise ExperimentError("GDB command arguments must not contain NUL or newline characters")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _gdb_path(path: Path) -> str:
    # Forward slashes avoid treating Windows separators as GDB escape characters.
    return path.resolve().as_posix()


def _write_gdb_command(
    command_directory: Path,
    compiler: Path,
    compiler_args: Sequence[str],
    profile_path: Path,
    snapshot_directory: Path,
) -> Path:
    lines = [
        "set pagination off",
        "set confirm off",
        "set breakpoint pending on",
        f"file {_gdb_quote(_gdb_path(compiler))}",
        "set args " + " ".join(_gdb_quote(argument) for argument in compiler_args),
        # The snapshot command requires an attached/running inferior so that it can check
        # the loaded image mapping.  starti stops before compiler initialization, leaving
        # every backend breakpoint armed before any source compilation occurs.
        "starti",
        f"source {_gdb_path(SNAPSHOT_COMMAND)}",
        "b210-snapshot start"
        f" --profile {_gdb_quote(_gdb_path(profile_path))}"
        f" --output {_gdb_quote(_gdb_path(snapshot_directory))}",
        "continue",
        "if $_exitcode != 0",
        "  echo MWCCPS2 compiler exited with non-zero status\\n",
        "  quit 1",
        "end",
        "b210-snapshot stop",
        "quit",
        "",
    ]
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".mwccps2-gdb-",
            suffix=".gdb",
            dir=command_directory,
            delete=False,
        ) as command_file:
            command_file.write("\n".join(lines))
            return Path(command_file.name)
    except OSError as exc:
        raise ExperimentError(f"cannot create temporary GDB command file in {command_directory}: {exc}") from exc


def _relative_snapshot_file(snapshot_directory: Path, filename: str, location: str) -> Path:
    path = PurePath(filename)
    if path.is_absolute() or len(path.parts) != 1 or path.name != filename or ".." in path.parts:
        raise ExperimentError(f"{location} must name a file directly inside the snapshot directory")
    candidate = snapshot_directory / filename
    if not candidate.is_file():
        raise ExperimentError(f"{location} does not exist: {candidate}")
    return candidate


def _expect_schema(payload: Mapping[str, Any], name: str, version: int, location: str) -> None:
    schema = _require_mapping(payload.get("schema"), f"{location}.schema")
    if schema.get("name") != name or schema.get("version") != version:
        raise ExperimentError(
            f"{location}.schema must be {{name: {name!r}, version: {version}}}, got {schema!r}"
        )


def _parse_stage(
    snapshot_directory: Path,
    entry: Mapping[str, Any],
    expected_executable: Mapping[str, Any],
) -> dict[str, Any]:
    sequence = entry.get("sequence")
    if not _is_exact_int(sequence) or sequence < 1:
        raise ExperimentError("snapshot manifest stage sequence must be a positive integer")
    stage_name = _require_string(entry.get("stage"), "snapshot manifest stage.stage")
    filename = _require_string(entry.get("file"), f"snapshot manifest stage {stage_name}.file")
    stage_path = _relative_snapshot_file(snapshot_directory, filename, f"snapshot manifest stage {stage_name}.file")
    stage_payload = _require_mapping(_load_json(stage_path, "stage snapshot"), f"stage snapshot {filename}")
    _expect_schema(stage_payload, SNAPSHOT_SCHEMA_NAME, SNAPSHOT_SCHEMA_VERSION, f"stage snapshot {filename}")
    if stage_payload.get("sequence") != sequence:
        raise ExperimentError(f"stage snapshot {filename} sequence does not match its manifest entry")
    if stage_payload.get("stage") != stage_name:
        raise ExperimentError(f"stage snapshot {filename} stage does not match its manifest entry")
    status = _require_string(stage_payload.get("capture_status"), f"stage snapshot {filename}.capture_status")
    if status == "instrumentation_error":
        raise ExperimentError(f"snapshot instrumentation failed while capturing stage {stage_name}")
    manifest_status = entry.get("capture_status")
    if manifest_status != status:
        raise ExperimentError(f"snapshot manifest capture status disagrees with stage {stage_name}")
    executable = _require_mapping(stage_payload.get("executable"), f"stage snapshot {filename}.executable")
    if executable.get("sha256") != expected_executable["sha256"]:
        raise ExperimentError(f"stage snapshot {filename} was captured from the wrong compiler fingerprint")
    graph = _require_mapping(stage_payload.get("graph"), f"stage snapshot {filename}.graph")
    text_filename = _require_string(stage_payload.get("pcode_text_file"), f"stage snapshot {filename}.pcode_text_file")
    if entry.get("pcode_text_file") != text_filename:
        raise ExperimentError(f"snapshot manifest PCode text filename disagrees with stage {stage_name}")
    text_path = _relative_snapshot_file(
        snapshot_directory, text_filename, f"stage snapshot {filename}.pcode_text_file"
    )
    try:
        pcode_text = _normalize_text(text_path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise ExperimentError(f"PCode text file is not UTF-8: {text_path}") from exc
    except OSError as exc:
        raise ExperimentError(f"cannot read PCode text file {text_path}: {exc}") from exc
    expected_text = _normalize_text(format_pcode_text(graph))
    if pcode_text != expected_text:
        raise ExperimentError(
            f"PCode text file {text_path.name} is not the deterministic rendering of stage {stage_name}"
        )
    normalized_graph = _normalize_volatile_snapshot_value(graph)
    normalized_stage = _normalize_volatile_snapshot_value(
        {
            "schema": stage_payload["schema"],
            "sequence": sequence,
            "stage": stage_name,
            "capture_status": status,
            "profile": stage_payload.get("profile"),
            "executable": executable,
            "graph": normalized_graph,
        }
    )
    return {
        "stage": stage_name,
        "sequence": sequence,
        "capture_status": status,
        "normalized_graph": normalized_graph,
        "pcode_text": pcode_text,
        "normalized_stage_sha256": _digest_json(normalized_stage),
        "graph_sha256": _digest_json(normalized_graph),
        "pcode_text_sha256": _digest_text(pcode_text),
    }


def parse_snapshot_run(snapshot_directory: Path, expected_executable: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a b210 snapshot manifest and every referenced deterministic stage file."""

    manifest_path = snapshot_directory / "snapshot-manifest.json"
    manifest = _require_mapping(_load_json(manifest_path, "snapshot manifest"), "snapshot manifest")
    _expect_schema(manifest, MANIFEST_SCHEMA_NAME, MANIFEST_SCHEMA_VERSION, "snapshot manifest")
    executable = _require_mapping(manifest.get("executable"), "snapshot manifest.executable")
    if executable.get("sha256") != expected_executable["sha256"]:
        raise ExperimentError("snapshot manifest compiler fingerprint does not match requested b210 compiler")
    stage_plan_value = manifest.get("stage_plan")
    if not isinstance(stage_plan_value, list) or not stage_plan_value:
        raise ExperimentError("snapshot manifest.stage_plan must be a non-empty array")
    stage_order: list[str] = []
    for index, plan_entry in enumerate(stage_plan_value):
        plan = _require_mapping(plan_entry, f"snapshot manifest.stage_plan[{index}]")
        stage_name = _require_string(plan.get("stage"), f"snapshot manifest.stage_plan[{index}].stage")
        if stage_name in stage_order:
            raise ExperimentError(f"snapshot manifest.stage_plan repeats stage {stage_name!r}")
        stage_order.append(stage_name)
    stage_entries = manifest.get("stages")
    if not isinstance(stage_entries, list):
        raise ExperimentError("snapshot manifest.stages must be an array")
    stages: list[dict[str, Any]] = []
    sequences: set[int] = set()
    referenced_stage_files: set[str] = set()
    for index, raw_entry in enumerate(stage_entries):
        entry = _require_mapping(raw_entry, f"snapshot manifest.stages[{index}]")
        parsed = _parse_stage(snapshot_directory, entry, expected_executable)
        if parsed["sequence"] in sequences:
            raise ExperimentError(f"snapshot manifest repeats capture sequence {parsed['sequence']}")
        sequences.add(parsed["sequence"])
        stages.append(parsed)
        referenced_stage_files.add(
            _require_string(entry.get("file"), f"snapshot manifest.stages[{index}].file")
        )
    try:
        observed_stage_files = {
            candidate.name
            for candidate in snapshot_directory.glob("*.json")
            if candidate.name != manifest_path.name
        }
    except OSError as exc:
        raise ExperimentError(f"cannot enumerate snapshot stage files in {snapshot_directory}: {exc}") from exc
    unexpected_stage_files = sorted(observed_stage_files - referenced_stage_files)
    if unexpected_stage_files:
        raise ExperimentError(
            "snapshot directory contains unreferenced stage JSON file(s): "
            + ", ".join(unexpected_stage_files)
        )
    stages.sort(key=lambda stage: int(stage["sequence"]))
    if not stages:
        raise ExperimentError(
            f"snapshot run created {manifest_path} but captured no stages; GDB may not have armed the b210 breakpoints"
        )
    return {
        "stage_order": stage_order,
        "stages": stages,
        "normalized_manifest_sha256": _digest_json(_normalize_volatile_snapshot_value(manifest)),
    }


def _compile_with_snapshots(
    gdb: Path,
    compiler: Path,
    compiler_flags: Sequence[str],
    source: Path,
    object_path: Path,
    profile_path: Path,
    variant_directory: Path,
    timeout_seconds: int,
    expected_executable: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    snapshot_directory = variant_directory / "snapshots"
    snapshot_directory.mkdir(parents=True, exist_ok=False)
    compiler_args = _compile_command(compiler, compiler_flags, source, object_path)[1:]
    command_path = _write_gdb_command(
        variant_directory, compiler, compiler_args, profile_path, snapshot_directory
    )
    try:
        _run_process(
            [str(gdb), "--batch", "--nx", "--quiet", "--command", str(command_path)],
            variant_directory,
            timeout_seconds,
            f"GDB snapshot compilation of {source.name}",
        )
    finally:
        try:
            command_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ExperimentError(f"cannot remove temporary GDB command file {command_path}: {exc}") from exc
    if not object_path.is_file():
        raise ExperimentError(
            f"GDB snapshot compilation of {source.name} completed without creating expected object {object_path}"
        )
    sha256, size = _read_sha256(object_path, "GDB snapshot object")
    snapshots = parse_snapshot_run(snapshot_directory, expected_executable)
    return {"object_sha256": sha256, "object_size": size}, snapshots


def _stages_by_name(stages: Sequence[Mapping[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for stage in stages:
        grouped.setdefault(str(stage["stage"]), []).append(stage)
    return grouped


def _comparison_stage_order(
    baseline: Mapping[str, Any], variant: Mapping[str, Any]
) -> list[str]:
    order: list[str] = []
    for stage_name in [*baseline["stage_order"], *variant["stage_order"]]:
        if stage_name not in order:
            order.append(stage_name)
    for stage in [*baseline["stages"], *variant["stages"]]:
        stage_name = str(stage["stage"])
        if stage_name not in order:
            order.append(stage_name)
    return order


def _stage_digest_summary(stage: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sequence": stage["sequence"],
        "capture_status": stage["capture_status"],
        "normalized_stage_sha256": stage["normalized_stage_sha256"],
        "graph_sha256": stage["graph_sha256"],
        "pcode_text_sha256": stage["pcode_text_sha256"],
    }


def compare_variant_to_baseline(
    baseline_name: str,
    baseline: Mapping[str, Any],
    variant_name: str,
    variant: Mapping[str, Any],
    baseline_object: Mapping[str, Any],
    variant_object: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare semantic PCode text separately from opaque normalized snapshot graph data."""

    baseline_by_stage = _stages_by_name(baseline["stages"])
    variant_by_stage = _stages_by_name(variant["stages"])
    missing_stages: list[dict[str, Any]] = []
    capture_count_differences: list[dict[str, Any]] = []
    earliest_pcode_divergence: dict[str, Any] | None = None
    earliest_raw_graph_difference: dict[str, Any] | None = None
    for stage_name in _comparison_stage_order(baseline, variant):
        baseline_captures = baseline_by_stage.get(stage_name, [])
        variant_captures = variant_by_stage.get(stage_name, [])
        if not baseline_captures or not variant_captures:
            missing_from = []
            if not baseline_captures:
                missing_from.append("baseline")
            if not variant_captures:
                missing_from.append("variant")
            missing_stages.append(
                {
                    "stage": stage_name,
                    "missing_from": missing_from,
                    "baseline_capture_count": len(baseline_captures),
                    "variant_capture_count": len(variant_captures),
                }
            )
            continue
        if len(baseline_captures) != len(variant_captures):
            capture_count_differences.append(
                {
                    "stage": stage_name,
                    "baseline_capture_count": len(baseline_captures),
                    "variant_capture_count": len(variant_captures),
                }
            )
        for occurrence, (baseline_stage, variant_stage) in enumerate(
            zip(baseline_captures, variant_captures), start=1
        ):
            semantic_text_equal = baseline_stage["pcode_text"] == variant_stage["pcode_text"]
            raw_graph_equal = baseline_stage["normalized_graph"] == variant_stage["normalized_graph"]
            if earliest_pcode_divergence is None and not semantic_text_equal:
                earliest_pcode_divergence = {
                    "stage": stage_name,
                    "occurrence": occurrence,
                    "reason": "deterministic_pcode_text_differs",
                    "baseline": _stage_digest_summary(baseline_stage),
                    "variant": _stage_digest_summary(variant_stage),
                }
            if earliest_raw_graph_difference is None and not raw_graph_equal:
                earliest_raw_graph_difference = {
                    "stage": stage_name,
                    "occurrence": occurrence,
                    "reason": "normalized_snapshot_graph_differs",
                    "semantic_pcode_text_equal": semantic_text_equal,
                    "baseline": _stage_digest_summary(baseline_stage),
                    "variant": _stage_digest_summary(variant_stage),
                }

    return {
        "baseline_variant": baseline_name,
        "variant": variant_name,
        "earliest_pcode_divergence": earliest_pcode_divergence,
        "earliest_raw_graph_difference": earliest_raw_graph_difference,
        "missing_stages": missing_stages,
        "capture_count_differences": capture_count_differences,
        "final_object_equal": baseline_object["object_sha256"] == variant_object["object_sha256"],
    }


def _summary_variant(variant: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    snapshots = result["snapshots"]
    return {
        "name": variant["name"],
        "source": variant["source"],
        "function": variant["function"],
        "intent": variant["intent"],
        "direct_compile": result["direct_object"],
        "snapshot_compile": {
            **result["snapshot_object"],
            "matches_direct_object": (
                result["direct_object"]["object_sha256"] == result["snapshot_object"]["object_sha256"]
            ),
            "snapshot_manifest_sha256": snapshots["normalized_manifest_sha256"],
            "stages": [
                {"stage": stage["stage"], **_stage_digest_summary(stage)} for stage in snapshots["stages"]
            ],
        },
    }


def _write_summary(path: Path, summary: Mapping[str, Any]) -> None:
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
            json.dump(summary, output, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
            output.write("\n")
        temporary_path.replace(path)
    except OSError as exc:
        raise ExperimentError(f"cannot write summary {path}: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _prepare_output_directory(output_directory: Path) -> Path:
    resolved_build = BUILD_DIRECTORY.resolve()
    resolved_output = output_directory.resolve()
    try:
        resolved_output.relative_to(resolved_build)
    except ValueError as exc:
        raise ExperimentError(
            f"output directory must be inside ignored build directory {resolved_build}: {resolved_output}"
        ) from exc
    if resolved_output == resolved_build:
        raise ExperimentError("output directory must be a fresh subdirectory of ignored build/")
    if resolved_output.exists():
        raise ExperimentError(f"output directory already exists; choose a fresh directory: {resolved_output}")
    try:
        resolved_output.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise ExperimentError(f"cannot create output directory {resolved_output}: {exc}") from exc
    return resolved_output


def run_experiment(
    experiment_directory: Path,
    compiler: Path,
    gdb: Path,
    profile_path: Path,
    output_directory: Path,
    timeout_seconds: int,
) -> Path:
    experiment = load_experiment(experiment_directory)
    profile, executable, probe_report = fingerprint_b210(compiler, profile_path)
    output = _prepare_output_directory(output_directory)

    results: list[dict[str, Any]] = []
    for variant in experiment["variants"]:
        variant_directory = output / "variants" / variant["name"]
        variant_directory.mkdir(parents=True, exist_ok=False)
        direct_object_path = variant_directory / "direct.o"
        direct_object = _compile_direct(
            compiler,
            experiment["compiler_flags"],
            variant["source_path"],
            direct_object_path,
            variant_directory,
            timeout_seconds,
        )
        snapshot_object_path = variant_directory / "snapshot.o"
        snapshot_object, snapshots = _compile_with_snapshots(
            gdb,
            compiler,
            experiment["compiler_flags"],
            variant["source_path"],
            snapshot_object_path,
            profile_path,
            variant_directory,
            timeout_seconds,
            executable,
        )
        results.append(
            {
                "variant": variant,
                "direct_object": direct_object,
                "snapshot_object": snapshot_object,
                "snapshots": snapshots,
            }
        )

    baseline = results[0]
    comparisons = [
        compare_variant_to_baseline(
            baseline["variant"]["name"],
            baseline["snapshots"],
            result["variant"]["name"],
            result["snapshots"],
            baseline["direct_object"],
            result["direct_object"],
        )
        for result in results
    ]
    summary = {
        "schema": {"name": SUMMARY_SCHEMA_NAME, "version": SUMMARY_SCHEMA_VERSION},
        "experiment": {
            "schema_version": 1,
            "name": experiment["name"],
            "question": experiment["question"],
            "compiler_flags": experiment["compiler_flags"],
            "baseline_variant": baseline["variant"]["name"],
        },
        "compiler": {
            "profile": {
                "name": profile["name"],
                "binary_sha256": profile["binary"]["sha256"],
            },
            "fingerprint": _normalize_volatile_snapshot_value(executable),
            "probe": {
                "is_i386": probe_report["is_i386"],
                "is_mwccps2": probe_report["is_mwccps2"],
                "sha256": probe_report["sha256"],
                "size": probe_report["size"],
                "pe_timestamp": f"0x{int(probe_report['pe']['timestamp']):08x}",
            },
        },
        "variants": [_summary_variant(result["variant"], result) for result in results],
        "comparisons": comparisons,
    }
    summary_path = output / SUMMARY_FILENAME
    _write_summary(summary_path, summary)
    return summary_path


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run MWCCPS2 b210 PCode-difference experiments from an experiment.json manifest."
    )
    parser.add_argument("experiment", type=Path, help="experiment directory containing experiment.json")
    parser.add_argument(
        "--compiler",
        type=Path,
        default=DEFAULT_COMPILER,
        help=f"exact b210 mwccps2.exe (default: {DEFAULT_COMPILER})",
    )
    parser.add_argument("--gdb", type=Path, default=Path("gdb"), help="GDB executable")
    parser.add_argument(
        "--profile", type=Path, default=DEFAULT_PROFILE, help="validated b210 profile JSON"
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="fresh output directory below this tool's ignored build/ directory",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="per compiler/GDB process timeout (default: 300)",
    )
    args = parser.parse_args(argv)
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary_path = run_experiment(
            args.experiment,
            args.compiler,
            args.gdb,
            args.profile,
            args.output,
            args.timeout_seconds,
        )
    except ExperimentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
