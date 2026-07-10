#!/usr/bin/env python3
"""Run one b210 scheduler reducer with direct/instrumented object verification.

Unlike the general PCode experiment runner, this command arms only the scheduler
tracepoints.  It refuses a run with missing selector captures, incomplete predictions,
changed object bytes, or no observed cross-variant schedule divergence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

import mwccps2_experiment as experiment
from gdb.b210_scheduler_model import (
    SCHEDULER_CAPTURE_SCHEMA_NAME,
    SCHEDULER_CAPTURE_SCHEMA_VERSION,
    SCHEDULER_MANIFEST_SCHEMA_NAME,
    SCHEDULER_MANIFEST_SCHEMA_VERSION,
    SchedulerProfileError,
    format_scheduler_capture_text,
    validate_scheduler_profile,
)


RUNNER_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_COMPILER = Path("D:/mwcps2-3.0.1b210-060308/mwccps2.exe")
DEFAULT_PROFILE = RUNNER_DIRECTORY / "profiles" / "mwcps2-3.0.1-b210.json"
SCHEDULER_COMMAND = RUNNER_DIRECTORY / "gdb" / "mwccps2_b210_scheduler.py"
BUILD_DIRECTORY = RUNNER_DIRECTORY / "build"
SUMMARY_SCHEMA_NAME = "mwccps2-b210-scheduler-experiment-summary"
SUMMARY_SCHEMA_VERSION = 1
SUMMARY_FILENAME = f"scheduler-experiment-summary-v{SUMMARY_SCHEMA_VERSION}.json"
SUMMARY_TEXT_FILENAME = f"scheduler-experiment-summary-v{SUMMARY_SCHEMA_VERSION}.txt"


class SchedulerExperimentError(Exception):
    """Raised when the scheduler experiment cannot prove its contract."""


def _run_process(command: Sequence[str], cwd: Path, timeout: int, description: str) -> None:
    try:
        completed = subprocess.run(
            [str(value) for value in command],
            cwd=str(cwd),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SchedulerExperimentError(f"cannot start {description}: executable not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SchedulerExperimentError(f"{description} exceeded {timeout} seconds") from exc
    except OSError as exc:
        raise SchedulerExperimentError(f"cannot start {description}: {exc}") from exc
    if completed.returncode:
        output = "\n".join(
            part for part in (completed.stdout.strip(), completed.stderr.strip()) if part
        )
        raise SchedulerExperimentError(
            f"{description} failed with exit code {completed.returncode}\n{output}"
        )


def _write_gdb_command(
    directory: Path,
    compiler: Path,
    compiler_args: Sequence[str],
    profile: Path,
    output: Path,
) -> Path:
    lines = [
        "set pagination off",
        "set confirm off",
        "set breakpoint pending on",
        f"file {experiment._gdb_quote(experiment._gdb_path(compiler))}",
        "set args " + " ".join(experiment._gdb_quote(str(argument)) for argument in compiler_args),
        "starti",
        f"source {experiment._gdb_path(SCHEDULER_COMMAND)}",
        "b210-scheduler start"
        f" --profile {experiment._gdb_quote(experiment._gdb_path(profile))}"
        f" --output {experiment._gdb_quote(experiment._gdb_path(output))}",
        "continue",
        "if $_exitcode != 0",
        "  echo MWCCPS2 compiler exited with non-zero status\\n",
        "  quit 1",
        "end",
        "b210-scheduler stop",
        "quit",
        "",
    ]
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".mwccps2-scheduler-",
            suffix=".gdb",
            dir=directory,
            delete=False,
        ) as command_file:
            command_file.write("\n".join(lines))
            return Path(command_file.name)
    except OSError as exc:
        raise SchedulerExperimentError(f"cannot create GDB command file: {exc}") from exc


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SchedulerExperimentError(f"cannot read {description}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SchedulerExperimentError(f"{description} is not valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise SchedulerExperimentError(f"{description} must contain an object: {path}")
    return value


def _expect_schema(value: Mapping[str, Any], name: str, version: int, location: str) -> None:
    schema = value.get("schema")
    if not isinstance(schema, Mapping) or schema.get("name") != name or schema.get("version") != version:
        raise SchedulerExperimentError(
            f"{location} must have schema {name!r} version {version}"
        )


def _relative_file(directory: Path, name: Any, location: str) -> Path:
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise SchedulerExperimentError(f"{location} must name one file directly in the capture directory")
    path = directory / name
    if not path.is_file():
        raise SchedulerExperimentError(f"{location} is missing: {path}")
    return path


def _load_scheduler_capture_run(directory: Path, executable_sha256: str) -> dict[str, Any]:
    manifest = _read_json(directory / "scheduler-manifest.json", "scheduler manifest")
    _expect_schema(manifest, SCHEDULER_MANIFEST_SCHEMA_NAME, SCHEDULER_MANIFEST_SCHEMA_VERSION, "scheduler manifest")
    executable = manifest.get("executable")
    if not isinstance(executable, Mapping) or executable.get("sha256") != executable_sha256:
        raise SchedulerExperimentError("scheduler manifest compiler fingerprint does not match b210")
    failures = manifest.get("handler_failures")
    if not isinstance(failures, list) or failures:
        raise SchedulerExperimentError("scheduler instrumentation reported handler failures")
    entries = manifest.get("captures")
    if not isinstance(entries, list) or not entries:
        raise SchedulerExperimentError("scheduler run captured no ready-selector decisions")

    captures: list[dict[str, Any]] = []
    seen_sequences: set[int] = set()
    for entry in entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("sequence"), int):
            raise SchedulerExperimentError("scheduler manifest has malformed capture entry")
        sequence = int(entry["sequence"])
        if sequence < 1 or sequence in seen_sequences:
            raise SchedulerExperimentError("scheduler manifest repeats or invalidates a capture sequence")
        seen_sequences.add(sequence)
        stage_path = _relative_file(directory, entry.get("file"), "scheduler manifest capture file")
        capture = _read_json(stage_path, "scheduler capture")
        _expect_schema(capture, SCHEDULER_CAPTURE_SCHEMA_NAME, SCHEDULER_CAPTURE_SCHEMA_VERSION, stage_path.name)
        if capture.get("sequence") != sequence:
            raise SchedulerExperimentError(f"scheduler capture {stage_path.name} has a mismatched sequence")
        stage_executable = capture.get("executable")
        if not isinstance(stage_executable, Mapping) or stage_executable.get("sha256") != executable_sha256:
            raise SchedulerExperimentError(f"scheduler capture {stage_path.name} has the wrong compiler fingerprint")
        scheduler = capture.get("scheduler")
        if not isinstance(scheduler, Mapping):
            raise SchedulerExperimentError(f"scheduler capture {stage_path.name} has no scheduler payload")
        text_path = _relative_file(directory, capture.get("scheduler_text_file"), "scheduler text file")
        expected_text = format_scheduler_capture_text(scheduler)
        try:
            observed_text = text_path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except OSError as exc:
            raise SchedulerExperimentError(f"cannot read scheduler text file {text_path}") from exc
        if observed_text != expected_text:
            raise SchedulerExperimentError(f"scheduler text file is not a deterministic rendering: {text_path.name}")
        captures.append(
            {
                "sequence": sequence,
                "driver_sequence": capture.get("driver_sequence"),
                "selection_ordinal": capture.get("selection_ordinal"),
                "prediction": scheduler.get("prediction"),
                "observed": scheduler.get("observed"),
                "prediction_matches_observed": scheduler.get("prediction_matches_observed"),
            }
        )
    captures.sort(key=lambda item: item["sequence"])
    observed_order = manifest.get("observed_pcode_order")
    if not isinstance(observed_order, list) or len(observed_order) != len(captures):
        raise SchedulerExperimentError("scheduler manifest observed PCode order is incomplete")
    return {"manifest": manifest, "captures": captures, "observed_order": observed_order}


def _compile_instrumented(
    gdb: Path,
    compiler: Path,
    flags: Sequence[str],
    source: Path,
    object_path: Path,
    profile: Path,
    variant_directory: Path,
    timeout: int,
    executable_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    capture_directory = variant_directory / "scheduler-captures"
    capture_directory.mkdir(parents=True, exist_ok=False)
    compiler_args = experiment._compile_command(compiler, flags, source, object_path)[1:]
    command_path = _write_gdb_command(variant_directory, compiler, compiler_args, profile, capture_directory)
    try:
        _run_process(
            [str(gdb), "--batch", "--nx", "--quiet", "--command", str(command_path)],
            variant_directory,
            timeout,
            f"GDB scheduler compilation of {source.name}",
        )
    finally:
        try:
            command_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SchedulerExperimentError(f"cannot remove temporary GDB command file {command_path}") from exc
    if not object_path.is_file():
        raise SchedulerExperimentError(f"GDB scheduler compilation did not write {object_path}")
    sha256, size = experiment._read_sha256(object_path, "instrumented object")
    return {"object_sha256": sha256, "object_size": size}, _load_scheduler_capture_run(
        capture_directory, executable_sha256
    )


def _schedule_signature(run: Mapping[str, Any]) -> list[Any]:
    order = run["observed_order"]
    return [entry.get("pcode_signature") for entry in order]


def _write_summary(path: Path, value: Mapping[str, Any]) -> None:
    temporary: Path | None = None
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
            temporary = Path(output.name)
            json.dump(value, output, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
            output.write("\n")
        temporary.replace(path)
    except OSError as exc:
        raise SchedulerExperimentError(f"cannot write summary {path}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _format_summary_text(summary: Mapping[str, Any]) -> str:
    lines = [
        "# MWCCPS2 b210 scheduler experiment summary v1",
        f"experiment: {summary['experiment']['name']}",
        f"schedule_diverged: {str(summary['schedule_diverged']).lower()}",
        "",
    ]
    for variant in summary["variants"]:
        lines.extend(
            [
                f"{variant['name']}:",
                f"  direct_sha256: {variant['direct_compile']['object_sha256']}",
                f"  instrumented_sha256: {variant['instrumented_compile']['object_sha256']}",
                f"  object_sha_matches: {str(variant['object_sha_matches']).lower()}",
                f"  selection_count: {len(variant['observed_pcode_order'])}",
                f"  complete_prediction_matches: {variant['complete_prediction_match_count']}",
                "",
            ]
        )
    return "\n".join(lines)


def _prepare_output(directory: Path) -> Path:
    build = BUILD_DIRECTORY.resolve()
    output = directory.resolve()
    try:
        output.relative_to(build)
    except ValueError as exc:
        raise SchedulerExperimentError(f"output must be within ignored build directory {build}") from exc
    if output == build or output.exists():
        raise SchedulerExperimentError(f"output must be a fresh build subdirectory: {output}")
    output.mkdir(parents=True, exist_ok=False)
    return output


def run_experiment(
    experiment_directory: Path,
    compiler: Path,
    gdb: Path,
    profile_path: Path,
    output_directory: Path,
    timeout: int,
) -> Path:
    reducer = experiment.load_experiment(experiment_directory)
    if len(reducer["variants"]) < 2:
        raise SchedulerExperimentError("scheduler experiment requires at least two source-equivalent variants")
    try:
        profile, executable, probe = experiment.fingerprint_b210(compiler, profile_path)
        validate_scheduler_profile(profile)
    except (experiment.ExperimentError, SchedulerProfileError) as exc:
        raise SchedulerExperimentError(f"exact b210 scheduler profile validation failed: {exc}") from exc
    output = _prepare_output(output_directory)
    variants: list[dict[str, Any]] = []
    for variant in reducer["variants"]:
        variant_directory = output / "variants" / variant["name"]
        variant_directory.mkdir(parents=True, exist_ok=False)
        direct = experiment._compile_direct(
            compiler,
            reducer["compiler_flags"],
            variant["source_path"],
            variant_directory / "direct.o",
            variant_directory,
            timeout,
        )
        instrumented, captures = _compile_instrumented(
            gdb,
            compiler,
            reducer["compiler_flags"],
            variant["source_path"],
            variant_directory / "instrumented.o",
            profile_path,
            variant_directory,
            timeout,
            executable["sha256"],
        )
        if direct["object_sha256"] != instrumented["object_sha256"]:
            raise SchedulerExperimentError(
                f"instrumentation changed object bytes for {variant['name']}: "
                f"direct {direct['object_sha256']} != instrumented {instrumented['object_sha256']}"
            )
        complete_matches = [
            entry
            for entry in captures["captures"]
            if entry["prediction_matches_observed"] is True
            and isinstance(entry["prediction"], Mapping)
            and entry["prediction"].get("status") == "complete"
        ]
        variants.append(
            {
                "name": variant["name"],
                "source": variant["source"],
                "intent": variant["intent"],
                "direct_compile": direct,
                "instrumented_compile": instrumented,
                "object_sha_matches": True,
                "observed_pcode_order": captures["observed_order"],
                "capture_count": len(captures["captures"]),
                "complete_prediction_match_count": len(complete_matches),
            }
        )
    schedule_signatures = [_schedule_signature({"observed_order": variant["observed_pcode_order"]}) for variant in variants]
    schedule_diverged = any(signature != schedule_signatures[0] for signature in schedule_signatures[1:])
    if not schedule_diverged:
        raise SchedulerExperimentError("source-equivalent variants did not produce divergent observed scheduler PCode order")
    if not any(variant["complete_prediction_match_count"] for variant in variants):
        raise SchedulerExperimentError("no complete scheduler prediction matched an observed selector result")
    summary = {
        "schema": {"name": SUMMARY_SCHEMA_NAME, "version": SUMMARY_SCHEMA_VERSION},
        "experiment": {
            "schema_version": 1,
            "name": reducer["name"],
            "question": reducer["question"],
            "compiler_flags": reducer["compiler_flags"],
        },
        "compiler": {
            "profile": {"name": profile["name"], "binary_sha256": profile["binary"]["sha256"]},
            "fingerprint": executable,
            "probe": {
                "is_i386": probe["is_i386"],
                "is_mwccps2": probe["is_mwccps2"],
                "sha256": probe["sha256"],
            },
        },
        "schedule_diverged": schedule_diverged,
        "variants": variants,
    }
    _write_summary(output / SUMMARY_FILENAME, summary)
    (output / SUMMARY_TEXT_FILENAME).write_text(_format_summary_text(summary), encoding="utf-8", newline="\n")
    return output / SUMMARY_FILENAME


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one exact-b210 scheduler reducer and verify prediction/object invariants."
    )
    parser.add_argument("experiment", type=Path, help="scheduler experiment directory")
    parser.add_argument("--compiler", type=Path, default=DEFAULT_COMPILER)
    parser.add_argument("--gdb", type=Path, default=Path("gdb"))
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, required=True, help="fresh directory below build/")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args(argv)
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        summary = run_experiment(
            args.experiment,
            args.compiler,
            args.gdb,
            args.profile,
            args.output,
            args.timeout_seconds,
        )
    except SchedulerExperimentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"summary: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
