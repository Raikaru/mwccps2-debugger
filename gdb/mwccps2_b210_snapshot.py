"""Auto-continuing GDB snapshots for the MWCCPS2 3.0.1 b210 backend.

Load this file from a GDB session already attached to the suspended compiler, then run:

    b210-snapshot start --output C:/tmp/mwccps2-b210-snapshots

The command validates the exact executable selected by GDB before it creates any
breakpoint.  Its breakpoint handlers only read inferior memory and write JSON; they
always return ``False`` so they do not stop, modify, or otherwise alter the compiler.
"""

from __future__ import annotations

import datetime as _datetime
import json
import os
import sys
from pathlib import Path
from typing import Any

import gdb


_SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(_SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIRECTORY))

from b210_snapshot_model import (  # noqa: E402 - GDB sources this module by path.
    B210_LAYOUT_EVIDENCE,
    MANIFEST_SCHEMA_NAME,
    MANIFEST_SCHEMA_VERSION,
    SNAPSHOT_SCHEMA_NAME,
    SNAPSHOT_SCHEMA_VERSION,
    MemoryReadError,
    SnapshotModelError,
    capture_status,
    collect_runtime_graph,
    fingerprint_executable,
    format_address,
    format_pcode_text,
    load_b210_profile,
    normalize_runtime_graph,
    parse_address,
    profile_manifest,
)


DEFAULT_PROFILE_PATH = _SCRIPT_DIRECTORY.parent / "profiles" / "mwcps2-3.0.1-b210.json"
MANIFEST_FILENAME = "snapshot-manifest.json"
STAGE_ORDER = (
    ("codegen_entry", ("functions", "CodeGen_Generator", "address")),
    ("before_scheduling", ("pcode_breakpoints", "before_scheduling")),
    ("after_scheduling", ("pcode_breakpoints", "after_scheduling")),
    ("before_register_allocation", ("pcode_breakpoints", "before_register_allocation")),
    ("after_register_allocation", ("pcode_breakpoints", "after_register_allocation")),
    ("after_colorgraph_assignment", ("pcode_breakpoints", "after_colorgraph_assignment")),
)


class _InferiorMemory:
    """The only GDB-dependent memory adapter used by the pure snapshot model."""

    def __init__(self, inferior: gdb.Inferior) -> None:
        self._inferior = inferior

    def read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self._inferior.read_memory(address, size))
        except Exception as exc:
            raise MemoryReadError("inferior memory is unreadable") from exc


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat()


def _atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
    """Make every observable manifest and stage file independently parseable."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(payload, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_text_write(path: Path, content: str) -> None:
    """Atomically publish a deterministic PCode text companion for a stage JSON file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as output:
            output.write(content)
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _lookup_profile_address(profile: dict[str, Any], path: tuple[str, ...]) -> int:
    value: Any = profile
    for key in path:
        value = value[key]
    return parse_address(value, ".".join(path))


def _gdb_argv(argument: str) -> list[str]:
    """Use GDB's platform-aware argument lexer when it is available."""

    parser = getattr(gdb, "string_to_argv", None)
    if parser is None:
        import shlex

        return shlex.split(argument)
    return list(parser(argument))


def _parse_positive_limit(text: str, option: str) -> int:
    try:
        value = int(text, 10)
    except ValueError as exc:
        raise gdb.GdbError(f"{option} requires a base-10 positive integer") from exc
    if value < 1:
        raise gdb.GdbError(f"{option} requires a positive integer")
    return value


def _parse_start_options(argument: str) -> dict[str, Any]:
    tokens = _gdb_argv(argument)
    if not tokens or tokens[0] != "start":
        raise gdb.GdbError("expected: b210-snapshot start [options]")
    options: dict[str, Any] = {
        "profile": DEFAULT_PROFILE_PATH,
        "output": None,
        "max_blocks": 4096,
        "max_nodes": 65536,
        "max_operands": 65536,
    }
    index = 1
    while index < len(tokens):
        option = tokens[index]
        if option not in {"--profile", "--output", "--max-blocks", "--max-nodes", "--max-operands"}:
            raise gdb.GdbError(f"unknown b210-snapshot option: {option}")
        if index + 1 == len(tokens):
            raise gdb.GdbError(f"{option} requires a value")
        value = tokens[index + 1]
        if option == "--profile":
            options["profile"] = Path(value)
        elif option == "--output":
            options["output"] = Path(value)
        elif option == "--max-blocks":
            options["max_blocks"] = _parse_positive_limit(value, option)
        elif option == "--max-nodes":
            options["max_nodes"] = _parse_positive_limit(value, option)
        else:
            options["max_operands"] = _parse_positive_limit(value, option)
        index += 2
    if options["output"] is None:
        raise gdb.GdbError("b210-snapshot start requires --output DIRECTORY")
    return options


def _loaded_executable() -> Path:
    program_space = gdb.current_progspace()
    filename = getattr(program_space, "filename", None)
    if not filename:
        raise gdb.GdbError(
            "GDB has no executable selected. Start GDB with mwccps2.exe (or run 'file PATH') before attaching."
        )
    return Path(filename)


def _verify_preferred_image_mapping(inferior: gdb.Inferior, image_base: int) -> None:
    """Confirm static profile addresses refer to the live process before breakpoints."""

    try:
        signature = bytes(inferior.read_memory(image_base, 2))
    except Exception as exc:
        raise gdb.GdbError(
            f"cannot read b210 profile image base {format_address(image_base)} in the inferior"
        ) from exc
    if signature != b"MZ":
        raise gdb.GdbError(
            f"b210 profile image base {format_address(image_base)} is not the loaded PE image; no breakpoints installed"
        )


class _SnapshotBreakpoint(gdb.Breakpoint):
    """A silent tracepoint-like software breakpoint that never stops the inferior."""

    def __init__(self, recorder: "_SnapshotRecorder", stage: str, profile_address: int) -> None:
        super().__init__(f"*{format_address(profile_address)}", internal=True)
        self._recorder = recorder
        self._stage = stage
        self._profile_address = profile_address
        try:
            self.silent = True
        except Exception:
            # Returning False from stop is sufficient on GDB versions without this property.
            pass

    def stop(self) -> bool:
        try:
            self._recorder.capture(self._stage, self._profile_address)
        except Exception:
            # An instrumentation failure must not change target control flow or exit status.
            self._recorder.record_handler_failure(self._stage, self._profile_address)
        return False


class _SnapshotRecorder:
    """Owns one snapshot session and the auto-continuing breakpoint set."""

    def __init__(self, profile: dict[str, Any], executable: dict[str, Any], options: dict[str, Any]) -> None:
        self.profile = profile
        self.executable = executable
        self.output_directory = Path(options["output"]).resolve()
        self.max_blocks = options["max_blocks"]
        self.max_nodes = options["max_nodes"]
        self.max_operands = options["max_operands"]
        self.breakpoints: list[_SnapshotBreakpoint] = []
        self.sequence = 0
        self.manifest: dict[str, Any] = {
            "schema": {
                "name": MANIFEST_SCHEMA_NAME,
                "version": MANIFEST_SCHEMA_VERSION,
            },
            "created_at": _utc_now(),
            "profile": profile_manifest(profile),
            "executable": executable,
            "configuration": {
                "max_blocks": self.max_blocks,
                "max_nodes": self.max_nodes,
                "max_operands": self.max_operands,
                "auto_continue": True,
                "runtime_heap_addresses_serialized": True,
                "structural_heap_addresses_serialized": False,
            },
            "layout_evidence": B210_LAYOUT_EVIDENCE,
            "stage_plan": [
                {
                    "stage": stage,
                    "profile_address": format_address(_lookup_profile_address(profile, path)),
                }
                for stage, path in STAGE_ORDER
            ],
            "stages": [],
        }

    @property
    def manifest_path(self) -> Path:
        return self.output_directory / MANIFEST_FILENAME

    def start(self) -> None:
        self.output_directory.mkdir(parents=True, exist_ok=True)
        if self.manifest_path.exists():
            raise gdb.GdbError(
                f"refusing to overwrite existing manifest {self.manifest_path}; choose a fresh --output directory"
            )
        try:
            for stage, path in STAGE_ORDER:
                address = _lookup_profile_address(self.profile, path)
                self.breakpoints.append(_SnapshotBreakpoint(self, stage, address))
            _atomic_json_write(self.manifest_path, self.manifest)
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        for breakpoint in self.breakpoints:
            try:
                breakpoint.delete()
            except Exception:
                pass
        self.breakpoints = []

    def _append_stage(self, stage_entry: dict[str, Any]) -> None:
        self.manifest["stages"].append(stage_entry)
        _atomic_json_write(self.manifest_path, self.manifest)

    def _next_filename(self, stage: str) -> str:
        return f"{self.sequence:06d}-{stage}.json"

    def capture(self, stage: str, profile_address: int) -> None:
        self.sequence += 1
        filename = self._next_filename(stage)
        text_filename = f"{filename[:-5]}.pcode.txt"
        inferior = gdb.selected_inferior()
        pcbasicblocks_address = _lookup_profile_address(
            self.profile, ("globals", "pcbasicblocks", "address")
        )
        raw = collect_runtime_graph(
            _InferiorMemory(inferior),
            pcbasicblocks_address,
            self.max_blocks,
            self.max_nodes,
            self.profile["pcode_opcode_table"],
            self.max_operands,
        )
        graph = normalize_runtime_graph(raw)
        status = capture_status(graph)
        snapshot = {
            "schema": {
                "name": SNAPSHOT_SCHEMA_NAME,
                "version": SNAPSHOT_SCHEMA_VERSION,
            },
            "captured_at": _utc_now(),
            "sequence": self.sequence,
            "stage": stage,
            "breakpoint": {"profile_address": format_address(profile_address)},
            "profile": profile_manifest(self.profile),
            "executable": self.executable,
            "capture_status": status,
            "pcode_text_file": text_filename,
            "graph": graph,
        }
        _atomic_text_write(self.output_directory / text_filename, format_pcode_text(graph))
        _atomic_json_write(self.output_directory / filename, snapshot)
        self._append_stage(
            {
                "sequence": self.sequence,
                "stage": stage,
                "profile_address": format_address(profile_address),
                "file": filename,
                "pcode_text_file": text_filename,
                "capture_status": status,
            }
        )

    def record_handler_failure(self, stage: str, profile_address: int) -> None:
        """Persist a generic, address-free error record if a GDB callback faults."""

        self.sequence += 1
        filename = self._next_filename(stage)
        snapshot = {
            "schema": {
                "name": SNAPSHOT_SCHEMA_NAME,
                "version": SNAPSHOT_SCHEMA_VERSION,
            },
            "captured_at": _utc_now(),
            "sequence": self.sequence,
            "stage": stage,
            "breakpoint": {"profile_address": format_address(profile_address)},
            "profile": profile_manifest(self.profile),
            "executable": self.executable,
            "capture_status": "instrumentation_error",
            "graph": {
                "blocks": [],
                "pcodes": [],
                "collection": {
                    "block_walk": {"reason": "instrumentation_error"},
                    "pcode_walks": [],
                    "errors": [{"scope": "instrumentation", "reason": "handler_failure"}],
                },
            },
        }
        try:
            _atomic_json_write(self.output_directory / filename, snapshot)
            self._append_stage(
                {
                    "sequence": self.sequence,
                    "stage": stage,
                    "profile_address": format_address(profile_address),
                    "file": filename,
                    "capture_status": "instrumentation_error",
                }
            )
        except Exception:
            # No target-visible side effect is permitted if the host filesystem is unavailable.
            pass


_ACTIVE_RECORDER: _SnapshotRecorder | None = None


class B210SnapshotCommand(gdb.Command):
    """Install or remove b210 backend snapshot breakpoints."""

    def __init__(self) -> None:
        super().__init__("b210-snapshot", gdb.COMMAND_DATA)

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _ACTIVE_RECORDER
        argv = _gdb_argv(argument)
        if argv == ["stop"]:
            if _ACTIVE_RECORDER is None:
                raise gdb.GdbError("no b210 snapshot session is active")
            _ACTIVE_RECORDER.stop()
            _ACTIVE_RECORDER = None
            gdb.write("b210 snapshot breakpoints removed\n")
            return
        if argv == ["status"]:
            if _ACTIVE_RECORDER is None:
                gdb.write("b210 snapshot session: inactive\n")
            else:
                gdb.write(
                    "b210 snapshot session: active; "
                    f"{len(_ACTIVE_RECORDER.breakpoints)} breakpoints; "
                    f"{len(_ACTIVE_RECORDER.manifest['stages'])} snapshots; "
                    f"output {_ACTIVE_RECORDER.output_directory}\n"
                )
            return
        if _ACTIVE_RECORDER is not None:
            raise gdb.GdbError("a b210 snapshot session is already active; use 'b210-snapshot stop'")

        options = _parse_start_options(argument)
        try:
            profile = load_b210_profile(options["profile"])
            executable = fingerprint_executable(_loaded_executable(), profile)
        except SnapshotModelError as exc:
            raise gdb.GdbError(f"b210 identity validation failed: {exc}") from exc

        inferior = gdb.selected_inferior()
        if not inferior or inferior.pid == 0:
            raise gdb.GdbError("attach to the suspended compiler before starting b210 snapshots")
        image_base = parse_address(profile["binary"]["image_base"], "profile.binary.image_base")
        _verify_preferred_image_mapping(inferior, image_base)

        recorder = _SnapshotRecorder(profile, executable, options)
        recorder.start()
        _ACTIVE_RECORDER = recorder
        gdb.write(
            "b210 snapshots armed: "
            f"{len(recorder.breakpoints)} auto-continuing breakpoints, output {recorder.output_directory}\n"
        )


B210SnapshotCommand()
