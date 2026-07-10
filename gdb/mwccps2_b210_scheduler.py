"""Auto-continuing ready-selector captures for MWCCPS2 3.0.1 b210.

Load from an attached, suspended b210 compiler and run:

    b210-scheduler start --output C:/tmp/mwccps2-b210-scheduler

The command observes selector entry, its eligibility callback results, and selector
return.  It never writes inferior memory and every breakpoint callback returns False.
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

from b210_scheduler_model import (  # noqa: E402 - GDB sources this file by path.
    SCHEDULER_CAPTURE_SCHEMA_NAME,
    SCHEDULER_CAPTURE_SCHEMA_VERSION,
    SCHEDULER_MANIFEST_SCHEMA_NAME,
    SCHEDULER_MANIFEST_SCHEMA_VERSION,
    SchedulerCollectionError,
    SchedulerProfileError,
    apply_selector_predicates,
    collect_ready_candidates,
    format_address,
    format_scheduler_capture_text,
    normalize_scheduler_capture,
    observed_selection,
    scheduler_layout_evidence,
    scheduler_profile_manifest,
    validate_scheduler_profile,
)
from b210_snapshot_model import (  # noqa: E402 - exact executable identity is shared.
    SnapshotModelError,
    fingerprint_executable,
    load_b210_profile,
    parse_address,
)


DEFAULT_PROFILE_PATH = _SCRIPT_DIRECTORY.parent / "profiles" / "mwcps2-3.0.1-b210.json"
MANIFEST_FILENAME = "scheduler-manifest.json"


class _InferiorMemory:
    """The scheduler model's only GDB-dependent memory adapter."""

    def __init__(self, inferior: gdb.Inferior) -> None:
        self._inferior = inferior

    def read(self, address: int, size: int) -> bytes:
        return bytes(self._inferior.read_memory(address, size))


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat()


def _atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(payload, output, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_text_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            output.write(content)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _gdb_argv(argument: str) -> list[str]:
    parser = getattr(gdb, "string_to_argv", None)
    if parser is not None:
        return list(parser(argument))
    import shlex

    return shlex.split(argument)


def _positive_decimal(value: str, option: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise gdb.GdbError(f"{option} requires a base-10 positive integer") from exc
    if parsed < 1:
        raise gdb.GdbError(f"{option} requires a positive integer")
    return parsed


def _parse_start_options(argument: str) -> dict[str, Any]:
    argv = _gdb_argv(argument)
    if not argv or argv[0] != "start":
        raise gdb.GdbError("expected: b210-scheduler start [options]")
    options: dict[str, Any] = {
        "profile": DEFAULT_PROFILE_PATH,
        "output": None,
        "max_nodes": 4096,
        "max_edges": 65536,
    }
    known = {"--profile", "--output", "--max-nodes", "--max-edges"}
    index = 1
    while index < len(argv):
        option = argv[index]
        if option not in known:
            raise gdb.GdbError(f"unknown b210-scheduler option: {option}")
        if index + 1 >= len(argv):
            raise gdb.GdbError(f"{option} requires a value")
        value = argv[index + 1]
        if option == "--profile":
            options["profile"] = Path(value)
        elif option == "--output":
            options["output"] = Path(value)
        elif option == "--max-nodes":
            options["max_nodes"] = _positive_decimal(value, option)
        else:
            options["max_edges"] = _positive_decimal(value, option)
        index += 2
    if options["output"] is None:
        raise gdb.GdbError("b210-scheduler start requires --output DIRECTORY")
    return options


def _loaded_executable() -> Path:
    filename = getattr(gdb.current_progspace(), "filename", None)
    if not filename:
        raise gdb.GdbError("GDB has no executable selected; run 'file PATH' before b210-scheduler")
    return Path(filename)


def _verify_image_mapping(inferior: gdb.Inferior, image_base: int) -> None:
    try:
        signature = bytes(inferior.read_memory(image_base, 2))
    except Exception as exc:
        raise gdb.GdbError(
            f"cannot read b210 profile image base {format_address(image_base)} in the inferior"
        ) from exc
    if signature != b"MZ":
        raise gdb.GdbError(
            f"b210 profile image base {format_address(image_base)} is not the loaded PE image"
        )


def _read_u32(memory: _InferiorMemory, address: int) -> int:
    data = memory.read(address, 4)
    if len(data) != 4:
        raise SchedulerCollectionError("short_read")
    return int.from_bytes(data, byteorder="little", signed=False)


def _read_u16(memory: _InferiorMemory, address: int) -> int:
    data = memory.read(address, 2)
    if len(data) != 2:
        raise SchedulerCollectionError("short_read")
    return int.from_bytes(data, byteorder="little", signed=False)


class _AutoContinueBreakpoint(gdb.Breakpoint):
    """A silent breakpoint whose subclasses must not alter inferior control flow."""

    def __init__(self, address: int) -> None:
        super().__init__(f"*{format_address(address)}", internal=True)
        try:
            self.silent = True
        except Exception:
            pass


class _DriverBreakpoint(_AutoContinueBreakpoint):
    def __init__(self, recorder: "_SchedulerRecorder", address: int) -> None:
        super().__init__(address)
        self._recorder = recorder

    def stop(self) -> bool:
        try:
            self._recorder.record_driver_entry()
        except Exception:
            self._recorder.record_handler_failure("scheduler_driver_entry")
        return False


class _ReadySelectorBreakpoint(_AutoContinueBreakpoint):
    def __init__(self, recorder: "_SchedulerRecorder", address: int) -> None:
        super().__init__(address)
        self._recorder = recorder

    def stop(self) -> bool:
        try:
            self._recorder.record_selector_entry()
        except Exception:
            self._recorder.record_handler_failure("ready_selector_entry")
        return False


class _SelectorResultBreakpoint(_AutoContinueBreakpoint):
    """Observe a fixed instruction immediately after a selector-owned call."""

    def __init__(self, recorder: "_SchedulerRecorder", address: int, kind: str, node_register: str | None = None) -> None:
        super().__init__(address)
        self._recorder = recorder
        self._kind = kind
        self._node_register = node_register

    def stop(self) -> bool:
        try:
            if self._kind == "selection":
                self._recorder.record_selector_return()
            elif self._kind == "predicate" and self._node_register is not None:
                self._recorder.record_predicate_return(self._node_register)
            elif self._kind == "resource_score" and self._node_register is not None:
                self._recorder.record_resource_score_return(self._node_register)
            else:
                raise SchedulerCollectionError("invalid_selector_result_breakpoint")
        except Exception:
            self._recorder.record_handler_failure(f"selector_{self._kind}_return")
        return False



class _SchedulerRecorder:
    """Owns one scheduler tracepoint session and deterministic output state."""

    def __init__(self, profile: dict[str, Any], executable: dict[str, Any], options: dict[str, Any]) -> None:
        validate_scheduler_profile(profile)
        self.profile = profile
        self.scheduler = profile["scheduler"]
        self.executable = executable
        self.output_directory = Path(options["output"]).resolve()
        self.max_nodes = int(options["max_nodes"])
        self.max_edges = int(options["max_edges"])
        self.breakpoints: list[gdb.Breakpoint] = []
        self.sequence = 0
        self.driver_sequence = 0
        self.selection_ordinal = 0
        self.context_sequence = 0
        self.contexts: dict[int, dict[str, Any]] = {}
        self.manifest: dict[str, Any] = {
            "schema": {
                "name": SCHEDULER_MANIFEST_SCHEMA_NAME,
                "version": SCHEDULER_MANIFEST_SCHEMA_VERSION,
            },
            "created_at": _utc_now(),
            "profile": scheduler_profile_manifest(profile),
            "executable": executable,
            "configuration": {
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "auto_continue": True,
                "writes_inferior_memory": False,
                "heap_addresses_in_normalized_capture": False,
            },
            "layout_evidence": scheduler_layout_evidence(profile),
            "breakpoints": {
                "scheduler_driver": format_address(int(self.scheduler["driver"], 0)),
                "ready_selector": format_address(int(self.scheduler["ready_selector"], 0)),
                "resource_pressure_score": format_address(
                    int(self.scheduler["resource_pressure_score"], 0)
                ),
            },
            "driver_entries": [],
            "captures": [],
            "observed_pcode_order": [],
            "handler_failures": [],
        }

    @property
    def manifest_path(self) -> Path:
        return self.output_directory / MANIFEST_FILENAME

    def _write_manifest(self) -> None:
        _atomic_json_write(self.manifest_path, self.manifest)

    def start(self) -> None:
        self.output_directory.mkdir(parents=True, exist_ok=True)
        if self.manifest_path.exists():
            raise gdb.GdbError(f"refusing to overwrite existing manifest {self.manifest_path}; choose fresh --output")
        driver = parse_address(self.scheduler["driver"], "scheduler.driver")
        selector = parse_address(self.scheduler["ready_selector"], "scheduler.ready_selector")
        try:
            self.breakpoints = [
                _DriverBreakpoint(self, driver),
                _ReadySelectorBreakpoint(self, selector),
                _SelectorResultBreakpoint(self, 0x004C094D, "selection"),
                _SelectorResultBreakpoint(self, 0x004C0A2F, "predicate", "ebx"),
                _SelectorResultBreakpoint(self, 0x004C0AA9, "predicate", "esi"),
                _SelectorResultBreakpoint(self, 0x004C0B11, "predicate", "esi"),
                _SelectorResultBreakpoint(self, 0x004C0A86, "resource_score", "ebx"),
                _SelectorResultBreakpoint(self, 0x004C0AB6, "resource_score", "esi"),
                _SelectorResultBreakpoint(self, 0x004C0AC4, "resource_score", "esi"),
            ]
            self._write_manifest()
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
        self.contexts.clear()

    def record_handler_failure(self, stage: str) -> None:
        failure = {"stage": stage, "sequence": self.sequence + 1}
        if failure not in self.manifest["handler_failures"]:
            self.manifest["handler_failures"].append(failure)
        try:
            self._write_manifest()
        except Exception:
            pass

    def record_driver_entry(self) -> None:
        self.driver_sequence += 1
        self.selection_ordinal = 0
        self.manifest["driver_entries"].append(
            {
                "driver_sequence": self.driver_sequence,
                "profile_address": format_address(parse_address(self.scheduler["driver"], "scheduler.driver")),
            }
        )
        self._write_manifest()

    def _selector_predicate_callback(self, memory: _InferiorMemory) -> int | None:
        callback_table_global = parse_address(
            self.scheduler["globals"]["callback_table"], "scheduler.globals.callback_table"
        )
        table = _read_u32(memory, callback_table_global)
        callback = _read_u32(memory, table + 0x10) if table else 0
        if callback == 0:
            return None
        rendered = format_address(callback)
        existing = self.manifest["breakpoints"].get("selector_eligibility_callback")
        if existing is None:
            self.manifest["breakpoints"]["selector_eligibility_callback"] = rendered
        elif existing != rendered:
            raise SchedulerCollectionError("selector_eligibility_callback_changed_during_session")
        return callback

    def _selector_arguments(self, memory: _InferiorMemory) -> tuple[int, int]:
        stack = int(gdb.parse_and_eval("$esp")) & 0xFFFFFFFF
        return _read_u32(memory, stack + 4), _read_u16(memory, stack + 8)

    def record_selector_entry(self) -> None:
        inferior = gdb.selected_inferior()
        memory = _InferiorMemory(inferior)
        head, cycle = self._selector_arguments(memory)
        pressure_address = parse_address(
            self.scheduler["globals"]["pressure_mode"], "scheduler.globals.pressure_mode"
        )
        pressure_mode = _read_u32(memory, pressure_address) != 0
        predicate_callback = self._selector_predicate_callback(memory)
        raw = collect_ready_candidates(memory, self.scheduler, head, cycle, self.max_nodes, self.max_edges)
        self.context_sequence += 1
        self.selection_ordinal += 1
        context_id = self.context_sequence
        self.contexts[context_id] = {
            "raw": raw,
            "pressure_mode": pressure_mode,
            "driver_sequence": self.driver_sequence,
            "selection_ordinal": self.selection_ordinal,
            "predicate_callback": predicate_callback,
            "predicate_results": {},
            "resource_scores": {},
        }

    def _active_context_id(self) -> int | None:
        return max(self.contexts) if self.contexts else None

    def _pcode_from_node_register(self, register: str) -> int | None:
        context_id = self._active_context_id()
        if context_id is None:
            return None
        node = int(gdb.parse_and_eval(f"${register}")) & 0xFFFFFFFF
        if node == 0:
            return None
        return _read_u32(_InferiorMemory(gdb.selected_inferior()), node + 0x0C)

    def record_predicate_return(self, node_register: str) -> None:
        context_id = self._active_context_id()
        pcode = self._pcode_from_node_register(node_register)
        if context_id is None or pcode is None:
            return
        result = bool(int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF)
        self.contexts[context_id]["predicate_results"].setdefault(pcode, []).append(result)

    def record_resource_score_return(self, node_register: str) -> None:
        context_id = self._active_context_id()
        pcode = self._pcode_from_node_register(node_register)
        if context_id is None or pcode is None:
            return
        raw_score = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
        score = raw_score if raw_score < 0x80000000 else raw_score - 0x100000000
        self.contexts[context_id]["resource_scores"].setdefault(pcode, []).append(score)

    def record_selector_return(self) -> None:
        context_id = self._active_context_id()
        if context_id is None:
            return
        selected = int(gdb.parse_and_eval("$eax")) & 0xFFFFFFFF
        self.complete_selector(context_id, selected)

    def _predicate_map(self, context: dict[str, Any]) -> tuple[dict[int, bool], int]:
        resolved: dict[int, bool] = {}
        conflicts = 0
        for pcode, results in context["predicate_results"].items():
            values = set(results)
            if len(values) == 1:
                resolved[pcode] = values.pop()
            else:
                conflicts += 1
        return resolved, conflicts

    @staticmethod
    def _score_map(context: dict[str, Any]) -> tuple[dict[int, int], int]:
        resolved: dict[int, int] = {}
        conflicts = 0
        for pcode, scores in context["resource_scores"].items():
            values = set(scores)
            if len(values) == 1:
                resolved[pcode] = values.pop()
            else:
                conflicts += 1
        return resolved, conflicts

    def complete_selector(self, context_id: int, selected_node_address: int) -> None:
        context = self.contexts.pop(context_id, None)
        if context is None:
            return
        predicates, predicate_conflicts = self._predicate_map(context)
        resource_scores, score_conflicts = self._score_map(context)
        raw = apply_selector_predicates(context["raw"], predicates, resource_scores)
        normalized = normalize_scheduler_capture(raw, bool(context["pressure_mode"]))
        observed = observed_selection(normalized, selected_node_address, raw)
        prediction = normalized["prediction"]
        prediction_matches = (
            prediction.get("status") == "complete"
            and observed.get("status") == "complete"
            and prediction.get("winner_id") == observed.get("winner_id")
        )
        normalized["observed"] = observed
        normalized["prediction_matches_observed"] = prediction_matches
        normalized["selector_predicate_observation"] = {
            "callback_address": (
                None
                if context["predicate_callback"] is None
                else format_address(int(context["predicate_callback"]))
            ),
            "resolved_pcode_count": len(predicates),
            "conflicting_result_count": predicate_conflicts,
        }
        normalized["resource_score_observation"] = {
            "callback_address": format_address(
                parse_address(
                    self.scheduler["resource_pressure_score"], "scheduler.resource_pressure_score"
                )
            ),
            "resolved_pcode_count": len(resource_scores),
            "conflicting_result_count": score_conflicts,
        }
        self.sequence += 1
        filename = f"{self.sequence:06d}-ready-selection.json"
        text_filename = f"{self.sequence:06d}-ready-selection.scheduler.txt"
        capture = {
            "schema": {
                "name": SCHEDULER_CAPTURE_SCHEMA_NAME,
                "version": SCHEDULER_CAPTURE_SCHEMA_VERSION,
            },
            "captured_at": _utc_now(),
            "sequence": self.sequence,
            "driver_sequence": int(context["driver_sequence"]),
            "selection_ordinal": int(context["selection_ordinal"]),
            "breakpoint": {
                "profile_address": format_address(
                    parse_address(self.scheduler["ready_selector"], "scheduler.ready_selector")
                ),
                "capture_boundary": "selector_entry_with_live_predicate_results_then_selector_return",
            },
            "profile": scheduler_profile_manifest(self.profile),
            "executable": self.executable,
            "scheduler": normalized,
            "scheduler_text_file": text_filename,
        }
        _atomic_text_write(self.output_directory / text_filename, format_scheduler_capture_text(normalized))
        _atomic_json_write(self.output_directory / filename, capture)
        manifest_entry = {
            "sequence": self.sequence,
            "driver_sequence": int(context["driver_sequence"]),
            "selection_ordinal": int(context["selection_ordinal"]),
            "file": filename,
            "scheduler_text_file": text_filename,
            "prediction_status": prediction.get("status"),
            "prediction_winner_id": prediction.get("winner_id"),
            "observed_status": observed.get("status"),
            "observed_winner_id": observed.get("winner_id"),
            "prediction_matches_observed": prediction_matches,
        }
        self.manifest["captures"].append(manifest_entry)
        self.manifest["observed_pcode_order"].append(
            {
                "driver_sequence": int(context["driver_sequence"]),
                "selection_ordinal": int(context["selection_ordinal"]),
                "pcode_opcode_u16": observed.get("pcode_opcode_u16"),
                "pcode_signature": observed.get("pcode_signature"),
                "observed_winner_id": observed.get("winner_id"),
                "prediction_matches_observed": prediction_matches,
            }
        )
        self._write_manifest()


_ACTIVE_RECORDER: _SchedulerRecorder | None = None


class B210SchedulerCommand(gdb.Command):
    """Install or remove exact-b210 scheduler capture breakpoints."""

    def __init__(self) -> None:
        super().__init__("b210-scheduler", gdb.COMMAND_DATA)

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _ACTIVE_RECORDER
        argv = _gdb_argv(argument)
        if argv == ["stop"]:
            if _ACTIVE_RECORDER is None:
                raise gdb.GdbError("no b210 scheduler session is active")
            _ACTIVE_RECORDER.stop()
            _ACTIVE_RECORDER = None
            gdb.write("b210 scheduler breakpoints removed\n")
            return
        if argv == ["status"]:
            if _ACTIVE_RECORDER is None:
                gdb.write("b210 scheduler session: inactive\n")
            else:
                gdb.write(
                    "b210 scheduler session: active; "
                    f"{len(_ACTIVE_RECORDER.manifest['captures'])} completed captures; "
                    f"output {_ACTIVE_RECORDER.output_directory}\n"
                )
            return
        if _ACTIVE_RECORDER is not None:
            raise gdb.GdbError("a b210 scheduler session is active; use 'b210-scheduler stop'")

        options = _parse_start_options(argument)
        try:
            profile = load_b210_profile(options["profile"])
            validate_scheduler_profile(profile)
            executable = fingerprint_executable(_loaded_executable(), profile)
        except (SnapshotModelError, SchedulerProfileError) as exc:
            raise gdb.GdbError(f"b210 scheduler identity/profile validation failed: {exc}") from exc
        inferior = gdb.selected_inferior()
        if not inferior or inferior.pid == 0:
            raise gdb.GdbError("attach to the suspended compiler before starting b210 scheduler capture")
        image_base = parse_address(profile["binary"]["image_base"], "profile.binary.image_base")
        _verify_image_mapping(inferior, image_base)
        recorder = _SchedulerRecorder(profile, executable, options)
        recorder.start()
        _ACTIVE_RECORDER = recorder
        gdb.write(
            "b210 scheduler captures armed: driver and ready-selector auto-continuing breakpoints, "
            f"output {recorder.output_directory}\n"
        )


B210SchedulerCommand()
