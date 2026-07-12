"""GDB command for profile-driven MWCCPS2 frontend, PCode, scheduler, and regalloc captures.

Usage inside GDB:
    source gdb/mwccps2_capture.py
    mwccps2-capture start --profile PROFILE --output DIRECTORY [--function NAME]
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import gdb

_SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(_SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIRECTORY))

from mwccps2_profile_model import (  # noqa: E402
    MemoryReadError,
    ProfileError,
    address,
    codegen_function_name,
    collect_pcode,
    collect_regalloc_list,
    collect_scheduler_ready,
    fingerprint_executable,
    format_pcode,
    format_regalloc,
    load_profile,
)


class _Memory:
    def __init__(self, inferior: gdb.Inferior) -> None:
        self.inferior = inferior

    def read(self, pointer: int, size: int) -> bytes:
        return bytes(self.inferior.read_memory(pointer, size))


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _write_text(path: Path, value: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    os.replace(temporary, path)


def _u32_expression(expression: str) -> int:
    return int(gdb.parse_and_eval(expression)) & 0xFFFFFFFF


def _slug(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return result or "anonymous"


def _tokens(argument: str) -> dict[str, Any]:
    values = gdb.string_to_argv(argument)
    if not values or values[0] != "start":
        raise gdb.GdbError("expected: mwccps2-capture start --profile FILE --output DIRECTORY [--function NAME]")
    options: dict[str, Any] = {"profile": None, "output": None, "function": None, "max_blocks": 4096, "max_instructions": 65536, "max_nodes": 32767}
    index = 1
    while index < len(values):
        option = values[index]
        if option not in {"--profile", "--output", "--function", "--max-blocks", "--max-instructions", "--max-nodes"}:
            raise gdb.GdbError(f"unknown mwccps2-capture option: {option}")
        if index + 1 >= len(values):
            raise gdb.GdbError(f"{option} requires a value")
        raw = values[index + 1]
        key = option[2:].replace("-", "_")
        if key.startswith("max_"):
            try:
                options[key] = int(raw, 10)
            except ValueError as exc:
                raise gdb.GdbError(f"{option} requires a positive integer") from exc
            if options[key] < 1:
                raise gdb.GdbError(f"{option} requires a positive integer")
        else:
            options[key] = raw
        index += 2
    if not options["profile"] or not options["output"]:
        raise gdb.GdbError("mwccps2-capture start requires --profile and --output")
    return options


class _CodeGenEntry(gdb.Breakpoint):
    def __init__(self, recorder: "_Recorder") -> None:
        super().__init__(f"*{address(recorder.profile['functions']['CodeGen_Generator']['address']):#x}", internal=True)
        self.silent = True
        self.recorder = recorder

    def stop(self) -> bool:
        try:
            name = codegen_function_name(self.recorder.memory(), _u32_expression("$esp"), self.recorder.profile)
            self.recorder.enter_function(name)
        except Exception as exc:
            self.recorder.error("codegen-entry", exc)
        return False


class _CodeGenReturn(gdb.Breakpoint):
    def __init__(self, recorder: "_Recorder") -> None:
        super().__init__(f"*{address(recorder.profile['functions']['CodeGen_Generator']['return_address']):#x}", internal=True)
        self.silent = True
        self.recorder = recorder

    def stop(self) -> bool:
        self.recorder.leave_function()
        return False


class _StageBreakpoint(gdb.Breakpoint):
    def __init__(self, recorder: "_Recorder", stage: dict[str, Any]) -> None:
        super().__init__(f"*{address(stage['address']):#x}", internal=True)
        self.silent = True
        self.recorder = recorder
        self.stage = stage["name"]

    def stop(self) -> bool:
        if self.recorder.active:
            self.recorder.capture_pcode(self.stage)
        return False


class _FrontendBreakpoint(gdb.Breakpoint):
    def __init__(self, recorder: "_Recorder", name: str, target: Any) -> None:
        super().__init__(f"*{address(target):#x}", internal=True)
        self.silent = True
        self.recorder = recorder
        self.name = name

    def stop(self) -> bool:
        self.recorder.capture_frontend(self.name)
        return False


class _ColorgraphEntry(gdb.Breakpoint):
    def __init__(self, recorder: "_Recorder") -> None:
        super().__init__(f"*{address(recorder.profile['register_allocation']['colorgraph']):#x}", internal=True)
        self.silent = True
        self.recorder = recorder

    def stop(self) -> bool:
        if self.recorder.active:
            try:
                self.recorder.pending_colorgraph_head = self.recorder.read_u32(
                    _u32_expression("$esp") + 4
                )
            except Exception as exc:
                self.recorder.error("colorgraph-entry", exc)
        return False


class _ColorgraphReturn(gdb.Breakpoint):
    def __init__(self, recorder: "_Recorder") -> None:
        target = recorder.profile["register_allocation"]["colorgraph_return"]
        super().__init__(f"*{address(target):#x}", internal=True)
        self.silent = True
        self.recorder = recorder

    def stop(self) -> bool:
        head = self.recorder.pending_colorgraph_head
        self.recorder.pending_colorgraph_head = None
        if self.recorder.active and head is not None:
            self.recorder.capture_regalloc(head, _u32_expression("$eax"))
        return False


class _SchedulerEntry(gdb.Breakpoint):
    def __init__(self, recorder: "_Recorder") -> None:
        super().__init__(f"*{address(recorder.profile['scheduler']['ready_selector']):#x}", internal=True)
        self.silent = True
        self.recorder = recorder

    def stop(self) -> bool:
        if self.recorder.active:
            try:
                ready = collect_scheduler_ready(
                    self.recorder.memory(), self.recorder.profile, self.recorder.max_nodes
                )
                sequence = self.recorder.scheduler_sequence
                self.recorder.scheduler_sequence += 1
                self.recorder.pending_scheduler = (sequence, ready)
            except Exception as exc:
                self.recorder.error("scheduler-selector", exc)
        return False


class _SchedulerReturn(gdb.Breakpoint):
    def __init__(self, recorder: "_Recorder") -> None:
        target = recorder.profile["scheduler"]["ready_selector_return"]
        super().__init__(f"*{address(target):#x}", internal=True)
        self.silent = True
        self.recorder = recorder

    def stop(self) -> bool:
        pending = self.recorder.pending_scheduler
        self.recorder.pending_scheduler = None
        if self.recorder.active and pending is not None:
            sequence, ready = pending
            self.recorder.capture_scheduler(sequence, ready, _u32_expression("$eax"))
        return False


class _Recorder:
    def __init__(self, profile: dict[str, Any], executable: dict[str, Any], options: dict[str, Any]) -> None:
        self.profile = profile
        self.executable = executable
        self.output = Path(options["output"]).resolve()
        self.function_filter = options["function"]
        self.max_blocks = options["max_blocks"]
        self.max_instructions = options["max_instructions"]
        self.max_nodes = options["max_nodes"]
        self.active = False
        self.current_function = ""
        self.function_sequence = 0
        self.stage_sequence = 0
        self.regalloc_sequence = 0
        self.scheduler_sequence = 0
        self.frontend_sequence = 0
        self.errors: list[dict[str, str]] = []
        self.artifacts: list[dict[str, Any]] = []
        self.scheduler_events: list[dict[str, Any]] = []
        self.pending_colorgraph_head: int | None = None
        self.pending_scheduler: tuple[int, list[dict[str, Any]]] | None = None
        self.breakpoints: list[gdb.Breakpoint] = []
        self.output.mkdir(parents=True, exist_ok=False)
        self.install()
        self.flush_manifest("running")

    def memory(self) -> _Memory:
        return _Memory(gdb.selected_inferior())

    def read_u32(self, pointer: int) -> int:
        return int.from_bytes(self.memory().read(pointer, 4), "little")

    def install(self) -> None:
        self.breakpoints.extend((_CodeGenEntry(self), _CodeGenReturn(self)))
        self.breakpoints.extend(_StageBreakpoint(self, stage) for stage in self.profile["pcode_breakpoints"])
        frontend = self.profile["frontend_ir"]["breakpoints"]
        self.breakpoints.extend(_FrontendBreakpoint(self, name, target) for name, target in frontend.items())
        self.breakpoints.extend(
            (
                _ColorgraphEntry(self),
                _ColorgraphReturn(self),
                _SchedulerEntry(self),
                _SchedulerReturn(self),
            )
        )

    def enter_function(self, name: str) -> None:
        self.current_function = name
        self.function_sequence += 1
        self.stage_sequence = 0
        self.active = self.function_filter is None or name == self.function_filter
        if self.active:
            gdb.write(f"MWCCPS2: capturing {name}\n")

    def leave_function(self) -> None:
        self.active = False
        self.current_function = ""

    def prefix(self) -> str:
        return f"{self.function_sequence:03d}-{_slug(self.current_function)}"

    def capture_pcode(self, stage: str) -> None:
        try:
            graph = collect_pcode(self.memory(), self.profile, self.max_blocks, self.max_instructions)
            basename = f"{self.prefix()}-backend-{self.stage_sequence:02d}-{stage}"
            _write_json(self.output / f"{basename}.json", {"profile": self.profile["name"], "function": self.current_function, "stage": stage, "graph": graph})
            _write_text(self.output / f"{basename}.txt", format_pcode(graph))
            self.artifacts.append({"kind": "pcode", "function": self.current_function, "stage": stage, "json": f"{basename}.json", "text": f"{basename}.txt", "blocks": graph["block_count"], "instructions": graph["instruction_count"]})
            self.stage_sequence += 1
        except Exception as exc:
            self.error(f"pcode:{stage}", exc)

    def capture_frontend(self, boundary: str) -> None:
        try:
            memory = self.memory()
            globals_ = self.profile["frontend_ir"]["globals"]
            function_pointer = self.read_u32(address(globals_["gFunction"]))
            root_pointer = self.read_u32(address(globals_["iro_root"]))
            name = "<anonymous>"
            if function_pointer:
                layout = self.profile["function_name"]
                record = self.read_u32(
                    function_pointer + int(layout["name_record_pointer_offset"])
                )
                if record:
                    from mwccps2_profile_model import read_c_string
                    name = read_c_string(
                        memory,
                        record + int(layout["inline_name_offset"]),
                        int(layout["max_bytes"]),
                    )
            if self.function_filter is not None and name != self.function_filter:
                return
            preview_bytes = int(self.profile["frontend_ir"]["capture"]["root_preview_bytes"])
            preview = memory.read(root_pointer, preview_bytes).hex() if root_pointer else None
            value = {"profile": self.profile["name"], "boundary": boundary, "function": name, "function_pointer": f"0x{function_pointer:08x}", "iro_root": f"0x{root_pointer:08x}", "iro_root_preview": preview}
            basename = f"frontend-{self.frontend_sequence:02d}-{_slug(name)}-{boundary}"
            _write_json(self.output / f"{basename}.json", value)
            _write_text(self.output / f"{basename}.txt", f"{name}: {boundary}\nfunction record: 0x{function_pointer:08x}\nIRO root: 0x{root_pointer:08x}\nIRO root preview ({preview_bytes} bytes): {preview or '-'}\n")
            self.artifacts.append({"kind": "frontend", "function": name, "stage": boundary, "json": f"{basename}.json", "text": f"{basename}.txt"})
            self.frontend_sequence += 1
        except Exception as exc:
            self.error(f"frontend:{boundary}", exc)

    def capture_regalloc(self, head: int, result: int) -> None:
        try:
            capture = collect_regalloc_list(self.memory(), self.profile, head, self.max_nodes)
            capture["colorgraph_result"] = result
            basename = f"{self.prefix()}-regalloc-{self.regalloc_sequence:02d}-{_slug(capture['class']['name'])}"
            _write_json(self.output / f"{basename}.json", capture)
            _write_text(self.output / f"{basename}.txt", format_regalloc(capture))
            self.artifacts.append({"kind": "regalloc", "function": self.current_function, "register_class": capture["class"]["name"], "json": f"{basename}.json", "text": f"{basename}.txt", "nodes": capture["node_count"]})
            self.regalloc_sequence += 1
        except Exception as exc:
            self.error("regalloc", exc)

    def capture_scheduler(self, sequence: int, ready: list[dict[str, Any]], selected: int) -> None:
        selected_index = next((index for index, node in enumerate(ready) if node["address"] == selected), None)
        self.scheduler_events.append({"sequence": sequence, "function": self.current_function, "ready": ready, "selected_address": selected, "selected_index": selected_index})

    def error(self, stage: str, exc: Exception) -> None:
        value = {"stage": stage, "type": type(exc).__name__, "message": str(exc)}
        self.errors.append(value)
        gdb.write(f"MWCCPS2 capture warning [{stage}]: {exc}\n", gdb.STDERR)

    def flush_manifest(self, status: str) -> None:
        if self.scheduler_events:
            _write_json(self.output / "scheduler.json", self.scheduler_events)
            lines = ["Scheduler selections:"]
            for event in self.scheduler_events:
                selected_index = event["selected_index"]
                if event["selected_address"] == 0:
                    lines.append(
                        f"\n{event['sequence']:04d}: no eligible node among "
                        f"{len(event['ready'])} candidates; scheduler advances the cycle"
                    )
                else:
                    lines.append(
                        f"\n{event['sequence']:04d}: chose ready["
                        f"{selected_index if selected_index is not None else '?'}] "
                        f"from {len(event['ready'])} candidates"
                    )
                for index, node in enumerate(event["ready"]):
                    marker = "*" if index == selected_index else " "
                    lines.append(
                        f"  {marker} ready[{index}] "
                        f"pcode=0x{node['pcode']:08x} "
                        f"pending={node['pending_predecessors']} "
                        f"earliest={node['earliest_issue_cycle']} "
                        f"deadline={node['critical_deadline_cycle']} "
                        f"critical={node['critical_path_length']} "
                        f"latency={node['heuristic_latency']}"
                    )
            _write_text(self.output / "scheduler.txt", "\n".join(lines) + "\n")
        manifest = {"schema": "mwccps2-human-capture-v1", "status": status, "profile": self.profile["name"], "compiler": self.executable, "function_filter": self.function_filter, "artifacts": self.artifacts, "scheduler": {"events": len(self.scheduler_events), "json": "scheduler.json" if self.scheduler_events else None, "text": "scheduler.txt" if self.scheduler_events else None}, "errors": self.errors}
        _write_json(self.output / "manifest.json", manifest)

    def stop(self) -> None:
        self.flush_manifest("complete" if not self.errors else "complete-with-warnings")
        for breakpoint in self.breakpoints:
            try:
                breakpoint.delete()
            except Exception:
                pass
        self.breakpoints.clear()


_RECORDER: _Recorder | None = None


class Mwccps2CaptureCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("mwccps2-capture", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _RECORDER
        values = gdb.string_to_argv(argument)
        if values and values[0] == "stop":
            if _RECORDER is None:
                raise gdb.GdbError("no MWCCPS2 capture is active")
            _RECORDER.stop()
            _RECORDER = None
            return
        if _RECORDER is not None:
            raise gdb.GdbError("an MWCCPS2 capture is already active")
        options = _tokens(argument)
        try:
            profile = load_profile(options["profile"])
            filename = gdb.current_progspace().filename
            if not filename:
                raise ProfileError("GDB has no compiler executable selected")
            executable = fingerprint_executable(filename, profile)
            _RECORDER = _Recorder(profile, executable, options)
        except (OSError, ProfileError, MemoryReadError) as exc:
            raise gdb.GdbError(str(exc)) from exc
        gdb.write(f"MWCCPS2 capture armed for {profile['display_name'] if 'display_name' in profile else profile['name']}\n")


Mwccps2CaptureCommand()
