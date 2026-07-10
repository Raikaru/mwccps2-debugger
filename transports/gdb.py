"""GDB command-file construction and host launch transports.

The GDB command sequence intentionally contains no b210 decoder imports. Snapshot
script/profile paths are opaque request inputs, allowing the same process transport
to launch another GDB command while keeping binary-layout decoding in ``gdb/``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Sequence

from .process import TransportError, run_checked


WINDOWS_GDB_TRANSPORT = "windows-gdb"
RETROWIN32_GDB_TRANSPORT = "retrowin32-gdb"
GDB_TRANSPORT_KINDS = (WINDOWS_GDB_TRANSPORT, RETROWIN32_GDB_TRANSPORT)


@dataclass(frozen=True, slots=True)
class GdbSnapshotRequest:
    """All opaque paths and arguments required to run one GDB snapshot capture."""

    gdb_executable: Path
    compiler: Path
    compiler_args: Sequence[str]
    profile_path: Path
    snapshot_directory: Path
    command_directory: Path
    working_directory: Path
    snapshot_script: Path


def gdb_quote(value: str) -> str:
    """Quote exactly one argument for GDB's shell-like command lexer."""

    if "\0" in value or "\n" in value or "\r" in value:
        raise TransportError("GDB command arguments must not contain NUL or newline characters")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def gdb_path(path: Path) -> str:
    """Format a host path so GDB does not interpret Windows separators as escapes."""

    return path.resolve().as_posix()


def build_gdb_command_lines(request: GdbSnapshotRequest) -> list[str]:
    """Build the canonical auto-continuing command file for one snapshot capture."""

    compiler_args = [str(argument) for argument in request.compiler_args]
    return [
        "set pagination off",
        "set confirm off",
        "set breakpoint pending on",
        f"file {gdb_quote(gdb_path(request.compiler))}",
        "set args " + " ".join(gdb_quote(argument) for argument in compiler_args),
        # ``starti`` leaves the image loaded and all backend breakpoints armed before
        # source compilation starts. It is intentionally identical to the former
        # Windows GDB invocation.
        "starti",
        f"source {gdb_path(request.snapshot_script)}",
        "b210-snapshot start"
        f" --profile {gdb_quote(gdb_path(request.profile_path))}"
        f" --output {gdb_quote(gdb_path(request.snapshot_directory))}",
        "continue",
        "if $_exitcode != 0",
        "  echo MWCCPS2 compiler exited with non-zero status\\n",
        "  quit 1",
        "end",
        "b210-snapshot stop",
        "quit",
        "",
    ]


def write_gdb_command_file(request: GdbSnapshotRequest) -> Path:
    """Write the canonical GDB command file beneath the caller-owned directory."""

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".mwccps2-gdb-",
            suffix=".gdb",
            dir=request.command_directory,
            delete=False,
        ) as command_file:
            command_file.write("\n".join(build_gdb_command_lines(request)))
            return Path(command_file.name)
    except OSError as exc:
        raise TransportError(
            f"cannot create temporary GDB command file in {request.command_directory}: {exc}"
        ) from exc


class GdbTransport:
    """Base class for a concrete host capable of launching a GDB command file."""

    name: str

    def build_process_command(self, request: GdbSnapshotRequest, command_path: Path) -> list[str]:
        raise NotImplementedError

    def execute(
        self,
        request: GdbSnapshotRequest,
        timeout_seconds: int,
        description: str,
    ) -> None:
        """Write, execute, and remove one command file without retaining host state."""

        command_path = write_gdb_command_file(request)
        try:
            run_checked(
                self.build_process_command(request, command_path),
                request.working_directory,
                timeout_seconds,
                description,
            )
        finally:
            try:
                command_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise TransportError(f"cannot remove temporary GDB command file {command_path}: {exc}") from exc


class WindowsGdbTransport(GdbTransport):
    """Run a Windows-native GDB exactly as the original debugger invocation did."""

    name = WINDOWS_GDB_TRANSPORT

    def build_process_command(self, request: GdbSnapshotRequest, command_path: Path) -> list[str]:
        return [
            str(request.gdb_executable),
            "--batch",
            "--nx",
            "--quiet",
            "--command",
            str(command_path),
        ]


@dataclass(frozen=True, slots=True)
class Retrowin32GdbTransport(GdbTransport):
    """Launch a Windows GDB under retrowin32's documented native CLI form.

    retrowin32 accepts ``-C DIRECTORY`` before the Windows executable, followed by
    that executable's arguments. This is a configuration path only: it does not
    assert that retrowin32 can run this GDB/inferior pair. Capability reporting
    deliberately keeps it unvalidated until a real capture succeeds.
    """

    retrowin32_executable: Path
    name: str = RETROWIN32_GDB_TRANSPORT

    def build_process_command(self, request: GdbSnapshotRequest, command_path: Path) -> list[str]:
        return [
            str(self.retrowin32_executable),
            "-C",
            str(request.working_directory),
            str(request.gdb_executable),
            "--batch",
            "--nx",
            "--quiet",
            "--command",
            str(command_path),
        ]


def create_gdb_transport(kind: str, retrowin32_executable: Path | None = None) -> GdbTransport:
    """Create a configured transport or fail before launching a child process."""

    if kind == WINDOWS_GDB_TRANSPORT:
        return WindowsGdbTransport()
    if kind == RETROWIN32_GDB_TRANSPORT:
        if retrowin32_executable is None:
            raise TransportError("retrowin32-gdb transport requires a retrowin32 executable")
        return Retrowin32GdbTransport(retrowin32_executable)
    choices = ", ".join(GDB_TRANSPORT_KINDS)
    raise TransportError(f"unknown GDB transport {kind!r}; expected one of: {choices}")
