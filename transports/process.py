"""Checked host-process execution shared by debugger transports.

The process boundary has no knowledge of MWCCPS2, GDB Python commands, or snapshot
schemas. Callers supply a command and translate :class:`TransportError` into their
own domain error when necessary.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence


class TransportError(Exception):
    """Raised when a transport command cannot be run successfully."""


def format_command(command: Sequence[str]) -> str:
    """Render a command with Windows quoting for actionable diagnostic output."""

    return subprocess.list2cmdline([str(argument) for argument in command])


def format_process_output(completed: subprocess.CompletedProcess[str]) -> str:
    """Return non-empty child output without host-specific decoration."""

    pieces = []
    if completed.stdout:
        pieces.append("stdout:\n" + completed.stdout.rstrip())
    if completed.stderr:
        pieces.append("stderr:\n" + completed.stderr.rstrip())
    return "\n".join(pieces) if pieces else "(no process output)"


def run_checked(
    command: Sequence[str],
    working_directory: Path,
    timeout_seconds: int,
    description: str,
) -> subprocess.CompletedProcess[str]:
    """Run one command and convert launch, timeout, and exit failures to TransportError."""

    if not command or not str(command[0]):
        raise TransportError(f"cannot start {description}: command must name an executable")
    if timeout_seconds < 1:
        raise TransportError(f"cannot start {description}: timeout must be positive")
    normalized_command = [str(argument) for argument in command]
    try:
        completed = subprocess.run(
            normalized_command,
            cwd=str(working_directory),
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise TransportError(
            f"cannot start {description}: executable not found: {normalized_command[0]}"
        ) from exc
    except OSError as exc:
        raise TransportError(f"cannot start {description}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        raise TransportError(
            f"{description} exceeded {timeout_seconds} seconds\n"
            f"command: {format_command(normalized_command)}\n{output.rstrip()}"
        ) from exc
    if completed.returncode:
        raise TransportError(
            f"{description} failed with exit code {completed.returncode}\n"
            f"command: {format_command(normalized_command)}\n{format_process_output(completed)}"
        )
    return completed
