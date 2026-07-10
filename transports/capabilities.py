"""Deterministic evidence for optional Windows-emulation command availability."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Mapping, Sequence

from .process import TransportError


CAPABILITY_SCHEMA_NAME = "mwccps2-debugger-transport-capabilities"
CAPABILITY_SCHEMA_VERSION = 1
_SMOKE_TIMEOUT_SECONDS = 10

Which = Callable[[str], str | None]
Run = Callable[..., subprocess.CompletedProcess[str]]


def _tool_capability(
    candidates: Sequence[str],
    which: Which,
    run: Run,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Report a tool only as available after locating and exercising its executable."""

    selected = next((candidate for candidate in candidates if which(candidate) is not None), None)
    smoke_command = [selected or candidates[0], "--version"]
    evidence: dict[str, Any] = {
        "candidate_commands": list(candidates),
        "selected_command": selected,
        "smoke_command": smoke_command,
        "smoke_timeout_seconds": timeout_seconds,
    }
    if selected is None:
        evidence["smoke"] = {"attempted": False, "exit_code": None, "outcome": "not_run"}
        return {
            "availability": "unavailable",
            "evidence": evidence,
            "found": False,
            # A command absence must never be presented as a snapshot transport.
            "validated_for_b210_gdb_snapshots": False,
        }

    try:
        completed = run(
            smoke_command,
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        evidence["smoke"] = {"attempted": True, "exit_code": None, "outcome": "timed_out"}
        availability = "available_smoke_timed_out"
    except OSError as exc:
        evidence["smoke"] = {
            "attempted": True,
            "exit_code": None,
            "outcome": "could_not_start",
            "error_kind": type(exc).__name__,
        }
        availability = "available_smoke_failed"
    else:
        exit_code = int(completed.returncode)
        evidence["smoke"] = {
            "attempted": True,
            "exit_code": exit_code,
            "outcome": "passed" if exit_code == 0 else "failed",
        }
        availability = "available" if exit_code == 0 else "available_smoke_failed"
    return {
        "availability": availability,
        "evidence": evidence,
        "found": True,
        # A version/help smoke establishes only tool launchability. Wine/Wibo have
        # no validated GDB attach/inferior path here, so they must not be advertised
        # as usable b210 snapshot transports.
        "validated_for_b210_gdb_snapshots": False,
    }


def probe_capabilities(
    *,
    which: Which = shutil.which,
    run: Run = subprocess.run,
    smoke_timeout_seconds: int = _SMOKE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Probe Wine and Wibo in stable order, smoking each only when it is on PATH."""

    if smoke_timeout_seconds < 1:
        raise TransportError("capability smoke timeout must be positive")
    return {
        "capabilities": {
            "wibo": _tool_capability(("wibo",), which, run, smoke_timeout_seconds),
            "wine": _tool_capability(("wine", "wine64"), which, run, smoke_timeout_seconds),
        },
        "evidence": {
            "b210_snapshot_transport": (
                "Wine and Wibo are evaluated only for executable availability and a "
                "real --version smoke; neither result validates GDB attachment or b210 capture."
            ),
            "ordering": "capability keys and candidate command lists are fixed by schema-v1",
        },
        "schema": {"name": CAPABILITY_SCHEMA_NAME, "version": CAPABILITY_SCHEMA_VERSION},
    }


def canonical_json(payload: Mapping[str, Any]) -> str:
    """Return schema artifacts in stable, newline-terminated JSON form."""

    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"


def write_capabilities(path: Path, report: Mapping[str, Any]) -> None:
    """Atomically write a capability report without timestamps or resolved host paths."""

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
            output.write(canonical_json(report))
        temporary_path.replace(path)
    except OSError as exc:
        raise TransportError(f"cannot write capability report {path}: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
