"""Persona 3 FES boundary adapter for the generic function explainer."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from solver.p3_verify import P3VerifierConfigurationError, verify_candidate


_SYMBOL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*0x([0-9A-Fa-f]{8})\s*;")
_ADDRESS_RE = re.compile(r"[0-9A-Fa-f]{8}\Z")


class P3AdapterError(ValueError):
    """A safe, user-facing Persona 3 adapter failure."""


def _load_verifier(root: Path) -> ModuleType:
    verifier_path = root / "tools" / "verify.py"
    if not verifier_path.is_file():
        raise P3AdapterError("P3 root does not contain tools/verify.py")
    module_name = f"_mwccps2_explain_p3_verify_{abs(hash(verifier_path))}"
    spec = importlib.util.spec_from_file_location(module_name, verifier_path)
    if spec is None or spec.loader is None:
        raise P3AdapterError("could not load the P3 verifier module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, ValueError) as exc:
        sys.modules.pop(module_name, None)
        raise P3AdapterError("could not initialize the P3 verifier module") from exc
    return module


def _resolve_source(root: Path, source: Path | str) -> Path:
    value = Path(source)
    resolved = (root / value).resolve() if not value.is_absolute() else value.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise P3AdapterError("source must remain inside the P3 repository") from exc
    if not resolved.is_file() or resolved.suffix.lower() != ".c":
        raise P3AdapterError("source must be an existing C file inside the P3 repository")
    return resolved


def _load_map(root: Path) -> dict[str, Any]:
    path = root / "tools" / "slus21621_functions.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise P3AdapterError("could not read the canonical P3 function map") from exc
    if not isinstance(value, dict) or not isinstance(value.get("windows"), dict):
        raise P3AdapterError("canonical P3 function map has an invalid schema")
    return value


def _select_marker(verifier: ModuleType, source: Path, function_name: str, address: str | None) -> dict[str, Any]:
    markers = verifier.scan_markers(source)
    matches = [marker for marker in markers if marker.get("name") == function_name]
    if address is not None:
        normalized = address.removeprefix("0x").lower()
        if not _ADDRESS_RE.fullmatch(normalized):
            raise P3AdapterError("address must contain exactly eight hexadecimal digits")
        matches = [marker for marker in matches if marker.get("addr") == int(normalized, 16)]
    if not matches:
        raise P3AdapterError("function marker was not found in the selected source")
    if len(matches) != 1:
        raise P3AdapterError("function marker is ambiguous in the selected source")
    return matches[0]


def _boundaries(verifier: ModuleType, root: Path, function_map: dict[str, Any]) -> list[int]:
    windows = function_map["windows"]
    result = {int(address, 16) for address in windows}
    for address, window in windows.items():
        if isinstance(window, int) and window > 0:
            result.add(int(address, 16) + window)
    for cpath in sorted((root / "src").rglob("*.c")):
        if cpath.name.endswith(".match.c") or cpath.name.startswith(".permute_"):
            continue
        for marker in verifier.scan_markers(cpath):
            result.add(marker["addr"])
    return sorted(result)


def _symbols(root: Path) -> dict[int, str]:
    result: dict[int, str] = {}
    path = root / "config" / "symbol_addrs.txt"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return result
    for line in lines:
        match = _SYMBOL_RE.match(line.strip())
        if match:
            result[int(match.group(2), 16)] = match.group(1)
    return result


def collect_p3_evidence(
    *,
    p3_root: Path | str,
    source: Path | str,
    function_name: str,
    address: str | None = None,
    python_executable: Path | str = sys.executable,
    timeout_seconds: float = 120.0,
) -> dict[str, Any]:
    """Compile, verify, and extract one P3 candidate and retail function window."""
    root = Path(p3_root).resolve()
    if not root.is_dir():
        raise P3AdapterError("P3 root must be an existing directory")
    if not function_name or not function_name.isidentifier():
        raise P3AdapterError("function name must be a C identifier")
    cpath = _resolve_source(root, source)
    verifier = _load_verifier(root)
    function_map = _load_map(root)
    marker = _select_marker(verifier, cpath, function_name, address)
    address_value = marker["addr"]
    window = verifier.window_for(address_value, _boundaries(verifier, root, function_map))
    if not isinstance(window, int) or window <= 0 or window > 0x10000:
        raise P3AdapterError("function does not have a plausible canonical retail window")

    try:
        config = verifier.load_config()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise P3AdapterError("could not load the P3 verifier configuration") from exc
    try:
        retail = verifier.RetailElf(config["retail_elf"], expect_sha1=function_map.get("sha1"))
    except (OSError, ValueError, KeyError, SystemExit) as exc:
        raise P3AdapterError("could not validate the configured P3 retail executable") from exc

    with tempfile.TemporaryDirectory(prefix="mwccps2_explain_") as temporary:
        obj, compile_log = verifier.compile_object(cpath, config, Path(temporary))
        if obj is None:
            detail = compile_log.strip().splitlines()
            suffix = f": {detail[-1]}" if detail else ""
            raise P3AdapterError(f"P3 source did not compile{suffix}")
        try:
            candidate_bytes, relocations = obj.function(function_name)
        except KeyError as exc:
            raise P3AdapterError("compiled object does not contain the selected function") from exc

    retail_bytes = retail.bytes_at(address_value, window)
    source_text = cpath.read_text(encoding="utf-8")
    try:
        verification = verify_candidate(
            root,
            cpath,
            source_text,
            function_name,
            f"{address_value:08x}",
            python_executable,
            timeout_seconds,
        )
    except P3VerifierConfigurationError as exc:
        raise P3AdapterError(str(exc)) from exc

    return {
        "project": {
            "adapter": "persona3-fes",
            "program": function_map.get("program", "SLUS_216.21"),
            "retail_sha1": function_map.get("sha1"),
            "canonical_function_count": function_map.get("function_count"),
        },
        "function": {
            "name": function_name,
            "address": f"{address_value:08x}",
            "source": cpath.relative_to(root).as_posix(),
            "marker_line": marker.get("line"),
            "window": window,
            "nonmatching_marker": bool(marker.get("nonmatching")),
            "stub_marker": bool(marker.get("stub")),
        },
        "verification": verification.evidence,
        "candidate_bytes": candidate_bytes,
        "retail_bytes": retail_bytes,
        "relocations": tuple(relocations),
        "symbols": _symbols(root),
    }
