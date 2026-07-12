#!/usr/bin/env python3
"""Human-facing, one-command MWCCPS2 internal-state debugger."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parent
PROFILE_DIRECTORY = ROOT / "profiles"
CAPTURE_SCRIPT = ROOT / "gdb" / "mwccps2_capture.py"


class DebuggerError(RuntimeError):
    pass


def _quote(value: str) -> str:
    if any(character in value for character in "\0\r\n"):
        raise DebuggerError("GDB arguments cannot contain NUL or newline characters")
    return '"' + value.replace("\\", "/").replace('"', '\\"') + '"'


def _fingerprint(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as binary:
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def discover_profile(compiler: Path, requested: Path | None = None) -> Path:
    size, digest = _fingerprint(compiler)
    candidates = [requested] if requested is not None else sorted(PROFILE_DIRECTORY.glob("*.json"))
    supported: list[Path] = []
    for path in candidates:
        if path is None or not path.is_file():
            continue
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        binary = profile.get("binary", {}) if isinstance(profile, dict) else {}
        if (
            binary.get("size") == size
            and str(binary.get("sha256", "")).casefold() == digest.casefold()
            and profile.get("schema_version") == 2
        ):
            supported.append(path)
    if requested is not None and not supported:
        raise DebuggerError(f"compiler does not match requested profile {requested}")
    if not supported:
        raise DebuggerError(f"no live profile matches compiler SHA-256 {digest}; prepare 2.4 with mwccps2_prepare_24.py first")
    if len(supported) != 1:
        raise DebuggerError("multiple live profiles match the compiler: " + ", ".join(path.name for path in supported))
    return supported[0]


def _default_gdb() -> Path | None:
    environment = os.environ.get("MWCCPS2_GDB")
    if environment:
        return Path(environment)
    found = shutil.which("gdb")
    if found:
        return Path(found)
    common = Path(r"C:\msys64\mingw64\bin\gdb.exe")
    return common if common.is_file() else None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile one source file and dump readable MWCCPS2 frontend, PCode, scheduler, and register-allocation state.",
        epilog=(
            "Example: python mwccps2_debugger.py -e D:/mwcc24/debug/mwccps2.exe "
            "fixtures/codegen_smoke.c load_indexed -- -O4,p"
        ),
    )
    parser.add_argument("source", type=Path, help="C or C++ source file to compile")
    parser.add_argument("function", nargs="?", help="exact compiler function name to capture; omit to capture all")
    parser.add_argument("-e", "--compiler", required=True, type=Path, help="prepared mwccps2.exe")
    parser.add_argument("-g", "--gdb", type=Path, help="Windows GDB executable; defaults to MWCCPS2_GDB, PATH, or MSYS2")
    parser.add_argument("-p", "--profile", type=Path, help="live profile JSON; normally auto-detected by compiler hash")
    parser.add_argument("-o", "--output", type=Path, help="new capture directory; defaults beside the source")
    parser.add_argument("-a", "--args", help="quoted compiler flags, compatible with cadmic/mwcc-debugger's -a workflow")
    parser.add_argument("--cwd", type=Path, help="compiler working directory; defaults to the source directory")
    values, compiler_flags = parser.parse_known_args(argv)
    if compiler_flags[:1] == ["--"]:
        compiler_flags = compiler_flags[1:]
    if values.args and compiler_flags:
        parser.error("use either -a/--args or flags after --, not both")
    values.compiler_flags = compiler_flags
    return values


def _command_lines(compiler: Path, compiler_args: list[str], profile: Path, output: Path, capture_function: str | None) -> list[str]:
    start = f"mwccps2-capture start --profile {_quote(str(profile.resolve()))} --output {_quote(str(output.resolve()))}"
    if capture_function:
        start += f" --function {_quote(capture_function)}"
    return [
        "set pagination off",
        "set confirm off",
        "set breakpoint pending on",
        f"file {_quote(str(compiler.resolve()))}",
        "set args " + " ".join(_quote(argument) for argument in compiler_args),
        "starti",
        f"source {str(CAPTURE_SCRIPT.resolve()).replace(chr(92), '/')}",
        start,
        "continue",
        "mwccps2-capture stop",
        "quit",
        "",
    ]


def _run_gdb(gdb: Path, lines: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", suffix=".gdb", prefix="mwccps2-human-", delete=False) as command_file:
        command_file.write("\n".join(lines))
        command_path = Path(command_file.name)
    try:
        return subprocess.run([str(gdb), "--batch", "--nx", "--quiet", "--command", str(command_path)], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, check=False)
    except subprocess.TimeoutExpired as exc:
        raise DebuggerError("GDB capture exceeded 300 seconds") from exc
    finally:
        try:
            command_path.unlink()
        except OSError:
            pass


def _summary(manifest: dict[str, Any], output: Path) -> str:
    artifacts = manifest.get("artifacts", [])
    counts: dict[str, int] = {}
    for artifact in artifacts:
        kind = str(artifact.get("kind", "unknown"))
        counts[kind] = counts.get(kind, 0) + 1
    lines = [f"Capture: {manifest.get('status', 'unknown')}", f"Output:  {output}", f"Profile: {manifest.get('profile')}"]
    if manifest.get("function_filter"):
        lines.append(f"Function: {manifest['function_filter']}")
    lines.append("Files:    " + (", ".join(f"{count} {kind}" for kind, count in sorted(counts.items())) or "none"))
    scheduler = manifest.get("scheduler", {})
    if scheduler.get("events"):
        lines.append(f"Scheduler: {scheduler['events']} decisions -> scheduler.txt")
    if manifest.get("errors"):
        lines.append(f"Warnings: {len(manifest['errors'])} (see manifest.json)")
    lines.append("Open the numbered .txt files for pass-by-pass compiler state; JSON files contain the same machine-readable evidence.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        compiler = args.compiler.resolve(strict=True)
        source = args.source.resolve(strict=True)
        gdb = (args.gdb or _default_gdb())
        if gdb is None or not gdb.resolve().is_file():
            raise DebuggerError("GDB not found; pass --gdb or set MWCCPS2_GDB")
        gdb = gdb.resolve()
        profile = discover_profile(compiler, args.profile.resolve() if args.profile else None)
        cwd = (args.cwd or source.parent).resolve(strict=True)
        output = (args.output or (source.parent / f"mwccps2-capture-{source.stem}")).resolve()
        if output.exists():
            raise DebuggerError(f"output already exists: {output}; choose a new -o directory")
        flags = shlex.split(args.args, posix=False) if args.args else list(args.compiler_flags)
        object_path = output.parent / f".{output.name}.o"
        compiler_args = [*flags, "-c", str(source), "-o", str(object_path)]
        completed = _run_gdb(gdb, _command_lines(compiler, compiler_args, profile, output, args.function), cwd)
        manifest_path = output / "manifest.json"
        if not manifest_path.is_file():
            detail = completed.stdout.strip()
            raise DebuggerError("GDB did not produce a capture manifest" + (f":\n{detail}" if detail else ""))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if completed.returncode != 0:
            raise DebuggerError(f"GDB exited with status {completed.returncode}:\n{completed.stdout.strip()}")
        print(_summary(manifest, output))
        return 0 if not manifest.get("errors") else 1
    except (DebuggerError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        try:
            if "object_path" in locals() and object_path.exists():
                object_path.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
