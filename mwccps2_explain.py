#!/usr/bin/env python3
"""Build one deterministic, retail-aware Persona 3 function dossier."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

from adapters.compiler import CompilerCaptureError, capture_candidate
from adapters.p3 import P3AdapterError, collect_p3_evidence
from explain.analysis import build_analysis
from explain.report import render_report


REPO = Path(__file__).resolve().parent
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _output_directory(requested: str | None, function_name: str, address: str) -> Path:
    build_root = (REPO / "build").resolve()
    name = _SAFE_NAME.sub("-", f"explain-{function_name}-{address}").strip("-")
    output = (Path(requested).resolve() if requested else build_root / name)
    try:
        output.relative_to(build_root)
    except ValueError as exc:
        raise ValueError("output must be a child of this repository's build directory") from exc
    if output.exists():
        raise ValueError("output directory already exists; choose a fresh path")
    output.mkdir(parents=True)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="P3 C source, relative to --p3-root or absolute")
    parser.add_argument("function", help="function definition selected by its // FUN_ marker")
    parser.add_argument("--p3-root", required=True, help="Persona3-FES-Decompilation checkout")
    parser.add_argument("--address", help="optional eight-digit retail address override")
    parser.add_argument("--p4-root", help="optional Persona4-Decompilation checkout with build/shared_p3.json")
    parser.add_argument("--compiler", help="exact b210 compiler for optional internal capture")
    parser.add_argument("--gdb", help="GDB with Python support for optional internal capture")
    parser.add_argument("--profile", help="exact b210 profile for optional internal capture")
    parser.add_argument("--capture-timeout", type=int, default=180, help="compiler capture timeout in seconds")
    parser.add_argument("--output", help="fresh directory under this repository's build/")
    parser.add_argument("--timeout", type=float, default=120.0, help="verifier timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    capture_values = (args.compiler, args.gdb, args.profile)
    if args.timeout <= 0 or args.capture_timeout <= 0:
        print("mwccps2-explain: timeouts must be positive", file=sys.stderr)
        return 2
    if any(capture_values) and not all(capture_values):
        print("mwccps2-explain: --compiler, --gdb, and --profile must be supplied together", file=sys.stderr)
        return 2
    output: Path | None = None
    try:
        evidence = collect_p3_evidence(
            p3_root=args.p3_root,
            source=args.source,
            function_name=args.function,
            address=args.address,
            p4_root=args.p4_root,
            timeout_seconds=args.timeout,
        )
        output = _output_directory(args.output, args.function, evidence["function"]["address"])
        compiler_capture = None
        if all(capture_values):
            compiler_capture = capture_candidate(
                source_root=args.p3_root,
                source=evidence["function"]["source"],
                candidate_source=evidence["source_text"],
                compiler=args.compiler,
                gdb=args.gdb,
                profile=args.profile,
                output_root=output / "compiler-capture",
                timeout_seconds=args.capture_timeout,
            )
        dossier = build_analysis(
            project=evidence["project"],
            function=evidence["function"],
            verification=evidence["verification"],
            candidate_bytes=evidence["candidate_bytes"],
            retail_bytes=evidence["retail_bytes"],
            relocations=evidence["relocations"],
            symbols=evidence["symbols"],
            gp=evidence["gp"],
            read_memory=evidence["read_memory"],
            callers=evidence["callers"],
            cross_game=evidence["cross_game"],
            compiler_capture=compiler_capture,
        )
        json_path = output / "function-dossier-v1.json"
        report_path = output / "function-dossier.txt"
        json_path.write_text(json.dumps(dossier, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        report_path.write_text(render_report(dossier), encoding="utf-8", newline="\n")
    except (CompilerCaptureError, P3AdapterError, OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        if output is not None:
            shutil.rmtree(output, ignore_errors=True)
        print(f"mwccps2-explain: {exc}", file=sys.stderr)
        return 1

    print(f"dossier: {json_path.relative_to(REPO).as_posix()}")
    print(f"report:  {report_path.relative_to(REPO).as_posix()}")
    print(f"verifier status: {dossier['verification'].get('row_status')}")
    print(f"findings: {len(dossier['findings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
