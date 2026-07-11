#!/usr/bin/env python3
"""Build one deterministic, retail-aware Persona 3 function dossier."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

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
    parser.add_argument("--output", help="fresh directory under this repository's build/")
    parser.add_argument("--timeout", type=float, default=120.0, help="verifier timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.timeout <= 0:
        print("mwccps2-explain: --timeout must be positive", file=sys.stderr)
        return 2
    try:
        evidence = collect_p3_evidence(
            p3_root=args.p3_root,
            source=args.source,
            function_name=args.function,
            address=args.address,
            timeout_seconds=args.timeout,
        )
        dossier = build_analysis(
            project=evidence["project"],
            function=evidence["function"],
            verification=evidence["verification"],
            candidate_bytes=evidence["candidate_bytes"],
            retail_bytes=evidence["retail_bytes"],
            relocations=evidence["relocations"],
            symbols=evidence["symbols"],
        )
        output = _output_directory(args.output, args.function, evidence["function"]["address"])
        json_path = output / "function-dossier-v1.json"
        report_path = output / "function-dossier.txt"
        json_path.write_text(json.dumps(dossier, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        report_path.write_text(render_report(dossier), encoding="utf-8", newline="\n")
    except (P3AdapterError, OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        print(f"mwccps2-explain: {exc}", file=sys.stderr)
        return 1

    print(f"dossier: {json_path.relative_to(REPO).as_posix()}")
    print(f"report:  {report_path.relative_to(REPO).as_posix()}")
    print(f"verifier status: {dossier['verification'].get('row_status')}")
    print(f"findings: {len(dossier['findings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
