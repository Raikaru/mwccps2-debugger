#!/usr/bin/env python3
"""Cluster recurring Persona 3 MWCC residuals from a fresh verifier baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from adapters.p3 import P3AdapterError, _load_map, _load_verifier
from explain.analysis import build_analysis


REPO = Path(__file__).resolve().parent


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--p3-root", required=True, help="Persona3-FES-Decompilation checkout")
    parser.add_argument("--output", required=True, help="fresh directory under this repository's build/")
    parser.add_argument("--baseline", help="existing full verifier JSON; default runs a fresh baseline")
    parser.add_argument("--max-window", type=int, default=512)
    parser.add_argument("--max-diff", type=int, default=40)
    parser.add_argument("--limit", type=int, default=0, help="maximum selected functions; zero means all")
    parser.add_argument("--timeout", type=int, default=1800, help="fresh verifier timeout in seconds")
    return parser


def _fresh_output(path: str) -> Path:
    output = Path(path).resolve()
    build = (REPO / "build").resolve()
    try:
        output.relative_to(build)
    except ValueError as exc:
        raise ValueError("output must be a child of this repository's build directory") from exc
    if output.exists():
        raise ValueError("output directory already exists; choose a fresh path")
    output.mkdir(parents=True)
    return output


def _load_baseline(root: Path, output: Path, requested: str | None, timeout: int) -> tuple[dict[str, Any], str]:
    if requested:
        path = Path(requested).resolve()
    else:
        path = output / "verifier-baseline.json"
        try:
            completed = subprocess.run(
                [sys.executable, "tools/verify.py", "--json", str(path)],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("could not complete the fresh P3 verifier baseline") from exc
        if not path.is_file():
            detail = completed.stdout.strip().splitlines()
            raise ValueError(f"P3 verifier did not write a baseline: {detail[-1] if detail else 'no output'}")
    try:
        raw = path.read_bytes()
        report = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("verifier baseline is unreadable or malformed") from exc
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ValueError("verifier baseline has an invalid schema")
    return report, hashlib.sha256(raw).hexdigest()


def _selected_rows(report: dict[str, Any], max_window: int, max_diff: int, limit: int) -> list[dict[str, Any]]:
    rows = []
    for row in report["results"]:
        if not isinstance(row, dict) or row.get("status") not in {"NONMATCHING", "MISMATCH"}:
            continue
        window, difference = row.get("window"), row.get("normalized_diff")
        if not isinstance(window, int) or not isinstance(difference, int):
            continue
        if window <= 0 or window > max_window or difference < 0 or difference > max_diff:
            continue
        if not all(isinstance(row.get(key), str) for key in ("file", "name", "addr")):
            continue
        rows.append({**row, "file": row["file"].replace("\\", "/")})
    rows.sort(key=lambda row: (row["normalized_diff"], row["window"], row["file"], row["addr"], row["name"]))
    return rows[:limit] if limit else rows


def _analyze(root: Path, rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    verifier = _load_verifier(root)
    function_map = _load_map(root)
    try:
        config = verifier.load_config()
        retail = verifier.RetailElf(config["retail_elf"], expect_sha1=function_map.get("sha1"))
    except (OSError, ValueError, KeyError, SystemExit) as exc:
        raise P3AdapterError("could not initialize P3 compilation for the family sweep") from exc

    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_file[row["file"]].append(row)
    functions: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="mwccps2_family_sweep_") as temporary:
        object_root = Path(temporary)
        for source_name in sorted(by_file):
            source = (root / source_name).resolve()
            try:
                source.relative_to(root)
            except ValueError:
                errors.append({"source": source_name, "error": "source_outside_root"})
                continue
            obj, log = verifier.compile_object(source, config, object_root)
            if obj is None:
                errors.append({"source": source_name, "error": "compile_error", "detail": log.strip()[-400:]})
                continue
            for row in by_file[source_name]:
                try:
                    candidate, relocations = obj.function(row["name"])
                    address = int(row["addr"], 16)
                    retail_bytes = retail.bytes_at(address, row["window"])
                    dossier = build_analysis(
                        project={"adapter": "persona3-fes-family-sweep"},
                        function={
                            "name": row["name"], "address": row["addr"].lower(),
                            "source": source_name, "marker_line": row.get("line"),
                            "window": row["window"], "nonmatching_marker": row["status"] == "NONMATCHING",
                            "stub_marker": False,
                        },
                        verification=row,
                        candidate_bytes=candidate,
                        retail_bytes=retail_bytes,
                        relocations=relocations,
                        symbols={},
                    )
                except (KeyError, ValueError, TypeError) as exc:
                    errors.append({"source": source_name, "name": row["name"], "address": row["addr"], "error": type(exc).__name__})
                    continue
                pairs: list[str] = []
                for alignment in dossier["alignment"]:
                    ci, ri = alignment["candidate_index"], alignment["retail_index"]
                    if ci is None or ri is None or alignment["relation"] in {"exact", "relocation"}:
                        continue
                    left = dossier["candidate"]["instructions"][ci]["mnemonic"]
                    right = dossier["retail"]["instructions"][ri]["mnemonic"]
                    pairs.append(f"{left}/{right}")
                functions.append({
                    "source": source_name,
                    "name": row["name"],
                    "address": row["addr"].lower(),
                    "window": row["window"],
                    "normalized_diff": row["normalized_diff"],
                    "finding_ids": [finding["id"] for finding in dossier["findings"]],
                    "mnemonic_pairs": sorted(set(pairs)),
                })
    functions.sort(key=lambda item: (item["source"], item["address"], item["name"]))
    return functions, errors


def _clusters(functions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for field, output_name in (("finding_ids", "findings"), ("mnemonic_pairs", "mnemonic_pairs")):
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for function in functions:
            identity = {key: function[key] for key in ("source", "name", "address")}
            for value in function[field]:
                grouped[value].append(identity)
        result[output_name] = [
            {"id": identifier, "function_count": len(members), "functions": members}
            for identifier, members in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))
        ]
    return result


def _render(summary: dict[str, Any]) -> str:
    lines = [
        "MWCCPS2 whole-decomp residual families",
        "========================================",
        "",
        f"Selected functions: {summary['selection']['selected_functions']}",
        f"Analyzed functions: {summary['selection']['analyzed_functions']}",
        f"Compilation/extraction errors: {len(summary['errors'])}",
        "",
        "Finding families",
    ]
    for family in summary["clusters"]["findings"]:
        lines.append(f"  {family['function_count']:5d}  {family['id']}")
    lines.extend(["", "Mnemonic-pair families"])
    for family in summary["clusters"]["mnemonic_pairs"][:50]:
        lines.append(f"  {family['function_count']:5d}  {family['id']}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if min(args.max_window, args.max_diff, args.timeout) <= 0 or args.limit < 0:
        print("mwccps2-family-sweep: numeric bounds must be positive (limit may be zero)", file=sys.stderr)
        return 2
    output: Path | None = None
    try:
        root = Path(args.p3_root).resolve()
        if not root.is_dir():
            raise ValueError("P3 root must be an existing directory")
        output = _fresh_output(args.output)
        report, baseline_sha256 = _load_baseline(root, output, args.baseline, args.timeout)
        rows = _selected_rows(report, args.max_window, args.max_diff, args.limit)
        functions, errors = _analyze(root, rows)
        summary = {
            "schema": {"name": "mwccps2-residual-families", "version": 1},
            "baseline_sha256": baseline_sha256,
            "selection": {
                "statuses": ["MISMATCH", "NONMATCHING"],
                "max_window": args.max_window,
                "max_diff": args.max_diff,
                "limit": args.limit,
                "selected_functions": len(rows),
                "analyzed_functions": len(functions),
            },
            "clusters": _clusters(functions),
            "functions": functions,
            "errors": errors,
        }
        json_path = output / "residual-families-v1.json"
        text_path = output / "residual-families.txt"
        json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        text_path.write_text(_render(summary), encoding="utf-8", newline="\n")
    except (OSError, UnicodeError, ValueError, P3AdapterError) as exc:
        if output is not None:
            shutil.rmtree(output, ignore_errors=True)
        print(f"mwccps2-family-sweep: {exc}", file=sys.stderr)
        return 1
    print(f"families: {json_path.relative_to(REPO).as_posix()}")
    print(f"report:   {text_path.relative_to(REPO).as_posix()}")
    print(f"analyzed: {len(functions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
