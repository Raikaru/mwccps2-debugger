"""Human-readable rendering for function dossier schema v1."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .model import SCHEMA_NAME, SCHEMA_VERSION


def _instruction_text(record: Mapping[str, Any] | None) -> str:
    if record is None:
        return "—"
    mnemonic = record.get("mnemonic", "?")
    operands = record.get("operands", "")
    return f"{mnemonic} {operands}".rstrip()


def render_report(dossier: Mapping[str, Any]) -> str:
    schema = dossier.get("schema")
    if schema != {"name": SCHEMA_NAME, "version": SCHEMA_VERSION}:
        raise ValueError("unsupported function dossier schema")
    function = dossier["function"]
    verification = dossier["verification"]
    artifacts = dossier["artifacts"]
    candidate = dossier["candidate"]["instructions"]
    retail = dossier["retail"]["instructions"]
    alignment = dossier["alignment"]

    lines = [
        f"MWCCPS2 function dossier: {function['name']}",
        "=" * (27 + len(function["name"])),
        "",
        "Identity",
        f"  address:          0x{function['address']}",
        f"  source:           {function['source']}:{function.get('marker_line', '?')}",
        f"  retail window:    {function['window']} bytes",
        f"  candidate size:   {artifacts['candidate_size']} bytes",
        "",
        "Authoritative verification",
        f"  status:           {verification.get('row_status') or verification.get('outcome')}",
        f"  certified MATCH:  {'yes' if verification.get('certified') else 'no'}",
        f"  normalized diff:  {verification.get('normalized_diff')}",
        f"  first byte diffs: {verification.get('first_diffs', [])}",
        "",
        "Observed control flow",
        f"  candidate blocks: {len(dossier['candidate']['blocks'])}",
        f"  retail blocks:    {len(dossier['retail']['blocks'])}",
        "",
        "Observed direct retail calls",
    ]
    calls = dossier.get("calls", [])
    if calls:
        for call in calls:
            suffix = f" {call['symbol']}" if call.get("symbol") else ""
            lines.append(f"  0x{call['address']}{suffix}")
    else:
        lines.append("  none")

    lines.extend(["", "Bounded findings"])
    for finding in dossier.get("findings", []):
        lines.extend([
            f"  [{finding['confidence']}] {finding['title']}",
            f"    evidence rows: {finding['evidence_rows']}",
            f"    next check: {finding['recommendation']}",
        ])

    differing = [
        (index, row) for index, row in enumerate(alignment)
        if row["relation"] not in {"exact", "relocation"}
    ]
    lines.extend(["", f"Differing alignment rows ({len(differing)})"])
    if not differing:
        lines.append("  none after relocation normalization")
    else:
        lines.append("  row   candidate                                      retail")
        for index, row in differing:
            candidate_record = candidate[row["candidate_index"]] if row["candidate_index"] is not None else None
            retail_record = retail[row["retail_index"]] if row["retail_index"] is not None else None
            left = _instruction_text(candidate_record)
            right = _instruction_text(retail_record)
            lines.append(f"  {index:04d}  {left:<45} {right}")

    lines.extend([
        "",
        "Trust boundary",
        "  MATCH authority: the Persona 3 verifier row only.",
        "  Findings are hypotheses derived from bytes, relocations, and CFG shape.",
        "  No retail AST, PCode, scheduler queue, or allocation graph is claimed.",
        "",
    ])
    return "\n".join(lines)
