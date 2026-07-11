"""Immutable records for a deterministic function-explanation dossier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final


SCHEMA_NAME: Final[str] = "mwccps2-function-dossier"
SCHEMA_VERSION: Final[int] = 1


@dataclass(frozen=True, slots=True)
class Instruction:
    offset: int
    address: int
    word: int
    mnemonic: str
    operands: str
    kind: str
    target: int | None = None
    relocation: str | None = None

    @property
    def text(self) -> str:
        return self.mnemonic if not self.operands else f"{self.mnemonic} {self.operands}"

    def evidence(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "offset": self.offset,
            "address": f"{self.address:08x}",
            "word": f"{self.word:08x}",
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "kind": self.kind,
        }
        if self.target is not None:
            result["target"] = f"{self.target:08x}"
        if self.relocation is not None:
            result["relocation"] = self.relocation
        return result


@dataclass(frozen=True, slots=True)
class BasicBlock:
    identifier: str
    start_offset: int
    end_offset: int
    instruction_indexes: tuple[int, ...]
    successors: tuple[int, ...]

    def evidence(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "instruction_indexes": list(self.instruction_indexes),
            "successors": list(self.successors),
        }


@dataclass(frozen=True, slots=True)
class AlignmentRow:
    candidate_index: int | None
    retail_index: int | None
    relation: str

    def evidence(self) -> dict[str, Any]:
        return {
            "candidate_index": self.candidate_index,
            "retail_index": self.retail_index,
            "relation": self.relation,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    identifier: str
    title: str
    confidence: str
    basis: str
    evidence_rows: tuple[int, ...]
    recommendation: str

    def evidence(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "title": self.title,
            "confidence": self.confidence,
            "basis": self.basis,
            "evidence_rows": list(self.evidence_rows),
            "recommendation": self.recommendation,
        }
