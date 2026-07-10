"""Evidence-bounded b210 instruction-selection model.

This module models only decisions observed in the exact MWCCPS2 3.0.1b210
compiler identified by ``PROFILE_NAME``.  It intentionally stops at PCode
selection: evaluation order, operand-slot normalization, and immediate/address
folding happen here, before scheduling and register allocation.

The model is deliberately not a general C lowering implementation.  Unknown
selector paths remain explicit rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


SELECTOR_MODEL_SCHEMA_NAME = "mwccps2-b210-instruction-selection"
SELECTOR_MODEL_SCHEMA_VERSION = 1
PROFILE_NAME = "mwcps2-3.0.1b210-060308"
PROFILE_SHA256 = "286548490e2e902cfef21dcf39cd5af23766731585d90dea747f8781eadcafd7"

DISPATCH_TABLE_ADDRESS = "0x005e8960"

# The b210 registry IDs below are not ISA encodings.  They are the PCode IDs
# passed to the backend's PCode builder/emitter.
OPCODES: dict[str, tuple[int, str]] = {
    "addu": (0x0004, "addu"),
    "add64_observed": (0x0079, "opcode_0079"),
    # 0x0079 is observed in the 64-bit branch; its registry mnemonic was not recovered here.
    "mul.s": (0x00B5, "mul.s"),
    "slt": (0x00D4, "slt"),
    "sltu": (0x00D7, "sltu"),
    "sge": (0x048F, "sge"),
    "sgeu": (0x0491, "sgeu"),
    "sgt": (0x0493, "sgt"),
    "sgtu": (0x0495, "sgtu"),
    "sle": (0x0497, "sle"),
    "sleu": (0x0499, "sleu"),
    "seq": (0x048D, "seq"),
    "sne": (0x049D, "sne"),
    "sext": (0x048B, "sext"),
    "zext": (0x048C, "zext"),
}


class SelectorModelError(ValueError):
    """Raised when a requested prediction is outside recovered b210 evidence."""


@dataclass(frozen=True)
class HandlerEvidence:
    """One exact selector dispatch target or selector-side helper."""

    address: str
    name: str
    role: str
    evidence: tuple[str, ...]
    dispatch_indices: tuple[str, ...] = ()
    dispatch_slots: tuple[str, ...] = ()


# Kept in ascending execution-address order.  All addresses are VAs in the
# profile above and all dispatch values are literal table indexes/slots.
HANDLERS: tuple[HandlerEvidence, ...] = (
    HandlerEvidence(
        address="0x00486d10",
        name="BuildExtensionPCode",
        role="Builds sext/zext PCode or copies a 64-bit-width selection result.",
        evidence=(
            "Rejects every opcode except 0x048b and 0x048c.",
            "For a non-64-bit width, calls the PCode builder with source result and bit width.",
        ),
    ),
    HandlerEvidence(
        address="0x0048d860",
        name="BuildThreeOperandPCode",
        role="Builds a structured three-operand PCode record without changing argument order.",
        evidence=(
            "Allocates PCode with the supplied opcode and operand count 3.",
            "Writes param_3 to operand slot 1 and param_4 to operand slot 2 before finalization.",
        ),
    ),
    HandlerEvidence(
        address="0x0049da90",
        name="SelectComparisonExpression",
        role="Selects integer comparison PCode and normalizes a left tag-3 descriptor.",
        evidence=(
            "Dispatches AST codes 0x13..0x18 to slt/sgt/sle/sge/seq/sne families.",
            "Swaps descriptor results and remaps ordered relations when the left tag is 3.",
        ),
        dispatch_indices=("0x13", "0x14", "0x15", "0x16", "0x17", "0x18"),
        dispatch_slots=(
            "0x005e89ac",
            "0x005e89b0",
            "0x005e89b4",
            "0x005e89b8",
            "0x005e89bc",
            "0x005e89c0",
        ),
    ),
    HandlerEvidence(
        address="0x0049eaa0",
        name="ComparisonSelectorDispatchThunk",
        role="Six comparison-table entries thunk to SelectComparisonExpression at 0x0049da90.",
        evidence=(
            "The table entries for indices 0x13 through 0x18 contain this exact interior code pointer.",
            "The thunk calls the comparison-dispatch body at 0x0049da91.",
        ),
        dispatch_indices=("0x13", "0x14", "0x15", "0x16", "0x17", "0x18"),
    ),
    HandlerEvidence(
        address="0x0049eab0",
        name="EmitFloatingBinaryPCode",
        role="Selects both operands, preserves their output slots, and emits floating binary PCode.",
        evidence=(
            "Calls SelectBinaryOperandsForPCode before emission.",
            "The 32-bit floating multiplication path receives PCode 0x00b5 from SelectMultiplyExpression.",
        ),
    ),
    HandlerEvidence(
        address="0x0049fcd0",
        name="SelectConversionExpression",
        role="Selects conversion PCode, including the recovered sext/zext branches.",
        evidence=(
            "Source expression is at AST +0x20; source type is child +0x0c and destination type is AST +0x0c.",
            "Calls BuildExtensionPCode with sext/zext and an explicit bit-width operand.",
        ),
        dispatch_indices=("0x32",),
        dispatch_slots=("0x005e8a28",),
    ),
    HandlerEvidence(
        address="0x004a3610",
        name="SelectAddOrAddressExpression",
        role="Selects integer/float addition and folds recovered address-plus-offset descriptors.",
        evidence=(
            "Direct 32-bit addu fallback emits PCode 0x0004 at 0x004a3e1a.",
            "Tag-2/tag-3 descriptor shapes can be swapped, folded, or emitted through the structured builder.",
        ),
        dispatch_indices=("0x0f",),
        dispatch_slots=("0x005e899c",),
    ),
    HandlerEvidence(
        address="0x004a66a0",
        name="SelectMultiplyExpression",
        role="Selects multiplication, including the recovered 32-bit floating mul.s path.",
        evidence=(
            "AST children are read at +0x20 (left) and +0x24 (right).",
            "32-bit floating result type selects PCode 0x00b5 through EmitFloatingBinaryPCode.",
        ),
        dispatch_indices=("0x09",),
        dispatch_slots=("0x005e8984",),
    ),
    HandlerEvidence(
        address="0x004a9250",
        name="SelectBinaryOperandsForPCode",
        role="Evaluates two child selectors by priority while retaining logical left/right result slots.",
        evidence=(
            "Evaluates right first iff left[+1] + 2 < right[+1].",
            "Writes the left child to left_result and right child to right_result regardless of evaluation order.",
        ),
    ),
)
MODEL_RULES: tuple[dict[str, tuple[str, ...] | str], ...] = (
    {
        "name": "binary_operand_evaluation",
        "handler_addresses": ("0x004a9250",),
        "evidence": (
            "The right child is selected first exactly when left[+1] + 2 < right[+1].",
            "The helper retains separate logical left/right output descriptors.",
        ),
    },
    {
        "name": "addu_address_normalization",
        "handler_addresses": ("0x004a3610", "0x0048d860", "0x0047caf0"),
        "evidence": (
            "Tag 2 is moved from the right descriptor position to the left before the address-aware branch.",
            "A left tag-3 descriptor is moved to the right; tag-2 plus tag-3 folds an offset instead of emitting addu.",
            "The direct fallback at 0x004a3e1a emits opcode 0x0004 with canonical right then canonical left operands.",
        ),
    },
    {
        "name": "mul_s_slot_order",
        "handler_addresses": ("0x004a66a0", "0x0049eab0", "0x004a9250"),
        "evidence": (
            "The observed 32-bit floating multiplication branch passes opcode 0x00b5 to the floating binary emitter.",
            "No multiplication-specific descriptor swap was observed after binary operand selection.",
        ),
    },
    {
        "name": "comparison_relation_remapping",
        "handler_addresses": ("0x0049da90", "0x004a9250", "0x0048d860"),
        "evidence": (
            "When the left descriptor tag is 3, the selector swaps descriptors and maps < to > plus <= to >= (and the reverse mappings).",
            "The integer PCode map is slt/sltu, sgt/sgtu, sle/sleu, sge/sgeu, seq, and sne.",
        ),
    },
    {
        "name": "integer_extension",
        "handler_addresses": ("0x0049fcd0", "0x00486d10"),
        "evidence": (
            "Ordinary widening selects sext or zext from source signedness and passes source_width * 8.",
            "Narrowing to a four-byte destination forces sext(..., 32); other recovered branches select by destination signedness.",
        ),
    },
)



@dataclass(frozen=True)
class OperandDescriptor:
    """Recovered subset of the selector's 0x2c-byte operand-result descriptor.

    ``tag`` is retained as a numeric evidence value: tag 2 participates in the
    addition selector's address-aware branch and tag 3 participates in its
    inline-offset/comparison-normalization branch.  Their full source-level
    enum names have not been recovered.  ``priority`` is AST byte +1 as used
    by SelectBinaryOperandsForPCode; it affects evaluation order only.
    """

    tag: int
    identity: str
    offset: int = 0
    priority: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.tag, int) or not 0 <= self.tag <= 0xFF:
            raise SelectorModelError("operand tag must be an unsigned byte")
        if not isinstance(self.identity, str) or not self.identity:
            raise SelectorModelError("operand identity must be a non-empty string")
        if not isinstance(self.offset, int):
            raise SelectorModelError("operand offset must be an integer")
        if not isinstance(self.priority, int) or not 0 <= self.priority <= 0xFF:
            raise SelectorModelError("operand priority must be an unsigned byte")


@dataclass(frozen=True)
class Selection:
    """PCode selection result for the bounded rules implemented here.

    ``source_order`` is the PCode operand-slot order, not evaluation order.
    ``opcode_id`` and ``mnemonic`` are ``None`` only where recovered selection
    folds/preserves a descriptor or deliberately marks an opaque special path.
    """

    opcode_id: int | None
    mnemonic: str | None
    source_order: tuple[str, ...]
    evaluation_order: tuple[str, ...]
    emission_route: str
    explanation: str
    folded_offset: int | None = None
    bit_width: int | None = None
    relation: str | None = None


def _opcode(name: str) -> tuple[int, str]:
    return OPCODES[name]


def _evaluation_order(left: OperandDescriptor, right: OperandDescriptor) -> tuple[str, str]:
    """Model the helper's priority evaluation without altering its output slots."""

    if left.priority + 2 < right.priority:
        return (right.identity, left.identity)
    return (left.identity, right.identity)


def _selection(
    opcode_name: str | None,
    source_order: tuple[str, ...],
    evaluation_order: tuple[str, ...],
    emission_route: str,
    explanation: str,
    *,
    folded_offset: int | None = None,
    bit_width: int | None = None,
    relation: str | None = None,
) -> Selection:
    if opcode_name is None:
        opcode_id: int | None = None
        mnemonic: str | None = None
    else:
        opcode_id, mnemonic = _opcode(opcode_name)
    return Selection(
        opcode_id=opcode_id,
        mnemonic=mnemonic,
        source_order=source_order,
        evaluation_order=evaluation_order,
        emission_route=emission_route,
        explanation=explanation,
        folded_offset=folded_offset,
        bit_width=bit_width,
        relation=relation,
    )


def select_addu(
    left: OperandDescriptor,
    right: OperandDescriptor,
    *,
    result_type_width: int = 4,
    left_source_id: int = 0,
    source_id_threshold: int = 0,
    source_id_sentinel: int = -1,
    is_observed_int64_class: bool = False,
) -> Selection:
    """Predict the recovered non-floating addition/address selection decision.

    ``left_source_id`` names the selector-source ID carried by the *post-
    normalization* tag-2 descriptor.  It is relevant only in the tag-2 direct
    fallback versus structured-builder split.  The threshold and sentinel have
    exact control-flow evidence but no recovered source-level names.
    """

    if not isinstance(result_type_width, int) or result_type_width <= 0:
        raise SelectorModelError("result_type_width must be a positive byte count")
    if not all(
        isinstance(value, int)
        for value in (left_source_id, source_id_threshold, source_id_sentinel)
    ):
        raise SelectorModelError("address source IDs must be integers")

    evaluation_order = _evaluation_order(left, right)
    canonical_left, canonical_right = left, right
    normalization: list[str] = []

    # These whole-descriptor exchanges occur in SelectAddOrAddressExpression,
    # not in the priority helper and not in later allocation/scheduling stages.
    if canonical_right.tag == 2:
        canonical_left, canonical_right = canonical_right, canonical_left
        normalization.append("moved right tag-2 descriptor to the left")
    if canonical_left.tag == 3:
        canonical_left, canonical_right = canonical_right, canonical_left
        normalization.append("moved tag-3 descriptor to the right")

    canonical_order = (canonical_left.identity, canonical_right.identity)
    prefix = "; ".join(normalization) or "kept descriptor order"

    if canonical_left.tag == 2:
        if canonical_right.tag == 2:
            raise SelectorModelError("b210 addition selector asserts on two tag-2 descriptors")
        if canonical_right.tag == 3:
            folded_offset = canonical_left.offset + canonical_right.offset
            return _selection(
                None,
                (canonical_left.identity,),
                evaluation_order,
                "address-offset-fold",
                f"{prefix}; tag-2 address result absorbs tag-3 inline offset, so no addu PCode is emitted",
                folded_offset=folded_offset,
            )

        structured = (
            left_source_id < source_id_threshold
            and left_source_id != source_id_sentinel
        )
        if structured:
            return _selection(
                "addu",
                canonical_order,
                evaluation_order,
                "structured-three-operand-builder",
                f"{prefix}; tag-2 source ID selects BuildThreeOperandPCode, which preserves canonical operand slots",
            )
        return _selection(
            "addu",
            (canonical_right.identity, canonical_left.identity),
            evaluation_order,
            "direct-addu-fallback",
            f"{prefix}; direct fallback at 0x004a3e1a emits addu D, right, left",
        )

    if canonical_right.tag == 3:
        return _selection(
            None,
            canonical_order,
            evaluation_order,
            "inline-right-address-helper",
            f"{prefix}; tag-3 remains on the right for the selector's address/inline helper path",
        )

    opcode_name = "add64_observed" if is_observed_int64_class and result_type_width == 8 else "addu"
    return _selection(
        opcode_name,
        canonical_order,
        evaluation_order,
        "structured-three-operand-builder",
        f"{prefix}; ordinary values retain logical operand slots through BuildThreeOperandPCode",
    )


def select_mul_s(left: OperandDescriptor, right: OperandDescriptor) -> Selection:
    """Predict the confirmed single-precision floating multiplication path.

    This model covers the reducer's 32-bit floating path only.  It does not
    invent rules for the alternate floating PCode 0x00b4.
    """

    return _selection(
        "mul.s",
        (left.identity, right.identity),
        _evaluation_order(left, right),
        "floating-binary-emitter",
        "SelectMultiplyExpression passes 0x00b5 to EmitFloatingBinaryPCode; the priority helper may change evaluation order but never swaps S/T output slots",
    )


Relation = Literal["<", ">", "<=", ">=", "==", "!="]
_RELATION_REMAP: dict[str, str] = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}
_SIGNED_COMPARISON_OPCODES: dict[str, str] = {
    "<": "slt",
    ">": "sgt",
    "<=": "sle",
    ">=": "sge",
    "==": "seq",
    "!=": "sne",
}
_UNSIGNED_COMPARISON_OPCODES: dict[str, str] = {
    "<": "sltu",
    ">": "sgtu",
    "<=": "sleu",
    ">=": "sgeu",
    "==": "seq",
    "!=": "sne",
}


def select_comparison(
    relation: Relation,
    left: OperandDescriptor,
    right: OperandDescriptor,
    *,
    left_unsigned: bool = False,
    right_unsigned: bool = False,
) -> Selection:
    """Predict recovered integer-comparison PCode and relation normalization."""

    if relation not in _RELATION_REMAP:
        raise SelectorModelError(f"unsupported comparison relation: {relation!r}")
    if not isinstance(left_unsigned, bool) or not isinstance(right_unsigned, bool):
        raise SelectorModelError("comparison signedness inputs must be booleans")

    evaluation_order = _evaluation_order(left, right)
    emitted_relation = relation
    source_order = (left.identity, right.identity)
    normalized = "kept descriptor order"
    if left.tag == 3:
        source_order = (right.identity, left.identity)
        emitted_relation = _RELATION_REMAP[relation]
        normalized = f"swapped left tag-3 descriptor and remapped {relation} to {emitted_relation}"

    opcode_map = _UNSIGNED_COMPARISON_OPCODES if (left_unsigned or right_unsigned) else _SIGNED_COMPARISON_OPCODES
    opcode_name = opcode_map[emitted_relation]
    signedness = "unsigned" if opcode_map is _UNSIGNED_COMPARISON_OPCODES else "signed"
    return _selection(
        opcode_name,
        source_order,
        evaluation_order,
        "structured-three-operand-builder",
        f"{normalized}; {signedness} integer comparison selects {opcode_name}",
        relation=emitted_relation,
    )


def select_extension(
    source_width: int,
    destination_width: int,
    source_unsigned: bool,
    destination_unsigned: bool,
    *,
    excluded_nested_shape: bool = False,
    destination_type_code: int | None = None,
) -> Selection:
    """Predict the recovered sext/zext branch and explicit width operand.

    Widths are byte widths.  The nested-AST exclusion is exposed because the
    observed selector bypasses the ordinary widening rule for a precise but
    not source-named AST shape (kinds 4 or 0x1e..0x28 with an inner byte 0x33).
    """

    if not all(isinstance(width, int) and width > 0 for width in (source_width, destination_width)):
        raise SelectorModelError("extension widths must be positive byte counts")
    if not isinstance(source_unsigned, bool) or not isinstance(destination_unsigned, bool):
        raise SelectorModelError("extension signedness inputs must be booleans")
    if destination_type_code is not None and not isinstance(destination_type_code, int):
        raise SelectorModelError("destination_type_code must be an integer or None")

    evaluation_order = ("source",)
    if excluded_nested_shape and source_width < destination_width:
        return _selection(
            None,
            ("source",),
            evaluation_order,
            "nested-ast-exclusion",
            "ordinary widening is bypassed by the observed nested-AST exclusion; its alternative lowering is intentionally not guessed",
        )

    if source_width < destination_width:
        opcode_name = "zext" if source_unsigned else "sext"
        return _selection(
            opcode_name,
            ("source",),
            evaluation_order,
            "extension-pcode-builder",
            f"widening selects {opcode_name} from source signedness and passes {source_width * 8} bits",
            bit_width=source_width * 8,
        )

    if destination_width < source_width:
        if destination_width == 4:
            return _selection(
                "sext",
                ("source",),
                evaluation_order,
                "extension-pcode-builder",
                "narrowing to a four-byte destination forces sext with a 32-bit width operand",
                bit_width=32,
            )
        opcode_name = "zext" if destination_unsigned else "sext"
        return _selection(
            opcode_name,
            ("source",),
            evaluation_order,
            "extension-pcode-builder",
            f"narrowing selects {opcode_name} from destination signedness and passes {destination_width * 8} bits",
            bit_width=destination_width * 8,
        )

    if source_unsigned == destination_unsigned:
        return _selection(
            None,
            ("source",),
            evaluation_order,
            "no-extension",
            "equal width with identical signedness emits no sext/zext PCode",
        )
    if destination_width == 4 or (destination_width == 8 and destination_type_code in {1, 3}):
        return _selection(
            None,
            ("source",),
            evaluation_order,
            "equal-width-exception",
            "the recovered equal-width exception emits no sext/zext for this destination shape",
        )

    opcode_name = "zext" if destination_unsigned else "sext"
    return _selection(
        opcode_name,
        ("source",),
        evaluation_order,
        "extension-pcode-builder",
        f"equal-width signedness conversion selects {opcode_name} from destination signedness and passes {destination_width * 8} bits",
        bit_width=destination_width * 8,
    )


def _handler_manifest(entry: HandlerEvidence) -> dict[str, Any]:
    return {
        "address": entry.address,
        "dispatch_indices": list(entry.dispatch_indices),
        "dispatch_slots": list(entry.dispatch_slots),
        "evidence": list(entry.evidence),
        "name": entry.name,
        "role": entry.role,
    }


def model_manifest() -> dict[str, Any]:
    """Return deterministic schema-v1 JSON-compatible recovered selector evidence."""

    return {
        "schema_name": SELECTOR_MODEL_SCHEMA_NAME,
        "schema_version": SELECTOR_MODEL_SCHEMA_VERSION,
        "profile": {
            "name": PROFILE_NAME,
            "sha256": PROFILE_SHA256,
        },
        "dispatch_table": {
            "address": DISPATCH_TABLE_ADDRESS,
            "name": "InstructionSelectorDispatchTable",
        },
        "handlers": [_handler_manifest(entry) for entry in HANDLERS],
        "rules": [
            {
                "evidence": list(rule["evidence"]),
                "handler_addresses": list(rule["handler_addresses"]),
                "name": rule["name"],
            }
            for rule in MODEL_RULES
        ],
        "opcodes": [
            {"id": f"0x{opcode:04x}", "mnemonic": mnemonic}
            for opcode, mnemonic in sorted(OPCODES.values())
        ],
        "descriptor_tags": [
            {
                "tag": 2,
                "meaning": "address-aware selection descriptor category; source enum name unrecovered",
                "evidence": "SelectAddOrAddressExpression brings a right tag-2 descriptor left before address-aware selection.",
            },
            {
                "tag": 3,
                "meaning": "inline-offset/blob selection descriptor category; source enum name unrecovered",
                "evidence": "SelectAddOrAddressExpression retains tag 3 on the right; SelectComparisonExpression swaps a left tag-3 descriptor.",
            },
        ],
    }
