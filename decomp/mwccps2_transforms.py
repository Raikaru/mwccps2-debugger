"""Evidence-bounded MWCCPS2 source transformation catalog.

Catalog membership is evidence, not permission: every candidate remains subject to
source-local semantic guards and no result represents a retail-object match.
"""
from __future__ import annotations

from typing import Iterable
from pathlib import Path

from .c_ast import Node, TranslationUnit, lex_c, parse_c
from .source_transforms import (SemanticGuard, TransformApplication, TransformSpec,
    apply_applications, canonical_json, enumerate_applications, guarded_application)

CATALOG_SCHEMA_NAME = "mwccps2-source-transform-catalog"
CATALOG_SCHEMA_VERSION = 1
_PURE = SemanticGuard("pure-operands", "Both operands have no calls, assignments, increment/decrement, volatile access, macro expansion, or unknown evaluation effect.", "assumption_required")
_TYPE = SemanticGuard("known-type", "Exact operand types and signedness are known from independent source/type evidence.", "assumption_required")
_REPRO = "reproducible_by_b210"
_RESHAPE = "requires_frontend_or_source_reshaping"
_DISABLED = "not_reachable_under_b210"

_EVIDENCE = {
    "commutative_mul_s": ("experiments/commutative_mul_s/experiment.json", "invariant_times_fresh"),
    "compare_destination:reversed_greater_than": ("experiments/compare_destination/experiment.json", "reversed_greater_than"),
    "commutative_addu:array_index_base": ("experiments/commutative_addu/experiment.json", "array_index_base"),
    "repeated_sign_extension:explicit_cast": ("experiments/repeated_sign_extension/experiment.json", "explicit_cast"),
    "u16_remask:redundant_remask": ("experiments/u16_remask/experiment.json", "redundant_remask"),
    "boolean_block_order:inverted_condition": ("experiments/boolean_block_order/experiment.json", "inverted_condition"),
    "boolean_block_order:result_local": ("experiments/boolean_block_order/experiment.json", "result_local"),
}

def _spec(identifier: str, title: str, kinds: tuple[str, ...], risk: str, guards: tuple[SemanticGuard, ...], evidence_id: str, reachability: str, default: bool, operators: tuple[str, ...] = (), cfg: bool = False) -> TransformSpec:
    path, variant = _EVIDENCE[evidence_id]
    return TransformSpec(identifier, title, kinds, risk, guards, {"checked_in_reducer": {"path": path, "variant": variant}, "compiler_profile": "mwcps2-3.0.1b210-060308", "scope": "-O2 checked-in reducer evidence; no retail equality claim"}, reachability, default, operators, cfg)

CATALOG: tuple[TransformSpec, ...] = (
    _spec("commutative-operand-swap", "Swap commutative operands", ("additive", "multiplicative"), "medium", (_PURE, _TYPE), "commutative_mul_s", _REPRO, True, ("+", "*")),
    _spec("relational-reversal", "Reverse relational operands and direction", ("relational",), "medium", (_PURE, _TYPE), "compare_destination:reversed_greater_than", _DISABLED, False, ("<", ">", "<=", ">=")),
    _spec("array-subscript-swap", "Swap array subscript base and index", ("subscript",), "high", (_PURE, _TYPE), "commutative_addu:array_index_base", _DISABLED, False, ("[]",)),
    _spec("explicit-integer-cast", "Insert explicit integer cast", ("atom", "additive", "multiplicative", "relational"), "high", (_TYPE,), "repeated_sign_extension:explicit_cast", _REPRO, True),
    _spec("unsigned-mask-insert", "Insert redundant unsigned mask", ("atom", "additive", "multiplicative"), "high", (_TYPE,), "u16_remask:redundant_remask", _DISABLED, False),
    _spec("unsigned-mask-remove", "Remove redundant unsigned mask", ("bitwise_and",), "high", (_TYPE,), "u16_remask:redundant_remask", _DISABLED, False, ("&",)),
    _spec("condition-invert-branch-swap", "Invert condition and swap branches", ("if_else",), "high", (_PURE, _TYPE), "boolean_block_order:inverted_condition", _RESHAPE, True, ("!",), True),
    _spec("local-temporary-extraction", "Extract expression to local temporary", ("function_body", "additive", "multiplicative", "relational", "logical_and", "logical_or"), "high", (_PURE, _TYPE), "boolean_block_order:result_local", _RESHAPE, True, cfg=True),
)

def _validate_catalog() -> None:
    seen: set[str] = set()
    root = Path(__file__).resolve().parent.parent
    for spec in CATALOG:
        if not spec.id or spec.id in seen:
            raise ValueError("catalog transform IDs must be unique and nonempty")
        seen.add(spec.id)
        if spec.reachability == _DISABLED and spec.default_search:
            raise ValueError("not-reachable transforms must be disabled for search")
        reducer = spec.evidence.get("checked_in_reducer")
        if not isinstance(reducer, dict):
            raise ValueError("catalog evidence requires checked_in_reducer")
        path, variant = reducer.get("path"), reducer.get("variant")
        if not isinstance(path, str) or not path.startswith("experiments/"):
            raise ValueError("reducer evidence path must be repo-relative under experiments/")
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts or not (root / relative).is_file():
            raise ValueError("reducer evidence path must name a checked-in experiment file")
        if not isinstance(variant, str) or not variant:
            raise ValueError("reducer evidence variant must be nonempty")


_validate_catalog()
_BY_ID = {spec.id: spec for spec in CATALOG}

def catalog() -> tuple[TransformSpec, ...]: return CATALOG

def catalog_manifest() -> dict[str, object]:
    return {"schema": {"name": CATALOG_SCHEMA_NAME, "version": CATALOG_SCHEMA_VERSION}, "transforms": [spec.manifest() for spec in CATALOG]}

def canonical_catalog_json() -> str: return canonical_json(catalog_manifest()) + "\n"
def get_spec(spec_id: str) -> TransformSpec: return _BY_ID[spec_id]


def _children(unit: TranslationUnit, node: Node) -> tuple[Node, Node] | None:
    if len(node.children) != 2: return None
    try: return unit.node(node.children[0]), unit.node(node.children[1])
    except KeyError: return None

def _swap(unit: TranslationUnit, spec: TransformSpec, node: Node) -> TransformApplication:
    children = _children(unit, node)
    if children is None: return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="ambiguous expression children")
    left, right = children
    if spec.id == "relational-reversal":
        inverse = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(node.operator or "")
        if inverse is None: return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="unsupported relational operator")
        replacement = f"{unit.source[right.start:right.end]} {inverse} {unit.source[left.start:left.end]}"
    elif spec.id == "array-subscript-swap":
        replacement = f"{unit.source[right.start:right.end]}[{unit.source[left.start:left.end]}]"
    else:
        replacement = f"{unit.source[right.start:right.end]} {node.operator} {unit.source[left.start:left.end]}"
    return guarded_application(spec, unit, node.id, replacement, assumptions=("exact operand type and signedness are independently proven",))


def _invert_if_else(unit: TranslationUnit, spec: TransformSpec, node: Node) -> TransformApplication:
    # c_ast emits this node only for the unambiguous braced form. Retain each
    # branch byte-for-byte and exchange their brace-delimited spans.
    significant = [t for t in lex_c(unit.source[node.start:node.end]) if t.kind not in {"whitespace", "comment"}]
    opens: dict[int, int] = {}; stack: list[int] = []
    for i, token in enumerate(significant):
        if token.text in "({": stack.append(i)
        elif token.text in ")}":
            if not stack: return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="ambiguous conditional delimiters")
            opens[stack.pop()] = i
    if len(significant) < 7 or significant[0].text != "if" or significant[1].text != "(":
        return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="unsupported conditional structure")
    close_condition = opens.get(1)
    if close_condition is None or close_condition + 1 >= len(significant) or significant[close_condition + 1].text != "{":
        return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="unsupported conditional structure")
    then_open = close_condition + 1; then_close = opens.get(then_open)
    if then_close is None or then_close + 2 >= len(significant) or significant[then_close + 1].text != "else" or significant[then_close + 2].text != "{":
        return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="unsupported conditional structure")
    else_open = then_close + 2; else_close = opens.get(else_open)
    if else_close is None: return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="unsupported conditional structure")
    condition = unit.source[node.start + significant[1].end:node.start + significant[close_condition].start]
    then_branch = unit.source[node.start + significant[then_open].start:node.start + significant[then_close].end]
    else_branch = unit.source[node.start + significant[else_open].start:node.start + significant[else_close].end]
    replacement = f"if (!({condition})) {else_branch} else {then_branch}"
    return guarded_application(spec, unit, node.id, replacement, require_pure=False, assumptions=("condition has scalar truth semantics and all branch effects are independently proven",))


def _extract_return_temporary(unit: TranslationUnit, spec: TransformSpec, node: Node, integer_type: str | None) -> TransformApplication | None:
    if integer_type not in {"int", "unsigned int", "long", "unsigned long"}:
        return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="explicit local integer type is required")
    for body in unit.nodes:
        if body.kind != "function_body" or not (body.start < node.start and node.end < body.end):
            continue
        inner = unit.source[body.start + 1:body.end - 1].strip()
        if inner != f"return {unit.source[node.start:node.end]};":
            continue
        replacement = f"{{ {integer_type} extracted_value = {unit.source[node.start:node.end]}; return extracted_value; }}"
        return guarded_application(spec, unit, body.id, replacement, assumptions=("expression is pure, local lifetime is sufficient, and declared type is exact",))
    return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="requires a single-expression braced return body")


def _candidate(unit: TranslationUnit, spec: TransformSpec, node: Node, *, integer_type: str | None = None) -> TransformApplication | None:
    if spec.id == "commutative-operand-swap" and node.operator in {"+", "*"}:
        return _swap(unit, spec, node)
    if spec.id == "relational-reversal" and node.operator in {"<", ">", "<=", ">="}:
        return _swap(unit, spec, node)
    if spec.id == "array-subscript-swap" and node.kind == "subscript":
        return _swap(unit, spec, node)
    if spec.id == "condition-invert-branch-swap" and node.kind == "if_else":
        return _invert_if_else(unit, spec, node)
    if spec.id == "local-temporary-extraction":
        return _extract_return_temporary(unit, spec, node, integer_type)
    if spec.id == "explicit-integer-cast":
        if not integer_type:
            return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="explicit target integer type is required")
        if integer_type not in {"char", "short", "int", "long", "unsigned char", "unsigned short", "unsigned int", "unsigned long"}:
            return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="unsupported integer type")
        return guarded_application(spec, unit, node.id, f"({integer_type})({unit.source[node.start:node.end]})", require_pure=False, assumptions=("integer conversion preserves the intended value",))
    if spec.id == "unsigned-mask-insert":
        if integer_type not in {"unsigned short", "unsigned int"}:
            return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="proven unsigned 16-bit narrowing type is required")
        return guarded_application(spec, unit, node.id, f"({unit.source[node.start:node.end]} & 0xFFFFu)", assumptions=("mask is redundant at every observable use",))
    if spec.id == "unsigned-mask-remove" and node.operator == "&":
        children = _children(unit, node)
        if children is None:
            return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="ambiguous mask operands")
        left, right = children
        left_text = unit.source[left.start:left.end].lower().rstrip("ul")
        right_text = unit.source[right.start:right.end].lower().rstrip("ul")
        if left_text == "0xffff":
            replacement = unit.source[right.start:right.end]
        elif right_text == "0xffff":
            replacement = unit.source[left.start:left.end]
        else:
            return TransformApplication(spec.id, node.id, node.start, node.end, "", status="rejected", rejection="only exact 0xFFFFu masks are supported")
        return guarded_application(spec, unit, node.id, replacement, assumptions=("value is already narrowed to unsigned 16 bits at every observable use",))
    return None


def enumerate_candidates(unit: TranslationUnit | str, *, include_disabled: bool = False, integer_type: str | None = None) -> tuple[TransformApplication, ...]:
    if isinstance(unit, str): unit = parse_c(unit)
    found: list[TransformApplication] = []
    for spec in CATALOG:
        if not include_disabled and not spec.default_search: continue
        found.extend(enumerate_applications(unit, spec, lambda n, s=spec: _candidate(unit, s, n, integer_type=integer_type)))
    return tuple(sorted(found, key=lambda a: (a.start, a.end, a.spec_id, a.node_id)))


def apply_candidates(unit: TranslationUnit | str, applications: Iterable[TransformApplication], *, allow_assumptions: bool = False):
    if isinstance(unit, str): unit = parse_c(unit)
    return apply_applications(unit, applications, allow_assumptions=allow_assumptions)
