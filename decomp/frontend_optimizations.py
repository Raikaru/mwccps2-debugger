"""Deterministic, evidence-bounded model of three b210 frontend reducer behaviors.

This model intentionally describes only outcomes observed at the first available
post-frontend boundary (``codegen_entry``).  It identifies the responsible
optimizer pipeline and trace-backed helpers, but never assigns a rewrite to a
subpass without decoded frontend-IR evidence.
"""

from __future__ import annotations

import json
from typing import Any, Mapping


PREDICTION_SCHEMA_NAME = "mwccps2-frontend-optimization-prediction"
PREDICTION_SCHEMA_VERSION = 1
COMPILER_PROFILE = "mwcps2-3.0.1b210-060308"
COMPILER_SHA256 = "286548490e2e902cfef21dcf39cd5af23766731585d90dea747f8781eadcafd7"


class FrontendOptimizationModelError(ValueError):
    """Raised when a requested reducer or checked-in variant is unsupported."""


def _address(value: int) -> str:
    return f"0x{value:08x}"


def _canonical_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    """Copy JSON-shaped evidence with stable key ordering and no shared state."""

    return json.loads(json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


def _pipeline_owner() -> dict[str, str]:
    return {
        "address": _address(0x004D13A0),
        "evidence": "IrOptimizer.c assertion plus the IRO_* trace-labeled call sequence in the b210 decompilation.",
        "name": "IRO_OptimizeFunction",
    }


def _observed_helper(address: int, name: str, evidence: str) -> dict[str, str]:
    return {
        "address": _address(address),
        "attribution": "executed_or_trace_backed_not_individually_causal",
        "evidence": evidence,
        "name": name,
    }


_U16_HELPERS = (
    _observed_helper(
        0x0057D900,
        "IRO_CopyAndConstantPropagation",
        "The O2 trace calls it and emits IRO_CopyAndConstantPropagation afterward; its decompilation discovers propagatable assignments.",
    ),
    _observed_helper(
        0x005A3300,
        "IRO_ConstantFolding",
        "The O2 trace calls it and emits IRO_ConstantFolding afterward; its decompilation visits every IR node in DAT_00635a5c.",
    ),
)

_BOOLEAN_HELPERS = (
    _observed_helper(
        0x005A28D0,
        "IRO_SimplifyConditionals",
        "The driver emits IRO_SimplifyConditionals after the call; the helper iterates flow blocks and rebuilds flow only after a reported change.",
    ),
    _observed_helper(
        0x005A2580,
        "IRO_SimplifyIfThenElse",
        "The driver emits IRO_SimplifyIfThenElse after the call; the helper recognizes a two-successor conditional shape and can nop a qualifying if.",
    ),
    _observed_helper(
        0x005AE640,
        "IRO_RegenerateExpressions",
        "The driver emits IRO_RegenerateExpressions after the call; the helper dispatches logical, conditional, and conditional-assignment rebuild helpers when enabled.",
    ),
)


def _pipeline(*helpers: Mapping[str, str]) -> dict[str, Any]:
    return {
        "helpers": [dict(helper) for helper in helpers],
        "owner": _pipeline_owner(),
        "scope": "completed frontend pipeline before the first observable PCode stage",
    }


_COMMON_EVIDENCE = {
    "compiler": {
        "name": COMPILER_PROFILE,
        "sha256": COMPILER_SHA256,
    },
    "first_observable_stage": "codegen_entry",
    "normalization": "Deterministic PCode text is compared after snapshot-local heap identity normalization.",
}


# The source-variant order follows each schema-v1 experiment manifest.  Outcome
# predicates describe source/IR facts, while evidence records what b210 preserved
# or eliminated by codegen_entry.
_PREDICTIONS: dict[str, dict[str, dict[str, Any]]] = {
    "u16_remask": {
        "single_mask": {
            "evidence": {
                "direct_vs_instrumented_object": {
                    "object_sha256": "53eb9d4ac8412b40bde52367739ae295f7ebd7bb9d55b2c4fc1ba77cc4a8b052",
                    "snapshot_matches_direct": True,
                },
                "pcode_sha256": "042a5ac2cf05ae0fb182b93a9e91597b16306769448471eba03da28ea0288810",
                "source": "experiments/u16_remask/single_mask.c",
            },
            "outcome": {
                "action": "keep",
                "layout": "one surviving 16-bit zero extension followed by shift-left, shift-right, and or",
                "relation_to_baseline": "baseline",
            },
            "predicate": {
                "kind": "initial_u16_narrowing",
                "must_hold": [
                    "operation is value & 0x0000ffff",
                    "the result is reused by the rotate-like expression",
                ],
                "rewrite": "no_reapplied_mask_exists",
            },
            "pipeline": _pipeline(*_U16_HELPERS),
        },
        "redundant_remask": {
            "evidence": {
                "direct_vs_instrumented_object": {
                    "object_sha256": "53eb9d4ac8412b40bde52367739ae295f7ebd7bb9d55b2c4fc1ba77cc4a8b052",
                    "snapshot_matches_direct": True,
                },
                "pcode_sha256": "042a5ac2cf05ae0fb182b93a9e91597b16306769448471eba03da28ea0288810",
                "source": "experiments/u16_remask/redundant_remask.c",
            },
            "outcome": {
                "action": "eliminate",
                "layout": "the same one-extension shift-left, shift-right, and or layout as single_mask",
                "relation_to_baseline": "same_deterministic_pcode_and_object",
            },
            "predicate": {
                "kind": "reapplied_u16_mask",
                "must_hold": [
                    "operation is narrowed_value & 0x0000ffff",
                    "narrowed_value is already known zero-extended from 16 bits",
                    "the repeated mask has no other observable use",
                ],
                "rewrite": "eliminate_each_reapplied_mask",
            },
            "pipeline": _pipeline(*_U16_HELPERS),
        },
    },
    "repeated_sign_extension": {
        "short_parameter": {
            "evidence": {
                "direct_vs_instrumented_object": {
                    "object_sha256": "1d4d62228e72d06ad1957a8d5243c33585cee80fc2dfa758559c92f66f632991",
                    "snapshot_matches_direct": True,
                },
                "pcode": {
                    "caller_sign_extensions": 3,
                    "helper_sign_extensions": 1,
                },
                "source": "experiments/repeated_sign_extension/short_parameter.c",
            },
            "outcome": {
                "action": "keep",
                "layout": "signed-16 formal places one sign extension at each of three caller argument edges",
                "relation_to_baseline": "baseline",
            },
            "predicate": {
                "kind": "signed16_formal_argument_lowering",
                "must_hold": [
                    "callee formal type is signed 16-bit",
                    "each call argument is the original int narrowed to signed 16-bit",
                    "the call edge must present the signed-16 formal value",
                ],
                "rewrite": "retain_sign_extension_at_each_call_edge",
            },
            "pipeline": _pipeline(),
        },
        "explicit_cast": {
            "evidence": {
                "direct_vs_instrumented_object": {
                    "object_sha256": "3921f724c6bceaf207f72cf12f3194c7701ceaf9d6d1d74e19998dc0bbcd762e",
                    "snapshot_matches_direct": True,
                },
                "pcode": {
                    "caller_sign_extensions": 0,
                    "helper_sign_extensions": 2,
                },
                "source": "experiments/repeated_sign_extension/explicit_cast.c",
            },
            "outcome": {
                "action": "keep",
                "layout": "int formal leaves three caller edges unextended and retains the signed-16 conversion in the helper body",
                "relation_to_baseline": "different_deterministic_pcode_and_object",
            },
            "predicate": {
                "kind": "signed16_cast_in_helper_body",
                "must_hold": [
                    "callee formal type is int",
                    "callee body explicitly converts the formal to signed 16-bit",
                    "the caller passes its int argument without a signed-16 formal requirement",
                ],
                "rewrite": "retain_conversion_in_helper_body",
            },
            "pipeline": _pipeline(),
        },
    },
    "boolean_block_order": {
        "logical_and_expression": {
            "evidence": {
                "direct_vs_instrumented_object": {
                    "object_sha256": "7399063f409ffbc07cec7b13a9fe70cd6ed8cd7242f44be4e5b69fdafe6cd756",
                    "snapshot_matches_direct": True,
                },
                "pcode_sha256": "5675c0a39afbf62f494bfb82aaba619de058c08b68b78d20a52c7a27c3b6870c",
                "source": "experiments/boolean_block_order/logical_and_expression.c",
            },
            "outcome": {
                "action": "layout",
                "layout": "direct && materializes a branch-to-false block followed by a true materialization block",
                "relation_to_baseline": "baseline",
            },
            "predicate": {
                "kind": "direct_boolean_materialization",
                "must_hold": ["return expression is left && right"],
                "rewrite": "preserve_direct_short_circuit_cfg_shape",
            },
            "pipeline": _pipeline(*_BOOLEAN_HELPERS),
        },
        "early_returns": {
            "evidence": {
                "direct_vs_instrumented_object": {
                    "object_sha256": "384cb83c922336e8e7af714697e599a14e21de0fbe70891bfb53af6abac0eef7",
                    "snapshot_matches_direct": True,
                },
                "pcode_sha256": "e71bfe6b995cf454804828fd39581c8223d76cd1df3394391c535d5187d733eb",
                "source": "experiments/boolean_block_order/early_returns.c",
            },
            "outcome": {
                "action": "layout",
                "layout": "two explicit false-return tests retain a distinct short-circuit CFG and boolean-normalization sequence",
                "relation_to_baseline": "different_deterministic_pcode_and_object",
            },
            "predicate": {
                "kind": "sequential_early_false_returns",
                "must_hold": [
                    "first if returns zero when left is false",
                    "second if returns zero when right is false",
                    "final return is one",
                ],
                "rewrite": "preserve_early_return_cfg_shape",
            },
            "pipeline": _pipeline(*_BOOLEAN_HELPERS),
        },
        "result_local": {
            "evidence": {
                "direct_vs_instrumented_object": {
                    "object_sha256": "24aff0c89dfa6644bed8cc8e3904bc1fd91d4c9cfc545ad642a1969870544cfa",
                    "snapshot_matches_direct": True,
                },
                "pcode_sha256": "a8f53f749f9ef078e88624370682b3e4724734dde42c5c3a220cf03a5a28977c",
                "source": "experiments/boolean_block_order/result_local.c",
            },
            "outcome": {
                "action": "layout",
                "layout": "a result-local assignment retains a temporary boolean materialization and its distinct result block",
                "relation_to_baseline": "different_deterministic_pcode_and_object",
            },
            "predicate": {
                "kind": "conditional_result_local_assignment",
                "must_hold": [
                    "a local result is assigned one in the true arm",
                    "the local result is assigned zero in the false arm",
                    "the local is returned after the conditional",
                ],
                "rewrite": "preserve_result_local_cfg_shape",
            },
            "pipeline": _pipeline(*_BOOLEAN_HELPERS),
        },
        "inverted_condition": {
            "evidence": {
                "direct_vs_instrumented_object": {
                    "object_sha256": "db264ab1bcfab1f333adfd2843f45d5aafe1f47eb7922512335a253754bd97ae",
                    "snapshot_matches_direct": True,
                },
                "pcode_sha256": "ff69c67824918789716ffb2f4d6793aa360747957272f8b12114128bbde70345",
                "source": "experiments/boolean_block_order/inverted_condition.c",
            },
            "outcome": {
                "action": "layout",
                "layout": "an inverted false condition retains forward false branches, a true materialization, and a separate false block",
                "relation_to_baseline": "different_deterministic_pcode_and_object",
            },
            "predicate": {
                "kind": "inverted_short_circuit_false_return",
                "must_hold": [
                    "condition is !(left && right)",
                    "the conditional return is zero",
                    "the final return is one",
                ],
                "rewrite": "preserve_inverted_condition_cfg_shape",
            },
            "pipeline": _pipeline(*_BOOLEAN_HELPERS),
        },
    },
}


_VARIANT_ORDER = {
    "u16_remask": ("single_mask", "redundant_remask"),
    "repeated_sign_extension": ("short_parameter", "explicit_cast"),
    "boolean_block_order": (
        "logical_and_expression",
        "early_returns",
        "result_local",
        "inverted_condition",
    ),
}


def predict_variant(reducer: str, variant: str) -> dict[str, Any]:
    """Return the evidence-bounded prediction for one checked-in source variant."""

    if not isinstance(reducer, str) or not isinstance(variant, str):
        raise FrontendOptimizationModelError("reducer and variant must be strings")
    try:
        prediction = _PREDICTIONS[reducer][variant]
    except KeyError as error:
        available = ", ".join(_VARIANT_ORDER.get(reducer, ()))
        if reducer not in _PREDICTIONS:
            raise FrontendOptimizationModelError(f"unknown reducer {reducer!r}") from error
        raise FrontendOptimizationModelError(
            f"unknown variant {variant!r} for {reducer}; expected one of: {available}"
        ) from error
    return _canonical_copy(
        {
            "evidence": {**_COMMON_EVIDENCE, **prediction["evidence"]},
            "outcome": prediction["outcome"],
            "pipeline": prediction["pipeline"],
            "predicate": prediction["predicate"],
            "reducer": reducer,
            "schema": {"name": PREDICTION_SCHEMA_NAME, "version": PREDICTION_SCHEMA_VERSION},
            "variant": variant,
        }
    )


def predict_checked_in_variants() -> list[dict[str, Any]]:
    """Predict every manifest variant in deterministic reducer and source order."""

    return [
        predict_variant(reducer, variant)
        for reducer in ("u16_remask", "repeated_sign_extension", "boolean_block_order")
        for variant in _VARIANT_ORDER[reducer]
    ]


def canonical_prediction_json(reducer: str, variant: str) -> str:
    """Serialize a prediction as deterministic schema-v1 JSON without host metadata."""

    return json.dumps(
        predict_variant(reducer, variant), ensure_ascii=True, indent=2, sort_keys=True
    ) + "\n"
