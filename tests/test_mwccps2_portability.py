"""Regression coverage for portability: policy loading, fingerprint validation, anchor discovery."""

from __future__ import annotations

import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from typing import Any

import mwccps2_portability as portability

from mwccps2_portability import (
    PortabilityError,
    _policy_path,
    _validate_binary_spec,
    _validate_anchor_signature,
    load_policy,
    _resolved_path_string,
    _hex32,
    _parse_hex32,
    _require_string,
    _require_int,
    _require_mapping,
    _require_list,
    _canonical_json,
    _digest_json,
    _matches_binary_spec,
    BUILD_PROFILE_SCHEMA_NAME,
    DIRECT_CAPTURE_SCHEMA_NAME,
    SCHEMA_VERSION,
)


class HexConversionsTests(unittest.TestCase):
    """_hex32 and _parse_hex32."""

    def test_hex32_zero_padded(self) -> None:
        self.assertEqual(_hex32(0x1), "0x00000001")

    def test_hex32_full(self) -> None:
        self.assertEqual(_hex32(0xFFFFFFFF), "0xffffffff")

    def test_hex32_masks(self) -> None:
        self.assertEqual(_hex32(0x1FFFFFFFF), "0xffffffff")

    def test_parse_hex32_valid(self) -> None:
        self.assertEqual(_parse_hex32("0x00001234", "test"), 0x1234)

    def test_parse_hex32_rejects_bad_string(self) -> None:
        with self.assertRaises(PortabilityError):
            _parse_hex32("not-hex", "test")

    def test_parse_hex32_rejects_overflow(self) -> None:
        with self.assertRaises(PortabilityError):
            _parse_hex32("0x100000000", "test")


class PolicyPathTests(unittest.TestCase):
    def test_absolute_path_windows(self) -> None:
        # Use a path that _is_absolute_path_string recognizes on Windows
        result = _policy_path("C:/tools/gdb.exe")
        self.assertEqual(result, Path("C:/tools/gdb.exe"))

    def test_relative_path_uses_runner_dir(self) -> None:
        result = _policy_path("relative/path")
        self.assertIsInstance(result, Path)
        # Should be RUNNER_DIRECTORY / "relative/path"
        runner = Path(__file__).resolve().parent.parent
        self.assertEqual(result, runner / "relative/path")


class ValidateBinarySpecTests(unittest.TestCase):
    def test_accepts_valid_spec(self) -> None:
        spec = {
            "sha256": "a" * 64,
            "size": 12345,
            "pe_timestamp": "0x539b4a3c",
            "image_base": "0x00400000",
        }
        result = _validate_binary_spec(spec, "test")
        self.assertEqual(result["sha256"], "a" * 64)
        self.assertEqual(result["pe_timestamp"], "0x539b4a3c")

    def test_rejects_extra_field(self) -> None:
        spec = {
            "sha256": "a" * 64,
            "size": 12345,
            "pe_timestamp": "0x539b4a3c",
            "image_base": "0x00400000",
            "extra": "bad",
        }
        with self.assertRaises(PortabilityError):
            _validate_binary_spec(spec, "test")

    def test_rejects_short_sha256(self) -> None:
        with self.assertRaises(PortabilityError):
            _validate_binary_spec(
                {"sha256": "abc", "size": 1, "pe_timestamp": "0x0", "image_base": "0x0"},
                "test",
            )

    def test_rejects_sha256_with_uppercase(self) -> None:
        with self.assertRaises(PortabilityError):
            _validate_binary_spec(
                {"sha256": "A" * 64, "size": 1, "pe_timestamp": "0x0", "image_base": "0x0"},
                "test",
            )

    def test_rejects_zero_size(self) -> None:
        with self.assertRaises(PortabilityError):
            _validate_binary_spec(
                {"sha256": "a" * 64, "size": 0, "pe_timestamp": "0x0", "image_base": "0x0"},
                "test",
            )


class ValidateAnchorSignatureTests(unittest.TestCase):
    def test_accepts_valid_signature(self) -> None:
        sig = {
            "required": [
                {"category": "string_anchor", "text": "PCode.c", "address": "0x005e6131"},
                {"category": "string_anchor", "text": "Scheduler.c", "address": "0x005e90c1"},
            ]
        }
        result = _validate_anchor_signature(sig, "test")
        self.assertEqual(len(result["required"]), 2)

    def test_rejects_extra_key_in_signature(self) -> None:
        with self.assertRaises(PortabilityError):
            _validate_anchor_signature({"required": [], "extra": "bad"}, "test")

    def test_rejects_empty_required(self) -> None:
        with self.assertRaises(PortabilityError):
            _validate_anchor_signature({"required": []}, "test")

    def test_rejects_missing_category(self) -> None:
        with self.assertRaises(PortabilityError):
            _validate_anchor_signature(
                {"required": [{"text": "PCode.c", "address": "0x0"}]}, "test",
            )

    def test_rejects_duplicate_pair(self) -> None:
        with self.assertRaises(PortabilityError, msg="repeats"):
            _validate_anchor_signature(
                {
                    "required": [
                        {"category": "a", "text": "x", "address": "0x1"},
                        {"category": "a", "text": "x", "address": "0x2"},
                    ]
                },
                "test",
            )

    def test_accepts_absolute_operand_site(self) -> None:
        sig = {
            "required": [
                {"category": "code_anchor", "text": "PCode.c", "address": "0x005e6131",
                 "absolute_operand_site": "0x005e6131"},
            ]
        }
        result = _validate_anchor_signature(sig, "test")
        self.assertIn("absolute_operand_site", result["required"][0])

    def test_sorts_by_category_then_text(self) -> None:
        sig = {
            "required": [
                {"category": "z", "text": "b", "address": "0x00000003"},
                {"category": "a", "text": "x", "address": "0x00000001"},
                {"category": "a", "text": "y", "address": "0x00000002"},
            ]
        }
        result = _validate_anchor_signature(sig, "test")
        texts = [item["text"] for item in result["required"]]
        self.assertEqual(texts, ["x", "y", "b"])


class LoadPolicyTests(unittest.TestCase):
    """load_policy with minimal valid policy."""

    def test_rejects_nonexistent_file(self) -> None:
        with self.assertRaises(PortabilityError):
            load_policy(Path("/nonexistent_policy_xyzzy.json"))

    def test_rejects_invalid_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not-json")
        try:
            with self.assertRaises(PortabilityError):
                load_policy(Path(f.name))
        finally:
            Path(f.name).unlink(missing_ok=True)

    def test_rejects_wrong_schema(self) -> None:
        policy = _valid_policy_dict()
        policy["schema"] = {"name": "wrong", "version": 2}
        with self.assertRaises(PortabilityError):
            _write_and_load_policy(policy)

    def test_rejects_empty_requested_builds(self) -> None:
        policy = _valid_policy_dict()
        policy["requested_builds"] = []
        with self.assertRaises(PortabilityError):
            _write_and_load_policy(policy)

    def test_rejects_duplicate_build_key(self) -> None:
        policy = _valid_policy_dict()
        policy["requested_builds"].append(policy["requested_builds"][0])
        with self.assertRaises(PortabilityError):
            _write_and_load_policy(policy)

    def test_deduplicates_candidate_paths(self) -> None:
        policy = _valid_policy_dict()
        policy["requested_builds"][0]["candidate_paths"] = ["path1", "path1"]
        result = _write_and_load_policy(policy)
        build = result["requested_builds"][0]
        self.assertEqual(len(build["candidate_paths"]), 1)


class MatchesBinarySpecTests(unittest.TestCase):
    """_matches_binary_spec field matching."""

    def test_exact_match(self) -> None:
        fp = {"sha256": "a" * 64, "size": 100, "pe": {"timestamp": "0x00001234", "image_base": "0x00400000"}}
        spec = {"sha256": "a" * 64, "size": 100, "pe_timestamp": "0x00001234", "image_base": "0x00400000"}
        self.assertTrue(_matches_binary_spec(fp, spec))

    def test_sha256_mismatch(self) -> None:
        fp = {"sha256": "a" * 64, "size": 100, "pe": {"timestamp": "0x00001234", "image_base": "0x00400000"}}
        spec = {"sha256": "b" * 64, "size": 100, "pe_timestamp": "0x00001234", "image_base": "0x00400000"}
        self.assertFalse(_matches_binary_spec(fp, spec))

    def test_size_mismatch(self) -> None:
        fp = {"sha256": "a" * 64, "size": 100, "pe": {"timestamp": "0x00001234", "image_base": "0x00400000"}}
        spec = {"sha256": "a" * 64, "size": 99, "pe_timestamp": "0x00001234", "image_base": "0x00400000"}
        self.assertFalse(_matches_binary_spec(fp, spec))



class CanonicalJsonTests(unittest.TestCase):
    def test_sorts_keys(self) -> None:
        result = _canonical_json({"z": 1, "a": 2})
        self.assertIn('"a": 2', result)

    def test_deterministic(self) -> None:
        self.assertEqual(
            _canonical_json({"b": 2, "a": 1}),
            _canonical_json({"a": 1, "b": 2}),
        )


class DigestJsonTests(unittest.TestCase):
    def test_deterministic_digest(self) -> None:
        self.assertEqual(
            _digest_json({"a": 1}),
            _digest_json({"a": 1}),
        )



class PublicPathSanitizationTests(unittest.TestCase):
    """Public portability artifacts must not reveal host-specific path prefixes."""

    def test_public_path_string_redacts_workspace_and_home_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-user-987"
            workspace = root / "workspace"
            home = root / "home"
            workspace_path = workspace / "toolchains" / "mwccps2.exe"
            home_path = home / ".local" / "mwccps2.exe"
            outside_path = root / "outside" / "mwccps2.exe"
            for path in (workspace_path, home_path, outside_path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

            with (
                mock.patch.object(portability, "WORKSPACE_DIRECTORY", workspace.resolve()),
                mock.patch.object(portability, "HOME_DIRECTORY", home.resolve()),
            ):
                self.assertEqual(
                    portability._public_path_string(workspace_path),
                    "<workspace>/toolchains/mwccps2.exe",
                )
                self.assertEqual(
                    portability._public_path_string(home_path),
                    "<home>/.local/mwccps2.exe",
                )
                self.assertEqual(
                    portability._public_path_string(outside_path),
                    outside_path.resolve().as_posix(),
                )

    def test_public_artifact_removes_runtime_fields_recursively(self) -> None:
        artifact = {
            "public": "kept",
            "_runtime": {"selected_path": "C:/private-user-987/mwccps2.exe"},
            "nested": {
                "public": "still kept",
                "_private": "removed",
                "items": [{"name": "kept"}, {"_cache": "removed", "value": 2}],
            },
        }

        self.assertEqual(
            portability._public_artifact(artifact),
            {
                "public": "kept",
                "nested": {
                    "public": "still kept",
                    "items": [{"name": "kept"}, {"value": 2}],
                },
            },
        )

    def test_discovery_and_write_redact_private_paths_but_preserve_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-user-987"
            workspace = root / "workspace"
            compiler = workspace / "toolchains" / "mwccps2.exe"
            compiler.parent.mkdir(parents=True)
            compiler.touch()
            binary = {
                "sha256": "a" * 64,
                "size": 1,
                "pe_timestamp": "0x00000001",
                "image_base": "0x00400000",
            }
            fingerprint = {
                "sha256": "a" * 64,
                "size": 1,
                "pe": {"timestamp": "0x00000001", "image_base": "0x00400000"},
            }
            policy = {
                "capture_schema": {"name": DIRECT_CAPTURE_SCHEMA_NAME, "version": SCHEMA_VERSION},
                "search_roots": [],
                "requested_builds": [
                    {
                        "key": "test",
                        "release": "mwcps2-test",
                        "candidate_paths": [str(compiler)],
                        "binary": binary,
                    }
                ],
            }

            with (
                mock.patch.object(portability, "WORKSPACE_DIRECTORY", workspace.resolve()),
                mock.patch.object(portability, "_iter_compiler_paths", return_value=([compiler], [])),
                mock.patch.object(portability, "_normalized_probe", return_value=fingerprint),
            ):
                profiles, evidence = portability.discover_builds(policy, [], workspace)

            self.assertEqual(evidence, [])
            profile = profiles[0]
            self.assertEqual(
                profile["availability"]["selected_path"],
                "<workspace>/toolchains/mwccps2.exe",
            )
            self.assertEqual(profile["_runtime"]["selected_path"], compiler.resolve().as_posix())

            output = root / "public-profiles"
            written = portability.write_profiles(output, profiles, {"_runtime": {"private": "removed"}})
            serialized = "\n".join(path.read_text(encoding="utf-8") for path in written)
            self.assertNotIn("private-user-987", serialized)
            self.assertNotIn(compiler.resolve().as_posix(), serialized)
            self.assertIn("<workspace>/toolchains/mwccps2.exe", serialized)
            self.assertNotIn('"_runtime"', serialized)

    def test_corpus_uses_runtime_selected_path_not_public_label(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler = root / "private-user-987" / "mwccps2.exe"
            source = root / "case.c"
            compiler.parent.mkdir(parents=True)
            compiler.touch()
            source.touch()
            profile = {
                "build": {"key": "test"},
                "_runtime": {"selected_path": compiler.resolve().as_posix()},
            }
            manifest = {
                "name": "case",
                "question": "does runtime survive serialization boundary?",
                "compiler_flags": ["-proc", "gekko"],
                "variants": [
                    {
                        "name": "baseline",
                        "source": "case.c",
                        "source_path": source,
                        "function": "case",
                        "intent": "test",
                    }
                ],
            }

            with (
                mock.patch.object(portability, "_load_experiment_manifest", return_value=manifest),
                mock.patch.object(
                    portability,
                    "_run_direct_compile",
                    return_value={"object_sha256": "b" * 64, "object_size": 1},
                ) as run_compile,
            ):
                result = portability._run_corpus_for_build(
                    profile, [root / "experiment"], root / "work", 5
                )

            self.assertEqual(result["status"], "completed")
            self.assertEqual(run_compile.call_args.args[0], compiler.resolve())
class ExperimentDirectoryTests(unittest.TestCase):
    def test_ignores_empty_work_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "valid"
            valid.mkdir()
            (valid / "experiment.json").write_text("{}", encoding="utf-8")
            (root / "empty-worktree").mkdir()
            self.assertEqual(portability._experiment_directories(root), [valid])

    def test_rejects_nonempty_directory_without_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = root / "malformed"
            malformed.mkdir()
            (malformed / "source.c").write_text("int f(void) { return 0; }", encoding="utf-8")
            with self.assertRaisesRegex(PortabilityError, "lacks experiment.json"):
                portability._experiment_directories(root)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_policy_dict() -> dict:
    return {
        "schema": {"name": "mwccps2-version-portability-policy", "version": 1},
        "capture_schema": {
            "name": DIRECT_CAPTURE_SCHEMA_NAME,
            "version": SCHEMA_VERSION,
            "stage_order": [
                "codegen_entry",
                "before_scheduling",
                "after_scheduling",
                "before_register_allocation",
                "after_register_allocation",
            ],
        },
        "search_roots": ["C:/tools"],
        "requested_builds": [
            {
                "key": "b210",
                "release": "3.0.1b210-060308",
                "candidate_paths": ["C:/mwccps2.exe"],
                "binary": {
                    "sha256": "a" * 64,
                    "size": 12345,
                    "pe_timestamp": "0x539b4a3c",
                    "image_base": "0x00400000",
                },
            }
        ],
    }


def _write_and_load_policy(policy: dict) -> dict:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(policy, f, indent=2)
    try:
        return load_policy(Path(f.name))
    finally:
        Path(f.name).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
