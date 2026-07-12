from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import mwccps2_prepare_24 as prepare


class PrepareBytesTests(unittest.TestCase):
    def test_applies_all_exact_preimages(self) -> None:
        source = bytes.fromhex("00112233445566778899aabbccddeeff")
        patches = (
            (2, bytes.fromhex("2233"), bytes.fromhex("aabb")),
            (10, bytes.fromhex("aabbcc"), bytes.fromhex("010203")),
        )
        with (
            mock.patch.object(prepare, "SOURCE_SIZE", len(source)),
            mock.patch.object(prepare, "PATCHES", patches),
            mock.patch.object(
                prepare,
                "_sha256",
                side_effect=[prepare.SOURCE_SHA256, prepare.PREPARED_SHA256],
            ),
        ):
            result = prepare.prepare_bytes(source)
        self.assertEqual(result, bytes.fromhex("0011aabb445566778899010203ddeeff"))

    def test_accepts_already_prepared_image_idempotently(self) -> None:
        data = b"prepared"
        with (
            mock.patch.object(prepare, "SOURCE_SIZE", len(data)),
            mock.patch.object(prepare, "_sha256", return_value=prepare.PREPARED_SHA256),
        ):
            self.assertIs(prepare.prepare_bytes(data), data)

    def test_rejects_unknown_hash(self) -> None:
        data = b"unknown"
        with (
            mock.patch.object(prepare, "SOURCE_SIZE", len(data)),
            mock.patch.object(prepare, "_sha256", return_value="0" * 64),
        ):
            with self.assertRaisesRegex(prepare.PreparationError, "unsupported compiler SHA-256"):
                prepare.prepare_bytes(data)

    def test_rejects_changed_patch_preimage(self) -> None:
        data = b"abcd"
        with (
            mock.patch.object(prepare, "SOURCE_SIZE", len(data)),
            mock.patch.object(prepare, "PATCHES", ((1, b"XX", b"YY"),)),
            mock.patch.object(prepare, "_sha256", return_value=prepare.SOURCE_SHA256),
        ):
            with self.assertRaisesRegex(prepare.PreparationError, "patch preimage mismatch"):
                prepare.prepare_bytes(data)


class PrepareFileTests(unittest.TestCase):
    def test_atomically_writes_prepared_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "mwccps2.exe"
            output = root / "prepared" / "mwccps2-debug.exe"
            source.write_bytes(b"source")
            (root / "LMGR326B.DLL").write_bytes(b"dll")
            with mock.patch.object(prepare, "prepare_bytes", return_value=b"prepared"):
                digest = prepare.prepare_file(source, output)
            self.assertEqual(digest, prepare.PREPARED_SHA256)
            self.assertEqual(output.read_bytes(), b"prepared")
            self.assertEqual((output.parent / "LMGR326B.DLL").read_bytes(), b"dll")
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])


class CheckedPolicyTests(unittest.TestCase):
    def test_v24_entry_matches_prepared_fingerprint(self) -> None:
        policy_path = (
            Path(__file__).resolve().parents[1]
            / "profiles"
            / "mwccps2-version-portability-policy-v1.json"
        )
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        v24 = next(build for build in policy["requested_builds"] if build["key"] == "v24")
        self.assertEqual(v24["binary"]["sha256"], prepare.PREPARED_SHA256)
        self.assertEqual(v24["binary"]["size"], prepare.SOURCE_SIZE)
        self.assertEqual(Path(v24["candidate_paths"][0]).name.casefold(), "mwccps2.exe")


if __name__ == "__main__":
    unittest.main()
