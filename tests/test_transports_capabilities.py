"""Regression coverage for transport capability probing: Wine/Wibo detection, writing."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from typing import Any
import tempfile

from transports.capabilities import (
    CAPABILITY_SCHEMA_NAME,
    CAPABILITY_SCHEMA_VERSION,
    _tool_capability,
    probe_capabilities,
    canonical_json,
    write_capabilities,
)
from transports.process import TransportError


class ToolCapabilityTests(unittest.TestCase):
    """_tool_capability with mock which/run."""

    def test_tool_not_found_reports_unavailable(self) -> None:
        def which(name: str) -> None:
            return None

        result = _tool_capability(
            candidates=("mytool",),
            which=which,
            run=lambda *a, **kw: subprocess.CompletedProcess([], 0),
            timeout_seconds=10,
        )
        self.assertEqual(result["availability"], "unavailable")
        self.assertFalse(result["found"])

    def test_tool_found_and_smoke_ok(self) -> None:
        def which(name: str) -> str:
            return f"/usr/bin/{name}"

        def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, stdout="version 1.0", stderr="")

        result = _tool_capability(
            candidates=("mytool",),
            which=which,
            run=run,
            timeout_seconds=10,
        )
        self.assertEqual(result["availability"], "available")
        self.assertTrue(result["found"])
        self.assertEqual(result["evidence"]["smoke"]["exit_code"], 0)

    def test_smoke_nonzero_exit_marks_available_smoke_failed(self) -> None:
        def which(name: str) -> str:
            return f"/usr/bin/{name}"

        def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 1)

        result = _tool_capability(
            candidates=("mytool",),
            which=which,
            run=run,
            timeout_seconds=10,
        )
        self.assertEqual(result["availability"], "available_smoke_failed")

    def test_smoke_timeout_reported(self) -> None:
        def which(name: str) -> str:
            return f"/usr/bin/{name}"

        def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd="test", timeout=10)

        result = _tool_capability(
            candidates=("mytool",),
            which=which,
            run=run,
            timeout_seconds=10,
        )
        self.assertEqual(result["availability"], "available_smoke_timed_out")

    def test_oserror_during_smoke_reported(self) -> None:
        def which(name: str) -> str:
            return f"/usr/bin/{name}"

        def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            raise OSError("access denied")

        result = _tool_capability(
            candidates=("mytool",),
            which=which,
            run=run,
            timeout_seconds=10,
        )
        self.assertEqual(result["availability"], "available_smoke_failed")
        evidence = result["evidence"]["smoke"]
        self.assertEqual(evidence["outcome"], "could_not_start")

    def test_selected_command_in_evidence(self) -> None:
        def which(name: str) -> str | None:
            return name if name == "primary" else None

        result = _tool_capability(
            candidates=("primary", "secondary"),
            which=which,
            run=lambda *a, **kw: subprocess.CompletedProcess([], 0),
            timeout_seconds=10,
        )
        # which() returns just the name (not full path), so selected_command is that name
        self.assertIsNotNone(result["evidence"]["selected_command"])


class ProbeCapabilitiesTests(unittest.TestCase):
    """probe_capabilities overall shape."""

    def test_produces_capability_report(self) -> None:
        def which(name: str) -> None:
            return None  # no tools found

        result = probe_capabilities(which=which)
        self.assertIn("schema", result)
        self.assertEqual(result["schema"]["name"], CAPABILITY_SCHEMA_NAME)
        self.assertEqual(result["schema"]["version"], CAPABILITY_SCHEMA_VERSION)

    def test_contains_wibo_and_wine_keys(self) -> None:
        def which(name: str) -> None:
            return None

        result = probe_capabilities(which=which)
        caps = result["capabilities"]
        self.assertIn("wibo", caps)
        self.assertIn("wine", caps)

    def test_rejects_zero_timeout(self) -> None:
        with self.assertRaises(TransportError, msg="must be positive"):
            probe_capabilities(
                which=lambda n: None,
                smoke_timeout_seconds=0,
            )

    def test_rejects_negative_timeout(self) -> None:
        with self.assertRaises(TransportError, msg="must be positive"):
            probe_capabilities(
                which=lambda n: None,
                smoke_timeout_seconds=-1,
            )

    def test_has_evidence_key(self) -> None:
        result = probe_capabilities(which=lambda n: None)
        self.assertIn("evidence", result)


class CanonicalJsonTests(unittest.TestCase):
    """canonical_json deterministic formatting."""

    def test_sorts_keys(self) -> None:
        payload = {"z": 1, "a": 2}
        result = canonical_json(payload)
        self.assertIn('"a": 2', result)
        self.assertIn('"z": 1', result)

    def test_trailing_newline(self) -> None:
        result = canonical_json({"a": 1})
        self.assertTrue(result.endswith("\n"))

    def test_no_nan(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json({"a": float("nan")})

    def test_stable_output(self) -> None:
        self.assertEqual(
            canonical_json({"b": 2, "a": 1}),
            canonical_json({"a": 1, "b": 2}),
        )


class WriteCapabilitiesTests(unittest.TestCase):
    """write_capabilities atomic write."""

    def test_writes_valid_json(self) -> None:
        report = {
            "schema": {"name": CAPABILITY_SCHEMA_NAME, "version": CAPABILITY_SCHEMA_VERSION},
            "capabilities": {
                "wibo": {"availability": "unavailable"},
                "wine": {"availability": "unavailable"},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capabilities.json"
            write_capabilities(path, report)
            self.assertTrue(path.exists())
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["capabilities"]["wibo"]["availability"], "unavailable")

    def test_writes_deterministic_json(self) -> None:
        report = {
            "schema": {"name": CAPABILITY_SCHEMA_NAME, "version": CAPABILITY_SCHEMA_VERSION},
            "capabilities": {
                "wine": {"availability": "unavailable"},
                "wibo": {"availability": "unavailable"},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capabilities.json"
            write_capabilities(path, report)
            self.assertGreater(path.stat().st_size, 10)


if __name__ == "__main__":
    unittest.main()
