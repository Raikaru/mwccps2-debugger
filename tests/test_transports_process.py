"""Regression coverage for transport process boundary: formatting, run_checked."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
import sys

from transports.process import (
    TransportError,
    format_command,
    format_process_output,
    run_checked,
)


class FormatCommandTests(unittest.TestCase):
    """format_command Windows quoting."""

    def test_single_argument(self) -> None:
        result = format_command(["gdb"])
        self.assertEqual(result, "gdb")

    def test_multiple_arguments(self) -> None:
        result = format_command(["gdb", "--batch", "--nx"])
        self.assertIn("--batch", result)

    def test_argument_with_spaces(self) -> None:
        result = format_command(["mwccps2", "-o", "object file.o"])
        self.assertIn('"object file.o"', result)

    def test_empty_command(self) -> None:
        result = format_command([])
        self.assertEqual(result, "")


class FormatProcessOutputTests(unittest.TestCase):
    """format_process_output text formatting."""

    def test_stdout_only(self) -> None:
        cp = subprocess.CompletedProcess([], 0, stdout="hello\nworld", stderr="")
        result = format_process_output(cp)
        self.assertIn("hello", result)
        self.assertIn("world", result)

    def test_stderr_only(self) -> None:
        cp = subprocess.CompletedProcess([], 0, stdout="", stderr="error msg")
        result = format_process_output(cp)
        self.assertIn("error msg", result)

    def test_no_output(self) -> None:
        cp = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        result = format_process_output(cp)
        self.assertEqual(result, "(no process output)")

    def test_removes_trailing_newline(self) -> None:
        cp = subprocess.CompletedProcess([], 0, stdout="hello\n\n", stderr="")
        result = format_process_output(cp)
        self.assertNotIn("hello\n\n", result)


class RunCheckedValidationTests(unittest.TestCase):
    """run_checked input validation without process launch."""

    def test_rejects_empty_command(self) -> None:
        with self.assertRaises(TransportError):
            run_checked([], Path("."), 10, "empty command")

    def test_rejects_all_empty_string(self) -> None:
        with self.assertRaises(TransportError):
            run_checked([""], Path("."), 10, "empty executable")

    def test_rejects_zero_timeout(self) -> None:
        with self.assertRaises(TransportError):
            run_checked(["echo"], Path("."), 0, "zero timeout")

    def test_rejects_negative_timeout(self) -> None:
        with self.assertRaises(TransportError):
            run_checked(["echo"], Path("."), -1, "negative timeout")

    def test_rejects_nonexistent_executable(self) -> None:
        with self.assertRaises(TransportError):
            run_checked(
                ["/nonexistent/bin/tool_xyzzy"],
                Path("."),
                10,
                "nonexistent tool",
            )


if __name__ == "__main__":
    unittest.main()
