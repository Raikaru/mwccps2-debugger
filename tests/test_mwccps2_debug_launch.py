"""Regression coverage for the suspended MWCCPS2 launcher."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import mwccps2_debug_launch as launcher


class RecordingProcessApi:
    """Deterministic process-control boundary used by launcher command tests."""

    def __init__(self, events: list[tuple[object, ...]], *, exit_code: int = 0) -> None:
        self.events = events
        self.exit_code = exit_code
        self.process_info = SimpleNamespace(
            hProcess=101,
            hThread=202,
            dwProcessId=303,
            dwThreadId=404,
        )

    def launch_suspended(
        self, compiler: Path, compiler_args: list[str], cwd: Path
    ) -> SimpleNamespace:
        self.events.append(("launch", compiler, compiler_args, cwd))
        return self.process_info

    def resume(self, thread_handle: int) -> None:
        self.events.append(("resume", thread_handle))

    def wait(self, process_handle: int) -> int:
        self.events.append(("wait", process_handle))
        return self.exit_code

    def terminate(self, process_handle: int) -> None:
        self.events.append(("terminate", process_handle))

    def close(self, handle: int) -> None:
        self.events.append(("close", handle))


class LauncherArgumentRegressionTests(unittest.TestCase):
    def test_parses_compiler_arguments_after_separator(self) -> None:
        """Arguments after -- remain compiler arguments even when they begin with dashes."""
        args = launcher.parse_args(
            [
                "--compiler",
                "compiler.exe",
                "--cwd",
                "work",
                "--",
                "-c",
                "source file.c",
                "-DNAME=value",
            ]
        )

        self.assertEqual(args.compiler_args, ["-c", "source file.c", "-DNAME=value"])


class LauncherCommandRegressionTests(unittest.TestCase):
    def test_main_reports_missing_compiler_or_working_directory_before_windows_api(self) -> None:
        """Invalid paths produce user-facing exit 2 without requiring Windows process APIs."""
        cases = (
            ("missing-compiler", "compiler", False, True),
            ("missing-cwd", "working directory", True, False),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            for name, error_fragment, create_compiler, create_cwd in cases:
                with self.subTest(name=name):
                    compiler = directory / f"{name}.exe"
                    cwd = directory / f"{name}-cwd"
                    if create_compiler:
                        compiler.touch()
                    if create_cwd:
                        cwd.mkdir()
                    errors = io.StringIO()
                    with (
                        mock.patch.object(
                            launcher,
                            "WindowsProcessApi",
                            side_effect=AssertionError("path validation must precede Windows API setup"),
                        ),
                        contextlib.redirect_stdout(io.StringIO()),
                        contextlib.redirect_stderr(errors),
                    ):
                        exit_code = launcher.main(
                            ["--compiler", str(compiler), "--cwd", str(cwd)]
                        )

                    self.assertEqual(exit_code, 2)
                    self.assertIn(f"error: {error_fragment} not found:", errors.getvalue())

    def test_main_resumes_waits_and_returns_the_child_exit_code(self) -> None:
        """After confirmation, the launcher resumes once, waits, closes both handles, and propagates exit status."""
        events: list[tuple[object, ...]] = []
        api = RecordingProcessApi(events, exit_code=23)

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            compiler = directory / "compiler.exe"
            compiler.touch()
            with (
                mock.patch.object(launcher, "WindowsProcessApi", return_value=api),
                mock.patch("builtins.input", return_value=""),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = launcher.main(
                    ["--compiler", str(compiler), "--cwd", str(directory), "--", "-c", "input.c"]
                )

            self.assertEqual(exit_code, 23)
            self.assertEqual(
                events,
                [
                    ("launch", compiler.resolve(), ["-c", "input.c"], directory.resolve()),
                    ("resume", 202),
                    ("wait", 101),
                    ("close", 202),
                    ("close", 101),
                ],
            )

    def test_main_terminates_and_closes_handles_when_interrupted_before_resume(self) -> None:
        """An interrupted confirmation terminates the suspended child and releases both handles."""
        events: list[tuple[object, ...]] = []
        api = RecordingProcessApi(events)

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            compiler = directory / "compiler.exe"
            compiler.touch()
            errors = io.StringIO()
            with (
                mock.patch.object(launcher, "WindowsProcessApi", return_value=api),
                mock.patch("builtins.input", side_effect=KeyboardInterrupt),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(errors),
            ):
                exit_code = launcher.main(["--compiler", str(compiler), "--cwd", str(directory)])

            self.assertEqual(exit_code, 130)
            self.assertIn("terminating suspended compiler", errors.getvalue())
            self.assertEqual(
                events,
                [
                    ("launch", compiler.resolve(), [], directory.resolve()),
                    ("terminate", 101),
                    ("close", 202),
                    ("close", 101),
                ],
            )

    def test_main_maps_lifecycle_failures_to_error_exit_after_cleanup(self) -> None:
        """A lifecycle API failure is reported as exit 2 after terminating and closing the child."""
        events: list[tuple[object, ...]] = []
        api = RecordingProcessApi(events)

        def failing_resume(thread_handle: int) -> None:
            events.append(("resume", thread_handle))
            raise launcher.LaunchError("ResumeThread failed: access denied")

        api.resume = failing_resume  # type: ignore[method-assign]

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            compiler = directory / "compiler.exe"
            compiler.touch()
            errors = io.StringIO()
            with (
                mock.patch.object(launcher, "WindowsProcessApi", return_value=api),
                mock.patch("builtins.input", return_value=""),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(errors),
            ):
                exit_code = launcher.main(["--compiler", str(compiler), "--cwd", str(directory)])

            self.assertEqual(exit_code, 2)
            self.assertIn("error: ResumeThread failed: access denied", errors.getvalue())
            self.assertEqual(
                events,
                [
                    ("launch", compiler.resolve(), [], directory.resolve()),
                    ("resume", 202),
                    ("terminate", 101),
                    ("close", 202),
                    ("close", 101),
                ],
            )


class WindowsProcessApiRegressionTests(unittest.TestCase):
    def test_launch_suspended_passes_windows_quoted_compiler_command_line(self) -> None:
        """CreateProcessW receives a mutable command line that preserves spaced, quoted, and empty compiler arguments."""
        compiler = Path(r"C:\Compiler Suite\mwccps2.exe")
        cwd = Path(r"C:\Build Output")
        compiler_args = ["-DNAME=two words", r"C:\source dir\input.c", 'quote"inside', ""]
        api = object.__new__(launcher.WindowsProcessApi)
        observed: dict[str, object] = {}

        def create_process(*arguments: object) -> bool:
            observed["application_name"] = arguments[0]
            observed["command_line"] = arguments[1].value  # type: ignore[union-attr]
            observed["creation_flags"] = arguments[5]
            observed["current_directory"] = arguments[7]
            return True

        api.create_process = create_process
        process_info = api.launch_suspended(compiler, compiler_args, cwd)

        self.assertEqual(observed["application_name"], str(compiler))
        self.assertEqual(
            observed["command_line"],
            '"C:\\Compiler Suite\\mwccps2.exe" "-DNAME=two words" "C:\\source dir\\input.c" quote\\"inside ""',
        )
        self.assertEqual(observed["creation_flags"], launcher.CREATE_SUSPENDED)
        self.assertEqual(observed["current_directory"], str(cwd))


if __name__ == "__main__":
    unittest.main()
