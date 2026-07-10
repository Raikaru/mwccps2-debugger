"""Regression coverage for GDB transport command construction and transport creation."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from transports.gdb import (
    GdbSnapshotRequest,
    TransportError,
    gdb_quote,
    gdb_path,
    build_gdb_command_lines,
    create_gdb_transport,
    WindowsGdbTransport,
    Retrowin32GdbTransport,
    WINDOWS_GDB_TRANSPORT,
    RETROWIN32_GDB_TRANSPORT,
)


class GdbQuoteTests(unittest.TestCase):
    """gdb_quote argument quoting."""

    def test_quotes_simple_string(self) -> None:
        self.assertEqual(gdb_quote("hello"), '"hello"')

    def test_escapes_backslash(self) -> None:
        self.assertEqual(gdb_quote("a\\b"), '"a\\\\b"')

    def test_escapes_double_quote(self) -> None:
        self.assertEqual(gdb_quote('a"b'), '"a\\"b"')

    def test_quotes_empty_string(self) -> None:
        self.assertEqual(gdb_quote(""), '""')

    def test_handles_spaces(self) -> None:
        self.assertEqual(gdb_quote("a b"), '"a b"')


class GdbPathTests(unittest.TestCase):
    """gdb_path POSIX normalization."""

    def test_returns_posix_style_path(self) -> None:
        path = Path(".") / "test" / "file.exe"
        result = gdb_path(path)
        # On Windows Path.resolve() adds drive letter but gdb_path uses as_posix()
        self.assertIn("/", result)
        self.assertNotIn("\\", result)

    def test_absolute_path_has_forward_slashes(self) -> None:
        path = Path(tempfile.gettempdir()) / "mwccps2.exe"
        result = gdb_path(path)
        self.assertIn("/", result)
        self.assertNotIn("\\\\", result)


class BuildGdbCommandLinesTests(unittest.TestCase):
    """build_gdb_command_lines produces deterministic command file."""

    def setUp(self) -> None:
        self.request = GdbSnapshotRequest(
            command_directory=Path(tempfile.gettempdir()),
            compiler=Path("C:/tools/mwccps2.exe"),
            compiler_args=["-O4", "-c", "test.c"],
            profile_path=Path("C:/profiles/b210.json"),
            snapshot_directory=Path("C:/output/snapshots"),
            working_directory=Path("C:/work"),
            snapshot_script=Path("C:/scripts/snapshot.py"),
            gdb_executable=Path("C:/gdb/powerpc-eabi-gdb.exe"),
        )

    def test_first_line_is_set_pagination_off(self) -> None:
        lines = build_gdb_command_lines(self.request)
        self.assertEqual(lines[0], "set pagination off")

    def test_includes_starti(self) -> None:
        lines = build_gdb_command_lines(self.request)
        self.assertIn("starti", lines)

    def test_includes_file_command(self) -> None:
        lines = build_gdb_command_lines(self.request)
        file_line = next(line for line in lines if line.startswith("file "))
        self.assertIn("mwccps2.exe", file_line)

    def test_includes_set_args(self) -> None:
        lines = build_gdb_command_lines(self.request)
        args_line = next(line for line in lines if line.startswith("set args "))
        self.assertIn("test.c", args_line)

    def test_includes_b210_snapshot_command(self) -> None:
        lines = build_gdb_command_lines(self.request)
        snap_line = next(line for line in lines if "b210-snapshot start" in line)
        self.assertIn("--profile", snap_line)
        self.assertIn("--output", snap_line)

    def test_includes_quit(self) -> None:
        lines = build_gdb_command_lines(self.request)
        self.assertIn("quit", lines)

    def test_ends_with_empty_string(self) -> None:
        lines = build_gdb_command_lines(self.request)
        self.assertEqual(lines[-1], "")

    def test_deterministic_output(self) -> None:
        lines1 = build_gdb_command_lines(self.request)
        lines2 = build_gdb_command_lines(self.request)
        self.assertEqual(lines1, lines2)


class WindowsGdbTransportTests(unittest.TestCase):
    """WindowsGdbTransport command construction."""

    def setUp(self) -> None:
        self.transport = WindowsGdbTransport()
        self.request = GdbSnapshotRequest(
            command_directory=Path("C:/temp"),
            compiler=Path("D:/mwccps2.exe"),
            compiler_args=["-O4"],
            profile_path=Path("C:/profiles/b210.json"),
            snapshot_directory=Path("C:/snapshots"),
            working_directory=Path("C:/work"),
            snapshot_script=Path("C:/scripts/snapshot.py"),
            gdb_executable=Path("C:/gdb/powerpc-eabi-gdb.exe"),
        )

    def test_name_is_windows_gdb(self) -> None:
        self.assertEqual(self.transport.name, WINDOWS_GDB_TRANSPORT)

    def test_command_includes_gdb_executable(self) -> None:
        cmd = self.transport.build_process_command(self.request, Path("C:/temp/cmd.gdb"))
        cmd_str = " ".join(cmd)
        self.assertIn("powerpc-eabi-gdb.exe", cmd_str)

    def test_command_includes_batch_flags(self) -> None:
        cmd = self.transport.build_process_command(self.request, Path("C:/temp/cmd.gdb"))
        self.assertIn("--batch", cmd)
        self.assertIn("--nx", cmd)
        self.assertIn("--quiet", cmd)

    def test_command_includes_command_file(self) -> None:
        cmd = self.transport.build_process_command(self.request, Path("C:/temp/cmd.gdb"))
        cmd_str = " ".join(cmd)
        self.assertIn("cmd.gdb", cmd_str)


class Retrowin32GdbTransportTests(unittest.TestCase):
    """Retrowin32GdbTransport command construction."""

    def setUp(self) -> None:
        self.transport = Retrowin32GdbTransport(retrowin32_executable=Path("C:/retrowin32/retrowin32.exe"))
        self.request = GdbSnapshotRequest(
            command_directory=Path("C:/temp"),
            compiler=Path("C:/tools/mwccps2.exe"),
            compiler_args=["-O4"],
            profile_path=Path("C:/profiles/b210.json"),
            snapshot_directory=Path("C:/snapshots"),
            working_directory=Path("C:/work"),
            snapshot_script=Path("C:/scripts/snapshot.py"),
            gdb_executable=Path("C:/gdb/powerpc-eabi-gdb.exe"),
        )

    def test_name_is_retrowin32_gdb(self) -> None:
        self.assertEqual(self.transport.name, RETROWIN32_GDB_TRANSPORT)

    def test_command_starts_with_retrowin32(self) -> None:
        cmd = self.transport.build_process_command(self.request, Path("C:/temp/cmd.gdb"))
        cmd_str = " ".join(cmd)
        self.assertIn("retrowin32.exe", cmd_str)

    def test_command_includes_C_flag(self) -> None:
        cmd = self.transport.build_process_command(self.request, Path("C:/temp/cmd.gdb"))
        self.assertIn("-C", cmd)

    def test_command_includes_working_directory_after_C(self) -> None:
        cmd = self.transport.build_process_command(self.request, Path("C:/temp/cmd.gdb"))
        c_index = cmd.index("-C")
        # On Windows paths contain drive letter
        self.assertIn("work", cmd[c_index + 1])

    def test_command_includes_gdb_after_working_directory(self) -> None:
        cmd = self.transport.build_process_command(self.request, Path("C:/temp/cmd.gdb"))
        cmd_str = " ".join(cmd)
        self.assertIn("powerpc-eabi-gdb.exe", cmd_str)


class CreateGdbTransportTests(unittest.TestCase):
    """create_gdb_transport factory."""

    def test_creates_windows_gdb(self) -> None:
        transport = create_gdb_transport(WINDOWS_GDB_TRANSPORT)
        self.assertIsInstance(transport, WindowsGdbTransport)

    def test_creates_retrowin32_gdb(self) -> None:
        transport = create_gdb_transport(
            RETROWIN32_GDB_TRANSPORT,
            retrowin32_executable=Path("C:/retrowin32/retrowin32.exe"),
        )
        self.assertIsInstance(transport, Retrowin32GdbTransport)

    def test_retrowin32_requires_executable(self) -> None:
        with self.assertRaises(TransportError, msg="requires a retrowin32"):
            create_gdb_transport(RETROWIN32_GDB_TRANSPORT)

    def test_unknown_kind_raises(self) -> None:
        with self.assertRaises(TransportError, msg="unknown GDB transport"):
            create_gdb_transport("unknown-kind")


if __name__ == "__main__":
    unittest.main()
