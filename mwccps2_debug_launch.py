#!/usr/bin/env python3
"""Launch mwccps2.exe suspended so a debugger can install breakpoints first."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import sys


CREATE_SUSPENDED = 0x00000004
INFINITE = 0xFFFFFFFF
WAIT_FAILED = 0xFFFFFFFF
STILL_ACTIVE = 259


class LaunchError(Exception):
    """Raised when the Windows process-control API fails."""


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class WindowsProcessApi:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise LaunchError("the suspended launcher requires Windows")

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        self.create_process = kernel32.CreateProcessW
        self.create_process.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW),
            ctypes.POINTER(PROCESS_INFORMATION),
        ]
        self.create_process.restype = wintypes.BOOL

        self.resume_thread = kernel32.ResumeThread
        self.resume_thread.argtypes = [wintypes.HANDLE]
        self.resume_thread.restype = wintypes.DWORD

        self.wait_for_single_object = kernel32.WaitForSingleObject
        self.wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.wait_for_single_object.restype = wintypes.DWORD

        self.get_exit_code_process = kernel32.GetExitCodeProcess
        self.get_exit_code_process.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.get_exit_code_process.restype = wintypes.BOOL

        self.terminate_process = kernel32.TerminateProcess
        self.terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.terminate_process.restype = wintypes.BOOL

        self.close_handle = kernel32.CloseHandle
        self.close_handle.argtypes = [wintypes.HANDLE]
        self.close_handle.restype = wintypes.BOOL

    @staticmethod
    def _last_error(operation: str) -> LaunchError:
        error = ctypes.WinError(ctypes.get_last_error())
        return LaunchError(f"{operation} failed: {error}")

    def launch_suspended(
        self, compiler: Path, compiler_args: list[str], cwd: Path
    ) -> PROCESS_INFORMATION:
        startup_info = STARTUPINFOW()
        startup_info.cb = ctypes.sizeof(startup_info)
        process_info = PROCESS_INFORMATION()
        command_line = ctypes.create_unicode_buffer(
            subprocess.list2cmdline([str(compiler), *compiler_args])
        )

        created = self.create_process(
            str(compiler),
            command_line,
            None,
            None,
            False,
            CREATE_SUSPENDED,
            None,
            str(cwd),
            ctypes.byref(startup_info),
            ctypes.byref(process_info),
        )
        if not created:
            raise self._last_error("CreateProcessW")
        return process_info

    def resume(self, thread_handle: int) -> None:
        previous_count = self.resume_thread(thread_handle)
        if previous_count == 0xFFFFFFFF:
            raise self._last_error("ResumeThread")
        if previous_count == 0:
            raise LaunchError("compiler main thread was not suspended")

    def wait(self, process_handle: int) -> int:
        wait_result = self.wait_for_single_object(process_handle, INFINITE)
        if wait_result == WAIT_FAILED:
            raise self._last_error("WaitForSingleObject")

        exit_code = wintypes.DWORD()
        if not self.get_exit_code_process(process_handle, ctypes.byref(exit_code)):
            raise self._last_error("GetExitCodeProcess")
        if exit_code.value == STILL_ACTIVE:
            raise LaunchError("compiler remained active after the process wait completed")
        return int(exit_code.value)

    def terminate(self, process_handle: int, exit_code: int = 130) -> None:
        if not self.terminate_process(process_handle, exit_code):
            error_code = ctypes.get_last_error()
            if error_code != 5:
                raise self._last_error("TerminateProcess")

    def close(self, handle: int) -> None:
        if handle:
            self.close_handle(handle)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Launch mwccps2.exe with its main thread suspended, wait for debugger "
            "attachment, then resume it."
        )
    )
    parser.add_argument("--compiler", required=True, type=Path, help="path to mwccps2.exe")
    parser.add_argument(
        "--cwd",
        type=Path,
        default=Path.cwd(),
        help="compiler working directory; defaults to the current directory",
    )
    parser.add_argument(
        "compiler_args",
        nargs=argparse.REMAINDER,
        help="compiler arguments, normally following --",
    )
    args = parser.parse_args(argv)
    if args.compiler_args[:1] == ["--"]:
        args.compiler_args = args.compiler_args[1:]
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    compiler = args.compiler.resolve()
    cwd = args.cwd.resolve()

    if not compiler.is_file():
        print(f"error: compiler not found: {compiler}", file=sys.stderr)
        return 2
    if not cwd.is_dir():
        print(f"error: working directory not found: {cwd}", file=sys.stderr)
        return 2

    try:
        api = WindowsProcessApi()
        process_info = api.launch_suspended(compiler, args.compiler_args, cwd)
    except LaunchError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"compiler PID: {process_info.dwProcessId}", flush=True)
    print(f"main thread ID: {process_info.dwThreadId}", flush=True)
    print(
        "Attach the debugger and install breakpoints before resuming. "
        "For b210, CodeGen_Generator is 0x00435d90.",
        flush=True,
    )

    try:
        input("Press Enter to resume mwccps2.exe... ")
        api.resume(process_info.hThread)
        return api.wait(process_info.hProcess)
    except (EOFError, KeyboardInterrupt):
        print("\nterminating suspended compiler", file=sys.stderr)
        api.terminate(process_info.hProcess)
        return 130
    except LaunchError as error:
        print(f"error: {error}", file=sys.stderr)
        api.terminate(process_info.hProcess)
        return 2
    finally:
        api.close(process_info.hThread)
        api.close(process_info.hProcess)


if __name__ == "__main__":
    raise SystemExit(main())
