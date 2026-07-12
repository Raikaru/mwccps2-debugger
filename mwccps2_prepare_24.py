#!/usr/bin/env python3
"""Prepare the exact MWCCPS2 2.4 engineering build for unattended debugging.

The archived 0017 compiler requires a FLEXlm license checkout before it enters
its compile pipeline.  This tool applies a narrowly fingerprinted patch that
skips the checkout and the zero-handle rejection while preserving the compiler
code, data layouts, image base, and all backend addresses used by a live
profile.  No compiler binary is distributed by this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
from pathlib import Path
import tempfile


SOURCE_SHA256 = "98d3fb6fc362c6b28208e1cc05ff25e32b7c78ffca0c3114cde5392a67c06294"
PREPARED_SHA256 = "1233acf014b53ae39669da4cc050062f316d73dd63257150024ad25ad33dbb30"
SOURCE_SIZE = 1_379_328
COMPANION_DLLS = ("LMGR326B.DLL",)

# File offsets, not virtual addresses.  Each preimage is checked before writing.
PATCHES: tuple[tuple[int, bytes, bytes], ...] = (
    (
        0x0001EFB9,
        bytes.fromhex("e822d0ffffc6056054540001"),
        bytes.fromhex("83c4189090c6056054540000"),
    ),
    (
        0x0001F079,
        bytes.fromhex("7445"),
        bytes.fromhex("9090"),
    ),
)


class PreparationError(Exception):
    """Raised when the input is not the exact supported compiler build."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare_bytes(data: bytes) -> bytes:
    """Return a deterministically prepared image after exact identity checks."""

    if len(data) != SOURCE_SIZE:
        raise PreparationError(
            f"unsupported compiler size {len(data)}; expected {SOURCE_SIZE}"
        )
    digest = _sha256(data)
    if digest == PREPARED_SHA256:
        return data
    if digest != SOURCE_SHA256:
        raise PreparationError(
            f"unsupported compiler SHA-256 {digest}; expected {SOURCE_SHA256}"
        )

    prepared = bytearray(data)
    for offset, expected, replacement in PATCHES:
        actual = bytes(prepared[offset : offset + len(expected)])
        if actual != expected:
            raise PreparationError(
                f"patch preimage mismatch at file offset 0x{offset:08x}: "
                f"got {actual.hex()}, expected {expected.hex()}"
            )
        prepared[offset : offset + len(replacement)] = replacement

    result = bytes(prepared)
    result_digest = _sha256(result)
    if result_digest != PREPARED_SHA256:
        raise PreparationError(
            f"prepared compiler SHA-256 {result_digest} does not match "
            f"the validated result {PREPARED_SHA256}"
        )
    return result


def prepare_file(source: Path, output: Path) -> str:
    """Prepare ``source`` and atomically write ``output`` with required DLLs."""

    try:
        data = source.read_bytes()
    except OSError as exc:
        raise PreparationError(f"cannot read compiler {source}: {exc}") from exc
    prepared = prepare_bytes(data)

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
        ) as stream:
            stream.write(prepared)
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, output)
        if source.resolve().parent != output.parent:
            for companion_name in COMPANION_DLLS:
                companion = source.resolve().parent / companion_name
                if not companion.is_file():
                    raise PreparationError(
                        f"required companion DLL not found beside compiler: {companion}"
                    )
                shutil.copy2(companion, output.parent / companion_name)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise PreparationError(f"cannot write prepared compiler {output}: {exc}") from exc
    return PREPARED_SHA256


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare exact MWCCPS2 2.4 build 0017 for unattended debugger use"
    )
    parser.add_argument("compiler", type=Path, help="original mwccps2.exe from the 2000-12-13 archive")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="destination for the prepared executable; no binary is stored in the repository",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        digest = prepare_file(args.compiler.resolve(), args.output)
    except PreparationError as exc:
        print(f"error: {exc}")
        return 2
    print(f"prepared: {args.output.resolve()}")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
