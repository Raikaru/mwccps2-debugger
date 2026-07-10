"""Authoritative adapter for Persona 3's retail match verifier.

This module deliberately treats ``tools/verify.py`` as the only retail authority.
Its process exit status is diagnostic evidence only: a candidate is certified solely
when the report row for the requested function and address says ``MATCH``.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import json
from pathlib import Path
import re
import secrets
import subprocess
from typing import Any, Final


_ADDRESS_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{8}\Z")
_REPORT_KEYS: Final[frozenset[str]] = frozenset({"summary", "results"})
_VERIFIER_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "MATCH",
        "NONMATCHING",
        "STALE_NONMATCHING",
        "MISMATCH",
        "SIZE_MISMATCH",
        "STUB",
        "NO_SYMBOL",
        "COMPILE_ERROR",
        "UNKNOWN_ADDR",
    }
)
_ROW_REQUIRED_KEYS: Final[frozenset[str]] = frozenset({"addr", "name", "status"})


class P3VerifierConfigurationError(ValueError):
    """Raised only when an adapter caller supplies an invalid configuration."""


@dataclass(frozen=True, slots=True)
class P3VerificationResult:
    """Sanitized, durable result of one authoritative verifier invocation.

    ``evidence`` intentionally excludes process output and host paths.  Those can
    contain compiler configuration details and are not proof of a retail match.
    """

    candidate_sha256: str
    command: tuple[str, ...]
    exit_code: int | None
    certified: bool
    outcome: str
    error: str | None
    row_status: str | None
    normalized_diff: int | None
    object_size: int | None
    window: int | None
    first_diffs: tuple[int, ...]

    @property
    def evidence(self) -> dict[str, Any]:
        """Return a new JSON-safe public evidence record."""
        return {
            "candidate_sha256": self.candidate_sha256,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "certified": self.certified,
            "outcome": self.outcome,
            "error": self.error,
            "row_status": self.row_status,
            "normalized_diff": self.normalized_diff,
            "object_size": self.object_size,
            "window": self.window,
            "first_diffs": list(self.first_diffs),
        }


def verify_candidate(
    p3_root: Path | str,
    original_source: Path | str,
    candidate_source: str,
    function_name: str,
    address: str,
    python_executable: Path | str,
    timeout_seconds: float,
    verifier_path: Path | str = "tools/verify.py",
) -> P3VerificationResult:
    """Verify one candidate against retail bytes using the P3 verifier.

    Configuration violations raise :class:`P3VerifierConfigurationError`.  Every
    operational failure, including a verifier timeout or malformed report, is
    represented by an uncertified result instead.
    """
    root, source, verifier, normalized_address = _validate_configuration(
        p3_root,
        original_source,
        candidate_source,
        function_name,
        address,
        python_executable,
        timeout_seconds,
        verifier_path,
    )
    candidate_sha256 = hashlib.sha256(candidate_source.encode("utf-8")).hexdigest()
    token = secrets.token_hex(16)
    candidate = source.parent / f".permute_mwccsolve_{token}.c"
    report = source.parent / f".permute_mwccsolve_{token}.json"
    candidate_rel = candidate.relative_to(root).as_posix()
    report_rel = report.relative_to(root).as_posix()
    verifier_rel = verifier.relative_to(root).as_posix()
    command = (
        _portable_executable_name(python_executable),
        verifier_rel,
        candidate_rel,
        "--json",
        report_rel,
    )

    exit_code: int | None = None
    error: str | None = None
    parsed_report: dict[str, Any] | None = None
    try:
        candidate.write_text(candidate_source, encoding="utf-8", newline="")
        try:
            completed = subprocess.run(
                [str(python_executable), verifier_rel, candidate_rel, "--json", report_rel],
                cwd=str(root),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            error = "timeout"
        except (OSError, ValueError):
            error = "launch_error"

        if error is None:
            try:
                parsed_report = _load_report(report)
            except FileNotFoundError:
                error = "missing_report"
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                error = "invalid_report"
    except (OSError, UnicodeError):
        error = "materialization_error"
    finally:
        cleanup_error = _cleanup(candidate, report)
        if cleanup_error is not None:
            # An otherwise matching row is not durable evidence if its temporary
            # artifacts could not be removed as promised.
            error = "cleanup_failed"

    if error is not None:
        return _result(candidate_sha256, command, exit_code, False, "error", error)

    assert parsed_report is not None
    rows = [
        row for row in parsed_report["results"]
        if row["name"] == function_name and _normalize_report_address(row["addr"]) == normalized_address
    ]
    if not rows:
        return _result(candidate_sha256, command, exit_code, False, "unverified", "target_not_found")
    if len(rows) != 1:
        return _result(candidate_sha256, command, exit_code, False, "unverified", "ambiguous_target")

    row = rows[0]
    status = row["status"]
    certified = status == "MATCH"
    return P3VerificationResult(
        candidate_sha256=candidate_sha256,
        command=command,
        exit_code=exit_code,
        certified=certified,
        outcome="certified" if certified else "unverified",
        error=None if certified else _status_error(status),
        row_status=status,
        normalized_diff=_optional_nonnegative_int(row, "normalized_diff"),
        object_size=_optional_nonnegative_int(row, "object_size"),
        window=_optional_nonnegative_int(row, "window"),
        first_diffs=_optional_int_list(row, "first_diffs"),
    )


def _validate_configuration(
    p3_root: Path | str,
    original_source: Path | str,
    candidate_source: str,
    function_name: str,
    address: str,
    python_executable: Path | str,
    timeout_seconds: float,
    verifier_path: Path | str,
) -> tuple[Path, Path, Path, str]:
    if not isinstance(candidate_source, str):
        raise P3VerifierConfigurationError("candidate_source must be text")
    try:
        candidate_source.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise P3VerifierConfigurationError("candidate_source must be UTF-8 encodable") from exc
    if not isinstance(function_name, str) or not function_name:
        raise P3VerifierConfigurationError("function_name must be a non-empty string")
    if not isinstance(address, str) or _ADDRESS_RE.fullmatch(address) is None:
        raise P3VerifierConfigurationError("address must be exactly eight hexadecimal characters")
    if not isinstance(python_executable, (str, Path)) or not str(python_executable):
        raise P3VerifierConfigurationError("python_executable must name an executable")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise P3VerifierConfigurationError("timeout_seconds must be a finite positive number")

    if not isinstance(p3_root, (str, Path)):
        raise P3VerifierConfigurationError("p3_root must be a path")
    if not isinstance(original_source, (str, Path)):
        raise P3VerifierConfigurationError("original_source must be a path")
    if not isinstance(verifier_path, (str, Path)):
        raise P3VerifierConfigurationError("verifier_path must be a path")
    root = Path(p3_root).resolve()
    if not root.is_dir():
        raise P3VerifierConfigurationError("p3_root must be an existing directory")
    source = Path(original_source).resolve()
    if not source.is_file() or source.suffix.lower() != ".c":
        raise P3VerifierConfigurationError("original_source must be an existing C source file")
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise P3VerifierConfigurationError("original_source must be contained by p3_root") from exc

    verifier = Path(verifier_path)
    if not verifier.is_absolute():
        verifier = root / verifier
    verifier = verifier.resolve()
    if not verifier.is_file():
        raise P3VerifierConfigurationError("verifier_path must be an existing file")
    try:
        verifier.relative_to(root)
    except ValueError as exc:
        raise P3VerifierConfigurationError("verifier_path must be contained by p3_root") from exc
    return root, source, verifier, address.lower()


def _load_report(path: Path) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(report, dict) or set(report) != _REPORT_KEYS:
        raise ValueError("report must contain exactly summary and results")
    if not isinstance(report["summary"], dict) or not all(
        isinstance(key, str) and key in _VERIFIER_STATUSES and _is_nonnegative_int(value)
        for key, value in report["summary"].items()
    ):
        raise ValueError("report summary must map status names to non-negative integers")
    if not isinstance(report["results"], list):
        raise ValueError("report results must be a list")
    for row in report["results"]:
        _validate_row(row)
    return report


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_row(row: Any) -> None:
    if not isinstance(row, dict) or not _ROW_REQUIRED_KEYS.issubset(row):
        raise ValueError("report row lacks required fields")
    if not isinstance(row["addr"], str) or not isinstance(row["status"], str):
        raise ValueError("report row has invalid required field types")
    if not isinstance(row["name"], (str, type(None))):
        raise ValueError("report row has invalid required field types")
    if row["status"] not in _VERIFIER_STATUSES:
        raise ValueError("report row has an unknown verifier status")
    _normalize_report_address(row["addr"])
    for key in ("normalized_diff", "object_size", "window"):
        if key in row and not _is_nonnegative_int(row[key]):
            raise ValueError(f"report row has invalid {key}")
    if "first_diffs" in row and (
        not isinstance(row["first_diffs"], list)
        or not all(_is_nonnegative_int(value) for value in row["first_diffs"])
    ):
        raise ValueError("report row has invalid first_diffs")


def _normalize_report_address(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("report address is not text")
    text = value[2:] if value.startswith(("0x", "0X")) else value
    if _ADDRESS_RE.fullmatch(text) is None:
        raise ValueError("report address is not eight hexadecimal characters")
    return text.lower()


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _optional_nonnegative_int(row: dict[str, Any], key: str) -> int | None:
    value = row.get(key)
    return value if _is_nonnegative_int(value) else None


def _optional_int_list(row: dict[str, Any], key: str) -> tuple[int, ...]:
    value = row.get(key)
    return tuple(value) if isinstance(value, list) else ()


def _portable_executable_name(executable: Path | str) -> str:
    """Keep durable command evidence free of absolute host paths."""
    text = str(executable)
    name = Path(text).name
    return name or "python"


def _cleanup(candidate: Path, report: Path) -> str | None:
    failed = False
    for path in (candidate, report):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            failed = True
    return "cleanup_failed" if failed else None


def _result(
    candidate_sha256: str,
    command: tuple[str, ...],
    exit_code: int | None,
    certified: bool,
    outcome: str,
    error: str | None,
) -> P3VerificationResult:
    return P3VerificationResult(
        candidate_sha256=candidate_sha256,
        command=command,
        exit_code=exit_code,
        certified=certified,
        outcome=outcome,
        error=error,
        row_status=None,
        normalized_diff=None,
        object_size=None,
        window=None,
        first_diffs=(),
    )


def _status_error(status: str) -> str:
    """Classify known verifier rows without deriving a match from their metrics."""
    if status == "COMPILE_ERROR":
        return "compiler_error"
    if status == "UNKNOWN_ADDR":
        return "unknown_address"
    return "verifier_status_not_match"
