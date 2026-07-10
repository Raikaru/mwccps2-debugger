from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mwccps2_solve import SolveConfig, SolveError, _check_or_write_identity, _run_identity
from solver.search import Objective, SearchConfig


class SolverRunIdentityTests(unittest.TestCase):
    def test_resume_identity_binds_p3_python_environment_and_capture_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config" / "slus21621_functions.json").write_text("{}", encoding="ascii")
            verifier = root / "tools" / "verify.py"
            verifier.parent.mkdir()
            verifier.write_text("# verifier", encoding="ascii")
            python = root / "python.exe"
            python.write_bytes(b"python")
            gdb = root / "gdb.exe"
            gdb.write_bytes(b"gdb")
            environment = root / "p3.env"
            environment.write_text("first", encoding="ascii")
            config = SolveConfig(root / "input.c", "f", p3_root=root, address="80000000", verifier="tools/verify.py", python=str(python), gdb=gdb, capture_timeout=10)
            baseline = "int f(void) { return 0; }"
            catalog = ({"id": "swap"},)
            search = SearchConfig()
            evaluator = type("E", (), {"configuration_sha256": "a" * 64})()
            with patch.dict(os.environ, {"P3_MWCC": str(environment)}, clear=False):
                identity = _run_identity(baseline, catalog, Objective(), search, config, True, True, evaluator, ())
                output = root / "run"
                output.mkdir()
                _check_or_write_identity(output, False, identity)
                _check_or_write_identity(output, True, identity)
                changed_address = _run_identity(baseline, catalog, Objective(), search, SolveConfig(**{**config.__dict__, "address": "80000001"}), True, True, evaluator, ())
                with self.assertRaises(SolveError):
                    _check_or_write_identity(output, True, changed_address)
                gdb.write_bytes(b"changed-gdb")
                changed_toolchain = _run_identity(baseline, catalog, Objective(), search, config, True, True, evaluator, ())
                with self.assertRaises(SolveError):
                    _check_or_write_identity(output, True, changed_toolchain)
                gdb.write_bytes(b"gdb")
                environment.write_text("changed", encoding="ascii")
                changed_environment = _run_identity(baseline, catalog, Objective(), search, config, True, True, evaluator, ())
                with self.assertRaises(SolveError):
                    _check_or_write_identity(output, True, changed_environment)
                environment.write_text("first", encoding="ascii")
                other_python = root / "python-other.exe"
                other_python.write_bytes(b"other-python")
                changed_python = _run_identity(baseline, catalog, Objective(), search, SolveConfig(**{**config.__dict__, "python": str(other_python)}), True, True, evaluator, ())
                with self.assertRaises(SolveError):
                    _check_or_write_identity(output, True, changed_python)
