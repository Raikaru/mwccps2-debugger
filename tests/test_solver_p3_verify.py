from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from solver.p3_verify import verify_candidate


class P3VerifierAdapterTests(unittest.TestCase):
    def test_fake_verifier_covers_match_nonmatch_and_operational_failures_with_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src" / "target.c"
            source.parent.mkdir()
            source.write_text("int f(void) { return 0; }", encoding="utf-8")
            verifier = root / "verify.py"
            verifier.write_text(
                "import json, pathlib, sys, time\n"
                "text=pathlib.Path(sys.argv[1]).read_text()\n"
                "out=pathlib.Path(sys.argv[3])\n"
                "if 'timeout' in text: time.sleep(1)\n"
                "elif 'missing' in text: pass\n"
                "elif 'invalid' in text: out.write_text('{')\n"
                "else:\n"
                " status='MATCH' if '/* match */' in text else 'MISMATCH'\n"
                " rows=[{'addr':'80000000','name':'f','status':status}]\n"
                " if 'ambiguous' in text: rows*=2\n"
                " out.write_text(json.dumps({'summary':{},'results':rows}))\n"
                " sys.exit(7 if status == 'MISMATCH' else 0)\n",
                encoding="utf-8",
            )
            def verify(text: str, timeout: float = 0.3):
                return verify_candidate(root, source, text, "f", "80000000", sys.executable, timeout, verifier)
            matched = verify("/* match */")
            mismatch = verify("/* mismatch */")
            ambiguous = verify("/* ambiguous */")
            missing = verify("/* missing */")
            invalid = verify("/* invalid */")
            timed = verify("/* timeout */", 0.05)
            self.assertTrue(matched.certified)
            self.assertEqual(mismatch.error, "verifier_status_not_match")
            self.assertEqual(mismatch.exit_code, 7)
            self.assertEqual(ambiguous.error, "ambiguous_target")
            self.assertEqual(missing.error, "missing_report")
            self.assertEqual(invalid.error, "invalid_report")
            self.assertEqual(timed.error, "timeout")
            self.assertFalse(list(source.parent.glob(".permute_mwccsolve_*")))
