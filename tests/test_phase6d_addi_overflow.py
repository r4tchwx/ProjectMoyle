"""Regression tests for R3000A ADDI signed-overflow semantics."""

import sys
from pathlib import Path
import unittest

PROOF_DIR = Path(__file__).resolve().parents[1] / "tools" / "recomp" / "proof"
sys.path.insert(0, str(PROOF_DIR))

from mips import RNAME, decode
from sym import Exec, Path as ExecPath


BASE = 0x80010000


class AddiOverflowTest(unittest.TestCase):
    def execute_alu(self, word, rs_value):
        engine = Exec(object())
        path = ExecPath([0] * len(RNAME), BASE)
        path.r[8] = rs_value
        ins = decode(word, BASE)
        return engine.alu(path, ins)

    def test_addiu_still_wraps(self):
        reg, value = self.execute_alu(0x25080001, 0x7fffffff)
        self.assertEqual(reg, 8)
        self.assertEqual(value, 0x80000000)

    def test_addi_positive_overflow_fails_closed(self):
        with self.assertRaisesRegex(AssertionError, "ADDI.*overflow"):
            self.execute_alu(0x21080001, 0x7fffffff)

    def test_addi_negative_overflow_fails_closed(self):
        with self.assertRaisesRegex(AssertionError, "ADDI.*overflow"):
            self.execute_alu(0x2108ffff, 0x80000000)

    def test_addi_without_overflow_executes(self):
        reg, value = self.execute_alu(0x21080001, 1)
        self.assertEqual(reg, 8)
        self.assertEqual(value, 2)

    def test_symbolic_addi_fails_closed(self):
        with self.assertRaisesRegex(AssertionError, "ADDI.*overflow"):
            self.execute_alu(0x21080001, ("S", "bios_pointer"))

    def test_symbolic_addi_requires_explicit_no_overflow_contract(self):
        def contract(pc, lhs, simm):
            return (
                pc == BASE
                and lhs == ("S", "bios_pointer")
                and simm == 1
            )

        engine = Exec(object(), addi_no_overflow=contract)
        path = ExecPath([0] * len(RNAME), BASE)
        path.r[8] = ("S", "bios_pointer")
        ins = decode(0x21080001, BASE)

        reg, value = engine.alu(path, ins)

        self.assertEqual(reg, 8)
        self.assertEqual(value, ("+", ("S", "bios_pointer"), 1))
        self.assertIn(
            ("addi_no_overflow", BASE, ("S", "bios_pointer"), 1),
            path.assumptions,
        )

    def test_addi_contract_cannot_authorize_concrete_overflow(self):
        engine = Exec(object(), addi_no_overflow=lambda pc, lhs, simm: True)
        path = ExecPath([0] * len(RNAME), BASE)
        path.r[8] = 0x7fffffff
        ins = decode(0x21080001, BASE)

        with self.assertRaisesRegex(AssertionError, "ADDI.*overflow"):
            engine.alu(path, ins)


if __name__ == "__main__":
    unittest.main()
