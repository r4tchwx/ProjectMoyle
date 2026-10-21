"""Regression tests for conservative PS1 syscall summaries."""

import sys
from pathlib import Path
import unittest

PROOF_DIR = Path(__file__).resolve().parents[1] / "tools" / "recomp" / "proof"
sys.path.insert(0, str(PROOF_DIR))

from mips import RNAME, decode
from sym import Exec, Path as ExecPath


BASE = 0x80010000
SYSCALL = decode(0x0000000c, BASE)


class SyscallSummaryTest(unittest.TestCase):
    def make_path(self, code):
        p = ExecPath([0] * len(RNAME), BASE)
        p.r[4] = code
        return p

    def test_enter_critical_returns_fresh_identity_each_time(self):
        engine = Exec(object())

        p1 = self.make_path(1)
        p2 = self.make_path(1)

        r1 = engine.exec1(p1, SYSCALL)
        r2 = engine.exec1(p2, SYSCALL)

        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        self.assertEqual(r1[0:2], ("reg", 2))
        self.assertEqual(r2[0:2], ("reg", 2))
        self.assertNotEqual(r1[2], r2[2])

    def test_exit_critical_does_not_overwrite_v0(self):
        engine = Exec(object())
        p = self.make_path(2)
        p.r[2] = 0x12345678

        result = engine.exec1(p, SYSCALL)

        self.assertIsNone(result)
        self.assertEqual(p.r[2], 0x12345678)

    def test_syscall_invalidates_memory_by_default(self):
        engine = Exec(object())
        p = self.make_path(1)
        p.mem[0x80001000] = 0x12345678

        engine.exec1(p, SYSCALL)

        self.assertTrue(p.mem_unknown)
        self.assertNotIn(0x80001000, p.mem)

    def test_syscall_can_preserve_only_explicit_fact(self):
        keep = 0x80001000
        drop = 0x80002000

        def contract(callsite, syscall_pc, code, word_key):
            return (
                callsite == 0x80020000
                and syscall_pc == BASE
                and code == 1
                and word_key == keep
            )

        engine = Exec(
            object(),
            syscall_memory_preserve=contract,
        )
        p = self.make_path(1)
        p.last_callsite = 0x80020000
        p.mem[keep] = 0x11111111
        p.mem[drop] = 0x22222222

        engine.exec1(p, SYSCALL)

        self.assertTrue(p.mem_unknown)
        self.assertEqual(p.mem, {keep: 0x11111111})
        self.assertIn(
            (
                "syscall_memory_preserve",
                0x80020000,
                BASE,
                1,
                keep,
            ),
            p.assumptions,
        )

    def test_syscall_memory_contract_must_return_bool(self):
        engine = Exec(
            object(),
            syscall_memory_preserve=lambda *args: "yes",
        )
        p = self.make_path(1)
        p.mem[0x80001000] = 1

        with self.assertRaisesRegex(
            AssertionError,
            "syscall memory-preserve contract must return bool",
        ):
            engine.exec1(p, SYSCALL)

    def test_enter_critical_records_exact_return_identity_on_path(self):
        engine = Exec(object())
        p = self.make_path(1)
        p.last_callsite = 0x80020000

        result = engine.exec1(p, SYSCALL)

        self.assertIsNotNone(result)
        self.assertEqual(
            p.syscall_returns,
            [
                (
                    0x80020000,
                    BASE,
                    1,
                    result[2],
                )
            ],
        )

        forked = p.fork()
        self.assertEqual(forked.syscall_returns, p.syscall_returns)

        same_label_different_identity = (
            "?",
            "EnterCS.ret",
            ("TEST_MUTANT", 0),
        )
        self.assertNotEqual(
            p.syscall_returns[0][3],
            same_label_different_identity,
        )

    def test_syscall_disables_pristine_image_fallback_by_default(self):
        class Image:
            def has(self, addr):
                return addr == 0x80010000

            def word(self, addr):
                return 0x12345678

        engine = Exec(Image())
        p = self.make_path(1)

        engine.exec1(p, SYSCALL)
        value = engine.load(p, 0x80010000, 4, False)

        self.assertNotEqual(value, 0x12345678)
        self.assertTrue(p.mem_unknown)

    def test_explicit_syscall_image_words_materialize_only_selected_word(self):
        class Image:
            WORDS = {
                0x80010000: 0x12345678,
                0x80010004: 0x87654321,
            }

            def has(self, addr):
                return addr in self.WORDS

            def word(self, addr):
                return self.WORDS[addr]

        def contract(callsite, syscall_pc, code):
            if (
                callsite == 0x80020000
                and syscall_pc == BASE
                and code == 1
            ):
                return (0x80010000,)
            return ()

        engine = Exec(
            Image(),
            syscall_image_words=contract,
        )
        p = self.make_path(1)
        p.last_callsite = 0x80020000
        p.mem[0x80002000] = 0xaaaaaaaa

        engine.exec1(p, SYSCALL)

        # A syscall still invalidates general pristine-image fallback.
        self.assertTrue(p.mem_unknown)

        # Ordinary RAM disappeared; exactly one admitted image word survived
        # as an explicit memory fact.
        self.assertEqual(p.mem, {0x80010000: 0x12345678})
        self.assertEqual(
            engine.load(p, 0x80010000, 4, False),
            0x12345678,
        )

        # A different word from the same image must NOT become readable merely
        # because one pinned word was admitted.
        other = engine.load(p, 0x80010004, 4, False)
        self.assertNotEqual(other, 0x87654321)

        self.assertIn(
            (
                "syscall_image_word_preserve",
                0x80020000,
                BASE,
                1,
                0x80010000,
            ),
            p.assumptions,
        )

    def test_syscall_image_words_cannot_heal_prior_unknown_image(self):
        class Image:
            def has(self, addr):
                return addr == 0x80010000

            def word(self, addr):
                return 0x12345678

        engine = Exec(
            Image(),
            syscall_image_words=lambda *args: (0x80010000,),
        )
        p = self.make_path(1)
        p.mem_unknown = True

        engine.exec1(p, SYSCALL)

        self.assertTrue(p.mem_unknown)
        self.assertNotIn(0x80010000, p.mem)
        self.assertFalse(
            any(a[0] == "syscall_image_word_preserve"
                for a in p.assumptions)
        )

    def test_syscall_image_words_contract_must_return_tuple(self):
        engine = Exec(
            object(),
            syscall_image_words=lambda *args: True,
        )
        p = self.make_path(1)

        with self.assertRaisesRegex(
            AssertionError,
            "syscall image-words contract must return tuple",
        ):
            engine.exec1(p, SYSCALL)


if __name__ == "__main__":
    unittest.main()
