"""Regression tests for R3000A COP0 move delay semantics."""

import sys
from pathlib import Path
import unittest

PROOF_DIR = Path(__file__).resolve().parents[1] / "tools" / "recomp" / "proof"
sys.path.insert(0, str(PROOF_DIR))

from mips import RNAME, decode
from sym import Exec, Path as ExecPath, SENTINEL


BASE = 0x80010000

# mfc0 v0,$12
MFC0_V0_SR = decode(0x40026000, BASE)

# sll zero,zero,0
NOP = decode(0x00000000, BASE + 4)


class Cop0DelayTest(unittest.TestCase):
    def test_mfc0_write_is_delayed_one_instruction(self):
        engine = Exec(object())

        p = ExecPath([0] * len(RNAME), BASE)
        old_v0 = 0x11223344
        p.r[2] = old_v0

        engine.tick(p, MFC0_V0_SR)

        # R3000A MFC0 has a one-instruction delayed write just like MFC2/CFC2.
        self.assertEqual(
            p.r[2],
            old_v0,
            "MFC0 became visible immediately instead of entering pending state",
        )

        self.assertIsNotNone(
            p.pending,
            "MFC0 did not create a delayed register write",
        )
        self.assertEqual(p.pending[0], 2)
        self.assertEqual(p.pending[1], ("S", "cop0r12"))

        engine.tick(p, NOP)

        self.assertIsNone(p.pending)
        self.assertEqual(p.r[2], ("S", "cop0r12"))


class DelayedWriteCancellationTest(unittest.TestCase):
    def setUp(self):
        self.engine = Exec(object())
        self.p = ExecPath([0] * len(RNAME), BASE)
        self.p.r[2] = 123
        self.p.r[4] = 0x80020000
        self.p.mem[0x80020000] = 456

    def tick(self, word, offset=0):
        self.engine.tick(self.p, decode(word, BASE + offset))

    def test_mfc0_mfc0_observer_sees_entry_value(self):
        self.tick(0x40026000)
        self.tick(0x40026800, 4)
        self.assertEqual(self.p.r[2], 123)
        self.tick(0x00401821, 8)  # addu v1,v0,zero
        self.assertEqual(self.p.r[3], 123)
        self.assertEqual(self.p.r[2], ('S', 'cop0r13'))
        self.assertEqual(self.p.prov[2], ('PAL_INSTRUCTION', BASE + 4, 'mfc0'))
        self.assertIsNone(self.p.pending)

    def test_lw_mfc0_observer_sees_entry_value(self):
        self.tick(0x8c820000)
        self.tick(0x40026000, 4)
        self.tick(0x00401821, 8)
        self.assertEqual(self.p.r[3], 123)
        self.assertEqual(self.p.r[2], ('S', 'cop0r12'))

    def test_mfc0_addiu_wins(self):
        self.tick(0x40026000)
        self.tick(0x24020007, 4)
        self.assertEqual(self.p.r[2], 7)
        self.assertIsNone(self.p.pending)
        self.assertIsNone(self.p.pending_prov)
        self.assertEqual(self.p.prov[2], ('PAL_INSTRUCTION', BASE + 4, 'addiu'))

    def test_ordinary_write_reads_old_value(self):
        self.tick(0x40026000)
        self.tick(0x24420007, 4)  # addiu v0,v0,7
        self.assertEqual(self.p.r[2], 130)
        self.assertIsNone(self.p.pending)

    def test_different_register_pending_matures(self):
        self.tick(0x40026000)
        self.tick(0x40036800, 4)  # mfc0 v1,$13
        self.assertEqual(self.p.r[2], ('S', 'cop0r12'))
        self.assertEqual(self.p.r[3], 0)
        self.assertEqual(self.p.pending, (3, ('S', 'cop0r13')))
        self.tick(0, 8)
        self.assertEqual(self.p.r[3], ('S', 'cop0r13'))
        self.assertIsNone(self.p.pending)

    def test_each_delayed_writer_cancels_pending(self):
        for word in (0x8c820000, 0x84820000, 0x80820000,
                     0x94820000, 0x90820000, 0x48020000, 0x48420000):
            with self.subTest(word=hex(word)):
                self.setUp()
                self.tick(0x40026000)
                self.tick(word, 4)
                result = self.p.pending[1]
                self.tick(0x00401821, 8)
                self.assertEqual(self.p.r[3], 123)
                self.assertEqual(self.p.r[2], result)

    def test_lw_ordinary_write_wins(self):
        self.tick(0x8c820000)
        self.tick(0x24020007, 4)
        self.assertEqual(self.p.r[2], 7)
        self.assertIsNone(self.p.pending)


class TransferDelayTest(unittest.TestCase):
    def run_words(self, words, init=None):
        from scan import Image
        image = Image('synthetic', b''.join(w.to_bytes(4, 'little') for w in words), BASE)
        return Exec(image).run(BASE, init=init)[0]

    def test_branch_reads_old_value_then_slot_sees_matured_load(self):
        p = self.run_words([
            0x40026000, 0x10400003, 0x00401821, 0x24030009,
            0, 0x03e00008, 0,
        ], {2: 0})
        self.assertEqual(p.r[3], ('S', 'cop0r12'))

    def test_jr_samples_old_target(self):
        p = self.run_words([0x40026000, 0x00400008, 0x00401821],
                           {2: SENTINEL})
        self.assertEqual(p.r[3], ('S', 'cop0r12'))

    def test_jalr_samples_old_target_and_link_cancels_pending(self):
        p = self.run_words([0x40026000, 0x00401009, 0x00401821],
                           {2: SENTINEL})  # jalr v0,v0
        self.assertEqual(p.r[2], BASE + 12)
        self.assertEqual(p.r[3], BASE + 12)
        self.assertIsNone(p.pending)
        self.assertEqual(p.prov[2], ('PAL_INSTRUCTION', BASE + 4, 'jalr'))

    def test_jal_link_cancels_pending(self):
        p = self.run_words([0x401f6000,  # mfc0 ra,$12
                            0x0c004004, 0x03e01821, 0,
                            0x01000008, 0], {8: SENTINEL})
        self.assertEqual(p.r[3], BASE + 12)
        self.assertEqual(p.r[31], BASE + 12)
        self.assertIsNone(p.pending)


class Cop0LivenessTest(unittest.TestCase):
    def effect(self, words):
        from scan import Image
        from live import Liveness
        image = Image('synthetic', b''.join(w.to_bytes(4, 'little') for w in words), BASE)
        live = Liveness(image, [], image.end, extra_entries=(BASE,))
        return live.summary(BASE, 2)

    def test_immediate_observer_is_live(self):
        self.assertEqual(self.effect([0x40026000, 0x00401821, 0x03e00008, 0]), 'READ')

    def test_observer_after_nop_is_dead(self):
        self.assertEqual(self.effect([0x40026000, 0, 0x00401821, 0x03e00008, 0]), 'KILL')

    def test_consecutive_delayed_writes_keep_entry_live(self):
        for first in (0x40026000, 0x8c820000):
            with self.subTest(first=hex(first)):
                self.assertEqual(self.effect([first, 0x40026800, 0x00401821,
                                              0x03e00008, 0]), 'READ')

    def test_ordinary_write_kills_entry_value(self):
        self.assertEqual(self.effect([0x40026000, 0x24020007, 0x00401821,
                                      0x03e00008, 0]), 'KILL')

    def test_other_register_does_not_extend_delay(self):
        self.assertEqual(self.effect([0x40026000, 0x40036800, 0x00401821,
                                      0x03e00008, 0]), 'KILL')

    def test_mfc0_in_branch_slot_keeps_entry_live_at_target(self):
        self.assertEqual(self.effect([0x10000001, 0x40026000, 0x00401821,
                                      0x03e00008, 0]), 'READ')


if __name__ == "__main__":
    unittest.main()
