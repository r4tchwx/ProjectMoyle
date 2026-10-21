"""REGIMM link regressions: synthetic ISA evidence, not PAL routine proofs.

PSX-SPX, CPU Jump Opcodes: BLTZAL/BGEZAL always link, taken or not.
https://psx-spx.consoledev.net/dev/ps1/cpu/cpuspecifications/
MIPS Technologies, Architecture For Programmers Vol II, rev 0.95,
BLTZAL/BGEZAL (marked MIPS I): sample condition, GPR[31] = PC + 8,
then execute the delay slot and select the successor.
https://courses.cs.washington.edu/courses/cse378/documentation/MIPS32_Architecture_For_Programmers_Volume_II.pdf

These tests deliberately remain RED until sym.py implements REGIMM links.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/recomp/proof'))
from mips import RNAME, decode
from scan import Image
from sym import Exec, Path as ExecPath, SENTINEL, preserved, exact_real_effects
from live import Liveness

BASE = 0x80010000
JR_T0 = 0x01000008


class RegimmLinkCases:
    def word(self):
        return (1 << 26) | (4 << 21) | (self.RT << 16) | 3

    def image(self, words):
        return Image('synthetic-regimm', b''.join(w.to_bytes(4, 'little') for w in words), BASE)

    def run_branch(self, value=None, slot=0x03e01821, prefix=()):
        # Two separate exits through t0 keep the test independent of ra's link.
        words = list(prefix) + [self.word(), slot, JR_T0, 0, JR_T0, 0]
        engine = Exec(self.image(words))
        init = {8: SENTINEL, 31: ('S', 'in.ra')}
        if value is not None:
            init[4] = value
        return engine.run(BASE, init=init)

    def assert_route(self, p, taken, pc=BASE):
        self.assertEqual(p.pc, SENTINEL)
        self.assertIn(pc + (16 if taken else 8), p.seen)
        self.assertNotIn(pc + (8 if taken else 16), p.seen)
        self.assertEqual(p.seen.count(pc + 4), 1)

    def test_decoder(self):
        i = decode(self.word(), BASE)
        self.assertEqual((i.name, i.kind, i.reads, i.writes, i.target),
                         (self.NAME, 'branch', {4}, {31}, BASE + 16))

    def test_concrete_taken(self):
        p, = self.run_branch(self.TAKEN)
        self.assert_route(p, True)
        self.assertEqual((p.r[31], p.r[3]), (BASE + 8, BASE + 8))
        self.assertEqual(p.prov[31], ('PAL_INSTRUCTION', BASE, self.NAME))

    def test_concrete_not_taken(self):
        p, = self.run_branch(self.NOT_TAKEN)
        self.assert_route(p, False)
        self.assertEqual((p.r[31], p.r[3]), (BASE + 8, BASE + 8))
        self.assertEqual(p.prov[31], ('PAL_INSTRUCTION', BASE, self.NAME))

    def test_symbolic_fork_links_both_paths(self):
        paths = self.run_branch()
        self.assertEqual(len(paths), 2)
        self.assertEqual({p.cond[0].taken for p in paths}, {False, True})
        for p in paths:
            with self.subTest(taken=p.cond[0].taken):
                self.assertEqual(p.cond[0].left, ('S', 'in.a0'))
                self.assert_route(p, p.cond[0].taken)
                self.assertEqual((p.r[31], p.r[3]), (BASE + 8, BASE + 8))
                self.assertEqual(p.prov[31], ('PAL_INSTRUCTION', BASE, self.NAME))
                self.assertIsNone(p.pending)

    def test_symbolic_link_is_not_entry_ra_preservation(self):
        paths = self.run_branch()
        self.assertFalse(preserved(paths, 31))
        self.assertEqual(exact_real_effects(paths, ['ra']), ({'ra'}, set()))
        self.assertTrue(all(p.r[31] == BASE + 8 for p in paths))

    def test_delay_slot_write_ra_wins_on_both_paths(self):
        paths = self.run_branch(slot=0x241f0007)  # addiu ra,zero,7
        self.assertEqual(len(paths), 2)
        for p in paths:
            self.assert_route(p, p.cond[0].taken)
            self.assertEqual(p.r[31], 7)
            self.assertEqual(p.prov[31], ('PAL_INSTRUCTION', BASE + 4, 'addiu'))
            self.assertIsNone(p.pending)

    def test_pending_ra_cancelled_before_slot_on_both_paths(self):
        # Exercise the shared transfer primitive independently of condition dispatch.
        for taken in (False, True):
            with self.subTest(taken=taken):
                engine = Exec(self.image([self.word(), 0x03e01821]))
                p = ExecPath([('S', 'in.' + n) for n in RNAME], BASE - 4)
                engine.tick(p, decode(0x401f6000, BASE - 4))  # mfc0 ra,$12
                engine.finish_branch(p, decode(self.word(), BASE), taken)
                self.assertIsNone(p.pending)
                self.assertIsNone(p.pending_prov)
                self.assertEqual(p.pc, BASE + (16 if taken else 8))
                self.assertEqual((p.r[31], p.r[3]), (BASE + 8, BASE + 8))
                self.assertEqual(p.prov[31], ('PAL_INSTRUCTION', BASE, self.NAME))

    def test_transfer_tick_cancels_pending_ra_without_retiring_it(self):
        # Like JAL/JALR, tick must cancel the old delayed write before the
        # transfer helper installs the link; a later overwrite can hide this bug.
        engine = Exec(self.image([self.word(), 0]))
        p = ExecPath([('S', 'in.' + n) for n in RNAME], BASE - 4)
        engine.tick(p, decode(0x401f6000, BASE - 4))
        engine.tick(p, decode(self.word(), BASE))
        self.assertIsNone(p.pending)
        self.assertIsNone(p.pending_prov)
        self.assertEqual(p.r[31], ('S', 'in.ra'))
        self.assertEqual(p.prov[31], ('ENTRY_VALUE', 'ra'))

    def test_pending_source_taken_samples_old_value(self):
        p, = self.run_branch(self.TAKEN, slot=0x00801821, prefix=(0x40046000,))
        self.assert_route(p, True, BASE + 4)
        self.assertEqual(p.r[3], ('S', 'cop0r12'))
        self.assertEqual(p.r[31], BASE + 12)
        self.assertIsNone(p.pending)

    def test_pending_source_not_taken_samples_old_value(self):
        p, = self.run_branch(self.NOT_TAKEN, slot=0x00801821, prefix=(0x40046000,))
        self.assert_route(p, False, BASE + 4)
        self.assertEqual(p.r[3], ('S', 'cop0r12'))
        self.assertEqual(p.r[31], BASE + 12)
        self.assertIsNone(p.pending)

    def test_symbolic_pending_source_fork_and_provenance(self):
        paths = self.run_branch(slot=0x00801821, prefix=(0x40046000,))
        self.assertEqual(len(paths), 2)
        self.assertEqual({p.cond[0].taken for p in paths}, {False, True})
        for p in paths:
            self.assertEqual(p.cond[0].left, ('S', 'in.a0'))
            self.assert_route(p, p.cond[0].taken, BASE + 4)
            self.assertEqual(p.r[3], ('S', 'cop0r12'))
            self.assertEqual(p.prov[4], ('PAL_INSTRUCTION', BASE, 'mfc0'))
            self.assertIsNone(p.pending)
        paths[0].prov[4] = ('AUDIT',)
        self.assertNotEqual(paths[0].prov[4], paths[1].prov[4])

    def test_delay_slot_delayed_ra_keeps_visible_link(self):
        for taken in (False, True):
            with self.subTest(taken=taken):
                engine = Exec(self.image([self.word(), 0x401f6000]))
                p = ExecPath([('S', 'in.' + n) for n in RNAME], BASE)
                engine.finish_branch(p, decode(self.word(), BASE), taken)
                self.assertEqual(p.pending, (31, ('S', 'cop0r12')))
                self.assertEqual(p.pending_prov, ('PAL_INSTRUCTION', BASE + 4, 'mfc0'))
                self.assertFalse(preserved([p], 31))
                self.assertEqual(exact_real_effects([p], ['ra']), (set(), {'ra'}))
                self.assertEqual(p.r[31], BASE + 8)
                self.assertEqual(p.prov[31], ('PAL_INSTRUCTION', BASE, self.NAME))

    def test_liveness_link_kills_entry_ra_but_reads_source(self):
        image = self.image([self.word(), 0x03e01821, JR_T0, 0, JR_T0, 0])
        live = Liveness(image, [], image.end, extra_entries=(BASE,))
        self.assertEqual(live.summary(BASE, 31), 'KILL')
        self.assertEqual(live.summary(BASE, 4), 'READ')


class BltzalLinkTest(RegimmLinkCases, unittest.TestCase):
    RT, NAME, TAKEN, NOT_TAKEN = 16, 'bltzal', 0xffffffff, 0


class BgezalLinkTest(RegimmLinkCases, unittest.TestCase):
    RT, NAME, TAKEN, NOT_TAKEN = 17, 'bgezal', 0, 0xffffffff


if __name__ == '__main__':
    unittest.main()
