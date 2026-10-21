"""Phase 6d R3000A model regressions: BIOS-entry / SYSCALL pending-load retirement, ra_restored, MFC0 delay
classification (scan.py / live.py / sym.py) and BREAK liveness. Synthetic only; no PAL assets required."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from phase6d_r3000a_asm import *  # noqa: F401,F403,E402
import phase6d_r3000a_asm as A  # noqa: E402
from mips import decode, is_delayed_write
from scan import sweep, bios_calls, delayed_write as scan_delayed_write
from live import Liveness, delayed_write as live_delayed_write, READ, KILL
from sym import (Exec, Path as ExecPath, RNAME, SENTINEL, preserved, ra_restored_at_return, restored,
                 exact_real_effects)

LANDING_A = BASE + 0x40     # return-to-link stub: v0 = 0x66
LANDING_B = BASE + 0x60     # return-to-loaded-ra stub: v0 = 0x55
HI16, LO16 = (SENTINEL >> 16) & 0xffff, SENTINEL & 0xffff


def finish_stub(v0):
    """addiu v0,zero,v0 ; lui at,hi(SENTINEL) ; ori at,at,lo(SENTINEL) ; jr at ; nop"""
    return [A.addiu(V0, ZERO, v0), A.lui(AT, HI16), A.ori(AT, AT, LO16), A.jr(AT), NOP]


def image_with_stubs(code, data=()):
    """code at BASE; v0=0x66 stub at LANDING_A; v0=0x55 stub at LANDING_B; data words at DATA."""
    img_words = [NOP] * 64
    for k, w in enumerate(code):
        img_words[k] = w
    for k, w in enumerate(finish_stub(0x66)):
        img_words[0x40 // 4 + k] = w
    for k, w in enumerate(finish_stub(0x55)):
        img_words[0x60 // 4 + k] = w
    return make_image(img_words, data)


def final_regs(p):
    """Architectural register file once the outstanding delayed write has landed."""
    r = list(p.r)
    if p.pending is not None:
        r[p.pending[0]] = p.pending[1]
    return r


class BiosEntryPendingLoadTest(unittest.TestCase):
    """The BIOS dispatcher reads t1 / a0..a3 / ra after a load issued in the transfer's delay slot has retired."""

    def run_one(self, code, data, init):
        engine = Exec(image_with_stubs(code, data))
        paths = engine.run(BASE, init)
        self.assertEqual(len(paths), 1)
        return paths[0]

    def bios_events(self, p):
        return [e for e in p.events if e[0] == "bios"]

    def test_jr_slot_load_into_call_number_register(self):
        # jr t2 ; lw t1,0(a0)   -- t1 held 0x56 before; the slot load brings 0x57
        p = self.run_one([A.jr(T2), A.lw(T1, 0, A0)], [0x57], {T2: 0xB0, T1: 0x56, A0: DATA})
        self.assertEqual(self.bios_events(p), [("bios", "B0", 0x57, DATA)])
        self.assertEqual(p.pc, SENTINEL)

    def test_jalr_slot_load_into_call_number_register(self):
        p = self.run_one([A.jalr(RA, T2), A.lw(T1, 0, A0)], [0x57], {T2: 0xB0, T1: 0x56, A0: DATA})
        self.assertEqual(self.bios_events(p), [("bios", "B0", 0x57, DATA)])

    def test_call_number_result_follows_retired_value(self):
        # B0:57 has a documented result (v0 = B0 table); the stale B0:56 would produce the C0 table instead.
        p = self.run_one([A.jr(T2), A.lw(T1, 0, A0)], [0x57], {T2: 0xB0, T1: 0x56, A0: DATA})
        self.assertEqual(p.r[V0], ("S", "B0TBL"))

    def test_mfc0_slot_into_call_number_register_fails_closed(self):
        # MFC0 result is symbolic: the dispatcher would read an unresolved function number. The old t1 (0x56)
        # must NOT be used.
        engine = Exec(image_with_stubs([A.jr(T2), A.mfc0(T1, 12)], []))
        with self.assertRaises(AssertionError) as cm:
            engine.run(BASE, {T2: 0xB0, T1: 0x56})
        self.assertIn("unresolved function number", str(cm.exception))

    def test_cop2_slot_into_call_number_register_fails_closed(self):
        for enc in (A.mfc2(T1, 3), A.cfc2(T1, 3)):
            engine = Exec(image_with_stubs([A.jr(T2), enc], []))
            with self.assertRaises(AssertionError):
                engine.run(BASE, {T2: 0xB0, T1: 0x56})

    def test_argument_register_load_is_seen_by_bios(self):
        p = self.run_one([A.jr(T2), A.lw(A0, 0, A1)], [0x2222], {T2: 0xB0, T1: 0x56, A0: 0x1111, A1: DATA})
        self.assertEqual(self.bios_events(p), [("bios", "B0", 0x56, 0x2222)])

    def test_vector_register_load_in_slot_uses_old_value_for_transfer(self):
        # jr reads t2 BEFORE the slot load retires; the load into t2 does not redirect the transfer.
        p = self.run_one([A.jr(T2), A.lw(T2, 0, A1)], [0x00BADBAD], {T2: 0xB0, T1: 0x56, A1: DATA})
        self.assertEqual(self.bios_events(p)[0][1:3], ("B0", 0x56))

    def test_ra_loaded_in_jalr_slot_is_the_bios_return_address(self):
        # jalr ra,t2 ; lw ra,0(a1)   -- the BIOS returns to the LOADED ra, not the jalr link.
        code = [A.jalr(RA, T2), A.lw(RA, 0, A1)]
        p = self.run_one(code, [LANDING_B], {T2: 0xB0, T1: 0x56, A1: DATA})
        self.assertEqual(p.r[V0], 0x55, "BIOS returned to the stale jalr link instead of the loaded ra")
        self.assertEqual(p.pc, SENTINEL)

    def test_ra_not_loaded_returns_to_link(self):
        code = [A.jalr(RA, T2), NOP]
        # pc+8 is the first word after the slot: place the v0=0x66 stub there
        img_words = [NOP] * 64
        img_words[0] = code[0]
        for k, w in enumerate(finish_stub(0x66)):
            img_words[2 + k] = w
        engine = Exec(make_image(img_words))
        p, = engine.run(BASE, {T2: 0xB0, T1: 0x56})
        self.assertEqual(p.r[V0], 0x66)

    def test_non_bios_load_delay_is_unchanged(self):
        # lw t1 ; addu v0,t1,zero (sees OLD t1) ; addu v1,t1,zero (sees NEW t1) ; jr ra ; nop
        code = [A.lw(T1, 0, A1), A.addu(V0, T1, ZERO), A.addu(V1, T1, ZERO), A.jr(RA), NOP]
        p = self.run_one(code, [0x1234], {T1: 0x77, A1: DATA})
        self.assertEqual((p.r[V0], p.r[V1], p.r[T1]), (0x77, 0x1234, 0x1234))

    def test_retire_pending_is_not_global(self):
        # A pending write is NOT retired by an ordinary transfer: jr's own operand sampling and the slot
        # still follow tick() order.
        engine = Exec(image_with_stubs([A.jr(RA), A.lw(S0, 0, A1)], [0x4242]))
        p, = engine.run(BASE, {S0: 1, A1: DATA})
        self.assertEqual(p.r[S0], 1)
        self.assertEqual(p.pending, (S0, 0x4242))


class SyscallPendingLoadTest(unittest.TestCase):
    def run_one(self, code, data, init):
        engine = Exec(image_with_stubs(code, data))
        paths = engine.run(BASE, init)
        self.assertEqual(len(paths), 1)
        return paths[0]

    def test_syscall_sees_a0_loaded_by_previous_instruction(self):
        # lw a0,0(a1) ; syscall ; jr ra ; nop   -- the exception handler reads the retired a0
        code = [A.lw(A0, 0, A1), A.syscall(), A.jr(RA), NOP]
        p = self.run_one(code, [1], {A0: 2, A1: DATA})
        self.assertEqual([e for e in p.events if e[0] == "syscall"], [("syscall", 1)])
        self.assertEqual(len(p.syscall_returns), 1)       # EnterCriticalSection summary applied
        self.assertEqual(p.r[A0], 1)                      # the load still lands in a0

    def test_syscall_exit_critical_via_loaded_a0(self):
        code = [A.lw(A0, 0, A1), A.syscall(), A.jr(RA), NOP]
        p = self.run_one(code, [2], {A0: 1, A1: DATA, V0: 0x1234})
        self.assertEqual([e for e in p.events if e[0] == "syscall"], [("syscall", 2)])
        self.assertEqual(p.syscall_returns, [])
        self.assertEqual(p.r[V0], 0x1234)                 # ExitCriticalSection preserves v0

    def test_syscall_stale_a0_is_not_used(self):
        code = [A.lw(A0, 0, A1), A.syscall(), A.jr(RA), NOP]
        p = self.run_one(code, [2], {A0: 1, A1: DATA})
        self.assertNotIn(("syscall", 1), p.events)

    def test_syscall_with_symbolic_loaded_a0_fails_closed(self):
        engine = Exec(image_with_stubs([A.mfc0(A0, 12), A.syscall(), A.jr(RA), NOP], []))
        with self.assertRaises(AssertionError) as cm:
            engine.run(BASE, {A0: 1})
        self.assertIn("unresolved a0", str(cm.exception))

    def test_syscall_without_pending_unchanged(self):
        code = [A.addiu(A0, ZERO, 1), A.syscall(), A.jr(RA), NOP]
        p = self.run_one(code, [], {})
        self.assertEqual([e for e in p.events if e[0] == "syscall"], [("syscall", 1)])

    def test_enter_critical_cancels_pending_v0_load(self):
        # lw v0 ; syscall(a0=1): the handler's v0 result replaces the (older) pending load
        code = [A.addiu(A0, ZERO, 1), A.lw(V0, 0, A1), A.syscall(), A.jr(RA), NOP]
        p = self.run_one(code, [0x9999], {A1: DATA})
        self.assertNotEqual(final_regs(p)[V0], 0x9999)
        self.assertEqual(final_regs(p)[V0][0:2], ("?", "EnterCS.ret"))


class RaRestoredTest(unittest.TestCase):
    def run_one(self, code, data=(), init=None):
        engine = Exec(image_with_stubs(code, data))
        paths = engine.run(BASE, init or {})
        self.assertEqual(len(paths), 1)
        return paths[0]

    def old_predicate(self, paths):
        return all(p.r[31] == SENTINEL for p in paths)

    def test_normal_epilogue_is_restored(self):
        # lw ra,0(a0) ; nop ; jr ra ; nop   (loaded value is the caller's ra)
        p = self.run_one([A.lw(RA, 0, A0), NOP, A.jr(RA), NOP], [SENTINEL], {A0: DATA})
        self.assertIsNone(p.pending)
        self.assertTrue(ra_restored_at_return([p]))

    def test_untouched_ra_is_restored(self):
        p = self.run_one([A.jr(RA), NOP])
        self.assertTrue(ra_restored_at_return([p]))

    def test_load_into_ra_in_return_delay_slot_is_not_restored(self):
        # jr ra ; lw ra,0(a0): returns through the OLD ra but ra is architecturally the loaded value afterwards
        p = self.run_one([A.jr(RA), A.lw(RA, 0, A0)], [BASE + 0x123 * 4], {A0: DATA})
        self.assertEqual(p.r[RA], SENTINEL)                  # visible register file still looks restored ...
        self.assertEqual(p.pending[0], RA)                   # ... but a load into ra is in flight
        self.assertTrue(self.old_predicate([p]))             # the historical predicate was fooled
        self.assertFalse(ra_restored_at_return([p]))

    def test_load_of_same_value_into_ra_in_slot_fails_closed(self):
        # consistent with preserved(): any outstanding delayed write to the register is not a restored boundary
        p = self.run_one([A.jr(RA), A.lw(RA, 0, A0)], [SENTINEL], {A0: DATA})
        self.assertFalse(ra_restored_at_return([p]))

    def test_mfc0_into_ra_in_slot_is_not_restored(self):
        p = self.run_one([A.jr(RA), A.mfc0(RA, 12)])
        self.assertEqual(p.pending, (RA, ("S", "cop0r12")))
        self.assertFalse(ra_restored_at_return([p]))

    def test_load_into_other_register_does_not_poison_ra(self):
        p = self.run_one([A.jr(RA), A.lw(S0, 0, A0)], [0x1234], {A0: DATA})
        self.assertEqual(p.pending[0], S0)
        self.assertTrue(ra_restored_at_return([p]))
        self.assertFalse(preserved([p], S0))

    def test_ra_overwritten_is_not_restored(self):
        # ra clobbered, then control still reaches the caller through another register
        p = self.run_one([A.addiu(RA, ZERO, 5), A.lui(AT, HI16), A.ori(AT, AT, LO16), A.jr(AT), NOP])
        self.assertEqual(p.pc, SENTINEL)
        self.assertFalse(ra_restored_at_return([p]))

    def test_every_path_is_required(self):
        good = self.run_one([A.jr(RA), NOP])
        bad = self.run_one([A.jr(RA), A.lw(RA, 0, A0)], [SENTINEL], {A0: DATA})
        self.assertFalse(ra_restored_at_return([good, bad]))
        self.assertFalse(ra_restored_at_return([]))

    def test_restored_generalizes_preserved(self):
        p = self.run_one([A.jr(RA), NOP])
        self.assertEqual(preserved([p], S0), restored([p], S0, ("S", "in.s0")))


class Mfc0DelayClassificationTest(unittest.TestCase):
    """scan.py, live.py and sym.py must agree on which instructions write their GPR one instruction late."""

    CASES = [
        ("lw", A.lw(T0, 0, A0), True), ("lb", i_type(32, A0, T0, 0), True), ("lwl", i_type(34, A0, T0, 0), True),
        ("lwr", i_type(38, A0, T0, 0), True), ("mfc0", A.mfc0(T0, 12), True), ("mfc2", A.mfc2(T0, 3), True),
        ("cfc2", A.cfc2(T0, 3), True), ("mtc0", A.mtc0(T0, 12), False), ("addu", A.addu(T0, T1, T2), False),
        ("addiu", A.addiu(T0, ZERO, 1), False), ("mfhi", r_type(0x10, 0, 0, T0), False),
    ]

    def test_all_three_predicates_agree(self):
        for name, word, expected in self.CASES:
            with self.subTest(op=name):
                i = decode(word, BASE)
                self.assertEqual(is_delayed_write(i), expected)
                self.assertEqual(scan_delayed_write(i), expected)
                self.assertEqual(live_delayed_write(i), expected)

    def test_executor_agrees(self):
        engine = Exec(make_image([]))
        for name, word, expected in self.CASES:
            i = decode(word, BASE)
            if name in ("mtc0", "mfhi", "lwl", "lwr", "lb"):
                continue     # not modelled by the executor (fail closed) or not a GPR producer there
            with self.subTest(op=name):
                p = ExecPath([0] * len(RNAME), BASE)
                p.r[A0] = DATA
                old = 0x1111
                p.r[T0] = old
                engine.tick(p, i)
                if expected:
                    self.assertEqual(p.r[T0], old)
                    self.assertEqual(p.pending[0], T0)
                else:
                    self.assertIsNone(p.pending)

    def test_sweep_jr_target_uses_value_before_mfc0(self):
        # addiu t2,zero,0xb0 ; mfc0 t2,$12 ; jr t2 ; nop  -- jr is in the MFC0 delay slot and sees OLD t2
        img = make_image([A.addiu(T2, ZERO, 0xB0), A.mfc0(T2, 12), A.jr(T2), NOP])
        recs = sweep(img)
        self.assertEqual(recs[2]["tgt"], 0xB0)
        self.assertEqual([(c["vec"], c["pc"]) for c in bios_calls(img, recs)], [("B0", BASE + 8)])

    def test_sweep_jr_target_after_nop_is_new_value_unknown(self):
        img = make_image([A.addiu(T2, ZERO, 0xB0), A.mfc0(T2, 12), NOP, A.jr(T2), NOP])
        recs = sweep(img)
        self.assertIsNone(recs[3]["tgt"])

    def test_mfc0_cell_provenance_is_that_of_the_old_register(self):
        # lui t3,0x8001 ; lw t2,0x40(t3) ; mfc0 t2,$12 ; jr t2 ; nop
        # jr sits in the MFC0 delay slot, so it consumes the pointer LOADED FROM the cell, not the MFC0 result.
        img = make_image([A.lui(T3, 0x8001), A.lw(T2, 0x40, T3), A.mfc0(T2, 12), A.jr(T2), NOP])
        recs = sweep(img)
        self.assertEqual(recs[3]["cell"], BASE + 0x40)

    def test_t1_after_slot_not_stale_when_slot_is_delayed_write(self):
        for name, slot in (("lw", A.lw(T1, 0, A0)), ("mfc0", A.mfc0(T1, 12)),
                           ("mfc2", A.mfc2(T1, 3)), ("cfc2", A.cfc2(T1, 3))):
            for tname, transfer in (("jr", A.jr(T2)), ("jalr", A.jalr(RA, T2)), ("j", A.j(0xA0)),
                                    ("jal", i_type(3, 0, 0, 0) | ((0xA0 >> 2) & 0x3ffffff))):
                with self.subTest(slot=name, transfer=tname):
                    img = make_image([A.addiu(T1, ZERO, 0x56), A.addiu(T2, ZERO, 0xB0), transfer, slot])
                    recs = sweep(img)
                    self.assertIsNone(recs[2]["t1_after_slot"],
                                      "stale t1=0x56 survived a delayed write in the delay slot")

    def test_t1_after_slot_alu_still_exact(self):
        for tname, transfer in (("jr", A.jr(T2)), ("jalr", A.jalr(RA, T2)), ("j", A.j(0xA0))):
            with self.subTest(transfer=tname):
                img = make_image([A.addiu(T2, ZERO, 0xB0), transfer, A.addiu(T1, ZERO, 0x44)])
                recs = sweep(img)
                self.assertEqual(recs[1]["t1_after_slot"], 0x44)

    def test_bios_call_fn_unknown_when_slot_loads_t1(self):
        img = make_image([A.addiu(T1, ZERO, 0x56), A.addiu(T2, ZERO, 0xB0), A.jr(T2), A.lw(T1, 0, A0)])
        recs = sweep(img)
        calls = bios_calls(img, recs)
        self.assertEqual([(c["vec"], c["fn"]) for c in calls], [("B0", None)])

    def live_for(self, words):
        img = make_image(words)
        recs = sweep(img)
        end = BASE + 4 * len(words)
        return Liveness(img, recs, end, extra_entries=(BASE,), text_ranges=((BASE, end),))

    def test_liveness_direct_bios_call_with_unknown_function_number_reads_t1(self):
        # addiu t2,zero,0xb0 ; jalr t2 ; nop ; addiu t1,zero,1 ; jr ra ; nop
        # t1 is never set before the vector call, so the dispatcher consumes the entry t1.
        L = self.live_for([A.addiu(T2, ZERO, 0xB0), A.jalr(RA, T2), NOP, A.addiu(T1, ZERO, 1), A.jr(RA), NOP])
        self.assertEqual(L.summary(BASE, T1), READ)

    def test_liveness_direct_bios_call_with_known_function_number_does_not_read_t1(self):
        # same, but t1 = 0x56 is set locally before the call: entry t1 is dead
        L = self.live_for([A.addiu(T1, ZERO, 0x56), A.addiu(T2, ZERO, 0xB0), A.jalr(RA, T2), NOP,
                           A.addiu(T1, ZERO, 1), A.jr(RA), NOP])
        self.assertEqual(L.summary(BASE, T1), KILL)

    def test_liveness_mfc0_branch_reads_old_and_slot_reads_new(self):
        old = self.live_for([A.mfc0(T0, 12), A.beq(T0, ZERO, 1), NOP, A.jr(RA), NOP])
        self.assertEqual(old.summary(BASE, T0), READ)
        new = self.live_for([A.mfc0(T0, 12), A.beq(ZERO, ZERO, 1), A.addu(T1, T0, ZERO), A.jr(RA), NOP])
        self.assertEqual(new.summary(BASE, T0), KILL)


class BreakLivenessTest(unittest.TestCase):
    def live_for(self, words):
        img = make_image(words)
        recs = sweep(img)
        end = BASE + 4 * len(words)
        return Liveness(img, recs, end, extra_entries=(BASE,), text_ranges=((BASE, end),))

    def test_instruction_after_break_is_not_sequential_execution(self):
        # break ; addiu t0,zero,1 ; jr ra ; nop
        # With ordinary fall-through t0 is overwritten by the addiu and would be classified dead.
        L = self.live_for([A.break_(), A.addiu(T0, ZERO, 1), A.jr(RA), NOP])
        self.assertEqual(L.summary(BASE, T0), READ)
        self.assertEqual(L.query(T0, BASE, [], BASE)[0], "live")
        self.assertIn("BREAK", L.query(T0, BASE, [], BASE)[1])
        self.assertEqual(L.unmodeled_exceptions, {BASE})

    def test_code_after_break_cannot_kill_any_register(self):
        L = self.live_for([A.break_(), A.addiu(T0, ZERO, 1), A.addiu(S0, ZERO, 2), A.jr(RA), NOP])
        for reg in (T0, S0, V0, A0, RA):
            with self.subTest(reg=RNAME[reg]):
                self.assertEqual(L.summary(BASE, reg), READ)

    def test_code_after_break_cannot_be_the_only_reader_either(self):
        # no fabricated reads: a register already overwritten BEFORE the break stays dead
        L = self.live_for([A.addiu(T0, ZERO, 1), A.break_(), A.addu(V0, T0, ZERO), A.jr(RA), NOP])
        self.assertEqual(L.summary(BASE, T0), KILL)
        self.assertEqual(L.unmodeled_exceptions, set())

    def test_break_not_reached_is_irrelevant(self):
        # beq zero,zero past the break ; nop ; break ; addiu t0 ... : the break is skipped by the taken branch
        words = [A.beq(ZERO, ZERO, 2), NOP, A.break_(), A.addiu(T0, ZERO, 1), A.jr(RA), NOP]
        L = self.live_for(words)
        L.forced[BASE] = BASE + 4 * 3     # evidence-pinned successor: the taken edge only (addiu t0)
        self.assertEqual(L.summary(BASE, T0), KILL)
        self.assertEqual(L.unmodeled_exceptions, set())

    def test_break_in_delay_slot_fails_closed(self):
        L = self.live_for([A.beq(ZERO, ZERO, 1), A.break_(), A.addiu(T0, ZERO, 1), A.jr(RA), NOP])
        self.assertEqual(L.summary(BASE, T0), READ)
        self.assertEqual(L.unmodeled_exceptions, {BASE + 4})

    def test_break_after_in_flight_load_does_not_assume_resume(self):
        L = self.live_for([A.lw(T0, 0, A0), A.break_(), A.addiu(T1, ZERO, 1), A.jr(RA), NOP])
        self.assertEqual(L.summary(BASE, T1), READ)

    def test_executor_break_fails_closed(self):
        engine = Exec(make_image([A.break_(), A.addiu(V0, ZERO, 1), A.jr(RA), NOP]))
        with self.assertRaises(AssertionError):
            engine.run(BASE)


if __name__ == "__main__":
    unittest.main()
