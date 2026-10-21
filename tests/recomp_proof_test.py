"""Synthetic Phase 6d regressions; no PAL EXE or TITLE assets required."""

from pathlib import Path
import sys
import unittest


PROOF_DIR = Path(__file__).resolve().parents[1] / "tools" / "recomp" / "proof"
sys.path.insert(0, str(PROOF_DIR))

from sym import Exec, Path as ExecPath, RNAME, add
from scan import Image, sweep, synthetic_regressions
from live import Liveness, READ


class FakeImage:
    """One synthetic, little-endian word in the cached address segment."""

    BASE = 0x80010000
    INITIAL_WORD = 0x11223344

    def has(self, addr):
        return self.BASE <= addr < self.BASE + 4

    def word(self, addr):
        if addr != self.BASE:
            raise AssertionError("Unexpected image word address: %r" % addr)
        return self.INITIAL_WORD


class PartialStoreTest(unittest.TestCase):
    def setUp(self):
        self.image = FakeImage()
        self.engine = Exec(self.image)
        self.path = ExecPath([0] * len(RNAME), self.image.BASE)
        self.assertEqual(
            self.engine.load(self.path, self.image.BASE, 4, False),
            0x11223344,
        )

    def check_store(self, addr, width, value, expected):
        self.engine.store(self.path, addr, width, value)
        actual = self.engine.load(self.path, self.image.BASE, 4, False)
        self.assertEqual(
            actual,
            expected,
            "store width=%d addr=%s value=%s: expected %s, got %s"
            % (width, hex(addr), hex(value), hex(expected), hex(actual)),
        )

    def test_sb_offset_0(self):
        self.check_store(self.image.BASE + 0, 1, 0xAA, 0x112233AA)

    def test_sb_offset_1(self):
        self.check_store(self.image.BASE + 1, 1, 0xAA, 0x1122AA44)

    def test_sb_offset_3(self):
        self.check_store(self.image.BASE + 3, 1, 0xAA, 0xAA223344)

    def test_sh_offset_0(self):
        self.check_store(self.image.BASE + 0, 2, 0xBBAA, 0x1122BBAA)

    def test_sh_offset_2(self):
        self.check_store(self.image.BASE + 2, 2, 0xBBAA, 0xBBAA3344)



    def test_partial_store_over_unknown_word_does_not_resurrect_image(self):
        self.path.mem[self.image.BASE] = ("?", "unknown.word")

        self.engine.store(self.path, self.image.BASE, 1, 0xAA)
        actual = self.engine.load(self.path, self.image.BASE, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "partial store over unknown word must stay conservative; got %s"
            % repr(actual),
        )

class BiosPendingLoadTest(unittest.TestCase):
    LOAD_PC = 0x80001000

    def setUp(self):
        self.image = FakeImage()
        self.engine = Exec(self.image)
        self.path = ExecPath([0] * len(RNAME), self.image.BASE)

    def queue_load(self, reg, value):
        prov = ("PAL_INSTRUCTION", self.LOAD_PC, "lw")
        self.engine.commit(
            self.path,
            ("load", reg, value, prov),
            self.LOAD_PC,
        )
        self.assertEqual(self.path.pending, (reg, value))

    def test_bios_summary_overrides_pending_load_to_clobbered_result_register(self):
        self.queue_load(2, 0xDEADBEEF)

        self.engine.bios(self.path, "B0", 0x56, 0xB0)

        self.assertIsNone(self.path.pending)
        self.assertIsNone(self.path.pending_prov)
        self.assertEqual(self.path.r[2], ("S", "C0TBL"))

    def test_bios_summary_retires_pending_load_to_preserved_register(self):
        self.queue_load(16, 0xCAFEBABE)

        self.engine.bios(self.path, "B0", 0x56, 0xB0)

        self.assertIsNone(self.path.pending)
        self.assertIsNone(self.path.pending_prov)
        self.assertEqual(self.path.r[16], 0xCAFEBABE)
        self.assertEqual(
            self.path.prov[16],
            ("PAL_INSTRUCTION", self.LOAD_PC, "lw"),
        )


class IndirectLoadDelayProvenanceTest(unittest.TestCase):
    BASE = 0x80010000
    CELL = BASE + 0x20

    def test_existing_jalr_target_delay_regression(self):
        self.assertTrue(synthetic_regressions())

    def test_jalr_does_not_claim_new_load_cell_provenance(self):
        words = [
            0x3C088001,  # lui   t0,0x8001
            0x25080020,  # addiu t0,t0,0x20
            0x8D0A0000,  # lw    t2,0(t0)
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,
            0x80010010,  # CELL: tempting known target, but not visible to jalr yet
        ]

        img = Image(
            "synthetic-cell-delay",
            b"".join(w.to_bytes(4, "little") for w in words),
            self.BASE,
        )
        recs = sweep(img)
        jalr = next(r for r in recs if r["i"].pc == self.BASE + 12)

        # Old t2 is unknown at entry, so the immediately following jalr
        # cannot use the value loaded by lw.
        self.assertIsNone(jalr.get("tgt"))

        # The new load's source cell is equally ineligible as provenance
        # for resolving this transfer.
        self.assertIsNone(
            jalr.get("cell"),
            "jalr incorrectly inherited cell provenance from its preceding lw",
        )


    def test_jalr_preserves_old_cell_provenance_across_new_load(self):
        old_cell = self.BASE + 0x28
        new_cell = self.BASE + 0x2C

        words = [
            0x3C088001,  # lui   t0,0x8001
            0x25080028,  # addiu t0,t0,0x28
            0x8D0A0000,  # lw    t2,0(t0)       <- old_cell
            0x00000000,  # nop                  <- first load matures
            0x25080004,  # addiu t0,t0,4
            0x8D0A0000,  # lw    t2,0(t0)       <- new_cell
            0x0140F809,  # jalr  ra,t2          <- must still see old t2
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x80010010,  # old_cell
            0x80010014,  # new_cell
        ]

        img = Image(
            "synthetic-old-cell-delay",
            b"".join(w.to_bytes(4, "little") for w in words),
            self.BASE,
        )

        recs = sweep(img)
        jalr = next(r for r in recs if r["i"].pc == self.BASE + 24)

        self.assertEqual(
            jalr.get("cell"),
            old_cell,
            "jalr must retain the pre-load cell provenance across the load delay",
        )

class InvalidInstructionLivenessTest(unittest.TestCase):
    BASE = 0x80010000

    def test_invalid_instruction_is_conservative_for_liveness(self):
        words = [
            0xFC000000,  # reserved primary opcode -> kind == "invalid"
            0x24080001,  # addiu t0,zero,1
            0x03E00008,  # jr    ra
            0x00000000,  # nop
        ]

        img = Image(
            "synthetic-invalid-liveness",
            b"".join(w.to_bytes(4, "little") for w in words),
            self.BASE,
        )

        self.assertEqual(img.at(self.BASE).kind, "invalid")

        recs = sweep(img)
        live = Liveness(
            img,
            recs,
            self.BASE + len(words) * 4,
            extra_entries=(self.BASE,),
        )

        result, why = live.query(
            8,              # t0
            self.BASE,
            [],
            self.BASE,
        )

        self.assertEqual(
            result,
            "live",
            "unsupported instruction must conservatively keep t0 live; got %r (%r)"
            % (result, why),
        )


class KsegAliasMemoryTest(unittest.TestCase):
    KSEG0 = 0x80010000
    KSEG1 = 0xA0010000

    def make_state(self):
        image = FakeImage()
        engine = Exec(image)
        path = ExecPath([0] * len(RNAME), image.BASE)
        return engine, path

    def test_kseg1_load_aliases_initial_kseg0_image(self):
        engine, path = self.make_state()

        actual = engine.load(path, self.KSEG1, 4, False)

        self.assertEqual(
            actual,
            0x11223344,
            "KSEG1 must observe the same physical image word as KSEG0",
        )

    def test_kseg0_store_is_visible_through_kseg1(self):
        engine, path = self.make_state()

        engine.store(path, self.KSEG0, 4, 0xDEADBEEF)
        actual = engine.load(path, self.KSEG1, 4, False)

        self.assertEqual(
            actual,
            0xDEADBEEF,
            "KSEG1 load did not observe KSEG0 store",
        )

    def test_kseg1_store_is_visible_through_kseg0(self):
        engine, path = self.make_state()

        engine.store(path, self.KSEG1, 4, 0xCAFEBABE)
        actual = engine.load(path, self.KSEG0, 4, False)

        self.assertEqual(
            actual,
            0xCAFEBABE,
            "KSEG0 load did not observe KSEG1 store",
        )


    def test_kseg1_partial_store_is_visible_through_kseg0(self):
        engine, path = self.make_state()

        engine.store(path, self.KSEG1, 1, 0xAA)
        actual = engine.load(path, self.KSEG0, 4, False)

        self.assertEqual(
            actual,
            0x112233AA,
            "KSEG0 load did not observe KSEG1 byte store",
        )

    def test_kseg0_partial_store_is_visible_through_kseg1(self):
        engine, path = self.make_state()

        engine.store(path, self.KSEG0 + 2, 2, 0xBBAA)
        actual = engine.load(path, self.KSEG1, 4, False)

        self.assertEqual(
            actual,
            0xBBAA3344,
            "KSEG1 load did not observe KSEG0 halfword store",
        )

class SymbolicStoreAliasingTest(unittest.TestCase):
    BASE = 0x80010000

    def make_state(self):
        image = FakeImage()
        engine = Exec(image)
        path = ExecPath([0] * len(RNAME), image.BASE)
        return engine, path

    def test_symbolic_word_store_invalidates_concrete_cached_word(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        engine.store(path, ("S", "ptr"), 4, 0xCAFEBABE)

        actual = engine.load(path, self.BASE, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "unknown-address store left stale concrete memory value %r" % (actual,),
        )

    def test_symbolic_store_blocks_pristine_image_fallback(self):
        engine, path = self.make_state()

        engine.store(path, ("S", "ptr"), 4, 0xCAFEBABE)
        actual = engine.load(path, self.BASE, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "unknown-address store allowed stale image fallback %r" % (actual,),
        )

    def test_render_collision_does_not_create_false_exact_alias(self):
        engine, path = self.make_state()

        # These are structurally different symbolic addresses but render to
        # the same display text: "p+0x4".
        #
        # We do NOT know that they are non-aliasing. The sound requirement is
        # only that storing through the second address must never make a later
        # load through the first return the second store's exact value merely
        # because their rendered strings collide.
        first = ("S", "p+0x4")
        second = add(("S", "p"), 4)

        engine.store(path, first, 4, 0x11111111, pc=0x80001000)
        engine.store(path, second, 4, 0x22222222, pc=0x80001004)

        first_value = engine.load(path, first, 4, False)
        second_value = engine.load(path, second, 4, False)

        self.assertNotEqual(
            first_value,
            0x22222222,
            "render-string collision created false exact symbolic alias",
        )
        self.assertEqual(
            second_value,
            0x22222222,
            "most recent exact symbolic store must remain readable at its own address",
        )
    def test_exact_symbolic_word_store_remains_readable(self):
        engine, path = self.make_state()
        addr = ("S", "ptr")

        engine.store(path, addr, 4, 0xCAFEBABE)
        actual = engine.load(path, addr, 4, False)

        self.assertEqual(
            actual,
            0xCAFEBABE,
            "exact symbolic store/load pair lost its precise value",
        )

    def test_symbolic_partial_store_invalidates_concrete_memory(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        engine.store(path, ("S", "ptr"), 1, 0xAA)

        actual = engine.load(path, self.BASE, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "symbolic partial store left stale concrete memory value %r" % (actual,),
        )


    def test_concrete_store_after_symbolic_clobber_restores_precision(self):
        engine, path = self.make_state()

        engine.store(path, ("S", "ptr"), 4, 0xCAFEBABE)
        engine.store(path, self.BASE, 4, 0xDEADBEEF)

        actual = engine.load(path, self.BASE, 4, False)

        self.assertEqual(
            actual,
            0xDEADBEEF,
            "later concrete store must restore precision for its exact word",
        )

    def test_unknown_reload_after_symbolic_write_gets_new_identity(self):
        engine, path = self.make_state()

        observed_addr = ("S", "observed.addr")
        maybe_alias = ("S", "maybe.alias")

        before = engine.load(path, observed_addr, 4, False)

        # This store may alias observed_addr. Even though no exact fact for
        # observed_addr exists, it changes the possible memory state.
        engine.store(
            path,
            maybe_alias,
            4,
            0x12345678,
            pc=0x80001000,
        )

        after = engine.load(path, observed_addr, 4, False)

        self.assertNotEqual(
            before,
            after,
            "unknown memory read identity survived a potentially aliasing store",
        )
    def test_same_base_disjoint_symbolic_words_coexist(self):
        engine, path = self.make_state()

        sp = ("S", "in.sp")
        ra_slot = add(sp, (-4) & 0xFFFFFFFF)
        s0_slot = add(sp, (-8) & 0xFFFFFFFF)

        engine.store(path, ra_slot, 4, 0x11111111, pc=0x8005A358)
        engine.store(path, s0_slot, 4, 0x22222222, pc=0x8005A360)

        self.assertEqual(
            engine.load(path, ra_slot, 4, False),
            0x11111111,
            "disjoint symbolic stack word was incorrectly invalidated",
        )
        self.assertEqual(
            engine.load(path, s0_slot, 4, False),
            0x22222222,
        )
    def test_same_base_partial_overlap_invalidates_word(self):
        engine, path = self.make_state()

        base = ("S", "frame")
        word = add(base, 0x10)
        overlap = add(base, 0x12)

        engine.store(path, word, 4, 0x11223344, pc=0x80001000)
        engine.store(path, overlap, 2, 0xAABB, pc=0x80001004)

        actual = engine.load(path, word, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "overlapping symbolic halfword incorrectly preserved old word: %r"
            % (actual,),
        )

    def test_same_base_wraparound_overlap_invalidates_word(self):
        engine, path = self.make_state()

        base = ("S", "frame")
        # This four-byte range is:
        #   base+fffffffe, base+ffffffff, base+00000000, base+00000001
        word = add(base, 0xFFFFFFFE)
        overlap = base

        engine.store(path, word, 4, 0x11223344, pc=0x80001000)
        engine.store(path, overlap, 1, 0xAA, pc=0x80001004)

        actual = engine.load(path, word, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "32-bit wraparound overlap incorrectly preserved old word: %r"
            % (actual,),
        )
    def test_later_symbolic_store_invalidates_prior_exact_symbolic_value(self):
        engine, path = self.make_state()
        first = ("S", "ptr")
        second = ("S", "other")

        engine.store(path, first, 4, 0xCAFEBABE)
        engine.store(path, second, 4, 0xDEADBEEF)

        actual = engine.load(path, first, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "later unknown-address store left stale exact symbolic value %r"
            % (actual,),
        )

    def test_concrete_store_invalidates_prior_symbolic_alias_value(self):
        engine, path = self.make_state()
        addr = ("S", "ptr")

        engine.store(path, addr, 4, 0xCAFEBABE)
        engine.store(path, self.BASE, 4, 0xDEADBEEF)

        actual = engine.load(path, addr, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "concrete store left stale symbolic-alias value %r" % (actual,),
        )


    def test_explicit_symbolic_store_nonalias_contract_is_narrow(self):
        image = FakeImage()
        protected = self.BASE
        unprotected = self.BASE + 4
        contract_pc = self.BASE + 0x80

        def nonalias(pc, symbolic_addr, width, concrete_addr):
            return pc == contract_pc and concrete_addr == protected

        engine = Exec(
            image,
            symbolic_store_nonalias=nonalias,
        )
        path = ExecPath([0] * len(RNAME), self.BASE)

        engine.store(path, protected, 4, 0xDEADBEEF)
        engine.store(path, unprotected, 4, 0x12345678)

        path.pc = contract_pc
        engine.store(path, ("S", "bios_patch_dst"), 4, 0xCAFEBABE)

        self.assertTrue(
            path.mem_unknown,
            "opt-in non-alias contract must not make symbolic memory globally precise",
        )

        self.assertEqual(
            engine.load(path, protected, 4, False),
            0xDEADBEEF,
            "explicitly disjoint concrete word was not preserved",
        )

        actual = engine.load(path, unprotected, 4, False)
        self.assertFalse(
            isinstance(actual, int),
            "non-alias contract leaked to an unprotected concrete word: %r"
            % (actual,),
        )
class BiosMemoryEffectTest(unittest.TestCase):
    BASE = 0x80010000

    def make_state(self):
        image = FakeImage()
        engine = Exec(image)
        path = ExecPath([0] * len(RNAME), image.BASE)
        return engine, path

    def test_get_c0_table_preserves_modeled_memory(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        engine.bios(path, "B0", 0x56, 0xB0)

        self.assertEqual(
            engine.load(path, self.BASE, 4, False),
            0xDEADBEEF,
        )

    def test_get_b0_table_preserves_modeled_memory(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        engine.bios(path, "B0", 0x57, 0xB0)

        self.assertEqual(
            engine.load(path, self.BASE, 4, False),
            0xDEADBEEF,
        )

    def test_flush_cache_preserves_modeled_memory(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        engine.bios(path, "A0", 0x44, 0xA0)

        self.assertEqual(
            engine.load(path, self.BASE, 4, False),
            0xDEADBEEF,
        )

    def test_explicit_bios_memory_preserve_contract_is_narrow(self):
        keep_addr = ("S", "in.sp-0x4")
        drop_addr = ("S", "in.sp-0x8")
        callsite = 0x8005A364

        def preserve(site, vec, fn, word_key):
            return (
                site == callsite
                and vec == "B0"
                and fn == 0x4B
                and word_key == ("sym", keep_addr)
            )

        image = FakeImage()
        engine = Exec(image, bios_memory_preserve=preserve)
        path = ExecPath([0] * len(RNAME), image.BASE)

        # Seed two already-established symbolic memory facts directly.
        # Using store() here would test symbolic-store aliasing instead of
        # isolating the BIOS selective-preservation contract.
        path.mem[("sym", keep_addr)] = 0x11111111
        path.mem[("sym", drop_addr)] = 0x22222222

        path.last_callsite = callsite
        engine.bios(path, "B0", 0x4B, 0xB0)

        self.assertEqual(
            engine.load(path, keep_addr, 4, False),
            0x11111111,
            "explicitly preserved BIOS memory fact was lost",
        )

        dropped = engine.load(path, drop_addr, 4, False)
        self.assertFalse(
            isinstance(dropped, int),
            "unapproved BIOS memory fact survived the call: %r" % (dropped,),
        )

        self.assertTrue(
            path.mem_unknown,
            "partial BIOS preserve contract must not restore global memory precision",
        )

        self.assertEqual(
            path.assumptions,
            [
                (
                    "bios_memory_preserve",
                    callsite,
                    "B0",
                    0x4B,
                    ("sym", keep_addr),
                )
            ],
        )
    def test_bios_memory_preserve_contract_exception_aborts(self):
        image = FakeImage()

        def preserve(site, vec, fn, word_key):
            raise RuntimeError("boom")

        engine = Exec(image, bios_memory_preserve=preserve)
        path = ExecPath([0] * len(RNAME), image.BASE)
        path.mem[("sym", "stack")] = 0x11111111
        path.last_callsite = 0x8005A364

        with self.assertRaisesRegex(
            AssertionError,
            "BIOS memory-preserve contract failed",
        ):
            engine.bios(path, "B0", 0x4B, 0xB0)

    def test_bios_memory_preserve_contract_non_bool_aborts(self):
        image = FakeImage()

        def preserve(site, vec, fn, word_key):
            return 1

        engine = Exec(image, bios_memory_preserve=preserve)
        path = ExecPath([0] * len(RNAME), image.BASE)
        path.mem[("sym", "stack")] = 0x11111111
        path.last_callsite = 0x8005A364

        with self.assertRaisesRegex(
            AssertionError,
            "BIOS memory-preserve contract must return bool",
        ):
            engine.bios(path, "B0", 0x4B, 0xB0)
    def test_uncontracted_bios_call_invalidates_concrete_memory(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        engine.bios(path, "B0", 0x4B, 0xB0)

        actual = engine.load(path, self.BASE, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "uncontracted BIOS call left stale concrete memory %r" % (actual,),
        )

    def test_uncontracted_bios_call_blocks_image_fallback(self):
        engine, path = self.make_state()

        engine.bios(path, "B0", 0x4B, 0xB0)
        actual = engine.load(path, self.BASE, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "uncontracted BIOS call allowed pristine image fallback %r"
            % (actual,),
        )

    def test_uncontracted_bios_call_invalidates_symbolic_memory_fact(self):
        engine, path = self.make_state()
        addr = ("S", "ptr")

        engine.store(path, addr, 4, 0xCAFEBABE)
        engine.bios(path, "B0", 0x4B, 0xB0)

        actual = engine.load(path, addr, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "uncontracted BIOS call left stale symbolic memory %r" % (actual,),
        )


class SyscallMemoryEffectTest(unittest.TestCase):
    BASE = 0x80010000
    SYSCALL_PC = 0x80001000

    class SyscallInstruction:
        kind = "syscall"
        pc = 0x80001000

    def make_state(self):
        image = FakeImage()
        engine = Exec(image)
        path = ExecPath([0] * len(RNAME), image.BASE)
        return engine, path

    def execute_syscall(self, engine, path, number):
        path.r[4] = number
        insn = self.SyscallInstruction()
        result = engine.exec1(path, insn)
        engine.commit(path, result, insn.pc)

    def test_enter_critical_invalidates_modeled_memory_by_default(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        self.execute_syscall(engine, path, 1)

        actual = engine.load(path, self.BASE, 4, False)

        self.assertTrue(path.mem_unknown)
        self.assertFalse(isinstance(actual, int))

    def test_exit_critical_invalidates_modeled_memory_by_default(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        self.execute_syscall(engine, path, 2)

        actual = engine.load(path, self.BASE, 4, False)

        self.assertTrue(path.mem_unknown)
        self.assertFalse(isinstance(actual, int))

    def test_uncontracted_syscall_invalidates_concrete_memory(self):
        engine, path = self.make_state()

        engine.store(path, self.BASE, 4, 0xDEADBEEF)
        self.execute_syscall(engine, path, 3)

        actual = engine.load(path, self.BASE, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "uncontracted syscall left stale concrete memory %r" % (actual,),
        )

    def test_uncontracted_syscall_blocks_image_fallback(self):
        engine, path = self.make_state()

        self.execute_syscall(engine, path, 3)
        actual = engine.load(path, self.BASE, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "uncontracted syscall allowed pristine image fallback %r"
            % (actual,),
        )

    def test_uncontracted_syscall_invalidates_symbolic_memory_fact(self):
        engine, path = self.make_state()
        addr = ("S", "ptr")

        engine.store(path, addr, 4, 0xCAFEBABE)
        self.execute_syscall(engine, path, 3)

        actual = engine.load(path, addr, 4, False)

        self.assertFalse(
            isinstance(actual, int),
            "uncontracted syscall left stale symbolic memory %r" % (actual,),
        )




class Cop2SymbolicBankTest(unittest.TestCase):
    BASE = 0x80010000

    def test_cop2_delayed_write_liveness_across_transfer(self):
        for name, cop2_word in (
            ("mfc2", 0x48081800),  # mfc2 t0,$3
            ("cfc2", 0x48481800),  # cfc2 t0,$3
        ):
            with self.subTest(op=name, case="transfer-reads-old"):
                words = [
                    cop2_word,
                    0x11000001,  # beq t0,zero,+1 ; reads OLD t0
                    0x00000000,  # nop
                    0x03E00008,  # jr ra
                    0x00000000,  # nop
                ]

                img = Image(
                    "synthetic-%s-liveness-old" % name,
                    b"".join(w.to_bytes(4, "little") for w in words),
                    self.BASE,
                )
                recs = sweep(img)

                live = Liveness(
                    img,
                    recs,
                    self.BASE + len(words) * 4,
                    extra_entries=(self.BASE,),
                    text_ranges=((self.BASE, self.BASE + len(words) * 4),),
                )

                self.assertEqual(
                    live.summary(self.BASE, 8),  # t0
                    "READ",
                    "%s: immediately following branch did not consume old t0"
                    % name,
                )

            with self.subTest(op=name, case="delay-slot-reads-new"):
                words = [
                    cop2_word,
                    0x10000001,  # beq zero,zero,+1 ; does NOT read t0
                    0x01004821,  # addu t1,t0,zero ; sees NEW COP2 value
                    0x03E00008,  # jr ra
                    0x00000000,  # nop
                ]

                img = Image(
                    "synthetic-%s-liveness-new" % name,
                    b"".join(w.to_bytes(4, "little") for w in words),
                    self.BASE,
                )
                recs = sweep(img)

                live = Liveness(
                    img,
                    recs,
                    self.BASE + len(words) * 4,
                    extra_entries=(self.BASE,),
                    text_ranges=((self.BASE, self.BASE + len(words) * 4),),
                )

                self.assertEqual(
                    live.summary(self.BASE, 8),  # t0
                    "KILL",
                    "%s: branch delay-slot read was incorrectly attributed "
                    "to old t0 instead of the matured COP2 result" % name,
                )
    def test_mfc2_branch_reads_old_value_delay_slot_reads_new(self):
        words = [
            0x48081800,  # mfc2 t0,$3
            0x11000001,  # beq   t0,zero,+1
            0x01004821,  # addu  t1,t0,zero ; branch delay slot
            0x03E00008,  # jr    ra
            0x00000000,  # nop
        ]

        img = Image(
            "synthetic-mfc2-transfer-delay",
            b"".join(w.to_bytes(4, "little") for w in words),
            self.BASE,
        )

        done = Exec(img).run(self.BASE)

        self.assertEqual(
            len(done),
            2,
            "branch immediately after mfc2 should remain symbolic on old t0",
        )

        for p in done:
            self.assertEqual(
                p.r[9],  # t1
                ('S', 'cop2d3'),
                "branch delay slot did not observe the matured mfc2 result",
            )

            self.assertEqual(len(p.cond), 1)
            self.assertEqual(p.cond[0].left, ('S', 'in.t0'))
            self.assertEqual(p.cond[0].right, 0)
            self.assertEqual(p.cond[0].op, 'beq')

    def test_mfc2_and_cfc2_use_distinct_symbolic_banks(self):
        words = [
            0x48081800,  # mfc2 t0,$3
            0x00000000,  # nop ; mfc2 result matures
            0x48491800,  # cfc2 t1,$3
            0x00000000,  # nop ; cfc2 result matures
            0x03E00008,  # jr ra
            0x00000000,  # nop
        ]

        img = Image(
            "synthetic-cop2-distinct-banks",
            b"".join(w.to_bytes(4, "little") for w in words),
            self.BASE,
        )

        self.assertEqual(img.at(self.BASE).name, "mfc2")
        self.assertEqual(img.at(self.BASE).rd, 3)
        self.assertEqual(img.at(self.BASE + 8).name, "cfc2")
        self.assertEqual(img.at(self.BASE + 8).rd, 3)

        done = Exec(img).run(self.BASE)

        self.assertEqual(len(done), 1)
        p = done[0]

        self.assertNotEqual(
            p.r[8],   # t0 <- COP2 data register 3
            p.r[9],   # t1 <- COP2 control register 3
            "mfc2 data-register bank and cfc2 control-register bank "
            "collapsed to the same symbolic value",
        )
class RecursiveSummarySoundnessTest(unittest.TestCase):
    BASE = 0x80010000

    def test_recursive_summary_preserves_post_call_read(self):
        words = [
            0x0C004000,  # jal   BASE
            0x00000000,  # nop
            0x01001021,  # addu  v0,t0,zero ; reads t0 after recursive return
            0x03E00008,  # jr    ra
            0x00000000,  # nop
        ]

        img = Image(
            "synthetic-self-recursive-read",
            b"".join(w.to_bytes(4, "little") for w in words),
            self.BASE,
        )
        recs = sweep(img)

        live = Liveness(
            img,
            recs,
            self.BASE + len(words) * 4,
            extra_entries=(self.BASE,),
            text_ranges=((self.BASE, self.BASE + len(words) * 4),),
        )

        self.assertEqual(
            live.summary(self.BASE, 8),  # t0
            READ,
            "recursive busy-summary handling hid a read after recursive return",
        )
class IndirectClosureSoundnessTest(unittest.TestCase):
    BASE = 0x80010000

    def _assert_merge_store_prevents_cell_resolution(self, store_word, store_name):
        cell = self.BASE + 0x40
        target = self.BASE + 0x30
        call_pc = self.BASE + 0x14
        store_pc = self.BASE + 0x08

        words = [
            0x3C088001,  # lui   t0,0x8001
            0x25080040,  # addiu t0,t0,0x40   ; CELL
            store_word,  # swl/swr zero,0(t0) ; partial merge into CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                 ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,
            0x03E00008,  # TARGET @ +0x30: jr ra
            0x00000000,
            0x00000000,
            0x00000000,
            target,      # CELL initial value
        ]

        img = Image(
            "synthetic-%s-cell-overlap" % store_name,
            b"".join(w.to_bytes(4, "little") for w in words),
            self.BASE,
        )
        recs = sweep(img)

        store = next(r for r in recs if r["i"].pc == store_pc)
        jalr = next(r for r in recs if r["i"].pc == call_pc)

        self.assertEqual(store["i"].name, store_name)
        self.assertEqual(
            store.get("ea"),
            cell,
            "synthetic precondition: merge store must address CELL exactly",
        )
        self.assertEqual(
            store["i"].width,
            4,
            "synthetic precondition: decoder currently reports merge store width=4",
        )
        self.assertEqual(
            jalr.get("cell"),
            cell,
            "synthetic precondition: jalr must derive its target from CELL",
        )

        live = Liveness(
            img,
            recs,
            self.BASE + 0x38,
            extra_entries=(self.BASE, target),
            text_ranges=((self.BASE, self.BASE + 0x38),),
        )

        self.assertNotIn(
            call_pc,
            live.resolved,
            "%s was treated as a full-word replacement even though it is "
            "a partial/merge store to the function-pointer cell" % store_name,
        )

    def test_swl_store_prevents_cell_resolution(self):
        # op=0x2a, rs=t0, rt=zero, imm=0
        self._assert_merge_store_prevents_cell_resolution(
            0xA9000000,
            "swl",
        )

    def test_swr_store_prevents_cell_resolution(self):
        # op=0x2e, rs=t0, rt=zero, imm=0
        self._assert_merge_store_prevents_cell_resolution(
            0xB9000000,
            "swr",
        )
    def test_unknown_address_store_prevents_cell_resolution(self):
        cell = self.BASE + 0x40
        target = self.BASE + 0x30
        call_pc = self.BASE + 0x14

        words = [
            0xAD090000,  # sw    t1,0(t0)       ; t0 unknown: may alias CELL
            0x3C088001,  # lui   t0,0x8001
            0x25080040,  # addiu t0,t0,0x40
            0x8D0A0000,  # lw    t2,0(t0)       ; CELL
            0x00000000,  # nop                  ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,
            0x03E00008,  # TARGET: jr ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            target,      # CELL initial value
        ]

        img = Image(
            "synthetic-unknown-store-alias",
            b"".join(w.to_bytes(4, "little") for w in words),
            self.BASE,
        )
        recs = sweep(img)

        unknown_store = next(r for r in recs if r["i"].pc == self.BASE)
        jalr = next(r for r in recs if r["i"].pc == call_pc)

        self.assertIsNone(
            unknown_store.get("ea"),
            "synthetic precondition: first store must have unknown address",
        )
        self.assertEqual(
            jalr.get("cell"),
            cell,
            "synthetic precondition: jalr must derive its target from CELL",
        )

        live = Liveness(
            img,
            recs,
            self.BASE + 0x38,
            extra_entries=(self.BASE, target),
            text_ranges=((self.BASE, self.BASE + 0x38),),
        )

        self.assertNotIn(
            call_pc,
            live.resolved,
            "cell target was resolved despite an unknown-address store "
            "that may alias the cell",
        )


    def test_indirect_setter_call_prevents_cell_resolution(self):
        base = self.BASE
        setter = base + 0x20
        consumer = base + 0x40
        target = base + 0x70
        cell = base + 0x80
        setter_call_pc = base + 0x08
        consumer_call_pc = base + 0x50

        words = [
            # main: call setter through jalr, not jal
            0x3C098001,  # lui   t1,0x8001
            0x25290020,  # addiu t1,t1,0x20    ; setter
            0x0120F809,  # jalr  ra,t1
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            # setter @ +0x20: CELL = a0
            0x3C088001,  # lui   t0,0x8001
            0x25080080,  # addiu t0,t0,0x80    ; CELL
            0xAD040000,  # sw    a0,0(t0)
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,

            # consumer @ +0x40
            0x3C088001,  # lui   t0,0x8001
            0x25080080,  # addiu t0,t0,0x80    ; CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                  ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,

            # target @ +0x70
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            0x00000000,
            0x00000000,

            target,      # CELL @ +0x80 initial target
        ]

        img = Image(
            "synthetic-indirect-setter",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        setter_call = next(
            r for r in recs if r["i"].pc == setter_call_pc
        )
        setter_store = next(
            r for r in recs if r["i"].pc == setter + 0x08
        )
        consumer_call = next(
            r for r in recs if r["i"].pc == consumer_call_pc
        )

        self.assertEqual(
            setter_call.get("tgt"),
            setter,
            "synthetic precondition: jalr setter target must be statically known",
        )
        self.assertEqual(
            setter_store.get("ea"),
            cell,
            "synthetic precondition: setter must write the callback cell",
        )
        self.assertIsNone(
            setter_store.get("sval"),
            "synthetic precondition: setter stores an unknown a0 value",
        )
        self.assertEqual(
            consumer_call.get("cell"),
            cell,
            "synthetic precondition: consumer jalr must derive from CELL",
        )

        live = Liveness(
            img,
            recs,
            base + 0x78,
            extra_entries=(base, setter, consumer, target),
            text_ranges=((base, base + 0x78),),
        )

        self.assertNotIn(
            consumer_call_pc,
            live.resolved,
            "cell target was resolved even though the setter is reachable "
            "through a statically-known jalr ignored by direct-call enumeration",
        )

    def test_direct_j_tailcall_counts_as_setter_caller(self):
        base = self.BASE
        setter = base + 0x20
        consumer = base + 0x40
        tailcaller = base + 0x60
        target = base + 0x90
        cell = base + 0xA0
        consumer_call_pc = consumer + 0x10
        tailcall_pc = tailcaller

        words = [
            # main: known direct call to setter with a0 = TARGET
            0x3C048001,  # lui   a0,0x8001
            0x24840090,  # addiu a0,a0,0x90
            0x0C004008,  # jal   0x80010020     ; setter
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            # setter @ +0x20: CELL = a0
            0x3C088001,  # lui   t0,0x8001
            0x250800A0,  # addiu t0,t0,0xa0    ; CELL
            0xAD040000,  # sw    a0,0(t0)
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,

            # consumer @ +0x40
            0x3C088001,  # lui   t0,0x8001
            0x250800A0,  # addiu t0,t0,0xa0    ; CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                 ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            # tailcaller @ +0x60:
            # direct j tail-calls SETTER with unconstrained a0.
            0x08004008,  # j     0x80010020     ; SETTER
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,

            # padding @ +0x80
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,

            # target @ +0x90
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            target,      # CELL @ +0xA0 initial value
        ]

        img = Image(
            "synthetic-direct-j-setter-tailcall",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        tail = next(r for r in recs if r["i"].pc == tailcall_pc)
        setter_store = next(
            r for r in recs if r["i"].pc == setter + 0x08
        )
        consumer_call = next(
            r for r in recs if r["i"].pc == consumer_call_pc
        )

        self.assertEqual(tail["i"].kind, "j")
        self.assertEqual(
            tail["i"].target,
            setter,
            "synthetic precondition: j target must be SETTER",
        )
        self.assertEqual(setter_store.get("ea"), cell)
        self.assertIsNone(setter_store.get("sval"))
        self.assertEqual(consumer_call.get("cell"), cell)

        live = Liveness(
            img,
            recs,
            base + 0x98,
            extra_entries=(base, setter, consumer, tailcaller, target),
            text_ranges=((base, base + 0x98),),
        )

        self.assertNotIn(
            consumer_call_pc,
            live.resolved,
            "callback cell was resolved even though a direct j tail-call "
            "reaches the setter with unknown a0",
        )
    def test_known_target_jr_tailcall_counts_as_setter_caller(self):
        base = self.BASE
        setter = base + 0x20
        consumer = base + 0x40
        tailcaller = base + 0x60
        target = base + 0x90
        cell = base + 0xA0
        consumer_call_pc = consumer + 0x10
        tailcall_pc = tailcaller + 0x08

        words = [
            # main: known direct call to setter with a0 = TARGET
            0x3C048001,  # lui   a0,0x8001
            0x24840090,  # addiu a0,a0,0x90
            0x0C004008,  # jal   0x80010020     ; setter
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            # setter @ +0x20: CELL = a0
            0x3C088001,  # lui   t0,0x8001
            0x250800A0,  # addiu t0,t0,0xa0    ; CELL
            0xAD040000,  # sw    a0,0(t0)
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,

            # consumer @ +0x40
            0x3C088001,  # lui   t0,0x8001
            0x250800A0,  # addiu t0,t0,0xa0    ; CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                 ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            # tailcaller @ +0x60:
            # known-target jr tail-calls SETTER, but a0 is unconstrained.
            0x3C198001,  # lui   t9,0x8001
            0x27390020,  # addiu t9,t9,0x20    ; SETTER
            0x03200008,  # jr    t9
            0x00000000,  # nop

            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,

            # padding @ +0x80
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,

            # target @ +0x90
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            target,      # CELL @ +0xA0 initial value
        ]

        img = Image(
            "synthetic-known-jr-setter-tailcall",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        tail = next(r for r in recs if r["i"].pc == tailcall_pc)
        setter_store = next(
            r for r in recs if r["i"].pc == setter + 0x08
        )
        consumer_call = next(
            r for r in recs if r["i"].pc == consumer_call_pc
        )

        self.assertEqual(tail["i"].kind, "jr")
        self.assertEqual(
            tail.get("tgt"),
            setter,
            "synthetic precondition: jr target must be statically known",
        )
        self.assertEqual(setter_store.get("ea"), cell)
        self.assertIsNone(setter_store.get("sval"))
        self.assertEqual(consumer_call.get("cell"), cell)

        live = Liveness(
            img,
            recs,
            base + 0x98,
            extra_entries=(base, setter, consumer, tailcaller, target),
            text_ranges=((base, base + 0x98),),
        )

        self.assertNotIn(
            consumer_call_pc,
            live.resolved,
            "callback cell was resolved even though a known-target jr "
            "tail-call reaches the setter with unknown a0",
        )
    def test_same_cell_unresolved_jalr_makes_setter_callers_incomplete(self):
        base = self.BASE
        setter = base + 0x20
        consumer = base + 0x40
        same_cell_caller = base + 0x60
        target = base + 0x90
        cell = base + 0xA0
        consumer_call_pc = consumer + 0x10
        same_cell_call_pc = same_cell_caller + 0x10

        words = [
            # main: known direct call to SETTER with a0 = TARGET
            0x3C048001,  # lui   a0,0x8001
            0x24840090,  # addiu a0,a0,0x90
            0x0C004008,  # jal   0x80010020     ; SETTER
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            # setter @ +0x20: CELL = a0
            0x3C088001,  # lui   t0,0x8001
            0x250800A0,  # addiu t0,t0,0xa0    ; CELL
            0xAD040000,  # sw    a0,0(t0)
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,

            # consumer @ +0x40
            0x3C088001,  # lui   t0,0x8001
            0x250800A0,  # addiu t0,t0,0xa0    ; CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                 ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            # same-cell caller @ +0x60:
            # target is loaded from CELL itself, but remains unresolved in
            # the linear sweep. It could therefore call SETTER with arbitrary a0.
            0x3C088001,  # lui   t0,0x8001
            0x250800A0,  # addiu t0,t0,0xa0    ; CELL
            0x8D190000,  # lw    t9,0(t0)
            0x00000000,  # nop                 ; load matures
            0x0320F809,  # jalr  ra,t9
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            # padding @ +0x80
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,

            # target @ +0x90
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            0x00000000,
            0x00000000,

            target,      # CELL @ +0xA0 initial target
        ]

        img = Image(
            "synthetic-same-cell-unresolved-jalr",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        setter_store = next(
            r for r in recs if r["i"].pc == setter + 0x08
        )
        consumer_call = next(
            r for r in recs if r["i"].pc == consumer_call_pc
        )
        same_cell_call = next(
            r for r in recs if r["i"].pc == same_cell_call_pc
        )

        self.assertEqual(setter_store.get("ea"), cell)
        self.assertIsNone(setter_store.get("sval"))

        self.assertEqual(consumer_call.get("cell"), cell)

        self.assertIsNone(
            same_cell_call.get("tgt"),
            "synthetic precondition: same-cell jalr target must remain unresolved",
        )
        self.assertEqual(
            same_cell_call.get("cell"),
            cell,
            "synthetic precondition: unresolved jalr must derive from the same CELL",
        )

        live = Liveness(
            img,
            recs,
            base + 0x98,
            extra_entries=(
                base,
                setter,
                consumer,
                same_cell_caller,
                target,
            ),
            text_ranges=((base, base + 0x98),),
        )

        self.assertNotIn(
            consumer_call_pc,
            live.resolved,
            "callback cell was resolved even though an unresolved jalr loaded "
            "from that same cell could reach the setter with arbitrary a0",
        )
    def test_unresolved_indirect_jump_makes_setter_callers_incomplete(self):
        base = self.BASE
        setter = base + 0x20
        consumer = base + 0x40
        unknown_caller = base + 0x60
        target = base + 0x70
        cell = base + 0x80
        consumer_call_pc = base + 0x50

        words = [
            # main: one known direct call to setter with a0 = TARGET
            0x3C048001,  # lui   a0,0x8001
            0x24840070,  # addiu a0,a0,0x70
            0x0C004008,  # jal   0x80010020     ; setter
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            # setter @ +0x20: CELL = a0
            0x3C088001,  # lui   t0,0x8001
            0x25080080,  # addiu t0,t0,0x80    ; CELL
            0xAD040000,  # sw    a0,0(t0)
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,

            # consumer @ +0x40
            0x3C088001,  # lui   t0,0x8001
            0x25080080,  # addiu t0,t0,0x80    ; CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                 ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            # unknown caller @ +0x60:
            # unresolved tail-call could target SETTER with arbitrary a0.
            0x03200008,  # jr    t9
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            # target @ +0x70
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            target,      # CELL @ +0x80 initial value
        ]

        img = Image(
            "synthetic-unresolved-jr-setter-caller",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        tail = next(r for r in recs if r["i"].pc == unknown_caller)
        setter_store = next(
            r for r in recs if r["i"].pc == setter + 0x08
        )
        consumer_call = next(
            r for r in recs if r["i"].pc == consumer_call_pc
        )

        self.assertEqual(tail["i"].kind, "jr")
        self.assertIsNone(
            tail.get("tgt"),
            "synthetic precondition: jr t9 must have unresolved target",
        )
        self.assertEqual(setter_store.get("ea"), cell)
        self.assertIsNone(
            setter_store.get("sval"),
            "synthetic precondition: setter stores unknown a0",
        )
        self.assertEqual(consumer_call.get("cell"), cell)

        live = Liveness(
            img,
            recs,
            base + 0x78,
            extra_entries=(base, setter, consumer, unknown_caller, target),
            text_ranges=((base, base + 0x78),),
        )

        self.assertNotIn(
            consumer_call_pc,
            live.resolved,
            "callback cell was resolved even though an unresolved jr tail-call "
            "could reach the setter with arbitrary a0",
        )
    def test_unresolved_indirect_call_makes_setter_callers_incomplete(self):
        base = self.BASE
        setter = base + 0x20
        consumer = base + 0x40
        unknown_caller = base + 0x60
        target = base + 0x70
        cell = base + 0x80
        consumer_call_pc = base + 0x50

        words = [
            # main: one known direct call to the setter with a0 = TARGET
            0x3C048001,  # lui   a0,0x8001
            0x24840070,  # addiu a0,a0,0x70
            0x0C004008,  # jal   0x80010020     ; setter
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            # setter @ +0x20: CELL = a0
            0x3C088001,  # lui   t0,0x8001
            0x25080080,  # addiu t0,t0,0x80    ; CELL
            0xAD040000,  # sw    a0,0(t0)
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,
            0x00000000,

            # consumer @ +0x40
            0x3C088001,  # lui   t0,0x8001
            0x25080080,  # addiu t0,t0,0x80    ; CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                  ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            # unknown caller @ +0x60:
            # t9 is unknown, so this transfer could target SETTER.
            0x0320F809,  # jalr  ra,t9
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop

            # target @ +0x70
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            target,      # CELL @ +0x80 initial value
        ]

        img = Image(
            "synthetic-unresolved-setter-caller",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        direct_call = next(r for r in recs if r["i"].pc == base + 0x08)
        setter_store = next(r for r in recs if r["i"].pc == setter + 0x08)
        consumer_call = next(
            r for r in recs if r["i"].pc == consumer_call_pc
        )
        unknown_call = next(
            r for r in recs if r["i"].pc == unknown_caller
        )

        self.assertEqual(
            direct_call["i"].target,
            setter,
            "synthetic precondition: direct setter call target",
        )
        self.assertEqual(setter_store.get("ea"), cell)
        self.assertIsNone(
            setter_store.get("sval"),
            "synthetic precondition: setter value comes from argument a0",
        )
        self.assertEqual(consumer_call.get("cell"), cell)
        self.assertIsNone(
            unknown_call.get("tgt"),
            "synthetic precondition: second jalr must remain unresolved",
        )

        live = Liveness(
            img,
            recs,
            base + 0x78,
            extra_entries=(base, setter, consumer, unknown_caller, target),
            text_ranges=((base, base + 0x78),),
        )

        self.assertNotIn(
            consumer_call_pc,
            live.resolved,
            "cell target was resolved even though an unresolved indirect call "
            "could invoke the setter with an unaccounted argument",
        )

    def test_kseg_alias_store_prevents_cell_resolution(self):
        base = self.BASE
        target = base + 0x30
        cell = base + 0x40
        call_pc = base + 0x1C

        words = [
            0x3C08A001,  # lui   t0,0xa001
            0x25080040,  # addiu t0,t0,0x40    ; KSEG1 alias of CELL
            0xAD090000,  # sw    t1,0(t0)       ; unknown value may replace CELL
            0x3C088001,  # lui   t0,0x8001
            0x25080040,  # addiu t0,t0,0x40    ; KSEG0 CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                  ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,

            0x03E00008,  # TARGET @ +0x30
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            target,      # CELL @ +0x40 initial value
        ]

        img = Image(
            "synthetic-kseg-cell-alias",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        alias_store = next(r for r in recs if r["i"].pc == base + 0x08)
        consumer_call = next(r for r in recs if r["i"].pc == call_pc)

        self.assertEqual(
            alias_store.get("ea"),
            0xA0010040,
            "synthetic precondition: store must use the KSEG1 alias",
        )
        self.assertIsNone(
            alias_store.get("sval"),
            "synthetic precondition: alias store value must be unknown",
        )
        self.assertEqual(
            consumer_call.get("cell"),
            cell,
            "synthetic precondition: jalr must derive from KSEG0 CELL",
        )

        live = Liveness(
            img,
            recs,
            base + 0x38,
            extra_entries=(base, target),
            text_ranges=((base, base + 0x38),),
        )

        self.assertNotIn(
            call_pc,
            live.resolved,
            "cell target was resolved despite an unknown write through "
            "the KSEG1 alias of the same pointer cell",
        )

    def test_overlapping_partial_store_prevents_cell_resolution(self):
        base = self.BASE
        target = base + 0x30
        cell = base + 0x40
        call_pc = base + 0x1C

        words = [
            0x3C088001,  # lui   t0,0x8001
            0x25080041,  # addiu t0,t0,0x41    ; CELL+1
            0xA1090000,  # sb    t1,0(t0)       ; unknown byte overlaps CELL
            0x3C088001,  # lui   t0,0x8001
            0x25080040,  # addiu t0,t0,0x40    ; CELL
            0x8D0A0000,  # lw    t2,0(t0)
            0x00000000,  # nop                  ; load matures
            0x0140F809,  # jalr  ra,t2
            0x00000000,  # nop
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,

            0x03E00008,  # TARGET @ +0x30
            0x00000000,  # nop
            0x00000000,
            0x00000000,

            target,      # CELL @ +0x40 initial value
        ]

        img = Image(
            "synthetic-partial-cell-overlap",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        partial_store = next(r for r in recs if r["i"].pc == base + 0x08)
        consumer_call = next(r for r in recs if r["i"].pc == call_pc)

        self.assertEqual(partial_store["i"].name, "sb")
        self.assertEqual(
            partial_store.get("ea"),
            cell + 1,
            "synthetic precondition: byte store must overlap CELL",
        )
        self.assertIsNone(
            partial_store.get("sval"),
            "synthetic precondition: partial-store value must be unknown",
        )
        self.assertEqual(consumer_call.get("cell"), cell)

        live = Liveness(
            img,
            recs,
            base + 0x38,
            extra_entries=(base, target),
            text_ranges=((base, base + 0x38),),
        )

        self.assertNotIn(
            call_pc,
            live.resolved,
            "cell target was resolved despite an overlapping partial store",
        )

    def test_unresolved_indirect_jump_is_fail_closed(self):
        base = self.BASE
        target = base + 0x10
        text_end = base + 0x20

        words = [
            0x03200008,  # jr    t9              ; unresolved indirect jump
            0x00000000,  # nop                   ; delay slot
            0x00000000,
            0x00000000,

            0x24080001,  # TARGET: addiu t0,zero,1
            0x03E00008,  # jr    ra
            0x00000000,  # nop
            0x00000000,

            target,      # DATA: pointer-looking word into current function
        ]

        img = Image(
            "synthetic-unresolved-indirect-jump",
            b"".join(w.to_bytes(4, "little") for w in words),
            base,
        )
        recs = sweep(img)

        jump = next(r for r in recs if r["i"].pc == base)

        self.assertEqual(jump["i"].kind, "jr")
        self.assertEqual(jump["i"].rs, 25)  # t9
        self.assertIsNone(
            jump.get("tgt"),
            "synthetic precondition: indirect jump target must be unresolved",
        )

        live = Liveness(
            img,
            recs,
            text_end,
            extra_entries=(base,),
            text_ranges=((base, text_end),),
        )

        self.assertIn(
            target,
            live.tables,
            "synthetic precondition: data must contain a tempting in-function "
            "jump-table target",
        )

        state, why = live.walk(base, 8, base, ())  # t0

        self.assertEqual(
            state,
            "READ",
            "unresolved indirect jump must fail closed instead of treating "
            "pointer-looking data words as an exhaustive successor set; got %r (%r)"
            % (state, why),
        )
if __name__ == "__main__":
    unittest.main()
