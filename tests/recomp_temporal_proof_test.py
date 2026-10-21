"""Independent adversarial tests: identity is evidence, rendering is not."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/recomp/proof'))
from sym import (Exec, Path as State, RNAME, SENTINEL, Condition, add, render,
                 exact_real_effects, exact_value, preserved, is_opaque)
from mips import decode
from scan import Image


class EmptyImage:
    def has(self, addr):
        return False


class TemporalMemoryTest(unittest.TestCase):
    ADDRESS = 0x80020000

    def setUp(self):
        self.engine = Exec(EmptyImage())
        self.path = State([('S', 'in.' + n) for n in RNAME], 0x80010000)

    def read(self, address=None, width=4, signed=False, path=None):
        return self.engine.load(path or self.path,
                                self.ADDRESS if address is None else address,
                                width, signed)

    def test_repeated_unknown_ram_reads_are_identical(self):
        self.assertEqual(self.read(), self.read())

    def test_repeated_symbolic_reads_are_identical_in_ordinary_memory_domain(self):
        self.assertEqual(self.read(('S', 'p')), self.read(('S', 'p')))

    def test_symbolic_write_changes_old_read_identity(self):
        before = self.read()
        self.engine.store(self.path, ('S', 'may.alias'), 4, 42)
        self.assertNotEqual(before, self.read())
        self.assertEqual(self.read(), self.read())

    def test_concrete_write_changes_unknown_symbolic_read(self):
        before = self.read(('S', 'p'))
        self.engine.store(self.path, self.ADDRESS, 4, 42)
        self.assertNotEqual(before, self.read(('S', 'p')))
        self.assertEqual(self.read(), 42)

    def test_concrete_partial_write_changes_unknown_same_address(self):
        before = self.read()
        self.engine.store(self.path, self.ADDRESS, 1, 42)
        self.assertNotEqual(before, self.read())
        self.assertTrue(is_opaque(self.read()))

    def test_sibling_writes_do_not_reuse_local_epoch(self):
        before = self.read()
        sibling = self.path.fork()
        self.assertEqual(before, self.read(path=sibling))
        self.engine.store(self.path, ('S', 'x'), 4, 1)
        self.engine.store(sibling, ('S', 'x'), 4, 2)
        self.assertNotEqual(self.read(), self.read(path=sibling))

    def test_child_mutation_does_not_change_parent(self):
        before = self.read()
        sibling = self.path.fork()
        self.engine.store(sibling, ('S', 'x'), 4, 1)
        self.assertEqual(before, self.read())
        self.assertNotEqual(before, self.read(path=sibling))

    def test_cross_root_identity_even_with_same_engine(self):
        other = State(self.path.r, self.path.pc)
        self.assertNotEqual(self.read(), self.read(path=other))

    def test_cross_engine_identity(self):
        other = State(self.path.r, self.path.pc)
        self.assertNotEqual(self.read(), Exec(EmptyImage()).load(other, self.ADDRESS, 4, False))

    def test_read_identity_is_canonical_for_kseg_aliases(self):
        self.assertEqual(self.read(), self.read(0xa0020000))
        self.engine.store(self.path, 0xa0020000, 4, 73)
        self.assertEqual(self.read(), 73)

    def test_low_ram_write_invalidates_cached_segment_image_value(self):
        class RamImage:
            def has(self, addr): return addr == 0x80020000
            def word(self, addr): return 123
        engine = Exec(RamImage())
        self.assertEqual(engine.load(self.path, self.ADDRESS, 4, False), 123)
        engine.store(self.path, 0x20000, 4, 456)
        self.assertEqual(engine.load(self.path, self.ADDRESS, 4, False), 456)

    def test_low_ram_and_kseg_unknown_identity_match(self):
        self.assertEqual(self.read(), self.read(0x20000))

    def test_symbolic_segment_alias_is_not_proved_disjoint(self):
        base = ('S', 'p')
        self.engine.store(self.path, base, 4, 1)
        self.engine.store(self.path, add(base, 0x20000000), 4, 2)
        self.assertTrue(is_opaque(self.read(base)))

    def test_unmapped_segment_is_not_ordinary_ram(self):
        self.assertNotEqual(self.read(0xc0020000), self.read(0xc0020000))

    def test_unmapped_ram_mirror_is_not_assumed_stable(self):
        self.assertNotEqual(self.read(0x80420000), self.read(0x80420000))

    def test_uncached_scratchpad_is_not_assumed_stable(self):
        self.assertNotEqual(self.read(0xbf800000), self.read(0xbf800000))

    def test_mmio_read_invalidates_exact_ram_and_image_fallback(self):
        self.engine.store(self.path, self.ADDRESS, 4, 42)
        self.read(0x1f801070)
        self.assertTrue(is_opaque(self.read()))
        self.assertTrue(self.path.mem_unknown)

    def test_widths_remain_distinct(self):
        self.assertEqual(len({self.read(width=w) for w in (1, 2, 4)}), 3)

    def test_lb_and_lbu_are_distinct(self):
        self.assertNotEqual(self.read(width=1), self.read(width=1, signed=True))

    def test_lh_and_lhu_are_distinct(self):
        self.assertNotEqual(self.read(width=2), self.read(width=2, signed=True))

    def test_concrete_signed_extension(self):
        self.engine.store(self.path, self.ADDRESS, 4, 0x800080ff)
        self.assertEqual(self.read(width=1, signed=True), 0xffffffff)
        self.assertEqual(self.read(width=1), 0xff)
        self.assertEqual(self.read(width=2, signed=True), 0xffff80ff)
        self.assertEqual(self.read(width=2), 0x80ff)

    def test_selective_bios_preserves_fact_but_mutates_unknown_state(self):
        self.engine.bios_memory_preserve = lambda *args: args[-1] == self.ADDRESS
        self.engine.store(self.path, self.ADDRESS, 4, 37)
        before = self.read(self.ADDRESS + 4)
        self.engine.bios(self.path, 'B0', 0x4b)
        self.assertEqual(self.read(), 37)
        self.assertNotEqual(before, self.read(self.ADDRESS + 4))
        self.assertTrue(self.path.mem_unknown)

    def test_unknown_bios_invalidates_unknown_identity(self):
        before = self.read()
        self.engine.bios(self.path, 'A0', 0xfe)
        self.assertNotEqual(before, self.read())

    def test_memory_preserving_bios_keeps_identity(self):
        before = self.read()
        self.engine.bios(self.path, 'B0', 0x56)
        self.assertEqual(before, self.read())

    def test_unknown_syscall_changes_identity(self):
        before = self.read()
        self.path.r[4] = 3
        self.engine.tick(self.path, decode(0xc, self.path.pc))
        self.assertNotEqual(before, self.read())

    def test_critical_syscalls_each_change_identity(self):
        before = self.read()

        for number in (1, 2):
            self.path.r[4] = number
            self.engine.tick(self.path, decode(0xc, self.path.pc))

            after = self.read()
            self.assertNotEqual(before, after)
            before = after

    def test_pending_load_across_store_is_snapshot_value(self):
        before = self.read()
        self.engine.commit(self.path, ('load', 16, before))
        self.path.r[4], self.path.r[9] = ('S', 'may.alias'), 123
        self.engine.tick(self.path, decode(0xac890000, self.path.pc))
        self.assertEqual(self.path.r[16], before)
        self.assertNotEqual(self.path.r[16], self.read())

    def test_pending_load_across_unknown_bios_is_snapshot_value(self):
        before = self.read()
        self.engine.commit(self.path, ('load', 16, before))
        self.engine.bios(self.path, 'A0', 0xfe)
        self.assertEqual(self.path.r[16], before)
        self.assertNotEqual(self.path.r[16], self.read())
        self.assertIsNone(self.path.pending)

    def test_pending_load_across_unknown_syscall_is_snapshot_value(self):
        before = self.read()
        self.engine.commit(self.path, ('load', 16, before))
        self.path.r[4] = 3
        self.engine.tick(self.path, decode(0xc, self.path.pc))
        self.assertEqual(self.path.r[16], before)
        self.assertNotEqual(self.path.r[16], self.read())

    def test_partial_store_unknowns_at_same_pc_do_not_collide(self):
        self.engine.store(self.path, self.ADDRESS, 1, ('S', 'x'))
        before = self.read()
        self.engine.store(self.path, self.ADDRESS, 1, ('S', 'y'))
        self.assertNotEqual(before, self.read())

    def test_bios_clobbers_do_not_collide_across_runs(self):
        other = State(self.path.r, self.path.pc)
        self.engine.bios(self.path, 'A0', 0xfe)
        Exec(EmptyImage()).bios(other, 'A0', 0xfe)
        self.assertEqual(render(self.path.r[2]), render(other.r[2]))
        self.assertNotEqual(self.path.r[2], other.r[2])

    def test_mmio_repeated_reads_are_fresh(self):
        self.assertNotEqual(self.read(0x1f801070), self.read(0x1f801070))

    def test_mmio_does_not_forward_store_as_read_value(self):
        self.engine.store(self.path, 0xbf801070, 4, 0x1234)
        self.assertTrue(is_opaque(self.read(0x9f801070)))
        self.assertTrue(self.path.mem_unknown)

    def test_mmio_does_not_use_image_fallback(self):
        class DeviceImage:
            def has(self, addr): return True
            def word(self, addr): raise AssertionError('device image fallback')
        engine = Exec(DeviceImage())
        self.assertTrue(is_opaque(engine.load(self.path, 0x9f801070, 4, False)))

    def test_unaligned_access_fails_closed(self):
        with self.assertRaises(AssertionError):
            self.read(self.ADDRESS + 1)
        with self.assertRaises(AssertionError):
            self.engine.store(self.path, self.ADDRESS + 3, 2, 7)

    def test_hidden_epoch_does_not_establish_exact_effect(self):
        first = self.read()
        sibling = self.path.fork()
        self.engine.store(sibling, ('S', 'x'), 4, 1)
        second = self.read(path=sibling)
        self.assertEqual(render(first), render(second))
        self.path.r[2], sibling.r[2] = first, second
        self.assertEqual(exact_real_effects([self.path, sibling], ['v0']), (set(), {'v0'}))

    def test_render_collision_is_not_structural_equality(self):
        first, second = ('S', 'p+0x4'), add(('S', 'p'), 4)
        self.assertEqual(render(first), render(second))
        self.assertFalse(exact_value([first, second]))

    def test_labels_do_not_classify_unknowns(self):
        self.assertTrue(exact_value([('S', '?clob.name')]))
        self.assertFalse(exact_value([add(('?', 'innocent'), 4)]))
        self.assertFalse(exact_value([self.read()]))
        self.assertFalse(exact_value([]))

    def test_preservation_requires_every_path(self):
        sibling = self.path.fork()
        sibling.r[16] = 7
        self.assertFalse(preserved([self.path, sibling], 16))
        self.assertFalse(preserved([], 16))

    def test_condition_equality_includes_epoch_and_taken_bit(self):
        first = self.read()
        self.engine.store(self.path, ('S', 'x'), 4, 1)
        second = self.read()
        a = Condition(0x80010000, 'bne', first, 1, True)
        b = Condition(0x80010000, 'bne', second, 1, True)
        self.assertEqual(str(a), str(b))
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, Condition(a.pc, a.op, first, 1, False))
        self.assertEqual(a, Condition(a.pc, a.op, first, 1, True))
        self.assertEqual(len({a, b}), 2)

    def test_render_function_can_collide_without_affecting_semantics(self):
        with patch('sym.render', return_value='collision'):
            first = self.read(('S', 'p'))
            self.engine.store(self.path, ('S', 'q'), 4, 1)
            second = self.read(('S', 'p'))
            self.assertNotEqual(first, second)
            self.assertFalse(exact_value([first, second]))
            self.assertEqual(self.path.events[-2], ('store', ('S', 'q'), 4, 1))


class TransferTemporalTest(unittest.TestCase):
    BASE = 0x80010000

    def image(self, words):
        return Image('temporal-transfer', b''.join(w.to_bytes(4, 'little') for w in words), self.BASE)

    def test_branch_sees_old_register_and_delay_store_cannot_rewrite_retired_load(self):
        image = self.image([0x8c900000, 0x16000001, 0xaca90000, 0x03e00008, 0])
        engine = Exec(image)
        # The delay-slot store targets a concrete data word outside the 5-word instruction image and
        # at exactly the address the load read. (A symbolic store address may alias instruction fetch and is
        # rejected by the fail-closed self-modifying-fetch guard, which is deliberately unchanged.)
        paths = engine.run(self.BASE, {4: 0x80020000, 5: 0x80020000, 9: 1})
        self.assertEqual(len(paths), 2)
        for p in paths:
            self.assertEqual(p.cond[0].left, ('S', 'in.s0'))
            self.assertNotEqual(p.r[16], engine.load(p, 0x80020000, 4, False))
        self.assertEqual(paths[0].r[16], paths[1].r[16])
        self.assertNotEqual(paths[0].memory_state, paths[1].memory_state)

    def test_load_in_jalr_slot_is_captured_before_unknown_bios(self):
        image = self.image([0x0140f809, 0x8c900000, 0x02200008, 0])
        engine = Exec(image)
        p, = engine.run(self.BASE, {4: 0x80020000, 9: 0xfe, 10: 0xa0, 17: SENTINEL})
        first = next(e[4] for e in p.events if e[0] == 'load')
        self.assertEqual(p.r[16], first)
        self.assertNotEqual(first, engine.load(p, 0x80020000, 4, False))
        self.assertIsNone(p.pending)

    def test_repeated_run_on_one_executor_creates_new_namespace(self):
        image = self.image([0x8c900000, 0, 0x03e00008, 0])
        engine = Exec(image)
        a, = engine.run(self.BASE, {4: 0x80020000})
        b, = engine.run(self.BASE, {4: 0x80020000})
        self.assertNotEqual(a.r[16], b.r[16])


class PendingBoundaryEffectsTest(unittest.TestCase):
    BASE = 0x80010000

    def image(self, words):
        return Image(
            'synthetic',
            b''.join(w.to_bytes(4, 'little') for w in words),
            self.BASE,
        )

    def test_pending_write_at_sentinel_is_not_exact_real_effect(self):
        # addiu v0,zero,7 ; jr ra ; mfc0 v0,$12
        #
        # At the continuation boundary v0 is still 7, while the COP0 result is
        # a hidden delayed write. A summary that only inspects p.r must not call
        # v0 an exact completed effect.
        engine = Exec(self.image([
            0x24020007,
            0x03e00008,
            0x40026000,
        ]))

        p, = engine.run(self.BASE)

        self.assertEqual(p.pc, SENTINEL)
        self.assertEqual(p.r[2], 7)
        self.assertEqual(p.pending, (2, ('S', 'cop0r12')))
        self.assertIsNotNone(p.pending_prov)

        self.assertEqual(
            exact_real_effects([p], ['v0']),
            (set(), {'v0'}),
        )

    def test_pending_write_at_sentinel_is_not_preserved(self):
        # jr ra ; mfc0 s0,$12
        #
        # The visible register file still contains the entry s0 value, but a
        # hidden write to s0 is pending. That is not a preserved call boundary.
        engine = Exec(self.image([
            0x03e00008,
            0x40106000,
        ]))

        p, = engine.run(self.BASE)

        self.assertEqual(p.pc, SENTINEL)
        self.assertEqual(p.r[16], ('S', 'in.s0'))
        self.assertEqual(p.pending, (16, ('S', 'cop0r12')))

        self.assertFalse(preserved([p], 16))

    def test_pending_other_register_does_not_poison_exact_effect(self):
        # addiu v1,zero,9 ; jr ra ; mfc0 v0,$12
        engine = Exec(self.image([
            0x24030009,
            0x03e00008,
            0x40026000,
        ]))

        p, = engine.run(self.BASE)

        self.assertEqual(p.r[3], 9)
        self.assertEqual(p.pending[0], 2)

        self.assertEqual(
            exact_real_effects([p], ['v1']),
            ({'v1'}, set()),
        )


if __name__ == '__main__':
    unittest.main()
