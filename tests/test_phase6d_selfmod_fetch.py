"""Fail-closed instruction-fetch regressions; synthetic, not PAL BIOS bytes.

PSX-SPX memory map: stores do not invalidate the instruction cache; KSEG1
fetches are uncached. Without an explicit cache/code-integrity contract this
proof engine must reject potentially modified code, not silently certify the
original Image. These tests request conservative rejection, not an automatic
RAM-to-instruction forwarding policy for cached code.
https://psx-spx.consoledev.net/memorymap/#isolation-and-self-modifying-code
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/recomp/proof'))
from scan import Image
from sym import Exec, Path as ExecPath, RNAME, SENTINEL, canonical_mem_addr

BASE = 0x80010000
OLD = 0x24020001  # addiu v0,zero,1
NEW = 0x24020002  # addiu v0,zero,2
RETURN = 0x02000008  # jr s0: survives BIOS caller-clobbers
SW = 0xac850000  # sw a1,0(a0)


class SelfModFetchTest(unittest.TestCase):
    def image(self, words, base=BASE):
        return Image('synthetic-selfmod', b''.join(w.to_bytes(4, 'little') for w in words), base)

    def fixture(self, transfer='j', delay_store=False, base=BASE, store=SW, address=None, value=NEW):
        target = base + 16
        transfers = {'j': 0x08000000 | ((target >> 2) & 0x3ffffff),
                     'jal': 0x0c000000 | ((target >> 2) & 0x3ffffff),
                     'jr': 0x01400008, 'jalr': 0x0140f809,
                     'fallthrough': 0}
        t = transfers[transfer]
        words = [t, store, 0, 0, OLD, RETURN, 0] if delay_store else [store, t, 0, 0, OLD, RETURN, 0]
        init = {4: target if address is None else address, 5: value, 10: target, 16: SENTINEL}
        return Exec(self.image(words, base)), init

    def reject(self, engine, init, base=BASE):
        # A setup/decode/return error is not an acceptable false green.
        with self.assertRaisesRegex(AssertionError, r'(?i)fetch|code|instruction|alias|cache'):
            engine.run(base, init=init)

    def test_sw_before_j(self):
        self.reject(*self.fixture('j'))

    def test_sw_before_jr(self):
        self.reject(*self.fixture('jr'))

    def test_sw_before_jal(self):
        self.reject(*self.fixture('jal'))

    def test_sw_before_jalr(self):
        self.reject(*self.fixture('jalr'))

    def test_sw_before_fallthrough(self):
        self.reject(*self.fixture('fallthrough'))

    def test_store_in_transfer_delay_slot(self):
        for transfer in ('j', 'jr', 'jal', 'jalr'):
            with self.subTest(transfer=transfer):
                self.reject(*self.fixture(transfer, delay_store=True))

    def test_store_modifies_branch_delay_slot_instruction(self):
        jump = 0x08000000 | ((BASE + 16) >> 2 & 0x3ffffff)
        engine = Exec(self.image([SW, jump, OLD, 0, 0, RETURN, 0]))
        self.reject(engine, {4: BASE + 8, 5: NEW, 16: SENTINEL})

    def test_partial_instruction_store(self):
        for opcode in (0xa0850000, 0xa4850000):  # sb / sh a1,0(a0)
            with self.subTest(opcode=hex(opcode)):
                self.reject(*self.fixture(store=opcode, value=2))

    def test_store_aliases_of_cached_fetch(self):
        for address in (0x10010, 0xa0010010):
            with self.subTest(address=hex(address)):
                self.reject(*self.fixture(address=address))

    def test_store_aliases_of_retail_main_ram_mirrors(self):
        # Retail BIOS normally exposes the physical 2 MiB RAM mirrored
        # through the first 8 MiB CPU RAM aperture.
        for address in (
            0x00210010,
            0x80210010,
            0xa0210010,
            0x00410010,
            0x80410010,
            0xa0410010,
            0x00610010,
            0x80610010,
            0xa0610010,
        ):
            with self.subTest(address=hex(address)):
                self.reject(*self.fixture(address=address))

    def test_store_beyond_retail_ram_mirror_aperture_is_not_folded(self):
        engine, init = self.fixture(address=0x80810010)
        p, = engine.run(BASE, init)
        self.assertEqual(p.r[2], 1)

    def test_uncached_fetch_after_store_via_every_alias(self):
        for address in (0x10010, 0x80010010, 0xa0010010):
            with self.subTest(address=hex(address)):
                self.reject(*self.fixture(base=0xa0010000, address=address), base=0xa0010000)

    def test_symbolic_store_address_may_alias_future_code(self):
        self.reject(*self.fixture(address=('S', 'unknown.destination')))

    def test_symbolic_word_written_to_exact_code_address(self):
        self.reject(*self.fixture(value=('S', 'unknown.instruction')))

    def test_only_one_branch_path_modifies_code(self):
        engine = Exec(self.image([0x10c00003, 0, SW, 0, OLD, RETURN, 0]))
        self.reject(engine, {4: BASE + 16, 5: NEW, 16: SENTINEL})

    def test_dirty_fork_does_not_hide_behind_clean_sibling(self):
        engine = Exec(self.image([OLD, RETURN, 0]))
        regs = [('S', 'in.' + n) for n in RNAME]
        regs[0], regs[16] = 0, SENTINEL
        clean = ExecPath(regs, BASE)
        dirty = clean.fork()
        engine.store(dirty, BASE, 4, NEW)
        self.assertEqual(engine.step_path(clean, 20, []).r[2], 1)
        self.assertEqual(dirty.mem[canonical_mem_addr(BASE)], NEW)
        with self.assertRaisesRegex(AssertionError, r'(?i)fetch|code|instruction|alias|cache'):
            engine.step_path(dirty, 20, [])

    def test_flushcache_does_not_authorize_original_image_fetch(self):
        # sw ; jalr t2 (A0:44 FlushCache) ; nop ; nop ; overwritten word.
        engine = Exec(self.image([SW, 0x0140f809, 0, 0, OLD, RETURN, 0]))
        self.reject(engine, {4: BASE + 16, 5: NEW, 9: 0x44, 10: 0xa0, 16: SENTINEL})

    def test_clean_original_image_control(self):
        p, = Exec(self.image([OLD, RETURN, 0])).run(BASE, {16: SENTINEL})
        self.assertEqual(p.r[2], 1)

    def test_disjoint_concrete_store_control(self):
        engine, init = self.fixture(address=BASE + 0x1000)
        p, = engine.run(BASE, init)
        self.assertEqual(p.r[2], 1)
        self.assertEqual(p.mem[BASE + 0x1000], NEW)

    def test_data_memory_already_tracks_partial_and_alias_writes(self):
        for width, value in ((1, 2), (2, 2), (4, NEW)):
            engine = Exec(self.image([OLD]))
            p = ExecPath([0] * len(RNAME), BASE)
            engine.store(p, 0xa0010000, width, value)
            self.assertEqual(engine.load(p, BASE, 4, False), NEW)
            self.assertEqual(engine.img.at(BASE).w, OLD)


    def test_data_nonalias_policy_does_not_authorize_instruction_fetch(self):
        engine, init = self.fixture(
            address=('S', 'unknown.destination')
        )
        engine.symbolic_store_nonalias = lambda *args: True

        # A data-memory preservation policy must not certify code fetch.
        self.reject(engine, init)

    def test_instruction_fetch_policy_can_authorize_symbolic_store(self):
        engine, init = self.fixture(
            address=('S', 'documented.kernel.destination')
        )
        engine.instruction_fetch_nonalias = lambda *args: True

        p, = engine.run(BASE, init)

        self.assertEqual(p.r[2], 1)
        self.assertTrue(
            any(
                a[0] == 'instruction_fetch_nonalias'
                for a in p.assumptions
            )
        )
        self.assertFalse(
            any(
                a[0] == 'symbolic_store_nonalias'
                for a in p.assumptions
            )
        )

    def test_instruction_fetch_policy_does_not_preserve_data_memory(self):
        engine = Exec(
            self.image([OLD]),
            instruction_fetch_nonalias=lambda *args: True,
        )

        p = ExecPath([0] * len(RNAME), BASE)

        data_word = canonical_mem_addr(BASE + 0x100)
        p.mem[data_word] = 0x12345678

        engine.store(
            p,
            ('S', 'unknown.destination'),
            4,
            NEW,
            pc=BASE,
        )

        # Code-fetch authorization is not a data-memory non-alias fact.
        self.assertNotIn(data_word, p.mem)


if __name__ == '__main__':
    unittest.main()
