"""Phase 6b probe, part 2: symbolic execution of a PAL routine against a BIOS model that contains ONLY documented
calling-convention facts (no BIOS bytes, no BIOS addresses). Every value that would come from the BIOS is a symbol."""
from dataclasses import dataclass
from itertools import count
from uuid import uuid4

from mips import REG, RNAME, HI, LO, decode

M32 = 0xffffffff
SENTINEL = 0xFEEDF00C          # return address planted in ra: reaching it ends a path
VEC = {0xa0: 'A0', 0xb0: 'B0', 0xc0: 'C0'}
# Documented results (PSX-SPX "BIOS Misc Functions": B(56h) GetC0Table, B(57h) GetB0Table). The VALUE is unknown and
# stays symbolic; only the fact that v0 holds "the table address" is used.
RESULT = {('B0', 0x56): 'C0TBL', ('B0', 0x57): 'B0TBL'}
BIOS_MEM_PRESERVE = {('B0', 0x56), ('B0', 0x57), ('A0', 0x44)}
# Documented clobber set (PSX-SPX "BIOS Function Summary": BIOS functions may destroy R1-R15, R24-R25, R31, HI/LO).
CLOBBER = list(range(1, 16)) + [24, 25, 31, HI, LO]


def isint(e):
    return isinstance(e, int)


def canonical_mem_addr(addr):
    """Map low physical/KSEG0/KSEG1 addresses to one KSEG0 identity."""
    if not isint(addr):
        return addr
    addr &= M32
    if (addr >> 29) in (0, 4, 5):
        return 0x80000000 | (addr & 0x1fffffff)
    return addr


def _canonical_code_byte_addr(addr):
    """Canonical byte identity for retail-PS1 instruction integrity.

    In addition to KUSEG/KSEG0/KSEG1 aliases, conservatively collapse
    the default retail 2 MiB main-RAM mirrors across the first 8 MiB.
    If software later shrinks the mapped aperture, this can only cause
    false rejection, not a false proof of pristine code.
    """
    if not isint(addr):
        return addr

    addr &= M32

    if (addr >> 29) in (0, 4, 5):
        phys = addr & 0x1fffffff

        if phys < 0x00800000:
            phys %= 0x00200000

        return 0x80000000 | phys

    return addr


def add(a, b):
    if isint(a) and isint(b):
        return (a + b) & M32
    if isint(a):
        a, b = b, a
    if isint(b):
        if b == 0:
            return a
        if a[0] == '+':
            k = (a[2] + b) & M32
            return a[1] if k == 0 else ('+', a[1], k)
        return ('+', a, b)
    return ('add', a, b)


def _symbolic_ranges_disjoint(a, a_width, b, b_width):
    """Prove disjointness for two accesses sharing one symbolic affine base."""
    if not (
        isinstance(a_width, int)
        and isinstance(b_width, int)
        and 0 < a_width <= 4
        and 0 < b_width <= 4
    ):
        return False

    def affine(e):
        if isint(e):
            return None
        if (
            isinstance(e, tuple)
            and len(e) == 3
            and e[0] == '+'
            and isint(e[2])
        ):
            return e[1], e[2] & M32
        return e, 0

    aa = affine(a)
    bb = affine(b)

    if aa is None or bb is None:
        return False

    a_base, a_off = aa
    b_base, b_off = bb

    # Structural equality only: rendered strings are not proof evidence.
    if a_base != b_base:
        return False

    # Different virtual segments can name the same physical bytes. Prove
    # disjointness modulo the physical window, not merely modulo 2**32.
    a_bytes = {((a_off + i) & 0x1fffffff) for i in range(a_width)}
    b_bytes = {((b_off + i) & 0x1fffffff) for i in range(b_width)}

    return a_bytes.isdisjoint(b_bytes)


def render(e):
    if isint(e):
        return '0x%x' % e
    t = e[0]
    if t == 'S':
        return e[1]
    if t == '?':
        return '?' + e[1]
    if t == 'M':
        return 'M%d[%s]' % (e[2], render(e[1]))
    if t == '+':
        k = e[2]
        return '%s%s0x%x' % (render(e[1]), '+' if k < 0x80000000 else '-', k if k < 0x80000000 else (-k) & M32)
    if t == 'add':
        return '(%s + %s)' % (render(e[1]), render(e[2]))
    if t == 'and':
        return '(%s & 0x%x)' % (render(e[1]), e[2])
    if t == 'shl':
        return '(%s << %d)' % (render(e[1]), e[2])
    if t == 'cmp':
        return '(%s %s %s)' % (render(e[2]), e[1], render(e[3]))
    return repr(e)


@dataclass(frozen=True)
class Condition:
    pc: int
    op: str
    left: object
    right: object
    taken: bool

    def __str__(self):
        return '%08x:%s%s' % (
            self.pc, '' if self.taken else 'not ',
            render(('cmp', self.op, self.left, self.right)))


def is_opaque(value):
    """Unknown reads/clobbers cannot establish an exact replacement effect.

    Inspect expression structure, including nested unknowns, never labels.
    Named S terms are parameters of the entry/summary contract.
    """
    if isint(value):
        return False
    if not isinstance(value, tuple) or not value:
        return True
    if value[0] in ('?', 'M'):
        return True
    if value[0] == 'S':
        return False
    operands = {'+': (1,), 'add': (1, 2), 'and': (1,), 'or': (1, 2),
                'shl': (1,), 'cmp': (2, 3)}.get(value[0])
    return operands is None or any(is_opaque(value[k]) for k in operands)


def exact_value(values):
    values = list(values)
    return bool(values) and not is_opaque(values[0]) and all(
        value == values[0] for value in values[1:])


def restored(paths, reg, expected):
    """True iff, on every path, reg holds `expected` after the return boundary.

    Fail closed on a delayed write still pending for reg: the visible register file then differs from the
    architectural value that exists one instruction later, and the pending value is not compared with `expected`."""
    paths = list(paths)
    return bool(paths) and all(
        (p.pending is None or p.pending[0] != reg)
        and p.r[reg] == expected for p in paths)


def preserved(paths, reg):
    return restored(paths, reg, ('S', 'in.' + RNAME[reg]))


def ra_restored_at_return(paths):
    """RA equals the caller's planted return address on every path, with no delayed write to RA outstanding."""
    return restored(paths, 31, SENTINEL)


def exact_real_effects(paths, reg_names):
    paths = list(paths)
    exact, unresolved = set(), set()
    for name in reg_names:
        idx = RNAME.index(name)
        has_pending = any(p.pending is not None and p.pending[0] == idx for p in paths)
        (exact if not has_pending and exact_value(p.r[idx] for p in paths) else unresolved).add(name)
    return exact, unresolved


def volatile_addr(addr):
    """Known device/unmapped addresses are not immutable RAM observations.

    The symbolic-address domain models ordinary memory (as do exact symbolic
    store facts). It does not establish non-MMIO provenance for arbitrary guest
    pointers. Device alias analysis requires an additional address-domain model.
    """
    if not isint(addr):
        return False
    phys = addr & 0x1fffffff
    segment = (addr & M32) >> 29
    # Match src/ps1_memory.hpp: no RAM wraparound or uncached scratchpad.
    return not (segment in (0, 4, 5) and (
        phys < 0x00200000 or
        (segment != 5 and 0x1f800000 <= phys < 0x1f800400)))


class Path:
    def __init__(self, regs, pc, identities=None):
        # One allocator per root, shared by forks; never copy a local epoch
        # counter. UUID namespaces also separate independently created roots.
        self._identities = identities or (uuid4().hex, count())
        self.memory_state = self.fresh_identity()
        self.r = list(regs)
        self.pc = pc
        self.events = []
        self.syscall_returns = []
        self.mem = {}
        self.mem_unknown = False
        # Instruction fetch is deliberately not RAM-forwarded.  Instead, keep
        # path-local evidence that guest stores may have changed image bytes;
        # a later fetch of such bytes must fail closed.
        self.code_dirty = set()
        self.code_symbolic_stores = []
        self.assumptions = []
        self.cond = []
        self.pending = None      # (reg, value) load delay
        self.pending_prov = None
        self.steps = 0
        self.seen = []
        self.link = None
        self.last_callsite = None
        self.prov = {'zero': ('ENTRY_VALUE', 'zero')}
        for i, name in enumerate(RNAME):
            if i == 0:
                continue
            self.prov[i] = ('ENTRY_VALUE', name)

    def fresh_identity(self):
        namespace, serial = self._identities
        return namespace, next(serial)

    def mutate_memory(self):
        self.memory_state = self.fresh_identity()

    def unknown(self, label):
        return ('?', label, self.fresh_identity())

    def fork(self):
        p = Path(self.r, self.pc, self._identities)
        p.memory_state = self.memory_state
        p.events, p.mem, p.cond, p.pending, p.pending_prov, p.steps, p.seen = list(self.events), dict(self.mem), list(self.cond), \
            self.pending, self.pending_prov, self.steps, list(self.seen)
        p.syscall_returns = list(self.syscall_returns)
        p.mem_unknown = self.mem_unknown
        p.code_dirty = set(self.code_dirty)
        p.code_symbolic_stores = list(self.code_symbolic_stores)
        p.assumptions = list(self.assumptions)
        p.prov = dict(self.prov)
        p.link = self.link
        p.last_callsite = self.last_callsite
        return p


class Exec:
    def __init__(
        self,
        img,
        io_base=0x1f800000,
        symbolic_store_nonalias=None,
        bios_memory_preserve=None,
        addi_no_overflow=None,
        syscall_memory_preserve=None,
        syscall_image_words=None,
        instruction_fetch_nonalias=None,
    ):
        self.img = img
        self.cover = set()
        self.ncall = 0
        # Optional trusted assumption interfaces. Default execution remains
        # fail-closed.
        self.symbolic_store_nonalias = symbolic_store_nonalias
        self.instruction_fetch_nonalias = instruction_fetch_nonalias
        self.bios_memory_preserve = bios_memory_preserve
        self.addi_no_overflow = addi_no_overflow
        self.syscall_memory_preserve = syscall_memory_preserve
        self.syscall_image_words = syscall_image_words

    def rd(self, p, r):
        return 0 if r == 0 else p.r[r]

    def wr(self, p, r, v, prov=None):
        if r != 0:
            p.r[r] = v
            if prov is not None:
                p.prov[r] = prov

    def _record_code_store(self, p, addr, width, store_pc):
        """Remember bytes that a guest store may have changed.

        Concrete addresses are tracked byte-for-byte in canonical physical
        identity.  Symbolic addresses are retained until a future instruction
        fetch can either prove non-aliasing or reject the path.
        """
        caddr = _canonical_code_byte_addr(addr)
        if isint(caddr):
            for k in range(width):
                p.code_dirty.add(_canonical_code_byte_addr((caddr + k) & M32))
        else:
            p.code_symbolic_stores.append((store_pc, caddr, width))

    def fetch_instruction(self, p, pc):
        """Fetch pristine image code only when its integrity is established."""
        assert isint(pc), 'unresolved instruction fetch: %s' % render(pc)
        assert self.img.has(pc), 'control left the image at %s' % render(pc)

        fetch_bytes = {
            _canonical_code_byte_addr((pc + k) & M32)
            for k in range(4)
        }
        if p.code_dirty.intersection(fetch_bytes):
            raise AssertionError(
                'instruction fetch may observe modified code at %08x' % pc
            )

        word = canonical_mem_addr(pc) & ~3
        for store_pc, addr, width in p.code_symbolic_stores:
            if _symbolic_ranges_disjoint(addr, width, word, 4):
                continue

            policy = self.instruction_fetch_nonalias
            if policy is not None:
                try:
                    decision = policy(store_pc, addr, width, word)
                except Exception as exc:
                    raise AssertionError(
                        'instruction-fetch non-alias contract failed at %08x'
                        % store_pc
                    ) from exc

                if type(decision) is not bool:
                    raise AssertionError(
                        'instruction-fetch non-alias contract must return bool'
                    )

                if decision:
                    assumption = (
                        'instruction_fetch_nonalias',
                        store_pc,
                        addr,
                        width,
                        word,
                    )
                    if assumption not in p.assumptions:
                        p.assumptions.append(assumption)
                    continue

            raise AssertionError(
                'instruction fetch may alias symbolic store at %08x' % pc
            )

        return self.img.at(pc)

    def load(self, p, addr, width, signed):
        caddr = canonical_mem_addr(addr)
        assert width in (1, 2, 4), 'unsupported load width'
        assert not isint(caddr) or caddr % width == 0, 'unaligned load'
        if volatile_addr(addr):
            # Reads may have device side effects; without a device contract
            # neither stored RAM facts nor pristine image fallback are safe.
            p.mutate_memory()
            p.mem.clear()
            p.mem_unknown = True
            v = ('M', caddr, width, bool(signed and width < 4), p.memory_state)
            p.events.append(('load', caddr, width, bool(signed), v))
            return v
        if isint(caddr):
            a = caddr & ~3
            if a in p.mem:
                w = p.mem[a]
            elif not p.mem_unknown and self.img.has(a & M32) and (caddr >> 29) == 4:
                w = self.img.word(a)
            else:
                w = None
            if w is not None and isint(w):
                sh = (caddr & 3) * 8
                v = (w >> sh) & ((1 << (8 * width)) - 1)
                if signed and v >> (8 * width - 1):
                    v -= 1 << (8 * width)
                return v & M32
            if w is not None and width == 4 and caddr % 4 == 0:
                return w
        if not isint(caddr) and width == 4 and ('sym', caddr) in p.mem:
            return p.mem[('sym', caddr)]
        v = ('M', caddr, width, bool(signed and width < 4), p.memory_state)
        p.events.append(('load', caddr, width, bool(signed), v))
        return v

    def store(self, p, addr, width, val, pc=None):
        caddr = canonical_mem_addr(addr)
        assert width in (1, 2, 4), 'unsupported store width'
        assert not isint(caddr) or caddr % width == 0, 'unaligned store'
        p.events.append(('store', addr, width, val))
        self._record_code_store(
            p, addr, width, p.pc if pc is None else pc
        )
        p.mutate_memory()
        if volatile_addr(addr):
            # A device write may trigger DMA. Without a device contract no
            # precise RAM fact or pristine image fallback survives it.
            p.mem.clear()
            p.mem_unknown = True
            return
        if isint(caddr):
            # A concrete address may alias any previously precise symbolic address.
            for key in list(p.mem):
                if isinstance(key, tuple) and key and key[0] == 'sym':
                    del p.mem[key]
        if isint(caddr) and width == 4 and caddr % 4 == 0:
            p.mem[caddr] = val
        elif isint(caddr) and width in (1, 2):
            a = caddr & ~3
            if a in p.mem:
                w = p.mem[a]
            elif not p.mem_unknown and self.img.has(a & M32) and (caddr >> 29) == 4:
                w = self.img.word(a)
            else:
                w = None
            if isint(w) and isint(val):
                sh = (caddr & 3) * 8
                mask = ((1 << (8 * width)) - 1) << sh
                p.mem[a] = ((w & ~mask) | ((val << sh) & mask)) & M32
            else:
                p.mem[a] = p.unknown('partial.store@%08x' % a)
        elif isint(caddr):
            p.mem.pop(caddr & ~3, None)
        else:
            # An unknown address may alias every modeled memory word unless:
            #   1. affine structure itself proves two symbolic ranges disjoint, or
            #   2. an explicit policy proves disjointness from a concrete word.
            kept = {}
            used = []
            policy = self.symbolic_store_nonalias
            store_pc = p.pc if pc is None else pc

            for key, old_value in list(p.mem.items()):
                if isinstance(key, int):
                    if policy is None:
                        continue

                    word = canonical_mem_addr(key) & ~3

                    try:
                        decision = policy(store_pc, caddr, width, word)
                    except Exception as exc:
                        raise AssertionError(
                            'symbolic-store non-alias contract failed at %08x'
                            % store_pc
                        ) from exc

                    if type(decision) is not bool:
                        raise AssertionError(
                            'symbolic-store non-alias contract must return bool'
                        )

                    if decision:
                        kept[word] = old_value
                        used.append((
                            'symbolic_store_nonalias',
                            store_pc,
                            caddr,
                            width,
                            word,
                        ))

                elif (
                    isinstance(key, tuple)
                    and key
                    and key[0] == 'sym'
                ):
                    old_addr = key[1] if len(key) == 2 else None

                    if (
                        old_addr is not None
                        and _symbolic_ranges_disjoint(
                            old_addr,
                            4,
                            caddr,
                            width,
                        )
                    ):
                        kept[key] = old_value

            p.mem.clear()
            p.mem.update(kept)

            # Even with selected preserved facts, all other memory is unknown.
            p.mem_unknown = True
            p.assumptions.extend(used)

            if width == 4:
                key = ('sym', caddr)
                p.mem[key] = val

    def retire_pending(self, p, pc, label):
        """Make the outstanding delayed GPR write architecturally visible.

        Only for a boundary whose consumer runs at least one instruction after the transfer's delay slot (the BIOS
        dispatcher behind a 0xA0/0xB0/0xC0 vector, the SYSCALL exception handler). Ordinary instructions keep the
        one-instruction-late semantics of tick()."""
        if p.pending:
            reg, value = p.pending
            prov = p.pending_prov or ('PAL_INSTRUCTION', pc, label)
            p.pending = None
            p.pending_prov = None
            self.wr(p, reg, value, prov)

    def bios(self, p, vec, fn, pc=None):
        # Callers pass the function number read AFTER retire_pending(); do the same for a0 and for the clobber.
        self.retire_pending(p, 0 if pc is None else pc, 'load-delay')
        self.ncall += 1
        pc_label = 'unknown' if pc is None else '0x%08x' % pc
        p.events.append(('bios', vec, fn, self.rd(p, 4)))
        assert isint(fn), 'BIOS call with unresolved function number'
        if (vec, fn) not in BIOS_MEM_PRESERVE:
            p.mutate_memory()
            # No global modeled-memory contract: by default the BIOS call may
            # have changed every tracked location. An optional trusted policy
            # may preserve individual facts only.
            kept = {}
            used = []

            if self.bios_memory_preserve is not None:
                for word_key, old_value in p.mem.items():
                    try:
                        decision = self.bios_memory_preserve(
                            p.last_callsite,
                            vec,
                            fn,
                            word_key,
                        )
                    except Exception as exc:
                        raise AssertionError(
                            'BIOS memory-preserve contract failed at %s %s:%02x '
                            'for %r: %s'
                            % (
                                'unknown' if p.last_callsite is None
                                else '0x%08x' % p.last_callsite,
                                vec,
                                fn,
                                word_key,
                                exc,
                            )
                        ) from exc

                    if not isinstance(decision, bool):
                        raise AssertionError(
                            'BIOS memory-preserve contract must return bool'
                        )

                    if decision:
                        kept[word_key] = old_value
                        used.append((
                            'bios_memory_preserve',
                            p.last_callsite,
                            vec,
                            fn,
                            word_key,
                        ))

            p.mem.clear()
            p.mem.update(kept)

            # Preserving selected facts does not make any other memory precise.
            p.mem_unknown = True
            p.assumptions.extend(used)
        for r in CLOBBER:
            p.r[r] = p.unknown('clob%d.%s' % (self.ncall, RNAME[r]))
            p.prov[r] = ('BIOS_SUMMARY', vec, fn, pc_label,
                         p.last_callsite, RNAME[r])
        res = RESULT.get((vec, fn))
        if res:
            p.r[2] = ('S', res)
            p.prov[2] = ('BIOS_SUMMARY', vec, fn, pc_label,
                         p.last_callsite, 'v0')

    def run(self, entry, init=None, limit=4000):
        regs = [('S', 'in.' + n) for n in RNAME]
        regs[0] = 0
        regs[31] = SENTINEL
        if init:
            for k, v in init.items():
                regs[k] = v
        work = [Path(regs, entry)]
        done = []
        while work:
            p = work.pop()
            res = self.step_path(p, limit, work)
            done.append(res)
        return done

    def alu(self, p, i):
        def R(r): return self.rd(p, r)
        n = i.name
        if n == 'lui':
            return i.rt, (i.imm << 16) & M32
        if n == 'addiu':
            return i.rt, add(R(i.rs), i.simm & M32)
        if n == 'addi':
            a = R(i.rs)

            if not isint(a):
                contract = self.addi_no_overflow
                if contract is None:
                    raise AssertionError(
                        'ADDI overflow cannot be ruled out at %08x' % i.pc
                    )

                try:
                    decision = contract(i.pc, a, i.simm)
                except Exception as exc:
                    raise AssertionError(
                        'ADDI no-overflow contract failed at %08x' % i.pc
                    ) from exc

                if type(decision) is not bool:
                    raise AssertionError(
                        'ADDI no-overflow contract must return bool'
                    )

                if not decision:
                    raise AssertionError(
                        'ADDI overflow cannot be ruled out at %08x' % i.pc
                    )

                p.assumptions.append(
                    ('addi_no_overflow', i.pc, a, i.simm)
                )
                return i.rt, add(a, i.simm & M32)

            signed_a = a if a < 0x80000000 else a - 0x100000000
            result = signed_a + i.simm

            if result < -0x80000000 or result > 0x7fffffff:
                raise AssertionError(
                    'ADDI signed overflow at %08x' % i.pc
                )

            return i.rt, result & M32
        if n == 'andi':
            a = R(i.rs)
            return i.rt, (a & i.imm) if isint(a) else ('and', a, i.imm)
        if n == 'ori':
            a = R(i.rs)
            return i.rt, (a | i.imm) if isint(a) else (a if i.imm == 0 else ('or', a, i.imm))
        if n == 'addu':
            return i.rd, add(R(i.rs), R(i.rt))
        if n == 'or':
            a, b = R(i.rs), R(i.rt)
            if isint(a) and isint(b):
                return i.rd, a | b
            if b == 0:
                return i.rd, a
            if a == 0:
                return i.rd, b
            return i.rd, ('or', a, b)
        if n == 'sll':
            a = R(i.rt)
            return i.rd, ((a << i.sa) & M32) if isint(a) else (a if i.sa == 0 else ('shl', a, i.sa))
        if n in ('subu', 'and', 'xor', 'nor', 'slt', 'sltu', 'srl', 'sra'):
            a, b = R(i.rs), R(i.rt)
            if isint(a) and isint(b) and n == 'subu':
                return i.rd, (a - b) & M32
            return i.rd, p.unknown('alu@%08x' % i.pc)
        raise AssertionError('unmodelled ALU op %s at %08x' % (n, i.pc))

    def exec1(self, p, i):
        """Execute one non-transfer instruction (load delay handled by the caller)."""
        def R(r): return self.rd(p, r)
        if i.kind == 'alu':
            if i.w == 0:
                return None
            r, v = self.alu(p, i)
            return ('reg', r, v, ('PAL_INSTRUCTION', i.pc, i.name))
        if i.kind == 'load':
            assert i.name in ('lw', 'lh', 'lhu', 'lb', 'lbu'), i
            a = add(R(i.rs), i.simm & M32)
            return ('load', i.rt, self.load(p, a, i.width, i.name in ('lh', 'lb')), ('PAL_INSTRUCTION', i.pc, i.name))
        if i.kind == 'store':
            assert i.name in ('sw', 'sh', 'sb'), i
            self.store(
                p,
                add(R(i.rs), i.simm & M32),
                i.width,
                R(i.rt),
                pc=i.pc,
            )
            return None
        if i.kind == 'syscall':
            # The exception handler reads a0 after a load issued by the previous instruction has retired.
            a0 = p.pending[1] if p.pending is not None and p.pending[0] == 4 else R(4)
            assert isint(a0), 'syscall with unresolved a0 at %08x' % i.pc
            p.events.append(('syscall', a0))

            # Syscalls are memory-clobbering by default. One optional trusted
            # policy may preserve individual pre-existing RAM facts; another may
            # materialize explicitly enumerated pristine image words. General
            # image fallback never survives the syscall, and a later contract
            # cannot recover image knowledge that was already unknown.
            image_was_unknown = p.mem_unknown
            pre_syscall_mem = dict(p.mem)
            p.mutate_memory()
            kept = {}
            used = []

            if self.syscall_memory_preserve is not None:
                for word_key, old_value in p.mem.items():
                    try:
                        decision = self.syscall_memory_preserve(
                            p.last_callsite,
                            i.pc,
                            a0,
                            word_key,
                        )
                    except Exception as exc:
                        raise AssertionError(
                            'syscall memory-preserve contract failed at %08x '
                            'for %r: %s'
                            % (i.pc, word_key, exc)
                        ) from exc

                    if not isinstance(decision, bool):
                        raise AssertionError(
                            'syscall memory-preserve contract must return bool'
                        )

                    if decision:
                        kept[word_key] = old_value
                        used.append((
                            'syscall_memory_preserve',
                            p.last_callsite,
                            i.pc,
                            a0,
                            word_key,
                        ))

            p.mem.clear()
            p.mem.update(kept)
            p.assumptions.extend(used)

            # General pristine-image fallback never survives a syscall.
            # A narrow contract may instead materialize individual image words
            # as explicit memory facts, and only when image validity was known
            # before the syscall.
            p.mem_unknown = True

            if (
                not image_was_unknown
                and self.syscall_image_words is not None
            ):
                try:
                    image_words = self.syscall_image_words(
                        p.last_callsite,
                        i.pc,
                        a0,
                    )
                except Exception as exc:
                    raise AssertionError(
                        'syscall image-words contract failed at %08x: %s'
                        % (i.pc, exc)
                    ) from exc

                if type(image_words) is not tuple:
                    raise AssertionError(
                        'syscall image-words contract must return tuple'
                    )

                if len(set(image_words)) != len(image_words):
                    raise AssertionError(
                        'syscall image-words contract returned duplicate words'
                    )

                for word in image_words:
                    if (
                        type(word) is not int
                        or word < 0
                        or word > M32
                        or word % 4 != 0
                        or (word >> 29) != 4
                    ):
                        raise AssertionError(
                            'syscall image word must be an aligned KSEG0 '
                            'address, got %r' % (word,)
                        )

                    cword = canonical_mem_addr(word)

                    if cword != word:
                        raise AssertionError(
                            'syscall image word is not canonical: %08x'
                            % word
                        )

                    if not self.img.has(word & M32):
                        raise AssertionError(
                            'syscall image word is outside pinned image: %08x'
                            % word
                        )

                    image_value = self.img.word(word)

                    if type(image_value) is not int:
                        raise AssertionError(
                            'syscall image word is not concrete: %08x'
                            % word
                        )

                    # The contract preserves a pristine word; it must never
                    # restore an address that was already explicitly modified.
                    if (
                        word in pre_syscall_mem
                        and pre_syscall_mem[word] != image_value
                    ):
                        raise AssertionError(
                            'syscall image word was not pristine before '
                            'syscall: %08x' % word
                        )

                    p.mem[word] = image_value
                    p.assumptions.append((
                        'syscall_image_word_preserve',
                        p.last_callsite,
                        i.pc,
                        a0,
                        word,
                    ))

            if a0 == 1:
                result = p.unknown('EnterCS.ret')
                p.syscall_returns.append((
                    p.last_callsite,
                    i.pc,
                    a0,
                    result,
                ))
                return (
                    'reg',
                    2,
                    result,
                    (
                        'SYSCALL_SUMMARY',
                        'EnterCriticalSection',
                        i.pc,
                        'v0',
                    ),
                )

            if a0 == 2:
                # ExitCriticalSection is modeled as preserving the incoming v0.
                return None

            return None
        if i.kind == 'cop0' and i.name == 'mfc0':
            # R3000A MFC0 has the same one-instruction delayed register write
            # semantics modeled for MFC2/CFC2.
            return (
                'load',
                i.rt,
                ('S', 'cop0r%d' % i.rd),
                ('PAL_INSTRUCTION', i.pc, i.name),
            )
        if i.kind == 'cop2' and i.name in ('mfc2', 'cfc2'):
            bank = 'd' if i.name == 'mfc2' else 'c'
            return (
                'load',
                i.rt,
                ('S', 'cop2%s%d' % (bank, i.rd)),
                ('PAL_INSTRUCTION', i.pc, i.name),
            )
        raise AssertionError('unmodelled instruction %s' % i)

    def commit(self, p, res, pc=None):
        """Apply a result; a load result is delayed by one instruction (R3000 load delay slot)."""
        if res is None:
            return
        if res[0] == 'reg':
            prov = res[3] if len(res) > 3 else ('PAL_INSTRUCTION', pc, 'alu')
            self.wr(p, res[1], res[2], prov)
        else:
            p.pending = (res[1], res[2])
            p.pending_prov = res[3] if len(res) > 3 else (
                'PAL_INSTRUCTION', pc, 'load')

    def tick(self, p, i):
        self.cover.add(i.pc)
        p.seen.append(i.pc)
        p.steps += 1
        if i.kind == 'syscall':
            # The SYSCALL exception handler runs after a load/MFC0 issued by the previous instruction has
            # retired, so it observes (and exec1 reads) the retired value, not the pre-load register file.
            self.retire_pending(p, i.pc, 'syscall-entry-delay')
        pend = p.pending
        p.pending = None
        pend_prov = p.pending_prov
        p.pending_prov = None
        res = self.exec1(p, i) if i.kind not in (
            'branch', 'j', 'jal', 'jr', 'jalr') else None
        # exec1 (and transfer operand sampling in step_path) reads the old
        # register file. A current write cancels the previous delayed write,
        # whether the new result is immediate, delayed, or a link register.
        written = res[1] if res is not None else (
            31 if i.name in ('jal', 'bltzal', 'bgezal') else i.rd if i.kind == 'jalr' else None)
        if pend and pend[0] != written:
            self.wr(p, pend[0], pend[1], pend_prov or (
                'PAL_INSTRUCTION', i.pc, 'load-delay'))
        self.commit(p, res, i.pc)

    def step_path(self, p, limit, work):
        while True:
            if p.steps > limit:
                raise AssertionError('step limit at %08x' % p.pc)
            if p.pc == SENTINEL:
                return p
            pc = p.pc
            if isint(pc) and (pc & 0x1fffffff) in VEC and (pc >> 29) in (0, 4, 5):
                # A load/MFC0/MFC2/CFC2 issued in the delay slot of the transfer into the vector is retired
                # before the dispatcher reads t1 (function number), a0..a3 and ra: the vector stub executes at
                # least one instruction first. Retire BEFORE sampling fn/a0 and before capturing the return link.
                ra_pending = p.pending is not None and p.pending[0] == 31
                self.retire_pending(p, pc, 'bios-entry-delay')
                if ra_pending:
                    p.link = self.rd(p, 31)
                self.bios(p, VEC[pc & 0x1fffffff], self.rd(p, 9), pc)
                # the BIOS returns to the link register value it was entered with
                p.pc = p.link
                continue
            i = self.fetch_instruction(p, pc)
            if i.kind in ('branch', 'j', 'jal', 'jr', 'jalr'):
                def R(r): return self.rd(p, r)
                taken, target = None, None
                if i.kind == 'branch':
                    a, b = R(i.rs), (R(i.rt) if i.name in (
                        'beq', 'bne') else 0)
                    if isint(a) and isint(b):
                        sa = a - (1 << 32) if a >> 31 else a
                        taken = {'beq': a == b, 'bne': a != b, 'blez': sa <= 0, 'bgtz': sa > 0,
                                 'bltz': sa < 0, 'bgez': sa >= 0,
                                 'bltzal': sa < 0, 'bgezal': sa >= 0}[i.name]
                    else:
                        q = p.fork()
                        q.cond.append(Condition(pc, i.name, a, b, True))
                        p.cond.append(Condition(pc, i.name, a, b, False))
                        self.finish_branch(q, i, True)
                        work.append(q)
                        taken = False
                    target = i.target
                elif i.kind in ('j', 'jal'):
                    taken, target = True, i.target
                else:
                    taken, target = True, R(i.rs)
                self.finish_branch(p, i, taken, target)
                continue
            self.tick(p, i)
            p.pc = pc + 4

    def finish_branch(self, p, i, taken, target=None):
        if target is None:
            target = i.target
        # the transfer itself (no register effect except link below)
        self.tick(p, i)
        if i.kind in ('jal', 'jalr'):
            p.last_callsite = i.pc
            self.wr(p, 31 if i.kind == 'jal' else i.rd, i.pc +
                    8, ('PAL_INSTRUCTION', i.pc, i.name))
        if i.name in ('bltzal', 'bgezal'):
            # REGIMM links on both paths, before the delay slot.
            self.wr(p, 31, i.pc + 8, ('PAL_INSTRUCTION', i.pc, i.name))
        slot = self.fetch_instruction(p, i.pc + 4)
        assert slot.kind not in (
            'branch', 'j', 'jal', 'jr', 'jalr'), 'transfer in delay slot at %08x' % slot.pc
        self.tick(p, slot)
        p.link = self.rd(p, 31)
        p.pc = target if taken else i.pc + 8
        assert isint(p.pc), 'unresolved transfer target at %08x: %s' % (
            i.pc, render(p.pc))
