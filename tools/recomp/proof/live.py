"""Phase 6b probe, part 3: interprocedural register liveness from a continuation PC (read-only).
Function summaries: for register r, a function is READ (some path reads r before writing it), KILL (every path to a
return writes r first) or THRU (neither). Conservative rules (anything not provable counts as a read):
  * BIOS vector call: reads the documented argument registers (a0..a3 if undocumented), sp and ra; writes v0 only
    when a return value is documented; otherwise writes nothing;
  * syscall: reads a0; EnterCriticalSection (a0 = 1) writes v0 (documented return value);
  * load delay: a register written by a load is still the old value for the next instruction;
  * unresolved indirect call -> READ; unresolved indirect jump (not jr ra) -> READ;
  * an interrupt may be taken between instructions; the PAL's interrupt entry (harness InterruptEntry / BIOS
    SetCustomExitFromException path) saves and restores all GPRs without consuming them, so it is not a reader."""
import bisect
from mips import RNAME, is_delayed_write
from scan import VECTORS, phys

BIOS_ARGS = {('A0', 0x44): 0, ('B0', 0x56): 0, ('B0', 0x57): 0, ('B0', 0x4a): 1, ('B0', 0x4b): 0, ('B0', 0x4c): 0,
             ('B0', 0x5b): 1, ('A0', 0x70): 0, ('C0', 0x0a): 2, ('B0', 0x08): 4, ('B0', 0x0c): 1, ('B0', 0x0b): 1,
             ('B0', 0x09): 1, ('C0', 0x02): 2, ('C0', 0x03): 2, ('B0', 0x19): 1, ('B0', 0x17): 0, ('A0', 0x72): 0}
BIOS_RET = {('B0', 0x56), ('B0', 0x57), ('B0', 0x08),
            ('B0', 0x0c), ('B0', 0x0b), ('B0', 0x5b), ('C0', 0x0a)}
READ, KILL, THRU = 'READ', 'KILL', 'THRU'


def delayed_write(i):
    return is_delayed_write(i)


class Liveness:
    def __init__(self, img, recs, text_end, resolved=None, extra_entries=(), forced=None, restore_sites=(),
                 abi_sites=(), text_ranges=None):
        self.text_ranges = text_ranges or [(img.base, text_end)]
        self.restore_sites = set(restore_sites)
        # ASSUMPTION sites: callee reads only a0..a3/sp/ra, writes nothing
        self.abi_sites = set(abi_sites)
        self.abi_used = set()
        self.img, self.text_end = img, text_end
        # branch pc -> the only feasible successor (evidence in the probe)
        self.forced = dict(forced or {})
        self.rec = {r['i'].pc: r for r in recs}
        self.resolved = {k: (v if isinstance(v, list) else [
                             v]) for k, v in (resolved or {}).items()}
        self.notes = {k: 'declared' for k in self.resolved}
        self.store_recs = [
            r for r in recs if r['i'].kind == 'store'
        ]
        self.unknown_address_store_pcs = [
            r['i'].pc for r in recs
            if r['i'].kind == 'store' and r.get('ea') is None
        ]
        self.unresolved_indirect_calls = [
            r for r in recs
            if self.is_text(r['i'].pc)
            and (
                r['i'].kind == 'jalr'
                or (r['i'].kind == 'jr' and r['i'].rs != 31)
            )
            and r.get('tgt') is None
        ]
        ent = set(extra_entries)
        calls = {}
        for r in recs:
            i = r['i']
            if not self.is_text(i.pc):
                continue
            if i.kind in ('jal', 'j'):
                target = i.target
            elif i.kind == 'jalr' and isinstance(r.get('tgt'), int):
                target = r['tgt']
            elif (
                i.kind == 'jr'
                and i.rs != 31
                and isinstance(r.get('tgt'), int)
            ):
                target = r['tgt']
            else:
                continue
            ent.add(target)
            calls.setdefault(target, []).append(r)
        # function starts that are never called directly: an instruction right after a 'jr ra' + delay slot (or
        # after nop padding that follows one) starts a new function for boundary purposes
        for lo, hi in self.text_ranges:
            a = lo + 8
            while a < hi:
                p1, p2 = img.at(a - 8), img.at(a - 4)
                if p1.name == 'jr' and p1.rs == 31 and img.at(a).w != 0:
                    ent.add(a)
                elif p2.w == 0 and img.at(a).w != 0:
                    b = a - 4
                    while b > lo and img.at(b).w == 0:
                        b -= 4
                    if img.at(b - 4).name == 'jr' and img.at(b - 4).rs == 31:
                        ent.add(a)
                a += 4
        self.entries = sorted(e for e in ent if img.has(e) and self.is_text(e))
        self.unresolvable_cells = {}
        for r in recs:
            i = r['i']
            if i.kind == 'jalr' and self.is_text(i.pc) and isinstance(r.get('cell'), int) and i.pc not in self.resolved:
                vals, why = self.cell_values(
                    r['cell'],
                    calls,
                    resolving_pc=i.pc,
                )
                if vals is not None:
                    vals = sorted(v for v in vals if v != 0)
                    if all(img.has(v) and self.is_text(v) for v in vals):
                        self.resolved[i.pc] = vals
                        self.notes[i.pc] = why
                else:
                    self.unresolvable_cells[i.pc] = (r['cell'], why)
        for v in self.resolved.values():
            ent |= set(v)
        self.entries = sorted(e for e in ent if img.has(e) and self.is_text(e))
        self.tables = sorted(w for k, w in enumerate(img.words)
                             if not self.is_text(img.base + 4 * k) and self.is_text(w) and w % 4 == 0)
        self.memo, self.wit = {}, {}
        self.jt_used, self.unresolved = set(), set()
        # BREAK sites reached by a query. Their exception continuation is not modelled (fail closed -> READ).
        self.unmodeled_exceptions = set()

    def is_text(self, a):
        return any(lo <= a < hi for lo, hi in self.text_ranges)

    @staticmethod
    def canonical_cell_addr(addr):
        addr &= 0xffffffff
        if (addr >> 29) in (4, 5):
            return 0x80000000 | (addr & 0x1fffffff)
        return addr

    def cell_values(self, cell, calls, resolving_pc=None):
        """Conservative may-values for a static 32-bit function-pointer cell."""
        img = self.img
        cell = self.canonical_cell_addr(cell)

        if self.unknown_address_store_pcs:
            return None, (
                'unknown-address store(s) may alias cell %08x: %s'
                % (cell, ','.join('%08x' % pc
                                  for pc in self.unknown_address_store_pcs))
            )

        writes = []
        for r in self.store_recs:
            ea = r.get('ea')
            if ea is None:
                continue

            ea = self.canonical_cell_addr(ea)
            width = r['i'].width

            # Any overlap with the four-byte pointer cell matters. Only an
            # aligned full-word store can be modeled as a replacement value;
            # partial or offset overlap makes the target set non-exhaustive.
            if ea < cell + 4 and cell < ea + width:
                if r['i'].name != 'sw' or ea != cell or width != 4:
                    return None, (
                        'store %08x (%s at %08x) partially overlaps cell %08x'
                        % (r['i'].pc, r['i'].name, ea, cell)
                    )
                writes.append(r)

        vals = {img.word(cell)} if img.has(cell) else set()
        why = ['init %08x' % (img.word(cell) if img.has(cell) else 0)]

        for r in writes:
            pc = r['i'].pc
            v = r.get('sval')
            if v is not None:
                vals.add(v)
                why.append('%08x<-%08x' % (pc, v))
                continue

            st = img.at(pc)
            f = self.func_of(pc)
            if st.rt not in (4, 5, 6, 7) or f is None:
                return None, 'store %08x of non-argument register' % pc
            if any(st.rt in img.at(a).writes for a in range(f, pc, 4)):
                return None, 'store %08x: argument register rewritten before the store' % pc
            for c in self.unresolved_indirect_calls:
                # The indirect transfer currently being resolved is allowed to
                # depend on this cell; otherwise every cell-backed jalr would
                # block itself. Any other unresolved indirect transfer may
                # still reach this setter with an unconstrained argument.
                if c['i'].pc == resolving_pc:
                    continue
                return None, (
                    'setter %08x may be reached by unresolved %s %08x'
                    % (f, c['i'].name, c['i'].pc)
                )
            for c in calls.get(f, []):
                if c['i'].pc in self.restore_sites:
                    why.append('restore@%08x' % c['i'].pc)
                    continue
                a = c['st'].get(st.rt)
                slot = img.at(c['i'].pc + 4)
                if st.rt in slot.writes:
                    from scan import alu
                    rr = alu(slot, dict(c['st']))
                    a = rr[1] if rr else None
                if a is None:
                    return None, 'setter %08x called at %08x with unknown %s' % (f, c['i'].pc, RNAME[st.rt])
                vals.add(a)
                why.append('%08x(%s=%08x)@%08x' %
                           (f, RNAME[st.rt], a, c['i'].pc))
        return vals, 'cell %08x: ' % cell + ', '.join(why)

    def func_of(self, pc):
        k = bisect.bisect_right(self.entries, pc) - 1
        return self.entries[k] if k >= 0 else None

    def func_end(self, f):
        k = bisect.bisect_right(self.entries, f)
        return self.entries[k] if k < len(self.entries) else max(hi for _, hi in self.text_ranges)

    def bios_id(self, pc):
        r = self.rec.get(pc)
        t = r.get('tgt') if r else None
        if t is not None and phys(t) in VECTORS and (t >> 29) in (0, 4, 5):
            return (VECTORS[phys(t)], r.get('t1_after_slot'))
        return None

    def thunk_id(self, t):
        if not self.img.has(t):
            return None
        a, b, c = self.img.at(t), self.img.at(t + 4), self.img.at(t + 8)
        if a.name == 'addiu' and a.rs == 0 and a.rt == 10 and a.imm in VECTORS and b.name == 'jr' and b.rs == 10 \
                and c.name == 'addiu' and c.rs == 0 and c.rt == 9:
            return (VECTORS[a.imm], c.imm)
        return None

    def bios_effect(self, bid, reg):
        nargs = BIOS_ARGS.get(bid, 4)
        if reg in {4 + k for k in range(nargs)} | {29, 31}:
            return READ
        if bid[1] is None and reg == 9:
            # Direct vector call whose function number was not established as a block-local constant (for
            # example t1 comes from a delay-slot load/MFC0 or from the caller): the dispatcher consumes t1.
            return READ
        if reg == 2 and bid in BIOS_RET:
            return KILL
        return THRU

    def summary(self, f, reg):
        key = (f, reg)
        if key in self.memo:
            return self.memo[key] if self.memo[key] != 'busy' else THRU
        self.memo[key] = 'busy'
        res, wit = self.walk(f, reg, f, ())
        self.memo[key] = res
        self.wit[key] = wit
        return res

    def walk(self, start, reg, fn, chain):
        img = self.img
        seen = set()
        work = [(start, False, fn, chain)]
        reach_exit = False
        while work:
            item = work.pop()
            if item in seen:
                continue
            seen.add(item)
            pc, pend, f, ch = item
            if not (img.has(pc) and self.is_text(pc)):
                return READ, 'control reaches %08x outside text' % pc
            i = img.at(pc)
            if i.kind == 'invalid':
                return READ, '%08x %s (unsupported instruction)' % (pc, i.text())
            if reg in i.reads:
                return READ, '%08x %s%s' % (pc, i.text(), ' (load-delay slot)' if pend else '')
            if i.kind == 'break':
                # BREAK raises a Breakpoint exception. Whether control ever resumes at pc+4, and what the
                # exception handler observes, is not modelled, so BREAK is NOT ordinary fall-through. Fail
                # closed exactly like an unsupported instruction: the path is unresolved (READ), including
                # when a delayed write is still in flight (no claim is made about exception/load interaction).
                self.unmodeled_exceptions.add(pc)
                return READ, '%08x %s (BREAK: exception continuation not modeled)' % (pc, i.text())
            if i.kind not in ('branch', 'j', 'jal', 'jr', 'jalr'):
                if i.kind == 'syscall':
                    if reg == 4:
                        return READ, '%08x syscall' % pc
                    p = img.at(pc - 4)
                    if reg == 2 and p.name == 'addiu' and p.rt == 4 and p.rs == 0 and p.imm == 1:
                        continue
                if pend:
                    # Another delayed write to this register cancels the old
                    # pending kill: the entry value survives one more slot.
                    if reg in i.writes and delayed_write(i):
                        work.append((pc + 4, True, f, ch))
                    continue
                if reg in i.writes:
                    if delayed_write(i):
                        work.append((pc + 4, True, f, ch))
                    continue
                work.append((pc + 4, False, f, ch))
                continue
            if pend:
                continue
            s = img.at(pc + 4)
            if s.kind == 'break':
                # BREAK in a delay slot: exception with the branch-delay state; not modelled.
                self.unmodeled_exceptions.add(s.pc)
                return READ, '%08x %s (BREAK in delay slot: exception continuation not modeled)' % (s.pc, s.text())
            link = (i.kind == 'jal' and reg == 31) or (i.kind == 'jalr' and reg == i.rd) or \
                   (i.kind == 'branch' and reg in i.writes)
            if not link and reg in s.reads:
                return READ, '%08x %s (delay slot)' % (s.pc, s.text())
            if link or (reg in s.writes and not delayed_write(s)):
                continue
            sl = reg in s.writes and delayed_write(s)
            nxt = []
            if i.kind == 'branch':
                nxt = [self.forced[pc]] if pc in self.forced else [
                    i.target, pc + 8]
            elif i.kind == 'j':
                if i.target in self.entries and self.func_of(i.target) != f:
                    # tail call into another function
                    eff = self.summary(i.target, reg)
                    if eff == READ:
                        return READ, 'tail call %08x reads %s' % (i.target, RNAME[reg])
                    if eff == KILL:
                        continue
                    nxt = ['RET']
                else:
                    nxt = [i.target]
            elif i.kind in ('jal', 'jalr'):
                if i.kind == 'jal':
                    tid = self.thunk_id(i.target)
                    if tid:
                        eff, why = self.bios_effect(
                            tid, reg), 'BIOS %s:%x' % tid
                    else:
                        eff, why = self.summary(
                            i.target, reg), 'call %08x' % i.target
                else:
                    bid = self.bios_id(pc)
                    if bid:
                        eff = self.bios_effect(bid, reg)
                        why = 'BIOS %s:%s' % (bid[0], hex(
                            bid[1]) if bid[1] is not None else '?')
                    elif pc in self.resolved:
                        effs = [self.summary(t, reg)
                                for t in self.resolved[pc]]
                        eff = READ if READ in effs else (
                            KILL if all(e == KILL for e in effs) else THRU)
                        why = 'resolved indirect call %s' % [
                            hex(t) for t in self.resolved[pc]]
                    elif pc in self.abi_sites:
                        self.abi_used.add(pc)
                        eff = READ if reg in (4, 5, 6, 7, 29, 31) else THRU
                        why = 'ABI-ASSUMED indirect call'
                    else:
                        self.unresolved.add(pc)
                        return READ, '%08x %s (unresolved indirect call)' % (pc, i.text())
                if eff == READ:
                    return READ, '%s at %08x reads %s' % (why, pc, RNAME[reg])
                if eff == KILL:
                    continue
                nxt = [pc + 8]
            elif i.kind == 'jr':
                if i.rs == 31:
                    nxt = ['RET']
                else:
                    bid = self.bios_id(pc)
                    if bid:
                        eff = self.bios_effect(bid, reg)
                        if eff == READ:
                            return READ, 'BIOS tail call at %08x' % pc
                        if eff == KILL:
                            continue
                        nxt = ['RET']
                    else:
                        rec = self.rec.get(pc)
                        tgt = rec.get('tgt') if rec else None
                        if tgt is None:
                            self.unresolved.add(pc)
                            return READ, '%08x %s (unresolved indirect jump)' % (pc, i.text())
                        nxt = [tgt]
            for t in nxt:
                if t == 'RET':
                    if ch:
                        (rp, rf), ch2 = ch[-1], ch[:-1]
                        work.append((rp, sl, rf, ch2))
                    else:
                        reach_exit = True
                else:
                    work.append((t, sl, f, ch))
        return (THRU if reach_exit else KILL), None

    def query(self, reg, start, chain, func):
        res, wit = self.walk(start, reg, func, tuple(chain))
        if res == READ:
            return 'live', wit
        if res == THRU:
            return 'live', 'continuation chain exhausted without a write'
        return 'dead', None


def synthetic_delay_checks():
    """mfc0/mfc2/cfc2 use the same delayed-write semantics as an R3000A load."""
    assert delayed_write(__import__('mips').decode(0x40026000, 0x80010000))
    assert delayed_write(__import__('mips').decode(0x48020000, 0x80010000))
    assert delayed_write(__import__('mips').decode(0x48420000, 0x80010004))
    return True
