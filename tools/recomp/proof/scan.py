"""Phase 6b probe, part 1: image model and whole-image scans (read-only). No game bytes are stored in this file."""
import struct
from mips import decode, is_transfer, is_delayed_write, REG

M32 = 0xffffffff
VECTORS = {0xa0: 'A0', 0xb0: 'B0', 0xc0: 'C0'}


def phys(a):
    return a & 0x1fffffff


class Image:
    def __init__(self, name, data, base):
        self.name, self.data, self.base = name, data, base
        assert len(data) % 4 == 0, '%s: length %d not word aligned' % (
            name, len(data))
        self.n = len(data) // 4
        self.words = list(struct.unpack('<%dI' % self.n, data))
        self.ins = [decode(w, base + 4 * k) for k, w in enumerate(self.words)]
        self.end = base + 4 * self.n

    def has(self, a):
        return self.base <= a < self.end and (a - self.base) % 4 == 0

    def word(self, a):
        assert self.has(a), '%s: 0x%08x outside image' % (self.name, a)
        return self.words[(a - self.base) // 4]

    def at(self, a):
        return self.ins[(a - self.base) // 4]

    def rng(self, a, b):
        assert self.has(a) and self.has(b - 4) and b > a
        return [self.at(x) for x in range(a, b, 4)]


def load_exe(path):
    d = open(path, 'rb').read()
    assert d[:8] == b'PS-X EXE', 'not a PS-X EXE'
    pc0, gp0, t_addr, t_size = struct.unpack_from('<4I', d, 0x10)
    body = d[0x800:0x800 + t_size]
    assert len(body) == t_size, 'truncated text'
    return Image('EXE', body, t_addr), pc0, d


def alu(i, st):
    """Constant evaluation of one instruction's GPR result. Returns (reg, value-or-None) or None."""
    def g(r): return 0 if r == 0 else st.get(r)
    n = i.name
    if not i.writes or i.kind in ('load', 'jal', 'jalr', 'branch', 'cop0', 'cop2'):
        return None
    if n == 'lui':
        return i.rt, (i.imm << 16) & M32
    if n in ('addiu', 'addi'):
        a = g(i.rs)
        return i.rt, None if a is None else (a + i.simm) & M32
    if n in ('ori', 'andi', 'xori'):
        a = g(i.rs)
        if a is None:
            return i.rt, (0 if n == 'andi' and i.imm == 0 else None)
        return i.rt, {'ori': a | i.imm, 'andi': a & i.imm, 'xori': a ^ i.imm}[n]
    if n in ('addu', 'add', 'subu', 'sub', 'or', 'and', 'xor', 'nor', 'slt', 'sltu'):
        a, b = g(i.rs), g(i.rt)
        if a is None or b is None:
            return i.rd, None
        v = {'addu': a + b, 'add': a + b, 'subu': a - b, 'sub': a - b, 'or': a | b, 'and': a & b, 'xor': a ^ b,
             'nor': ~(a | b), 'slt': int((a - (1 << 32) if a >> 31 else a) < (b - (1 << 32) if b >> 31 else b)),
             'sltu': int(a < b)}[n]
        return i.rd, v & M32
    if n in ('sll', 'srl', 'sra'):
        a = g(i.rt)
        if a is None:
            return i.rd, None
        if n == 'sll':
            return i.rd, (a << i.sa) & M32
        if n == 'srl':
            return i.rd, a >> i.sa
        return i.rd, ((a - (1 << 32) if a >> 31 else a) >> i.sa) & M32
    w = list(i.writes)
    return (w[0], None) if len(w) == 1 and w[0] < 32 else None


def leaders(img):
    L = {img.base}
    for i in img.ins:
        if i.target is not None and img.has(i.target):
            L.add(i.target)
        if is_transfer(i) and i.kind != 'branch':
            # after j/jr (no fall-through) and after calls (callee clobbers state)
            L.add(i.pc + 8)
    return L


def delayed_write(i):
    return is_delayed_write(i)


def state_after_slot(st, slot):
    """Constant GPR state visible to a transfer's target after its delay-slot instruction.

    ALU results are exact. Any other GPR write made in the slot (a load, or a delayed MFC0/MFC2/CFC2 result) is not a
    constant, so the previous constant for that register must not survive."""
    st2 = dict(st)
    r = alu(slot, st2)
    if r:
        st2[r[0]] = r[1]
    for wr in slot.writes:
        if wr < 32 and (not r or wr != r[0]):
            st2[wr] = None
    return st2


def sweep(img):
    """Linear sweep with basic-block-local constant propagation over EVERY word of the image (a superset of the
    executable code). Yields per-instruction records the scans below consume."""
    L = leaders(img)
    st = {}
    prov = {}
    out = []
    k = 0
    while k < img.n:
        i = img.ins[k]
        if i.pc in L:
            st = {}
            prov = {}
        rec = {'i': i, 'st': dict(st), 'prov': dict(prov)}
        if i.kind in ('load', 'store'):
            b = 0 if i.rs == 0 else st.get(i.rs)
            rec['ea'] = None if b is None else (b + i.simm) & M32
            if i.kind == 'store':
                rec['sval'] = 0 if i.rt == 0 else st.get(i.rt)
            rec['bprov'] = prov.get(i.rs)
        if i.kind in ('jr', 'jalr'):
            cell = prov.get(i.rs)
            if k > 0 and delayed_write(img.ins[k - 1]) and i.rs in img.ins[k - 1].writes:
                cell = out[-1]['prov'].get(i.rs)
            rec['cell'] = cell
        if i.kind in ('jr', 'jalr'):
            prev = out[-1]['st'] if out else {}
            old = None
            if k > 0 and delayed_write(img.ins[k - 1]) and i.rs in img.ins[k - 1].writes:
                old = prev.get(i.rs)
            rec['tgt'] = old if old is not None else (
                0 if i.rs == 0 else st.get(i.rs))
            st2 = state_after_slot(st, img.ins[k + 1]) if k + 1 < img.n else dict(st)
            rec['t1_after_slot'] = st2.get(9)
        if i.kind in ('j', 'jal'):
            st2 = state_after_slot(st, img.ins[k + 1]) if k + 1 < img.n else dict(st)
            rec['t1_after_slot'] = st2.get(9)
        for wr in i.writes:
            prov.pop(wr, None)
        if i.name == 'lw' and rec.get('ea') is not None:
            prov[i.rt] = rec['ea']
        r = alu(i, st)
        if r:
            if r[1] is None:
                st.pop(r[0], None)
            else:
                st[r[0]] = r[1]
            rec['def'] = r
        for wr in i.writes:
            if wr < 32 and (not r or wr != r[0]):
                st.pop(wr, None)
        out.append(rec)
        k += 1
    return out


def bios_calls(img, recs):
    """Every control transfer whose destination is provably one of the BIOS vectors 0xA0/0xB0/0xC0 (any segment)."""
    res = []
    for rec in recs:
        i = rec['i']
        t = rec.get('tgt') if i.kind in ('jr', 'jalr') else (
            i.target if i.kind in ('j', 'jal') else None)
        if t is None:
            continue
        if phys(t) in VECTORS and (t >> 29) in (0, 4, 5):
            res.append({'pc': i.pc, 'via': i.name,
                       'vec': VECTORS[phys(t)], 'fn': rec.get('t1_after_slot')})
    return res


def vector_constants(img, recs):
    """Every place a register is set to a BIOS vector address, and every data word equal to one."""
    regs = [(rec['i'].pc, rec['def'][1]) for rec in recs if rec.get('def') and rec['def'][1] is not None
            and phys(rec['def'][1]) in VECTORS and (rec['def'][1] >> 29) in (0, 4, 5)]
    data = [(img.base + 4 * k, w) for k, w in enumerate(img.words)
            if phys(w) in VECTORS and (w >> 29) in (0, 4, 5)]
    return regs, data


def kernel_refs(img, recs, lo=0x0000, hi=0x10000):
    """Memory accesses / transfers / constants that provably address kernel RAM (physical lo..hi)."""
    acc, tr, cons = [], [], []
    for rec in recs:
        i = rec['i']
        ea = rec.get('ea')
        if ea is not None and lo <= phys(ea) < hi and (ea >> 29) in (0, 4, 5):
            acc.append((i.pc, i.name, ea))
        t = rec.get('tgt')
        if i.kind in ('jr', 'jalr') and t is not None and lo <= phys(t) < hi and (t >> 29) in (0, 4, 5) \
                and phys(t) not in VECTORS:
            tr.append((i.pc, i.name, t))
        d = rec.get('def')
        if d and d[1] is not None and lo <= phys(d[1]) < hi and (d[1] >> 29) in (4, 5):
            cons.append((i.pc, d[1]))
    return acc, tr, cons


def refs_to(imgs_recs, targets):
    """All references to each target address: j/jal, data word, or any register constant equal to it."""
    out = {t: [] for t in targets}
    for img, recs in imgs_recs:
        for rec in recs:
            i = rec['i']
            if i.kind in ('j', 'jal') and i.target in out:
                out[i.target].append((img.name, i.pc, i.name))
            d = rec.get('def')
            if d and d[1] in out:
                out[d[1]].append((img.name, i.pc, 'const'))
        for k, w in enumerate(img.words):
            if w in out:
                out[w].append((img.name, img.base + 4 * k, 'word'))
    return out


def data_words_in(img, lo, hi):
    """Data words whose value lies in [lo,hi) physical, in KUSEG/KSEG0/KSEG1."""
    return [(img.base + 4 * k, w) for k, w in enumerate(img.words) if lo <= phys(w) < hi and (w >> 29) in (0, 4, 5)]


def descend(img, entries):
    """Recursive-descent code discovery from the given entries (control flow only)."""
    code, bad = set(), set()
    work = [e for e in entries if img.has(e)]
    while work:
        pc = work.pop()
        while img.has(pc) and pc not in code:
            i = img.at(pc)
            if i.kind == 'invalid':
                bad.add(pc)
                break
            code.add(pc)
            if i.kind == 'branch':
                work += [i.target, pc + 8]
                pc += 4
                continue
            if i.kind == 'j':
                work.append(i.target)
                pc += 4
                code.add(pc) if img.has(pc) and img.at(
                    pc).kind != 'invalid' else None
                break
            if i.kind == 'jal':
                work += [i.target, pc + 8]
                pc += 4
                continue
            if i.kind == 'jr':
                pc += 4
                code.add(pc) if img.has(pc) and img.at(
                    pc).kind != 'invalid' else None
                break
            if i.kind == 'jalr':
                work.append(pc + 8)
                pc += 4
                continue
            pc += 4
    return code, bad


def discover_code(img, pc0, recs):
    """Iterate descent: entry + every code constant / jump-table word that points into the provisional text."""
    entries = {pc0}
    code, bad = descend(img, entries)
    for _ in range(20):
        lim = max(code) + 4
        cand = set()
        for rec in recs:
            i = rec['i']
            d = rec.get('def')
            if i.pc in code and d and d[1] is not None and img.base <= d[1] < lim and d[1] % 4 == 0:
                cand.add(d[1])
        for k, w in enumerate(img.words):
            a = img.base + 4 * k
            if a not in code and img.base <= w < lim and w % 4 == 0:
                cand.add(w)
        new = cand - code - entries
        new = {x for x in new if img.at(x).kind != 'invalid'}
        if not new:
            break
        entries |= new
        code, bad = descend(img, entries)
    return code, bad, max(code) + 4


def cell_writes(recs):
    """Constant-address stores: cell -> list of (pc, stored constant or None)."""
    out = {}
    for rec in recs:
        if rec['i'].kind == 'store' and rec.get('ea') is not None:
            out.setdefault(rec['ea'], []).append(
                (rec['i'].pc, rec.get('sval')))
    return out


def merged(title, exe):
    """One address space 0x80010200..EXE end: TITLE overlay image, a gap that is never text, then the EXE."""
    import struct as _s
    gap = exe.base - title.end
    assert gap >= 0 and gap % 4 == 0
    data = title.data + b'\xff\xff\xff\xff' * (gap // 4) + exe.data
    return Image('EXE+TITLE', data, title.base)


def synthetic_regressions():
    """Load-delay sanity check across a transfer: jalr must still use the pre-load register value."""
    code = [
        0x240a00b0,  # addiu t2,zero,0xb0
        0x8d0a0000,  # lw t2,0x0(t0)
        0x01400009,  # jalr t2
        0x00000000,  # nop
    ]
    img = Image('synthetic-delay', b''.join(w.to_bytes(4, 'little')
                for w in code), 0x80010000)
    recs = sweep(img)
    jalr = recs[2]
    assert jalr['i'].kind == 'jalr'
    assert jalr['tgt'] == 0x00B0, 'jalr must use the old value 0xB0 across the lw delay slot'
    return True
