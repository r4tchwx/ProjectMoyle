"""Minimal R3000A decoder for the Phase 6b probe (read-only analysis helper; no game data in this file)."""
REG = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
       's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra']
HI, LO = 32, 33
RNAME = REG + ['hi', 'lo']


def sx16(v):
    return v - 0x10000 if v & 0x8000 else v


class Ins:
    __slots__ = ('pc', 'w', 'op', 'rs', 'rt', 'rd', 'sa', 'imm', 'simm', 'target', 'name', 'reads', 'writes',
                 'kind', 'width')

    def __str__(self):
        return '%08x %08x %s' % (self.pc, self.w, self.text())

    def text(self):
        n = self.name
        R = lambda r: REG[r]
        if n in ('sll', 'srl', 'sra'):
            return 'nop' if self.w == 0 else '%s %s,%s,%d' % (n, R(self.rd), R(self.rt), self.sa)
        if n in ('sllv', 'srlv', 'srav'):
            return '%s %s,%s,%s' % (n, R(self.rd), R(self.rt), R(self.rs))
        if n in ('addu', 'add', 'subu', 'sub', 'and', 'or', 'xor', 'nor', 'slt', 'sltu'):
            return '%s %s,%s,%s' % (n, R(self.rd), R(self.rs), R(self.rt))
        if n == 'jr':
            return 'jr %s' % R(self.rs)
        if n == 'jalr':
            return 'jalr %s,%s' % (R(self.rd), R(self.rs))
        if n in ('mfhi', 'mflo'):
            return '%s %s' % (n, R(self.rd))
        if n in ('mthi', 'mtlo'):
            return '%s %s' % (n, R(self.rs))
        if n in ('mult', 'multu', 'div', 'divu'):
            return '%s %s,%s' % (n, R(self.rs), R(self.rt))
        if n in ('syscall', 'break', 'rfe', 'cop2cmd'):
            return '%s 0x%x' % (n, (self.w >> 6) & 0xfffff if n in ('syscall', 'break') else self.w & 0x1ffffff)
        if n in ('j', 'jal'):
            return '%s 0x%08x' % (n, self.target)
        if n in ('beq', 'bne'):
            return '%s %s,%s,0x%08x' % (n, R(self.rs), R(self.rt), self.target)
        if n in ('blez', 'bgtz', 'bltz', 'bgez', 'bltzal', 'bgezal'):
            return '%s %s,0x%08x' % (n, R(self.rs), self.target)
        if n == 'lui':
            return 'lui %s,0x%x' % (R(self.rt), self.imm)
        if n in ('andi', 'ori', 'xori'):
            return '%s %s,%s,0x%x' % (n, R(self.rt), R(self.rs), self.imm)
        if n in ('addi', 'addiu', 'slti', 'sltiu'):
            return '%s %s,%s,%s' % (n, R(self.rt), R(self.rs), hex(self.simm))
        if self.kind in ('load', 'store'):
            return '%s %s,%s(%s)' % (n, R(self.rt), hex(self.simm), R(self.rs))
        if n in ('mfc0', 'mtc0', 'mfc2', 'mtc2', 'cfc2', 'ctc2'):
            return '%s %s,$%d' % (n, R(self.rt), self.rd)
        if n in ('lwc2', 'swc2'):
            return '%s $%d,%s(%s)' % (n, self.rt, hex(self.simm), R(self.rs))
        return n


SPECIAL = {0: 'sll', 2: 'srl', 3: 'sra', 4: 'sllv', 6: 'srlv', 7: 'srav', 8: 'jr', 9: 'jalr', 12: 'syscall',
           13: 'break', 16: 'mfhi', 17: 'mthi', 18: 'mflo', 19: 'mtlo', 24: 'mult', 25: 'multu', 26: 'div',
           27: 'divu', 32: 'add', 33: 'addu', 34: 'sub', 35: 'subu', 36: 'and', 37: 'or', 38: 'xor', 39: 'nor',
           42: 'slt', 43: 'sltu'}
IOPS = {8: 'addi', 9: 'addiu', 10: 'slti', 11: 'sltiu', 12: 'andi', 13: 'ori', 14: 'xori', 15: 'lui'}
LOADS = {32: ('lb', 1), 33: ('lh', 2), 34: ('lwl', 4), 35: ('lw', 4), 36: ('lbu', 1), 37: ('lhu', 2), 38: ('lwr', 4)}
STORES = {40: ('sb', 1), 41: ('sh', 2), 42: ('swl', 4), 43: ('sw', 4), 46: ('swr', 4)}


def decode(w, pc):
    i = Ins()
    i.pc, i.w = pc, w
    op = w >> 26
    i.op, i.rs, i.rt, i.rd, i.sa = op, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31, (w >> 6) & 31
    i.imm = w & 0xffff
    i.simm = sx16(i.imm)
    i.target = None
    i.reads, i.writes = set(), set()
    i.kind = 'alu'
    i.width = 0
    i.name = '?'
    rs, rt, rd = i.rs, i.rt, i.rd
    if op == 0:
        f = w & 63
        n = SPECIAL.get(f, '?')
        i.name = n
        if n in ('sll', 'srl', 'sra'):
            i.reads, i.writes = {rt}, {rd}
        elif n in ('sllv', 'srlv', 'srav'):
            i.reads, i.writes = {rs, rt}, {rd}
        elif n == 'jr':
            i.reads, i.kind = {rs}, 'jr'
        elif n == 'jalr':
            i.reads, i.writes, i.kind = {rs}, {rd}, 'jalr'
        elif n in ('syscall', 'break'):
            i.kind = n
        elif n in ('mfhi', 'mflo'):
            i.reads, i.writes = {HI if n == 'mfhi' else LO}, {rd}
        elif n in ('mthi', 'mtlo'):
            i.reads, i.writes = {rs}, {HI if n == 'mthi' else LO}
        elif n in ('mult', 'multu', 'div', 'divu'):
            i.reads, i.writes = {rs, rt}, {HI, LO}
        elif n != '?':
            i.reads, i.writes = {rs, rt}, {rd}
        else:
            i.kind = 'invalid'
    elif op == 1:
        n = {0: 'bltz', 1: 'bgez', 16: 'bltzal', 17: 'bgezal'}.get(rt, '?')
        i.name, i.kind = n, ('branch' if n != '?' else 'invalid')
        i.reads = {rs}
        if n.endswith('al'):
            i.writes = {31}
        i.target = (pc + 4 + (i.simm << 2)) & 0xffffffff
    elif op in (2, 3):
        i.name = 'j' if op == 2 else 'jal'
        i.kind = i.name
        i.target = ((pc + 4) & 0xf0000000) | ((w & 0x3ffffff) << 2)
        if op == 3:
            i.writes = {31}
    elif op in (4, 5, 6, 7):
        i.name = {4: 'beq', 5: 'bne', 6: 'blez', 7: 'bgtz'}[op]
        i.kind = 'branch'
        i.reads = {rs, rt} if op in (4, 5) else {rs}
        i.target = (pc + 4 + (i.simm << 2)) & 0xffffffff
    elif op in IOPS:
        i.name = IOPS[op]
        i.reads, i.writes = ({rs} if op != 15 else set()), {rt}
    elif op in LOADS:
        i.name, i.width = LOADS[op]
        i.kind = 'load'
        i.reads, i.writes = ({rs, rt} if i.name in ('lwl', 'lwr') else {rs}), {rt}
    elif op in STORES:
        i.name, i.width = STORES[op]
        i.kind = 'store'
        i.reads = {rs, rt}
    elif op == 16:
        if rs == 0:
            i.name, i.writes, i.kind = 'mfc0', {rt}, 'cop0'
        elif rs == 4:
            i.name, i.reads, i.kind = 'mtc0', {rt}, 'cop0'
        elif rs == 16 and (w & 63) == 16:
            i.name, i.kind = 'rfe', 'cop0'
        else:
            i.kind = 'invalid'
    elif op == 18:
        if w & (1 << 25):
            i.name, i.kind = 'cop2cmd', 'cop2'
        elif rs in (0, 2):
            i.name, i.writes, i.kind = ('mfc2' if rs == 0 else 'cfc2'), {rt}, 'cop2'
        elif rs in (4, 6):
            i.name, i.reads, i.kind = ('mtc2' if rs == 4 else 'ctc2'), {rt}, 'cop2'
        else:
            i.kind = 'invalid'
    elif op == 50:
        i.name, i.reads, i.kind = 'lwc2', {rs}, 'cop2'
    elif op == 58:
        i.name, i.reads, i.kind = 'swc2', {rs}, 'cop2'
    else:
        i.kind = 'invalid'
    i.reads.discard(0)
    i.writes.discard(0)
    return i


def is_transfer(i):
    return i.kind in ('branch', 'j', 'jal', 'jr', 'jalr')


def is_delayed_write(i):
    """True when the instruction's GPR result is architecturally delayed by one instruction (R3000A load delay).

    Single source of truth for sym.py (via the exec1 'load' result), scan.py and live.py: loads (including
    LWL/LWR) and the COP moves MFC0, MFC2 and CFC2 all write their destination one instruction late."""
    return i.kind == 'load' or i.name in ('mfc0', 'mfc2', 'cfc2')
