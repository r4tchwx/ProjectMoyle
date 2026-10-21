"""Tiny R3000A assembler/image helpers shared by the Phase 6d R3000A model regression tests.

Test-only; encodes just the instructions the synthetic fixtures need. No game bytes."""
import sys
from pathlib import Path

PROOF_DIR = Path(__file__).resolve().parents[1] / "tools" / "recomp" / "proof"
if str(PROOF_DIR) not in sys.path:
    sys.path.insert(0, str(PROOF_DIR))

from scan import Image  # noqa: E402

BASE = 0x80010000
DATA = BASE + 0x80          # data words live here, inside the image (readable as pristine image words)
NOP = 0

ZERO, AT, V0, V1, A0, A1, A2, A3 = 0, 1, 2, 3, 4, 5, 6, 7
T0, T1, T2, T3 = 8, 9, 10, 11
S0, S1 = 16, 17
K0, K1, GP, SP, FP, RA = 26, 27, 28, 29, 30, 31


def r_type(funct, rs=0, rt=0, rd=0, sa=0):
    return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct


def i_type(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)


def addu(rd, rs, rt): return r_type(0x21, rs, rt, rd)
def jr(rs): return r_type(0x08, rs)
def jalr(rd, rs): return r_type(0x09, rs, 0, rd)
def syscall(): return 0x0000000c
def break_(): return 0x0000000d
def addiu(rt, rs, imm): return i_type(9, rs, rt, imm)
def lui(rt, imm): return i_type(15, 0, rt, imm)
def ori(rt, rs, imm): return i_type(13, rs, rt, imm)
def lw(rt, off, rs): return i_type(35, rs, rt, off)
def beq(rs, rt, off): return i_type(4, rs, rt, off)
def bne(rs, rt, off): return i_type(5, rs, rt, off)
def j(target): return (2 << 26) | ((target >> 2) & 0x3ffffff)
def mfc0(rt, rd): return 0x40000000 | (rt << 16) | (rd << 11)
def mfc2(rt, rd): return 0x48000000 | (rt << 16) | (rd << 11)
def cfc2(rt, rd): return 0x48400000 | (rt << 16) | (rd << 11)
def mtc0(rt, rd): return 0x40800000 | (rt << 16) | (rd << 11)


def make_image(words, data=(), name="synthetic", size_words=64):
    """`words` start at BASE; `data` words start at DATA. Remaining words are nops (0)."""
    w = [NOP] * size_words
    for k, x in enumerate(words):
        w[k] = x & 0xffffffff
    base_idx = (DATA - BASE) // 4
    for k, x in enumerate(data):
        w[base_idx + k] = x & 0xffffffff
    return Image(name, b"".join(x.to_bytes(4, "little") for x in w), BASE)
