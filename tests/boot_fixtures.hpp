#pragma once
// Phase 4 synthetic boot fixtures (hand-assembled, no game data). One image holds a small "PAL-shaped" boot program and one
// entry per scenario, so the generator test emits a single probe-enabled unit and the runtime test drives every entry:
//   * the PAL's own interrupt idiom: setjmp-style context save (0x8004f4f4 shape), buf.sp replaced by an interrupt stack,
//     B0:19 SetCustomExitFromException, ExitCriticalSection (SYSCALL 2), I_MASK write, service routine ending in B0:17;
//   * GP1 reset / GPU type query / GPUSTAT read, DMA2 configuration, DPCR / DICR / root counter 1;
//   * Phase 5: the libcard InitCARD shape (EnterCriticalSection, B0:4a thunk, then a kernel-patch routine that makes an inline
//     `li t1,0x56; li t2,0xb0; jalr ra,t2` B0:56 call, which the unit does not generate: an explicit boundary stub);
//   * negative entries: unsupported GP1 command, GPUSTAT before reset, unknown MMIO, DMA start, instruction-budget spin,
//     ADDI overflow, pinned callback set, noreturn BREAK root.
#include "closure_fixtures.hpp"
#include <vector>

namespace bfx {
using namespace cfx;
// Layout (EXE load address cfx::A).
constexpr u32 E_OK = A + 0x000, E_GP1BAD = A + 0x100, E_GPUSTAT_EARLY = A + 0x140, E_MMIO_UNKNOWN = A + 0x180, E_DMA_START = A + 0x1c0,
    E_DMA_CFG = A + 0x500, E_SPIN = A + 0x240, E_ADDI = A + 0x260, E_PINNED = A + 0x2a0, E_NORETURN = A + 0x2e0, E_DMA_MODE = A + 0x6c0;
constexpr u32 E_CARD = A + 0x200, TH_INITCARD = A + 0x460, CARD_PATCH = A + 0x4c0;
constexpr u32 SETJMP = A + 0x300, GPU_INIT = A + 0x340, IRQ_INIT = A + 0x3a0, TH_SETEXIT = A + 0x440, TH_RETEXC = A + 0x450,
    ISR = A + 0x700, WAIT = A + 0x4a0, PT0 = A + 0x680, PT1 = A + 0x690, END_TEXT = A + 0x7c0;
// Data cells (inside the image, after the text).
constexpr u32 C_STAT = A + 0x800, C_READ = A + 0x804, C_COUNT = A + 0x808, C_ISTAT = A + 0x80c, C_PTR = A + 0x810, C_RES = A + 0x814,
    C_DMA = A + 0x820, BUF = A + 0x840, ISR_STACK_TOP = A + 0x9f0;
constexpr u32 GP1 = 0x1f801814, GP0 = 0x1f801810, ISTAT = 0x1f801070, IMASK = 0x1f801074, DPCR = 0x1f8010f0, DICR = 0x1f8010f4,
    DMA2 = 0x1f8010a0, RCNT1 = 0x1f801110, RCNT1MODE = 0x1f801114;
constexpr u32 STACK_BASE = 0x801ff000U;   // PS-X EXE header stack (offset 0)

inline u32 beq(u32 rs, u32 rt, std::int32_t words) { return itype(4, rs, rt, u32(words)); }
inline u32 jmp(u32 addr) { return (2U << 26) | ((addr >> 2) & 0x3ffffffU); }
inline u32 addi(u32 rt, u32 rs, std::int32_t imm) { return itype(8, rs, rt, u32(imm)); }
constexpr u32 SYSCALL = 0x0000000cU;
enum : u32 { t6 = 14, s0 = 16, s1 = 17, s2 = 18, s3 = 19, s4 = 20, s5 = 21, s6 = 22, s7 = 23, t9 = 25, gp = 28, fp = 30 };

struct Program {
    Img img;
    std::vector<std::tuple<u32, std::string, u32>> seeds;
};
inline Program program() {
    Program p; auto& img = p.img; img.w.assign(0x300, 0);
    // thunks: addiu t2,zero,0xB0 ; jr t2 ; addiu t1,zero,N ; nop
    img.put(TH_SETEXIT, {itype(9, 0, t2, 0xb0), jr(t2), itype(9, 0, t1, 0x19), 0});
    img.put(TH_RETEXC, {itype(9, 0, t2, 0xb0), jr(t2), itype(9, 0, t1, 0x17), 0});
    // setjmp (the PAL shape): ra,gp,sp,fp,s0..s7 -> buf[0],[11],[1],[2],[3..10]; returns 0
    Fn sj(SETJMP);
    sj.ops({sw(ra, 0, a0), sw(gp, 44, a0), sw(sp, 4, a0), sw(fp, 8, a0)});
    for (unsigned n = 0; n < 8; ++n) sj.op(sw(s0 + n, 12 + 4 * std::int32_t(n), a0));
    sj.ops({addu(v0, zero, zero), JRRA, 0}).done(img);
    // GPU: GP1(0) reset, GP1(0x10000007) type query, GPUSTAT -> C_STAT, GPUREAD -> C_READ
    Fn g(GPU_INIT);
    g.prologue().li(t0, GP1).op(sw(zero, 0, t0)).li(t1, 0x10000007U).op(sw(t1, 0, t0)).op(lw(t2, 0, t0)).nop().stAbs(t2, C_STAT)
     .li(t3, GP0).op(lw(t4, 0, t3)).nop().stAbs(t4, C_READ).epilogue().done(img);
    // IRQ init: setjmp(BUF); beq v0,zero,CONT; nop; jal ISR; nop; CONT: buf[1] = interrupt stack; B0:19(BUF); ExitCriticalSection; I_MASK = 1
    Fn q(IRQ_INIT);
    q.prologue().li(a0, BUF).op(jal(SETJMP)).nop();
    const auto point = q.here();                    // the setjmp return point: buf.ra
    q.op(beq(v0, zero, 3)).nop().op(jal(ISR)).nop();   // CONT is 4 words after the beq
    q.li(t0, ISR_STACK_TOP).li(t1, BUF).op(sw(t0, 4, t1)).li(a0, BUF).op(jal(TH_SETEXIT)).nop()
     .op(addiu(a0, zero, 2)).op(SYSCALL).li(t0, IMASK).op(addiu(t1, zero, 1)).op(sw(t1, 0, t0)).epilogue().done(img);
    (void)point;
    // service routine: record I_STAT, acknowledge bit 0 (write ~1), count, ReturnFromException
    Fn s(ISR);
    s.prologue().li(t0, ISTAT).op(lw(v0, 0, t0)).nop().stAbs(v0, C_ISTAT).op(addiu(v1, zero, -2)).op(sw(v1, 0, t0))
     .ldAbs(v0, C_COUNT).nop().op(addiu(v0, v0, 1)).stAbs(v0, C_COUNT).op(jal(TH_RETEXC)).nop().epilogue().done(img);
    // wait for the interrupt handler to count: loop: lw v0,COUNT ; nop ; beq v0,zero,loop ; nop ; jr ra ; nop
    Fn w(WAIT);
    w.ldAbs(v0, C_COUNT).nop().op(beq(v0, zero, -4)).nop().op(JRRA).nop().done(img);
    // Phase 5 libcard shape: EnterCriticalSection ; InitCARD(0) ; kernel patch (inline B0:56 call) ; ExitCriticalSection
    img.put(TH_INITCARD, {itype(9, 0, t2, 0xb0), jr(t2), itype(9, 0, t1, 0x4a), 0});
    Fn(E_CARD).prologue().op(addiu(a0, zero, 1)).op(SYSCALL).op(addu(a0, zero, zero)).op(jal(TH_INITCARD)).nop().op(jal(CARD_PATCH)).nop()
        .op(addiu(a0, zero, 2)).op(SYSCALL).epilogue().done(img);
    img.put(CARD_PATCH, {itype(9, 0, t1, 0x56), itype(9, 0, t2, 0xb0), jalr(t2), 0, JRRA, 0});
    // main scenario
    Fn ok(E_OK);
    ok.prologue().op(jal(GPU_INIT)).nop().op(jal(IRQ_INIT)).nop().op(jal(WAIT)).nop().epilogue().done(img);
    // negative scenarios
    Fn(E_GP1BAD).li(t0, GP1).op(sw(zero, 0, t0)).li(t1, 0x08000080U).op(sw(t1, 0, t0)).op(JRRA).nop().done(img);
    Fn(E_GPUSTAT_EARLY).li(t0, GP1).op(lw(t1, 0, t0)).nop().op(JRRA).nop().done(img);
    Fn(E_MMIO_UNKNOWN).li(t0, 0x1f801800U).op(lw(t1, 0, t0)).nop().op(JRRA).nop().done(img);
    Fn(E_DMA_START).li(t0, DMA2).li(t1, 0x01000201U).op(sw(t1, 8, t0)).op(JRRA).nop().done(img);
    Fn(E_DMA_MODE).li(t0, DMA2).li(t1, 0x00000600U).op(sw(t1, 8, t0)).op(JRRA).nop().done(img);   // sync mode 3 (linked list is mode 2): bits 9..10 = 3
    // DMA2 configuration, DPCR, DICR, root counter 1: write then read back into C_DMA[..]
    Fn d(E_DMA_CFG);
    d.li(t0, DMA2).li(t1, 0x80100000U).op(sw(t1, 0, t0)).li(t1, 0x00010010U).op(sw(t1, 4, t0)).li(t1, 0x00000201U).op(sw(t1, 8, t0))
     .op(lw(t2, 0, t0)).nop().stAbs(t2, C_DMA).op(lw(t2, 4, t0)).nop().stAbs(t2, C_DMA + 4).op(lw(t2, 8, t0)).nop().stAbs(t2, C_DMA + 8)
     .li(t0, DPCR).li(t1, 0x03333333U).op(sw(t1, 0, t0)).op(lw(t2, 0, t0)).nop().stAbs(t2, C_DMA + 12)
     .li(t0, DICR).li(t1, 0x00900000U).op(sw(t1, 0, t0)).op(lw(t2, 0, t0)).nop().stAbs(t2, C_DMA + 16)
     .li(t0, RCNT1MODE).li(t1, 0x107U).op(sw(t1, 0, t0)).li(t0, RCNT1).op(lw(t2, 0, t0)).nop().stAbs(t2, C_DMA + 20)
     .op(JRRA).nop().done(img);
    Fn(E_SPIN).ldAbs(v0, C_RES).nop().op(beq(v0, zero, -4)).nop().op(JRRA).nop().done(img);   // spins while C_RES == 0 (budget probe)
    // ADDI: 5 -> C_RES, then 0x7fffffff + 1 must trap
    Fn(E_ADDI).op(addi(v1, zero, 5)).stAbs(v1, C_RES).li(v0, 0x7fffffffU).op(addi(v0, v0, 1)).op(JRRA).nop().done(img);
    // pinned callback set: jalr through an argument register
    Fn pin(E_PINNED);
    pin.prologue().op(jalr(a0)).nop().epilogue().done(img);   // callback supplied by the caller: no in-unit proof
    img.put(PT0, {JRRA, addiu(v1, zero, 0x70)});
    img.put(PT1, {JRRA, addiu(v1, zero, 0x71)});
    // noreturn root: a terminal BREAK 1
    Fn(E_NORETURN).op(0x0000004dU).nop().done(img);   // break 1: code field (word >> 6) = 1
    for (auto e : {E_OK, E_GP1BAD, E_GPUSTAT_EARLY, E_MMIO_UNKNOWN, E_DMA_START, E_DMA_MODE, E_DMA_CFG, E_SPIN, E_ADDI, E_PINNED, E_NORETURN, E_CARD})
        p.seeds.emplace_back(e, "confirmed", 128);
    return p;
}
// PS-X EXE file bytes for the program (header fields are parameters so tests can corrupt them).
struct Header {
    u32 pc = E_OK, gp = 0, load = A, size = 0, data = 0, dataSize = 0, bss = 0, bssSize = 0, stackBase = STACK_BASE, stackOffset = 0;
    std::string magic = "PS-X EXE";
};
inline std::vector<std::uint8_t> exeFile(const Img& img, Header h = {}) {
    std::vector<std::uint8_t> b(0x800 + 4 * img.w.size());
    if (!h.size) h.size = u32(4 * img.w.size());
    std::copy(h.magic.begin(), h.magic.end(), b.begin());
    auto put32 = [&](std::size_t p, u32 x) { for (unsigned i = 0; i < 4; ++i) b.at(p + i) = std::uint8_t(x >> (8 * i)); };
    put32(0x10, h.pc); put32(0x14, h.gp); put32(0x18, h.load); put32(0x1c, h.size); put32(0x20, h.data); put32(0x24, h.dataSize);
    put32(0x28, h.bss); put32(0x2c, h.bssSize); put32(0x30, h.stackBase); put32(0x34, h.stackOffset);
    for (std::size_t i = 0; i < img.w.size(); ++i) put32(0x800 + 4 * i, img.w[i]);
    return b;
}
}
