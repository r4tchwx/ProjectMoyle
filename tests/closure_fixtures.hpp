#pragma once
// Phase 3 synthetic fixtures: hand-assembled guest images (no game data) shared by the generator test (which runs the
// real discovery + closure + emitter on each scenario and writes one C++ unit per scenario) and the runtime test (which
// learns the addresses and drives the generated units). The images deliberately use the same shapes the PAL loader uses:
// stack-saved $ra, `lui; lw` pointer loads, `jalr` through the loaded register, `jal` to BIOS thunks, bounded `jr` tables
// and the `divu / bne / nop / break` divide-by-zero guard.
#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace cfx {
using u32 = std::uint32_t;
constexpr u32 A = 0x80020000U, TEXT_END = A + 0x400U, D = A + 0x400U, IMAGE_WORDS = 0x200U;
enum : u32 { zero = 0, at = 1, v0 = 2, v1 = 3, a0 = 4, a1 = 5, a2 = 6, a3 = 7, t0 = 8, t1 = 9, t2 = 10, t3 = 11, t4 = 12, t5 = 13, sp = 29, ra = 31 };

// Addresses shared with the runtime test.
constexpr u32 CELL = D, CELL2 = D + 4, P = D + 8, CELL3 = D + 0xC, CELL4 = D + 0x10, CELL5 = D + 0x14, OBJ = D + 0x40, TABLE = D + 0x80;
constexpr u32 T0 = A + 0x100, T1 = A + 0x110, T2 = A + 0x120, T3 = A + 0x130, T4 = A + 0x140, T5 = A + 0x150, T6 = A + 0x170;
constexpr u32 CALLER0 = A, CALLER2 = A + 0x30, CALLER3 = A + 0x60, CALLER4 = A + 0x90, CALLER6 = A + 0xC0, WRITER = A + 0x190, STALE = A + 0x200;
constexpr u32 SITE_OFF = 0x14; // cellCall: JALR at base + 0x14
constexpr u32 FIELD_SITE = A + 0x1c;
constexpr u32 SW_SITE = A + 0x1c, SW_SLOT = A + 0x20, SW_L0 = A + 0x24, SW_L1 = A + 0x2c, SW_L2 = A + 0x34, SW_DEF = A + 0x3c, SW_COUNT = 3;
constexpr u32 THUNK_WRITE = A + 0x1a0, THUNK_PAD = A + 0x1b0, THUNK_RCNT = A + 0x1c0, THUNK_BAD = A + 0x1d0;
constexpr u32 BIOS_WRITE = A, BIOS_PAD = A + 0x30, BIOS_RCNT = A + 0x60, BIOS_BAD = A + 0x90;
constexpr u32 STUB_U = A + 0x100, BRK_ENTRY = A;
constexpr u32 BREAK_WORD = 0x0007000dU;

inline u32 special(u32 rs, u32 rt, u32 rd, u32 sa, u32 fn) { return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | fn; }
inline u32 itype(u32 op, u32 rs, u32 rt, u32 value) { return (op << 26) | (rs << 21) | (rt << 16) | (value & 0xffffU); }
inline u32 hiAdj(u32 addr) { return (addr + 0x8000U) >> 16; }
inline u32 lui(u32 rt, u32 imm) { return itype(15, 0, rt, imm); }
inline u32 addiu(u32 rt, u32 rs, std::int32_t imm) { return itype(9, rs, rt, u32(imm)); }
inline u32 lw(u32 rt, std::int32_t off, u32 rs) { return itype(35, rs, rt, u32(off)); }
inline u32 sw(u32 rt, std::int32_t off, u32 rs) { return itype(43, rs, rt, u32(off)); }
inline u32 addu(u32 rd, u32 rs, u32 rt) { return special(rs, rt, rd, 0, 0x21); }
inline u32 sll(u32 rd, u32 rt, u32 sa) { return special(0, rt, rd, sa, 0); }
inline u32 sltiu(u32 rt, u32 rs, u32 imm) { return itype(11, rs, rt, imm); }
inline u32 jalr(u32 rs) { return special(rs, 0, 31, 0, 9); }
inline u32 jr(u32 rs) { return special(rs, 0, 0, 0, 8); }
inline u32 jal(u32 addr) { return (3U << 26) | ((addr >> 2) & 0x3ffffffU); }
inline u32 divu(u32 rs, u32 rt) { return special(rs, rt, 0, 0, 0x1b); }
inline u32 mflo(u32 rd) { return special(0, 0, rd, 0, 0x12); }
inline u32 bne(u32 rs, u32 rt, std::int32_t words) { return itype(5, rs, rt, u32(words)); }
constexpr u32 JRRA = 0x03e00008U;

struct Img {
    std::vector<u32> w = std::vector<u32>(IMAGE_WORDS, 0);
    void put(u32 addr, const std::vector<u32>& words) { auto i = (addr - A) / 4; for (auto x : words) w.at(i++) = x; }
    void data(u32 addr, u32 value) { w.at((addr - A) / 4) = value; }
    std::vector<std::uint8_t> bytes() const {
        std::vector<std::uint8_t> b(0x800 + 4 * w.size());
        const std::string magic = "PS-X EXE"; std::copy(magic.begin(), magic.end(), b.begin());
        auto put32 = [&](std::size_t p, u32 x) { for (unsigned i = 0; i < 4; ++i) b.at(p + i) = std::uint8_t(x >> (8 * i)); };
        put32(0x18, A); put32(0x1c, u32(4 * w.size()));
        for (std::size_t i = 0; i < w.size(); ++i) put32(0x800 + 4 * i, w[i]);
        return b;
    }
};
struct Fn {
    u32 base; std::vector<u32> words;
    explicit Fn(u32 b) : base(b) {}
    u32 here() const { return base + 4U * u32(words.size()); }
    Fn& op(u32 x) { words.push_back(x); return *this; }
    Fn& ops(std::initializer_list<u32> xs) { for (auto x : xs) words.push_back(x); return *this; }
    Fn& nop() { return op(0); }
    Fn& ldAbs(u32 rt, u32 addr) { return ops({lui(rt, hiAdj(addr)), lw(rt, std::int16_t(addr & 0xffffU), rt)}); }
    Fn& stAbs(u32 value, u32 addr) { return ops({lui(at, hiAdj(addr)), sw(value, std::int16_t(addr & 0xffffU), at)}); }
    Fn& li(u32 rt, u32 value) { return ops({lui(rt, hiAdj(value)), addiu(rt, rt, std::int16_t(value & 0xffffU))}); }
    Fn& prologue() { return ops({addiu(sp, sp, -8), sw(ra, 4, sp)}); }
    Fn& epilogue() { return ops({lw(ra, 4, sp), 0, JRRA, addiu(sp, sp, 8)}); }
    Fn& done(Img& img) { img.put(base, words); return *this; }
};
// Target bodies: each records its identity in $v1 from the `jr ra` delay slot.
inline void targets(Img& img, std::initializer_list<u32> which) {
    for (auto t : which) img.put(t, {JRRA, addiu(v1, zero, std::int32_t(0xA0 + (t - T0) / 0x10))});
}
inline void probeTargets(Img& img) {
    img.put(T3, {addu(t5, ra, zero), JRRA, addiu(v1, zero, 0xA3)});            // records the link register
    img.put(T4, {addu(t3, a3, zero), addu(t4, a3, zero), JRRA, 0});            // first insn sees the old $a3, the second the loaded one
    img.put(T5, {addiu(sp, sp, -8), sw(ra, 4, sp), jal(T0), addiu(a2, a2, 1), lw(ra, 4, sp), 0, JRRA, addiu(sp, sp, 8)}); // nested call
    img.put(T6, {addiu(a0, a0, -1), bne(a0, zero, -2), 0, JRRA, 0});          // counts $a0 down to zero (budget probe)
}
// prologue; ld v0,CELL; nop; jalr ra,v0; <slot>; epilogue. JALR at base + SITE_OFF.
inline u32 cellCall(Img& img, u32 base, u32 cell, u32 slot) {
    Fn f(base); f.prologue().ldAbs(v0, cell).nop().op(jalr(v0)).op(slot).epilogue().done(img); return base + SITE_OFF;
}

struct Scenario {
    std::string name;
    Img img;
    std::vector<std::tuple<u32, std::string, u32>> seeds; // entry, confidence, max words
    bool trapBreak = false, biosHle = false, callbacks = false;
};

inline Scenario cellScenario() {
    Scenario s; s.name = "Cell"; auto& img = s.img;
    targets(img, {T0, T1, T2}); probeTargets(img);
    cellCall(img, CALLER0, CELL, addiu(a1, a1, 1));
    cellCall(img, CALLER2, CELL2, addiu(a1, a1, 1));
    cellCall(img, CALLER3, CELL3, lw(a3, 0, sp));
    cellCall(img, CALLER4, CELL4, addiu(a1, a1, 1));
    cellCall(img, CALLER6, CELL5, addiu(a1, a1, 1));
    img.data(CELL, T0); img.data(CELL2, T3); img.data(CELL3, T4); img.data(CELL4, T5); img.data(CELL5, T6);
    Fn w(WRITER); w.li(t0, T1).stAbs(t0, CELL).op(JRRA).nop().done(img); // a code-constant writer joins {T0} -> {T0, T1}
    // Stale register: the target is loaded, the live cell is rewritten, and only then does the JALR use the old register.
    Fn st(STALE); st.prologue().ldAbs(v0, CELL).nop().li(t0, T1).stAbs(t0, CELL).op(jalr(v0)).op(addiu(a1, a1, 1)).epilogue().done(img);
    for (auto e : {CALLER0, CALLER2, CALLER3, CALLER4, CALLER6, WRITER, STALE}) s.seeds.emplace_back(e, "confirmed", 32);
    return s;
}
inline Scenario singleScenario() { // one initial value, no writers: the set is exactly {T0}
    Scenario s; s.name = "Single"; auto& img = s.img;
    targets(img, {T0, T1, T2});
    cellCall(img, A, CELL, addiu(a1, a1, 1)); img.data(CELL, T0);
    s.seeds.emplace_back(A, "confirmed", 32);
    return s;
}
inline Scenario fieldScenario() { // M[P] = object, method at object+8
    Scenario s; s.name = "Field"; auto& img = s.img;
    targets(img, {T0, T1, T2});
    Fn f(A); f.prologue().ldAbs(v0, P).nop().op(lw(v0, 8, v0)).nop().op(jalr(v0)).op(addiu(a1, a1, 1)).epilogue().done(img);
    img.data(P, OBJ); img.data(OBJ + 8, T0);
    s.seeds.emplace_back(A, "confirmed", 32);
    return s;
}
inline Scenario tableScenario() { // bounded jr table; the jr delay slot counts once in $a3
    Scenario s; s.name = "Table"; auto& img = s.img;
    Fn f(A);
    f.ops({sltiu(v0, a0, SW_COUNT), itype(4, v0, zero, 0), sll(v0, a0, 2)}); // beq offset patched below
    f.ops({lui(at, hiAdj(TABLE)), addu(at, at, v0), lw(v0, std::int16_t(TABLE & 0xffffU), at), 0});
    f.op(jr(v0)).op(addiu(a3, a3, 1));
    for (unsigned n = 0; n < SW_COUNT; ++n) f.op(JRRA).op(addiu(v1, zero, std::int32_t(0xB0 + n)));
    f.op(JRRA).op(addiu(v1, zero, 0xBF));
    f.words[1] |= u32((std::int32_t(SW_DEF) - std::int32_t(A + 8)) / 4) & 0xffffU;
    f.done(img);
    img.data(TABLE, SW_L0); img.data(TABLE + 4, SW_L1); img.data(TABLE + 8, SW_L2);
    s.seeds.emplace_back(A, "confirmed", 32);
    return s;
}
inline Scenario biosScenario(bool hle) {
    Scenario s; s.name = hle ? "Bios" : "BiosOff"; auto& img = s.img; s.biosHle = hle;
    img.put(THUNK_WRITE, {itype(9, 0, t2, 0xb0), jr(t2), itype(9, 0, t1, 0x35), 0});
    img.put(THUNK_PAD, {itype(9, 0, t2, 0xb0), jr(t2), itype(9, 0, t1, 0x5b), 0});
    img.put(THUNK_RCNT, {itype(9, 0, t2, 0xc0), jr(t2), itype(9, 0, t1, 0x0a), 0});
    img.put(THUNK_BAD, {itype(9, 0, t2, 0xb0), jr(t2), itype(9, 0, t1, 0x36), 0}); // B0:0x36 is not implemented
    const std::pair<u32, u32> calls[] = {{BIOS_WRITE, THUNK_WRITE}, {BIOS_PAD, THUNK_PAD}, {BIOS_RCNT, THUNK_RCNT}, {BIOS_BAD, THUNK_BAD}};
    for (const auto& c : calls) { Fn f(c.first); f.prologue().op(jal(c.second)).op(addiu(a3, a3, 1)).epilogue().done(img); s.seeds.emplace_back(c.first, "confirmed", 16); }
    for (auto t : {THUNK_WRITE, THUNK_PAD, THUNK_RCNT, THUNK_BAD}) s.seeds.emplace_back(t, "confirmed", 4);
    return s;
}
inline Scenario breakScenario(bool trap) { // divu a0,a1 ; bne a1,zero,+2 ; nop ; break 7 ; mflo v0 ; jr ra ; nop
    Scenario s; s.name = trap ? "Break" : "BreakOff"; s.trapBreak = trap;
    s.img.put(BRK_ENTRY, {divu(a0, a1), bne(a1, zero, 2), 0, BREAK_WORD, mflo(v0), JRRA, 0});
    s.seeds.emplace_back(BRK_ENTRY, "confirmed", 16);
    return s;
}
inline Scenario returnScenario() { // jr ra with $ra overwritten by a code address that is not a call continuation
    Scenario s; s.name = "Return";
    Fn f(A); f.li(ra, T1).op(JRRA).nop().done(s.img);
    targets(s.img, {T1});
    s.seeds.emplace_back(A, "confirmed", 16);
    return s;
}
inline Scenario stubScenario() { // a callee that discovery cannot resolve becomes a fatal boundary stub, not a guess
    Scenario s; s.name = "Stub";
    Fn f(A); f.prologue().op(jal(STUB_U)).nop().epilogue().done(s.img);
    Fn u(STUB_U); u.ops({jalr(a0), 0, JRRA, 0}).done(s.img);
    s.seeds.emplace_back(A, "confirmed", 16);
    return s;
}
inline std::vector<Scenario> scenarios() {
    std::vector<Scenario> v;
    v.push_back(cellScenario()); v.push_back(singleScenario()); v.push_back(fieldScenario()); v.push_back(tableScenario());
    v.push_back(biosScenario(true)); v.push_back(breakScenario(true)); v.push_back(returnScenario()); v.push_back(stubScenario());
    return v;
}
}
