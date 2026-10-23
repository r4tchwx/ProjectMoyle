// Phase 4 synthetic runtime test (no game data): PS-X EXE startup state, the minimal device model, interrupt entry and the
// harness checkpoints, driven through the probe unit emitted by tests/boot_generator_test.cpp (argv[1] = its function map).
#include "../src/boot_hardware.hpp"
#include "../src/boot_kernel_ram.hpp"
#include "boot_fixtures.hpp"
#include <fstream>
#include <iostream>
#include <iterator>

namespace moyle::detail::recomp { void executeBfx(Context&, std::uint32_t, std::uint64_t); }
namespace {
using namespace moyle::detail::recomp;
namespace f = bfx;
using boot::h8;
int checks = 0;
void require(bool ok, const std::string& what) { ++checks; if (!ok) throw std::runtime_error("FAILED: " + what); }
template <class F> std::string rejects(F fn, const std::string& part, const std::string& what) {
    std::string message;
    try { fn(); } catch (const std::exception& e) { message = e.what(); }
    require(!message.empty(), what + ": must fail");
    require(message.find(part) != std::string::npos, what + ": diagnostic '" + message + "' lacks '" + part + "'");
    return message;
}
using u32 = std::uint32_t;
constexpr u32 BOOT_SP = f::STACK_BASE;

struct Rig {
    std::unique_ptr<Context> context = std::make_unique<Context>();
    bios::BootDevice device;
    boot::Hardware hardware;
    boot::Trace trace;
    boot::Probe probe;
    boot::InterruptEntry irq;
    boot::FunctionMap map;
    boot::PsxExe exe;
    std::vector<std::uint8_t> file;
    Context& c = *context;
    Rig(const std::string& mapText, bool interrupts = true) {
        file = f::exeFile(f::program().img);
        exe = boot::parsePsxExe(file);
        map = boot::FunctionMap::parse(mapText);
        trace.ctx = &c; hardware.trace = &trace; hardware.ctx = &c;
        c.ram.recordEffects = false; c.ram.mmio = &hardware;
        c.biosPolicy = bios::bootPolicy; c.syscallPolicy = bios::bootSyscall; c.biosDevice = &device;
        boot::loadExe(c, exe, file);
        probe.trace = &trace; probe.watchEntries(map); probe.attach(c);
        irq.hw = &hardware; irq.trace = &trace; irq.probe = &probe; irq.map = &map;
        if (interrupts) probe.beforeInstruction = [this](Context& cc, u32 pc) { return irq.poll(cc, pc); };
    }
    boot::BootResult run(u32 entry, std::uint64_t budget, u32 a0 = 0) {
        auto state = boot::bootState(exe);
        boot::applyBootState(c, state);
        boot::traceExeEntry(trace, exe, state);
        c.r[4] = a0;
        return boot::runBoot(c, executeBfx, entry, budget, &map, &probe);
    }
    u32 word(u32 address) { return c.ram.read(address, 4); }
};
std::string slurpText(const std::string& path) {
    std::ifstream in(path, std::ios::binary); if (!in) throw std::runtime_error("cannot read " + path);
    return {std::istreambuf_iterator<char>(in), {}};
}

void exeTests() {
    const auto prog = f::program();
    const auto file = f::exeFile(prog.img);
    const auto exe = boot::parsePsxExe(file);
    require(exe.initialPc == f::E_OK && exe.load == f::A && exe.textSize == 4 * prog.img.w.size(), "PS-X EXE fields parsed");
    const auto st = boot::bootState(exe);
    require(st.pc == f::E_OK && st.sp == BOOT_SP && st.gp == 0 && st.ra == hostReturn, "startup state: PC from header, SP = stack base + offset, GP from header, RA = host return");
    require(st.sp >= exe.imageEnd() + 0x100U && st.sp <= 0x80200000U && !(st.sp & 3U), "stack pointer is aligned, outside the image, inside RAM");
    // load + apply
    Context c; boot::loadExe(c, exe, file); boot::applyBootState(c, st);
    require(c.ram.read(f::E_OK, 4) == prog.img.w[0] && c.ram.read(f::ISR, 4) == prog.img.w[(f::ISR - f::A) / 4], "image bytes loaded at the load address");
    require(c.r[29] == BOOT_SP && c.r[31] == hostReturn && c.pc == f::E_OK && c.r[1] == 0 && c.r[4] == 0, "registers initialised, nothing else set");
    // rejections
    auto bad = [&](const std::function<void(f::Header&)>& mutate, const std::string& part, const std::string& what) {
        f::Header h; mutate(h); rejects([&] { boot::parsePsxExe(f::exeFile(prog.img, h)); }, part, what);
    };
    bad([](f::Header& h) { h.magic = "PS-X EXF"; }, "bad magic", "wrong magic");
    bad([](f::Header& h) { h.pc = f::A - 4; }, "initial PC is outside", "entry below the image");
    bad([](f::Header& h) { h.pc = f::A + 0x2; }, "initial PC is outside", "unaligned entry");
    bad([&](f::Header& h) { h.pc = f::A + 4 * u32(prog.img.w.size()); }, "initial PC is outside", "entry past the image");
    bad([](f::Header& h) { h.stackBase = 0; }, "no stack base", "missing stack");
    bad([](f::Header& h) { h.stackBase = f::A + 0x100; }, "outside RAM or inside the image", "stack inside the image");
    bad([](f::Header& h) { h.stackBase = 0x80200004U; }, "outside RAM or inside the image", "stack beyond RAM");
    bad([](f::Header& h) { h.stackBase = BOOT_SP + 2; }, "not word aligned", "misaligned stack");
    bad([](f::Header& h) { h.bssSize = 16; }, "data/bss", "bss header fields");
    bad([](f::Header& h) { h.size = 6; }, "text size", "text size not word aligned");
    bad([](f::Header& h) { h.size = 0x00800000U; }, "shorter than header", "text size beyond the file");
    bad([](f::Header& h) { h.load = 0x80000100U; }, "load range", "load below the kernel area");
    rejects([&] { boot::parsePsxExe(std::vector<std::uint8_t>(16, 0)); }, "smaller than", "truncated file");
}

void mainRunTests(const std::string& mapText) {
    Rig r(mapText);
    const auto res = r.run(f::E_OK, 2000000);
    require(res.outcome == boot::Outcome::Returned, "main scenario returns to the host sentinel: " + res.report);
    require(r.word(f::C_STAT) == 0x14802000U, "GPUSTAT read after GP1 reset = 0x14802000");
    require(r.word(f::C_READ) == 2U, "GP1(10h) index 7 -> GPUREAD = modelled GPU type 2");
    require(r.word(f::C_COUNT) == 1U, "the PAL service routine counted exactly one VBlank (the host never touches the cell)");
    require(r.word(f::C_ISTAT) == 1U, "service routine saw I_STAT = VBlank");
    require(r.hardware.istat == 0, "I_STAT acknowledged by the PAL");
    require(r.device.interruptsEntered == 1 && r.device.interruptsReturned == 1 && r.device.interruptDepth == 0 && r.device.frames.empty(), "one interrupt entered and returned");
    require(r.device.irqEnabled, "interrupt enable state restored by ReturnFromException");
    require(r.c.r[29] == BOOT_SP && r.c.r[31] == hostReturn, "stack and return address restored: the interrupted context was resumed exactly");
    require(r.hardware.edgesSeen >= 1 && r.c.steps >= 338688U, "first VBlank edge after 338688 guest instructions (677376 cycles at 2 cycles each)");
    const auto text = r.trace.text();
    for (const char* part : {"exe-entry", "irq-enter #1", "irq-return", "enter 0x", "gp1 GP1_RESET", "mmio-w I_MASK", "mmio-w I_STAT"})
        require(text.find(part) != std::string::npos, std::string("trace has ") + part);
    require(text.find("interrupted=" + h8(f::WAIT)) != std::string::npos || text.find("interrupted=" + h8(f::WAIT + 4)) != std::string::npos ||
            text.find("interrupted=" + h8(f::WAIT + 8)) != std::string::npos || text.find("interrupted=" + h8(f::WAIT + 12)) != std::string::npos ||
            text.find("interrupted=" + h8(f::WAIT + 16)) != std::string::npos,
            "the interrupt landed inside the wait loop at a non-delay-slot instruction");
    require(text.find("sp=" + h8(f::ISR_STACK_TOP)) != std::string::npos, "service routine runs on the interrupt stack the PAL put into the jmp_buf");
    // determinism: a second identical run is byte-identical
    Rig r2(mapText);
    r2.run(f::E_OK, 2000000);
    require(r2.trace.text() == text, "two identical runs produce byte-identical traces");
    // without interrupt delivery the same wait never ends: budget exhaustion is a clean, classified stop with diagnostics
    Rig r3(mapText, false);
    const auto spin = r3.run(f::E_OK, 600000);
    require(spin.outcome == boot::Outcome::Fault && spin.boundaryType == "instruction-budget", "no delivery: instruction budget exhausted");
    require(spin.report.find("guest pc: ") != std::string::npos && spin.report.find("containing function: " + h8(f::WAIT)) != std::string::npos &&
            spin.report.find("remaining budget: 0") != std::string::npos && spin.report.find("registers:") != std::string::npos &&
            spin.report.find("call depth") != std::string::npos, "failure report names pc, containing function, registers, depth and remaining budget");
    r3.hardware.sync(); require(r3.hardware.istat == 1, "I_STAT stays latched while nothing consumes it");
    // call budget
    Rig r4(mapText);
    r4.probe.callBudget = 2;
    const auto cb = r4.run(f::E_OK, 2000000);
    require(cb.boundaryType == "call-budget", "call budget exhaustion is classified");
    // explicit stop address
    Rig r5(mapText);
    r5.probe.stopAt(f::WAIT);
    const auto st = r5.run(f::E_OK, 2000000);
    require(st.outcome == boot::Outcome::Stopped && st.boundaryType == "requested-stop", "explicit stop address");
}

void faultTests(const std::string& mapText) {
    struct Case {u32 entry; const char* kind; const char* part; u32 address; bool write; u32 value;};
    const Case cases[] = {
        {f::E_GP1BAD, "mmio", "not modelled", 0x1f801814U, true, 0x08000080U},
        {f::E_GPUSTAT_EARLY, "mmio", "not modelled", 0x1f801814U, false, 0},
        {f::E_MMIO_UNKNOWN, "mmio", "not modelled", 0x1f801800U, false, 0},
        {f::E_DMA_START, "mmio", "DMA2 block upload without a pending GP0 A0h data phase", 0x1f8010a8U, true, 0x01000201U},
        {f::E_DMA_MODE, "mmio", "not modelled", 0x1f8010a8U, true, 0x00000600U},
    };
    for (const auto& k : cases) {
        Rig r(mapText);
        const auto res = r.run(k.entry, 100000);
        require(res.outcome == boot::Outcome::Fault && res.boundaryType == k.kind, "classified as mmio boundary for " + h8(k.entry) + ": " + res.report);
        require(res.report.find(std::string("mmio: ") + (k.write ? "write" : "read") + " address " + h8(k.address)) != std::string::npos, "report names the register for " + h8(k.entry));
        if (k.write) require(res.report.find("value " + h8(k.value)) != std::string::npos, "report names the value for " + h8(k.entry));
        require(res.message.find(k.part) != std::string::npos, "diagnostic for " + h8(k.entry) + ": " + res.message);
        require(res.report.find("containing function: " + h8(k.entry)) != std::string::npos, "containing generated function reported");
    }
}

void deviceTests(const std::string& mapText) {
    Rig r(mapText);
    const auto res = r.run(f::E_DMA_CFG, 100000);
    require(res.outcome == boot::Outcome::Returned, "DMA2/DPCR/DICR/RCNT1 configuration scenario returns: " + res.report);
    require(r.word(f::C_DMA) == 0x00100000U, "DMA2 MADR holds 24 bits");
    require(r.word(f::C_DMA + 4) == 0x00010010U && r.word(f::C_DMA + 8) == 0x00000201U, "DMA2 BCR/CHCR configuration read back");
    require(r.word(f::C_DMA + 12) == 0x03333333U, "DPCR read back");
    require(r.word(f::C_DMA + 16) == 0x00900000U, "DICR read back (channel-2 enable + master enable, no flags, master flag clear)");
    require(r.word(f::C_DMA + 20) == 0U, "root counter 1 reads 0 until the first VBlank edge after the mode write");
    require(r.hardware.dma2Chcr == 0x201U && !(r.hardware.dma2Chcr & 0x01000000U), "DMA2 never started");
    require(r.trace.text().find("mmio-w D2_CHCR") != std::string::npos, "DMA2 configuration is traced");
}

void guardTests(const std::string& mapText) {
    { // ADDI: normal result then signed-overflow trap
        Rig r(mapText);
        const auto res = r.run(f::E_ADDI, 1000);
        require(res.outcome == boot::Outcome::Fault && res.message.find("Guest ADDI overflow") != std::string::npos && r.word(f::C_RES) == 5U, "ADDI computes 5 then traps on overflow");
    }
    { // pinned callback set: members run, everything else is fatal
        for (const auto& t : {std::make_pair(f::PT0, 0x70U), std::make_pair(f::PT1, 0x71U)}) {
            Rig r(mapText);
            const auto res = r.run(f::E_PINNED, 1000, t.first);
            require(res.outcome == boot::Outcome::Returned && r.c.r[3] == t.second, "pinned member " + h8(t.first) + " runs");
        }
        for (u32 bad : {0U, f::A + 0x100U, f::PT0 + 4U, f::PT0 + 2U}) {
            Rig r(mapText);
            const auto res = r.run(f::E_PINNED, 1000, bad);
            require(res.outcome == boot::Outcome::Fault, "pinned set rejects " + h8(bad) + ": " + res.report);
        }
    }
    { // noreturn root: the BREAK becomes the documented terminal trap
        Rig r(mapText);
        const auto res = r.run(f::E_NORETURN, 1000);
        require(res.outcome == boot::Outcome::Fault && res.boundaryType == "guest-break" && res.report.find("raw code 0x1") != std::string::npos, "BREAK 1 is a fatal trap: " + res.report);
    }
    { // wrong entry: only generated registry entries may start a run
        for (u32 bad : {f::E_OK + 4U, f::E_OK + 2U, f::A + 0x7f0U, 0x80123450U}) {
            Rig r(mapText);
            const auto res = r.run(bad, 1000);
            require(res.outcome == boot::Outcome::Fault, "entry " + h8(bad) + " is rejected: " + res.report);
        }
    }
}

void hardwareUnitTests() {
    Context c; boot::Hardware hw; hw.ctx = &c;
    auto rd = [&](u32 a, unsigned w) { return hw.mmioRead(a, w); };
    auto wr = [&](u32 a, u32 v, unsigned w) { hw.mmioWrite(a, v, w); };
    // I_STAT / I_MASK / VBlank tick
    c.steps = 338687; hw.sync(); require(hw.istat == 0, "no VBlank before the first field boundary");
    c.steps = 338688; hw.sync(); require(hw.istat == 1 && hw.edgesSeen == 1, "VBlank edge latches I_STAT bit 0 at the exact boundary even with I_MASK = 0");
    require(rd(0x1f801070, 2) == 1 && rd(0x1f801070, 4) == 1, "I_STAT reads");
    wr(0x1f801070, 0xfffe, 2); require(hw.istat == 0, "writing 0 acknowledges");
    wr(0x1f801070, 0xffff, 2); require(hw.istat == 0, "writing 1 leaves a clear bit clear");
    c.steps = 677376; require(rd(0x1f801070, 4) == 1, "next edge exactly one field later, observed by a plain I_STAT read");
    wr(0x1f801074, 0x0009, 2); require(rd(0x1f801074, 2) == 9, "I_MASK write/read");
    rejects([&] { wr(0x1f801074, 0x800, 4); }, "not modelled", "I_MASK reserved bit");
    rejects([&] { rd(0x1f801070, 1); }, "not modelled", "I_STAT byte read");
    rejects([&] { wr(0x1f801070, 0, 1); }, "not modelled", "I_STAT byte write");
    // DPCR / DICR
    wr(0x1f8010f0, 0x07654321, 4); require(rd(0x1f8010f0, 4) == 0x07654321U, "DPCR");
    rejects([&] { rd(0x1f8010f0, 2); }, "not modelled", "DPCR halfword");
    wr(0x1f8010f4, 0x00ff0000, 4); require(rd(0x1f8010f4, 4) == 0x00ff0000U, "DICR enables");
    rejects([&] { wr(0x1f8010f4, 0x00000001, 4); }, "not modelled", "DICR low bits (force/unused)");
    // GP1 / GPUSTAT
    rejects([&] { rd(0x1f801814, 4); }, "not modelled", "GPUSTAT before reset");
    rejects([&] { wr(0x1f801814, 0x10000007, 4); }, "not modelled", "GP1 info before reset");
    rejects([&] { wr(0x1f801814, 0x00000001, 4); }, "not modelled", "GP1 reset with parameter");
    wr(0x1f801814, 0, 4); require(rd(0x1f801814, 4) == 0x14802000U, "GPUSTAT after reset");
    rejects([&] { rd(0x1f801810, 4); }, "not modelled", "GPUREAD before GP1(10h)");
    wr(0x1f801814, 0x10000007, 4); require(rd(0x1f801810, 4) == 2U, "GPU type latch");
    rejects([&] { wr(0x1f801814, 0x10000002, 4); }, "not modelled", "unsupported GP1 info index");
    wr(0x1f801814, 0x03000000, 4);   // display enabled: modelled
    wr(0x1f801814, 0x03000001, 4);   // display disabled: modelled; restore reset state
    rejects([&] { wr(0x1f801814, 0x03000002, 4); }, "not modelled", "GP1 display enable parameter 2");
    rejects([&] { wr(0x1f801814, 0, 2); }, "not modelled", "GP1 halfword");
    wr(0x1f801810, 0x00000000, 4);
    wr(0x1f801810, 0xe1000000U, 4);
    rejects([&] { wr(0x1f801810, 0xe1000000U, 2); },
            "not modelled", "GP0 draw mode halfword");
    rejects([&] { wr(0x1f801810, 0xe7000000U, 4); },
            "not modelled", "GP0 unsupported opcode E7");
    // DMA2 modes / start
    wr(0x1f8010a0, 0x80101234, 4); require(rd(0x1f8010a0, 4) == 0x00101234U, "MADR");
    wr(0x1f8010a8, 0x00000401, 4); require(rd(0x1f8010a8, 4) == 0x401U, "CHCR sync mode 2 configuration");
    for (u32 bad : {0x10000401U, 0x00000600U, 0x80000000U, 0x00000004U})
        rejects([&] { wr(0x1f8010a8, bad, 4); }, "not modelled", "CHCR " + h8(bad));
    c.ram.write(0x80101234U, 0x00000001U, 4);
    rejects([&] { wr(0x1f8010a8, 0x01000401U, 4); },
            "DMA2 linked-list: invalid next pointer",
            "DMA2 linked-list rejects misaligned next pointer");
    rejects([&] { rd(0x1f8010a0, 2); }, "not modelled", "MADR halfword");
    // root counter 1
    rejects([&] { rd(0x1f801110, 4); }, "not modelled", "counter read before the mode write");
    rejects([&] { wr(0x1f801114, 0x100, 4); }, "not modelled", "unsupported counter mode");
    rejects([&] { wr(0x1f801110, 1, 4); }, "not modelled", "counter value write");
    c.steps = 700000; wr(0x1f801114, 0x107, 4);
    c.steps = 700000 + 100; require(rd(0x1f801110, 4) == 0, "counter does not run before the next VBlank edge (sync mode 3)");
    c.steps = 1016064 + 3 * 2168 / 2; // the first field edge after step 700000 is cycle 3*677376 = step 1016064; 3 lines later
    require(rd(0x1f801110, 4) == 3, "counter counts HBlank lines (2168 cycles) since the VBlank edge");
    // everything else
    for (u32 a : {0x1f801000U, 0x1f801040U, 0x1f801800U, 0x1f801100U, 0x1f801120U, 0x1f8010b0U, 0x1f801820U})
        rejects([&] { rd(a, 4); }, "not modelled", "unknown MMIO read " + h8(a));
    rejects([&] { wr(0x1f801800, 1, 1); }, "not modelled", "unknown MMIO write");
    // SPU file: write-then-read-back, never-written registers fatal, DMA modes fatal
    rejects([&] { rd(0x1f801c00, 2); }, "before any PAL write", "SPU register never written");
    wr(0x1f801c00, 0x1234, 2); require(rd(0x1f801c00, 2) == 0x1234U, "SPU register read back");
    wr(0x1f801daa, 0xc001, 2); require((rd(0x1f801dae, 2) & 0x3f) == 1, "SPUSTAT mirrors SPUCNT low bits");
    // SPUCNT transfer mode 2 (DMA write) became a modelled, stored-only mode in the first-boot sprint (the PAL's libspu selects it before
    // the DMA4 transfer, see tests/spu_dma_test.cpp); the DMA read mode (3) stays unsupported.
    rejects([&] { wr(0x1f801daa, 0xc030, 2); }, "not modelled", "SPUCNT DMA read mode");
    rejects([&] { wr(0x1f801daa, 0xc040, 2); }, "not modelled", "SPUCNT IRQ enable");
}

void interruptEntryTests(const std::string& mapText) {
    // gating conditions of the interrupt entry, one at a time, on a hand-built context
    const auto make = [&](Rig& r) {
        r.device.customExit = f::BUF; r.device.irqEnabled = true;
        r.hardware.imask = 1; r.hardware.istat = 1;
        r.c.ram.write(f::BUF, f::IRQ_INIT + 0x1c, 4); r.c.ram.write(f::BUF + 4, f::ISR_STACK_TOP, 4);
        r.c.pc = f::WAIT;
        r.c.steps = 400000;
    };
    const u32 pcPlain = f::WAIT + 8;   // `nop` in the wait loop, previous word is not a branch
    { Rig r(mapText); make(r); r.c.ram.write(f::BUF, f::E_OK, 4);
      require(r.irq.poll(r.c, pcPlain), "all conditions hold: entered"); require(r.c.redirectPending && r.c.redirectPc == f::E_OK, "redirect to buf.ra");
      require(r.c.r[29] == f::ISR_STACK_TOP && r.c.r[2] == 1 && r.device.interruptDepth == 1 && !r.device.irqEnabled && r.device.frames.size() == 1, "longjmp(buf,1) semantics and frame saved"); }
    { Rig r(mapText); make(r); r.device.customExit = 0; require(!r.irq.poll(r.c, pcPlain), "no custom exit registered: pending"); }
    { Rig r(mapText); make(r); r.device.irqEnabled = false; require(!r.irq.poll(r.c, pcPlain), "interrupts disabled (EnterCriticalSection): pending"); }
    { Rig r(mapText); make(r); r.hardware.imask = 2; require(!r.irq.poll(r.c, pcPlain), "masked: pending"); }
    { Rig r(mapText); make(r); r.hardware.istat = 4; r.hardware.imask = 1; r.c.steps = 1000; require(!r.irq.poll(r.c, pcPlain), "I_STAT & I_MASK == 0: no entry"); }
    { Rig r(mapText); make(r); r.device.interruptDepth = 1; require(!r.irq.poll(r.c, pcPlain), "already inside the service routine: no nesting"); }
    { Rig r(mapText); make(r); r.c.loadRegister = 5; require(!r.irq.poll(r.c, pcPlain), "load in flight: deferred"); }
    { Rig r(mapText); make(r); require(!r.irq.poll(r.c, f::WAIT + 16 + 0), "pc after `beq` (delay slot of the wait loop branch) is never an entry point") ; }
    { Rig r(mapText); make(r); r.c.ram.write(f::BUF, 0x80123450U, 4); rejects([&] { r.irq.poll(r.c, pcPlain); }, "not inside a generated function", "custom exit target outside generated code"); }
    // ReturnFromException without an interrupt
    { Rig r(mapText); rejects([&] { bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x17U); }, "outside an interrupt service routine", "B0:17 outside an ISR"); }
    // unsupported BIOS / syscall remain fatal
    { Rig r(mapText); rejects([&] { bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x4aU); }, "BIOS boundary", "B0:4a InitCARD is not implemented"); }
    { Rig r(mapText); r.c.r[4] = 3; rejects([&] { bios::bootSyscall(r.c, 0x80020000U, 0U); }, "", "SYSCALL with an unknown function"); }
}

// Phase 5: B0:4a InitCARD as a state-only boundary (opt-in). Everything it does not cover stays fatal.
void cardBoundaryTests(const std::string& mapText) {
    auto enabled = [&](Rig& r) { r.device.cardInitEnabled = true; };
    // disabled by default (Phase 4 behaviour)
    { Rig r(mapText); rejects([&] { bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x4aU); }, "kernel function is not implemented", "B0:4a is not implemented unless opted in"); }
    // success path: recorded, registers and memory untouched, no device access
    { Rig r(mapText); enabled(r); r.c.r[4] = 0; r.c.r[2] = 0x1234U; r.c.r[17] = 0x77U; r.c.r[31] = 0x80020008U;
      const auto before = r.c.r;
      bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x4aU);
      require(r.device.cardInit.calls == 1 && r.device.cardInit.padEnable == 0 && r.device.cardInit.site == 0x80020000U, "InitCARD(0) recorded with its call site");
      require(r.c.r == before, "InitCARD leaves every register untouched (the PAL never reads a result)");
      require(r.hardware.accesses == 0 && r.device.calls.size() == 1 && r.device.calls[0].table == 0xb0U && r.device.calls[0].function == 0x4aU, "no device access; call logged");
      require(r.device.customExit == 0 && r.device.gp0Words == 0 && r.device.eventsOpened == 0 && r.device.cdRemove == 0, "no other BIOS-device state changed"); }
    { Rig r(mapText); enabled(r); r.c.r[4] = 1;
      bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x4aU);
      require(r.device.cardInit.calls == 1 && r.device.cardInit.padEnable == 1, "InitCARD(1) is the other value the PAL can pass"); }
    // deterministic state: a repeated call is counted, the latest argument is kept
    { Rig r(mapText); enabled(r); r.c.r[4] = 1; bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x4aU); r.c.r[4] = 0; bios::bootPolicy(r.c, 0x80020010U, 0xb0U, 0x4aU);
      require(r.device.cardInit.calls == 2 && r.device.cardInit.padEnable == 0 && r.device.cardInit.site == 0x80020010U, "repeated InitCARD counted, latest state kept"); }
    // invalid arguments / state
    for (u32 bad : {2U, 3U, 0x80000000U, 0xffffffffU}) {
        Rig r(mapText); enabled(r); r.c.r[4] = bad;
        rejects([&] { bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x4aU); }, "argument", "InitCARD with a0=" + h8(bad));
        require(r.device.cardInit.calls == 0, "a rejected InitCARD changes no state");
    }
    { Rig r(mapText); enabled(r); r.c.r[4] = 0; r.device.irqEnabled = true;
      rejects([&] { bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x4aU); }, "critical section", "InitCARD with interrupts enabled");
      require(r.device.cardInit.calls == 0, "rejected outside a critical section without changing state"); }
    { Rig r(mapText); enabled(r); r.c.r[4] = 0; r.device.interruptDepth = 1;
      rejects([&] { bios::bootPolicy(r.c, 0x80020000U, 0xb0U, 0x4aU); }, "interrupt service routine", "InitCARD inside an interrupt service routine"); }
    // the rest of the card BIOS family and the kernel table getters stay fatal even when InitCARD is enabled
    for (auto id : std::vector<std::pair<u32, u32>>{{0xb0, 0x4b}, {0xb0, 0x4c}, {0xb0, 0x4d}, {0xb0, 0x4e}, {0xb0, 0x4f}, {0xb0, 0x50}, {0xb0, 0x56}, {0xb0, 0x57},
                                                    {0xb0, 0x12}, {0xb0, 0x13}, {0xb0, 0x14}, {0xb0, 0x15}, {0xa0, 0x70}, {0xa0, 0xab}, {0xa0, 0xac}, {0xc0, 0x02}, {0xc0, 0x03}}) {
        Rig r(mapText); enabled(r);
        rejects([&] { bios::bootPolicy(r.c, 0x80020000U, id.first, id.second); }, "kernel function is not implemented",
                "table " + h8(id.first) + " function " + h8(id.second) + " stays fatal with InitCARD enabled");
    }
    // supported-set bookkeeping used by discovery and the policy
    require(bios::findBootEntry(0xb0U, 0x4aU) == nullptr && bios::findBootEntry(0xb0U, 0x4aU, true) != nullptr, "B0:4a belongs to the opt-in card set only");
    require(bios::findBootEntry(0xb0U, 0x4bU, true) == nullptr && bios::findBootEntry(0xb0U, 0x56U, true) == nullptr && bios::findBootEntry(0xb0U, 0x57U, true) == nullptr,
            "no other card/kernel-table entry is in the card set");
    require(std::string(bios::findBootEntry(0xb0U, 0x4aU, true)->name) == "InitCARD", "name recorded (external PsyQ/psx-spx name, not evidence)");
    // generated-unit run: EnterCriticalSection ; B0:4a(0) ; kernel patch routine with an inline B0:56 call (not generated) -> explicit boundary
    { Rig r(mapText); enabled(r);
      const auto res = r.run(f::E_CARD, 100000);
      require(res.outcome == boot::Outcome::Fault && res.boundaryType == "ungenerated-function", "the run stops at the kernel patch routine: " + res.report);
      require(res.report.find("guest pc: " + h8(f::CARD_PATCH)) != std::string::npos, "stop point is the patch routine entry");
      require(r.device.cardInit.calls == 1 && r.device.cardInit.padEnable == 0 && r.device.cardInit.site == f::TH_INITCARD + 4, "InitCARD(0) was dispatched from inside the critical section");
      require(r.device.criticalEnters == 1 && r.device.criticalExits == 0 && !r.device.irqEnabled, "stopped inside the critical section");
      require(r.hardware.accesses == 0, "no MMIO touched by the card init sequence");
      require(r.trace.text().find("bios B0:4a") != std::string::npos, "InitCARD is a trace checkpoint"); }
    // same unit with the policy NOT opted in: the BIOS thunk is fatal at B0:4a (Phase 4 behaviour)
    { Rig r(mapText);
      const auto res = r.run(f::E_CARD, 100000);
      require(res.outcome == boot::Outcome::Fault && res.message.find("kernel function is not implemented") != std::string::npos, "without the opt-in B0:4a is fatal: " + res.report); }
    // determinism
    { Rig a(mapText), b(mapText); enabled(a); enabled(b);
      a.run(f::E_CARD, 100000); b.run(f::E_CARD, 100000);
      require(a.trace.text() == b.trace.text() && a.c.steps == b.c.steps, "identical runs, identical trace"); }
}

void kernelRamGuardTests(const std::string& mapText) {
    auto faults = [&](Rig& r, auto fn, const char* what) {
        try { fn(r); } catch (const boot::KernelRamFault&) { ++checks; return; } catch (...) { throw std::runtime_error(std::string("wrong exception: ") + what); }
        throw std::runtime_error(std::string("expected KernelRamFault: ") + what);
    };
    // without the guard installed, behaviour is unchanged (zero-initialised RAM)
    { Rig r(mapText); require(r.c.ram.read(0xdf80U, 4) == 0 && r.c.ram.guard == nullptr, "no guard by default: Phase 4 memory behaviour unchanged"); }
    auto install = [&](Rig& r, boot::KernelRamGuard& g) { g.trace = &r.trace; g.ctx = &r.c; r.c.ram.guard = &g; };
    // read-before-write is fatal in the window, including through the KSEG0/KSEG1 aliases
    for (u32 a : {0x00000000U, 0x0000df80U, 0x8000df80U, 0xa000df84U, 0x8000fffcU}) {
        Rig r(mapText); boot::KernelRamGuard g; install(r, g);
        faults(r, [&](Rig& x) { x.c.ram.read(a, 4); }, "word read before write");
        faults(r, [&](Rig& x) { x.c.ram.read(a, 1); }, "byte read before write");
        require(g.reads == 0, "a refused read is not counted");
    }
    // write then read works at the same width and through aliases; only written bytes become readable
    { Rig r(mapText); boot::KernelRamGuard g; install(r, g);
      r.c.ram.write(0x8000df80U, 0x11223344U, 4);
      require(r.c.ram.read(0xa000df80U, 4) == 0x11223344U && r.c.ram.read(0xdf81U, 1) == 0x33U && r.c.ram.read(0x8000df82U, 2) == 0x1122U, "written bytes read back at any width/alias");
      faults(r, [&](Rig& x) { x.c.ram.read(0xdf84U, 1); }, "adjacent unwritten byte");
      faults(r, [&](Rig& x) { x.c.ram.read(0xdf7cU, 4); }, "adjacent unwritten word");
      r.c.ram.write(0xdf90U, 0xabU, 1);
      faults(r, [&](Rig& x) { x.c.ram.read(0xdf90U, 4); }, "word read covering a single written byte");
      require(r.c.ram.read(0xdf90U, 1) == 0xabU, "the written byte itself is readable");
      require(g.writes == 2 && g.reads == 4, "counts: " + std::to_string(g.writes) + "/" + std::to_string(g.reads));
      const auto ranges = g.writtenRanges();
      require(ranges.size() == 2 && ranges[0] == std::make_pair(0xdf80U, 0xdf84U) && ranges[1] == std::make_pair(0xdf90U, 0xdf91U), "written ranges are exact"); }
    // partial stores mark only the lanes they write
    { Rig r(mapText); boot::KernelRamGuard g; install(r, g);
      r.c.ram.storeLeft(0xdfa3U, 0xaabbccddU);   // swl at offset 3: writes all four lanes
      require(r.c.ram.read(0xdfa0U, 4) == 0xaabbccddU, "swl at lane 3 writes the whole word");
      r.c.ram.storeRight(0xdfb2U, 0x11223344U);  // swr at offset 2: writes lanes 2..3
      require(r.c.ram.read(0xdfb2U, 2) == 0x3344U, "swr lanes are readable");
      faults(r, [&](Rig& x) { x.c.ram.read(0xdfb0U, 2); }, "swr must not mark lanes 0..1");
      r.c.ram.storeLeft(0xdfc1U, 0x55667788U);   // swl at offset 1: writes lanes 0..1
      require(r.c.ram.read(0xdfc0U, 2) == 0x7788U >> 0 || r.c.ram.read(0xdfc0U, 2) == 0x5566U, "swl lanes 0..1 are readable");
      faults(r, [&](Rig& x) { x.c.ram.read(0xdfc2U, 2); }, "swl must not mark lanes 2..3"); }
    // lwl/lwr consume only the lanes they use
    { Rig r(mapText); boot::KernelRamGuard g; install(r, g);
      r.c.ram.write(0xdfd0U, 0x0102U, 2);
      r.c.ram.loadLeft(0xdfd1U, 0);              // lwl at lane 1 uses lanes 0..1 only: allowed
      faults(r, [&](Rig& x) { x.c.ram.loadLeft(0xdfd2U, 0); }, "lwl at lane 2 needs unwritten lane 2");
      faults(r, [&](Rig& x) { x.c.ram.loadRight(0xdfd1U, 0); }, "lwr at lane 1 needs unwritten lanes 2..3"); }
    // addresses outside the window are not guarded (normal game RAM keeps zero-init semantics)
    { Rig r(mapText); boot::KernelRamGuard g; install(r, g);
      require(r.c.ram.read(0x80010000U, 4) == 0 && r.c.ram.read(0x80060000U, 4) == 0, "reads at/above 0x10000 are not kernel RAM");
      r.c.ram.write(0x80010000U, 1, 4);
      require(g.reads == 0 && g.writes == 0 && !g.touched(), "no kernel RAM traffic recorded outside the window"); }
    // fault classification and report
    { Rig r(mapText); boot::KernelRamGuard g; install(r, g);
      boot::KernelRamFault f(0x8000df80U, 4, false, "x");
      require(std::string(f.what()).find("Kernel RAM read at 0x8000df80 width 4") != std::string::npos, "message names the access"); }
    // determinism of the trace of kernel RAM events
    { Rig a(mapText), b(mapText); boot::KernelRamGuard ga, gb; install(a, ga); install(b, gb);
      for (Rig* r : {&a, &b}) { r->c.ram.write(0xdf80U, 1, 4); r->c.ram.read(0xdf80U, 4); }
      require(a.trace.text() == b.trace.text() && a.trace.text().find("kmem-w 0x0000df80 w4") != std::string::npos, "kernel RAM events are traced deterministically"); }
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("Usage: BootTest FUNCTION_MAP");
        const auto mapText = slurpText(argv[1]);
        exeTests(); hardwareUnitTests(); mainRunTests(mapText); faultTests(mapText); deviceTests(mapText); guardTests(mapText); interruptEntryTests(mapText); cardBoundaryTests(mapText); kernelRamGuardTests(mapText);
        std::cout << "boot tests passed (" << checks << " checks)\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
