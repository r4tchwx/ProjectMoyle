// SPUCNT transfer modes, SPU_DELAY, DMA channel 4 (RAM -> SPU block transfer, completion interrupt) and the root counter 2 SetRCnt
// writes: strict synthetic tests of the minimal models in src/boot_hardware.hpp (no game data). Every unsupported shape must stay a
// fatal MmioFault.
#include "../src/boot_hardware.hpp"
#include <iostream>
#include <memory>
namespace {
using namespace moyle::detail::recomp;
using u32 = std::uint32_t;
int checks = 0;
void require(bool ok, const std::string& what) { ++checks; if (!ok) throw std::runtime_error("FAILED: " + what); }
template <class F> void rejects(F fn, const std::string& part, const std::string& what) {
    std::string message;
    try { fn(); } catch (const std::exception& e) { message = e.what(); }
    require(!message.empty(), what + ": must fail");
    require(message.find(part) != std::string::npos, what + ": diagnostic '" + message + "' lacks '" + part + "'");
}
constexpr u32 SPUADDR = 0x1f801da6, SPUFIFO = 0x1f801da8, SPUCNT = 0x1f801daa, SPUSTAT = 0x1f801dae, SPU_DELAY = 0x1f801014;
constexpr u32 D4MADR = 0x1f8010c0, D4BCR = 0x1f8010c4, D4CHCR = 0x1f8010c8, DPCR = 0x1f8010f0, DICR = 0x1f8010f4, ISTAT = 0x1f801070;
constexpr u32 R2MODE = 0x1f801124, R2TARGET = 0x1f801128, R2COUNT = 0x1f801120;
struct Rig {
    std::unique_ptr<Context> context = std::make_unique<Context>();
    boot::Hardware hw;
    Context& c = *context;
    Rig() { hw.ctx = &c; }
    void w(u32 a, u32 v, unsigned width = 4) { hw.mmioWrite(a, v, width); }
    u32 r(u32 a, unsigned width = 4) { return hw.mmioRead(a, width); }
    // the guest's sequence (_spu_t cmd 2, then cmd 1 mode, then the DMA4 setup)
    void ready(u32 spuAddr8, u32 madr, u32 blocks, u32 dpcr = 0x00080000U) {
        w(SPUADDR, spuAddr8, 2); w(SPUCNT, 0xC021U, 2); w(DPCR, dpcr); w(D4MADR, madr); w(D4BCR, (blocks << 16) | 0x10U);
    }
    void fill(u32 addr, u32 words) { for (u32 i = 0; i < words; ++i) c.ram.write(0x80000000U | (addr + 4 * i), 0x01020304U * (i + 1) + i, 4); }
};
std::uint64_t fnvByte(std::uint64_t h, std::uint8_t b) { h ^= b; h *= 0x100000001b3ULL; return h; }
}
int main() {
    // --- SPUCNT --------------------------------------------------------------------------------------------------------------
    { Rig g; g.w(SPUCNT, 0xC021U, 2); require(g.r(SPUCNT, 2) == 0xC021U, "mode 2 (DMA write) is stored");
      g.w(SPUCNT, 0xC001U, 2); require(g.r(SPUCNT, 2) == 0xC001U, "mode 0 (stop) is stored"); }
    { Rig g; rejects([&] { g.w(SPUCNT, 0xC031U, 2); }, "DMA read transfer mode", "SPUCNT mode 3"); }
    { Rig g; rejects([&] { g.w(SPUCNT, 0xC061U, 2); }, "IRQ enable", "SPUCNT IRQ enable"); }
    { Rig g; rejects([&] { g.w(SPUSTAT, 0, 2); }, "read-only", "SPUSTAT write"); }
    { Rig g; g.w(SPUADDR, 0x0100, 2); g.w(SPUFIFO, 0xBEEF, 2); g.w(SPUFIFO, 0x1234, 2); g.w(SPUCNT, 0xC011U, 2);
      require(g.hw.spuRam[0x800] == 0xEF && g.hw.spuRam[0x801] == 0xBE && g.hw.spuRam[0x802] == 0x34 && g.hw.spuRam[0x803] == 0x12, "mode 1 manual write flushes the FIFO at address*8"); }
    { Rig g; g.w(SPUFIFO, 1, 2); rejects([&] { g.w(SPUCNT, 0xC001U, 2); }, "no transfer mode", "queued halfword without a mode"); }
    // --- SPU_DELAY -----------------------------------------------------------------------------------------------------------
    { Rig g; require(g.r(SPU_DELAY) == 0x200931e1U, "SPU_DELAY power-on value");
      g.w(SPU_DELAY, (0x200931e1U & 0xf0ffffffU) | 0x20000000U); require(g.r(SPU_DELAY) == 0x200931e1U, "the PAL's read-modify-write is value-preserving"); }
    { Rig g; for (u32 bad : {0x22000000U, 0x200931e0U, 0x0U, 0xffffffffU}) rejects([&] { g.w(SPU_DELAY, bad); }, "not modelled", "SPU_DELAY " + boot::h8(bad));
      rejects([&] { g.w(SPU_DELAY, 0x200931e1U, 2); }, "not modelled", "SPU_DELAY halfword"); }
    // --- DMA4 success: 2 blocks = 128 bytes RAM 0x9e000 -> SPU 0x1010, completion interrupt --------------------------------------
    { Rig g; g.fill(0x9e000, 32); g.w(DICR, 0x00900000U);   // channel 4 enable (bit 20) + master enable (bit 23)
      g.ready(0x0202, 0x9e000, 2); g.w(D4CHCR, 0x01000201U);
      require(g.hw.spuDmaTransfers == 1 && g.hw.spuDmaBytes == 128 && g.hw.dma4Interrupts == 1, "one 128-byte transfer, one interrupt");
      const auto& rec = g.hw.spuDmas.at(0); std::uint64_t h = 0xcbf29ce484222325ULL;
      for (u32 i = 0; i < 128; ++i) h = fnvByte(h, g.hw.spuRam[0x1010 + i]);
      require(rec.madr == 0x9e000 && rec.spuAddress == 0x1010 && rec.bytes == 128 && rec.hash == h, "record and payload hash");
      require(g.hw.spuRam[0x1010] == 0x04 && g.hw.spuRam[0x1011] == 0x03 && g.hw.spuRam[0x1012] == 0x02 && g.hw.spuRam[0x1013] == 0x01, "first word landed little-endian");
      require(g.hw.spuRam[0x1010 + 127] == std::uint8_t((0x01020304U * 32 + 31) >> 24), "last byte landed");
      require(g.hw.spuRam[0x100f] == 0 && g.hw.spuRam[0x1010 + 128] == 0, "nothing written outside the range");
      require(g.r(D4MADR) == 0x9e000 + 128 && (g.r(D4CHCR) & 0x01000000U) == 0, "MADR advanced, busy bit clear");
      require((g.r(DICR) & 0x90000000U) == 0x90000000U && (g.r(ISTAT) & 8U) == 8U, "DICR flag 28 + master flag, I_STAT bit 3");
      // a second transfer while the master flag is still set: no new rising edge, no second interrupt
      g.w(D4BCR, (1U << 16) | 0x10U); g.w(D4CHCR, 0x01000201U); require(g.hw.spuDmaTransfers == 2 && g.hw.dma4Interrupts == 1, "no second edge while the master flag stays set");
      // acknowledge: write 1 to flag 28 clears it, the next transfer raises a new edge
      g.w(DICR, 0x10900000U); g.w(ISTAT, 0xfff7U); require((g.r(DICR) & 0x90000000U) == 0 && (g.r(ISTAT) & 8U) == 0, "acknowledge clears DICR flag and I_STAT");
      g.w(D4BCR, (1U << 16) | 0x10U); g.w(D4CHCR, 0x01000201U); require(g.hw.dma4Interrupts == 2, "new rising edge after the acknowledge"); }
    { Rig g; g.fill(0x9e000, 16); g.ready(0x0200, 0x9e000, 1); g.w(D4CHCR, 0x01000201U);   // DICR channel enable not set
      require(g.hw.spuDmaTransfers == 1 && g.hw.dma4Interrupts == 0 && (g.r(ISTAT) & 8U) == 0, "no interrupt without the DICR channel enable"); }
    // --- DMA4 rejections ---------------------------------------------------------------------------------------------------------
    { Rig g; g.w(SPUADDR, 0x200, 2); g.w(DPCR, 0x00080000U); g.w(D4MADR, 0x1000); g.w(D4BCR, 0x00010010U);
      rejects([&] { g.w(D4CHCR, 0x01000201U); }, "not in DMA write mode", "SPUCNT never written"); }
    { Rig g; g.w(SPUCNT, 0xC011U, 2); g.w(SPUADDR, 0x200, 2); g.w(DPCR, 0x00080000U); g.w(D4MADR, 0x1000); g.w(D4BCR, 0x00010010U);
      rejects([&] { g.w(D4CHCR, 0x01000201U); }, "not in DMA write mode", "SPUCNT in manual mode"); }
    { Rig g; g.w(SPUCNT, 0xC021U, 2); g.w(DPCR, 0x00080000U); g.w(D4MADR, 0x1000); g.w(D4BCR, 0x00010010U);
      rejects([&] { g.w(D4CHCR, 0x01000201U); }, "transfer address", "no SPU transfer address"); }
    { Rig g; g.ready(0x200, 0x1000, 1, 0U); rejects([&] { g.w(D4CHCR, 0x01000201U); }, "channel 4 is disabled", "DPCR channel 4 off"); }
    { Rig g; g.ready(0x200, 0x1002, 1); rejects([&] { g.w(D4CHCR, 0x01000201U); }, "not word aligned", "unaligned MADR"); }
    { Rig g; g.ready(0x200, 0x1000, 1); g.w(D4BCR, 0x00010008U); rejects([&] { g.w(D4CHCR, 0x01000201U); }, "not 16 words", "block size 8"); }
    { Rig g; g.ready(0x200, 0x1000, 0); rejects([&] { g.w(D4CHCR, 0x01000201U); }, "zero blocks", "zero blocks"); }
    { Rig g; g.ready(0x200, 0x1ffff0 & ~3U, 2); rejects([&] { g.w(D4CHCR, 0x01000201U); }, "outside main RAM", "source past 2 MiB"); }
    { Rig g; g.ready(0xffff, 0x1000, 2); rejects([&] { g.w(D4CHCR, 0x01000201U); }, "past the 512 KiB", "destination past SPU RAM"); }
    { Rig g; g.w(SPUFIFO, 7, 2); g.w(SPUCNT, 0xC011U, 2);   // manual flush empties the FIFO; queue again and switch to DMA mode
      g.w(SPUFIFO, 9, 2); rejects([&] { g.w(SPUCNT, 0xC021U, 2); }, "FIFO holds data", "mode 2 with queued halfwords is not a DMA setup"); }
    for (u32 bad : {0x01000200U, 0x01000401U, 0x00000000U, 0x11000201U, 0x01000000U}) {
        Rig g; g.fill(0x9e000, 16); g.ready(0x200, 0x9e000, 1); rejects([&] { g.w(D4CHCR, bad); }, "not modelled", "CHCR " + boot::h8(bad)); }
    { Rig g; rejects([&] { g.w(D4CHCR, 0x01000201U, 2); }, "not modelled", "CHCR halfword write"); }
    { Rig g; rejects([&] { g.w(D4MADR, 0x1000, 2); }, "not modelled", "MADR halfword write"); }
    // --- root counter 2 (libapi SetRCnt(2, 0xffff, RCntMdNOINTR)) --------------------------------------------------------------------
    { Rig g; g.w(R2MODE, 0, 2); g.w(R2TARGET, 0xffff, 2); g.w(R2MODE, 0x0248, 2);
      require(g.hw.timer2Configured && g.hw.timer2Mode == 0x0248U && g.hw.timer2TargetSet, "the exact SetRCnt sequence is accepted"); }
    { Rig g; g.w(R2MODE, 0, 2); rejects([&] { g.w(R2MODE, 0x0248, 2); }, "not modelled", "final mode before the target"); }
    { Rig g; g.w(R2TARGET, 0xffff, 2); for (u32 bad : {0x0249U, 0x0258U, 0x0200U, 0x1248U, 0x0048U}) rejects([&] { g.w(R2MODE, bad, 2); }, "not modelled", "RCNT2 mode " + boot::h8(bad)); }
    { Rig g; for (u32 bad : {0x0U, 0x1000U, 0xfffeU, 0x10000U}) rejects([&] { g.w(R2TARGET, bad, 2); }, "not modelled", "RCNT2 target " + boot::h8(bad)); }
    { Rig g; rejects([&] { g.w(R2TARGET, 0xffff, 4); }, "not modelled", "RCNT2 target word write"); rejects([&] { g.w(R2MODE, 0, 4); }, "not modelled", "RCNT2 mode word write"); }
    { Rig g; g.w(R2MODE, 0, 2); g.w(R2TARGET, 0xffff, 2); g.w(R2MODE, 0x0248, 2);
      rejects([&] { (void)g.r(R2COUNT, 2); }, "not modelled", "the counter value is not readable yet"); rejects([&] { (void)g.r(R2MODE, 2); }, "not modelled", "the mode register is not readable yet"); }
    std::cout << "SPU/DMA4/RCNT2 hardware: " << checks << " checks passed\n";
}
