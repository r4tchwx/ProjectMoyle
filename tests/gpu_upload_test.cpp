// GP0 01h / A0h CPU->VRAM upload and DMA2 block-mode upload: strict synthetic tests of the minimal GPU upload model in
// src/boot_hardware.hpp (no game data). Every unsupported shape must stay a fatal MmioFault.
#include "../src/boot_hardware.hpp"
#include <array>
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
std::uint64_t fnv(std::uint64_t h, u32 w) { for (unsigned b = 0; b < 4; ++b) { h ^= (w >> (8 * b)) & 0xffU; h *= 0x100000001b3ULL; } return h; }
constexpr u32 GP0 = 0x1f801810, GP1 = 0x1f801814, MADR = 0x1f8010a0, BCR = 0x1f8010a4, CHCR = 0x1f8010a8, D6CHCR = 0x1f8010e8, DPCR = 0x1f8010f0, DICR = 0x1f8010f4;
struct Rig {
    std::unique_ptr<Context> context = std::make_unique<Context>();
    boot::Hardware hw;
    Context& c = *context;
    Rig(bool reset = true) { hw.ctx = &c; if (reset) w(GP1, 0); }
    void w(u32 a, u32 v, unsigned width = 4) { hw.mmioWrite(a, v, width); }
    u32 r(u32 a) { return hw.mmioRead(a, 4); }
    void begin(u32 xy, u32 wh) { w(GP0, 0xa0000000U); w(GP0, xy); w(GP0, wh); }
    void dmaSetup(u32 madr, u32 bcr, u32 dir = 2, u32 dpcr = 0x00000800U) { w(GP1, 0x04000000U | dir); w(DPCR, dpcr); w(MADR, madr); w(BCR, bcr); }
};
}
int main() {
    // --- GP0 01h -----------------------------------------------------------------------------------------------------------
    { Rig g; g.w(GP0, 0x01000000U); require(g.hw.gp0ResetNops == 1 && g.hw.upState == boot::Hardware::UpState::Idle, "exact 01000000 accepted as a counted no-op"); g.w(GP0, 0x01000000U); require(g.hw.gp0ResetNops == 2, "no-op counted twice"); }
    for (u32 bad : {0x01000001U, 0x01ffffffU, 0x01123456U, 0x01800000U, 0x01000100U}) { Rig g; rejects([&] { g.w(GP0, bad); }, "not modelled", "malformed 01xxxxxx " + boot::h8(bad)); }
    { Rig g(false); rejects([&] { g.w(GP0, 0x01000000U); }, "not modelled", "01000000 before the GPU reset"); rejects([&] { g.w(GP0, 0xa0000000U); }, "not modelled", "A0 before the GPU reset"); }
    { Rig g; rejects([&] { g.hw.mmioWrite(GP0, 0x01000000U, 2); }, "not modelled", "01000000 halfword write"); }
    // --- A0h PIO upload 1: (511,507) 1x4 -> 2 words ---------------------------------------------------------------------------
    { Rig g; g.begin(0x01fb01ffU, 0x00040001U);
      require(g.hw.upState == boot::Hardware::UpState::Data && g.hw.upRemaining == 2, "upload 1: 2 payload words expected");
      g.w(GP0, 0x11111111U); require(g.hw.upState == boot::Hardware::UpState::Data && g.hw.upRemaining == 1, "upload 1: one word left");
      g.w(GP0, 0x22222222U); require(g.hw.upState == boot::Hardware::UpState::Idle && g.hw.uploadsCompleted == 1, "upload 1: back to Idle");
      const auto& u = g.hw.uploads.at(0);
      require(u.x == 511 && u.y == 507 && u.w == 1 && u.h == 4 && u.totalWords == 2 && u.pioWords == 2 && u.dmaWords == 0, "upload 1: rectangle and accounting");
      require(u.hash == fnv(fnv(0xcbf29ce484222325ULL, 0x11111111U), 0x22222222U), "upload 1: payload hash");
      g.w(GP0, 0xa0000000U); require(g.hw.upState == boot::Hardware::UpState::ExpectXY, "a new A0 is accepted once the upload completed"); }
    // --- upload 2: (496,511) 16x1 CLUT -> 8 words -------------------------------------------------------------------------------
    { Rig g; g.begin(0x01ff01f0U, 0x00010010U); std::uint64_t h = 0xcbf29ce484222325ULL;
      for (u32 i = 0; i < 8; ++i) { require(g.hw.upState == boot::Hardware::UpState::Data, "upload 2: still in Data"); g.w(GP0, 0x01010101U * (i + 1)); h = fnv(h, 0x01010101U * (i + 1)); }
      require(g.hw.upState == boot::Hardware::UpState::Idle && g.hw.uploads.at(0).totalWords == 8 && g.hw.uploads.at(0).hash == h && g.hw.uploadWordsPio == 8, "upload 2: 8 PIO words"); }
    // --- odd pixel count rounds up -----------------------------------------------------------------------------------------------
    { Rig g; g.begin(0, 0x00010003U); require(g.hw.upRemaining == 2, "3 pixels = 2 words"); }
    { Rig g; g.begin(0, 0x00010001U); require(g.hw.upRemaining == 1, "1 pixel = 1 word"); g.w(GP0, 7); require(g.hw.upState == boot::Hardware::UpState::Idle, "1 pixel: Idle after 1 word"); }
    { Rig g; g.begin(0x00010001U, 0x00030003U); require(g.hw.upRemaining == 5, "9 pixels = 5 words"); }
    // --- payload that looks like commands is data ----------------------------------------------------------------------------------
    { Rig g; g.begin(0, 0x00010008U); require(g.hw.upRemaining == 4, "8 pixels = 4 words"); std::uint64_t h = 0xcbf29ce484222325ULL;
      for (u32 v : {0xe1000000U, 0xa0000000U, 0x01000000U, 0xb0000000U}) { g.w(GP0, v); h = fnv(h, v); }
      require(g.hw.upState == boot::Hardware::UpState::Idle && g.hw.uploadsCompleted == 1 && g.hw.uploads.at(0).hash == h, "E1/A0/01/B0-looking payload words are consumed as data");
      require(g.hw.gp0ResetNops == 0 && g.hw.counts.count("gp0 GP0_STATE") == 0 && g.hw.counts.count("gp0 GP0_A0_BEGIN") == 1, "payload never executed as a command"); }
    // --- invalid rectangles ----------------------------------------------------------------------------------------------------------
    for (u32 xy : {0x00000400U, 0x02000000U, 0x0000ffffU, 0xffff0000U}) { Rig g; g.w(GP0, 0xa0000000U); rejects([&] { g.w(GP0, xy); }, "XY origin", "XY " + boot::h8(xy)); }
    struct Bad { u32 xy, wh; };
    for (Bad b : {Bad{0, 0x00010000U}, Bad{0, 0x00000001U}, Bad{0, 0}, Bad{0, 0x00010401U}, Bad{0, 0x02010001U}, Bad{0x00000001U, 0x00010400U}, Bad{0x00010000U, 0x02000001U},
                  Bad{0x000003ffU, 0x00010002U}, Bad{0x01ff0000U, 0x00020001U}, Bad{0x01ff03ffU, 0x00020002U}}) {
        Rig g; g.w(GP0, 0xa0000000U); g.w(GP0, b.xy);
        rejects([&] { g.w(GP0, b.wh); }, "rectangle", "WH " + boot::h8(b.wh) + " at " + boot::h8(b.xy)); }
    { Rig g; g.begin(0, 0x02000400U); require(g.hw.upRemaining == 262144U, "largest rectangle 1024x512 is accepted"); }
    // --- incomplete upload followed by an incompatible command stays fatal -----------------------------------------------------------
    { Rig g; g.begin(0, 0x00010004U); g.w(GP0, 1); rejects([&] { g.w(GP1, 0); }, "incomplete GP0 A0h upload", "GP1 reset mid-upload"); }
    { Rig g; g.begin(0, 0x00010004U); rejects([&] { g.w(GP1, 0x01000000U); }, "incomplete GP0 A0h upload", "GP1 FIFO reset mid-upload"); }
    { Rig g; g.w(GP0, 0xa0000000U); rejects([&] { g.w(GP1, 0); }, "incomplete GP0 A0h upload", "GP1 reset while XY expected"); }
    { Rig g; g.w(GP0, 0xa0000000U); g.w(GP0, 0); rejects([&] { g.w(GP1, 0); }, "incomplete GP0 A0h upload", "GP1 reset while WH expected"); }
    { Rig g; g.w(GP0, 0xa0000000U); rejects([&] { g.w(GP0, 0xb0000000U); }, "XY origin", "StoreImage word where XY is expected"); }
    { Rig g; g.begin(0, 0x00010004U); g.w(GP1, 0x04000002U); require(g.hw.upState == boot::Hardware::UpState::Data, "GP1 DMA direction change keeps the upload pending"); }
    { Rig g; rejects([&] { g.w(GP0, 0xb0000000U); }, "not modelled", "StoreImage B0 in Idle"); rejects([&] { g.w(GP0, 0xc0000000U); }, "not modelled", "VRAM->VRAM copy C0"); rejects([&] { g.w(GP0, 0xa0000001U); }, "not modelled", "A0 with payload bits"); rejects([&] { g.w(GP0, 0x80000000U); }, "not modelled", "unsupported GP0 command"); }
    { Rig g; g.begin(0, 0x00010004U); g.w(MADR, 0); g.w(BCR, 0);
      rejects([&] { g.w(CHCR, 0x01000401U); }, "incomplete", "linked-list DMA while an upload is pending"); }
    // --- DMA2 block upload: rejected shapes ------------------------------------------------------------------------------------------
    { Rig g; g.dmaSetup(0x8009e05c, 0x00010010U); rejects([&] { g.w(CHCR, 0x01000201U); }, "without a pending", "block DMA with no A0 data phase"); }
    { Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x8009e05c, 0x00010010U); g.w(GP0, 1);   // 32x32 = 512 words; one PIO word -> 511 left, no fit
      rejects([&] { g.w(CHCR, 0x01000201U); }, "remaining upload words", "block count not matching the remaining words"); }
    for (u32 dir : {0U, 1U, 3U}) { Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x8009e05c, 0x00200010U, dir); rejects([&] { g.w(CHCR, 0x01000201U); }, "direction", "GP1 DMA direction " + std::to_string(dir)); }
    { Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x8009e05c, 0x00200010U, 2, 0); rejects([&] { g.w(CHCR, 0x01000201U); }, "channel 2 is disabled", "DPCR channel 2 off"); }
    for (u32 bcr : {0x00200000U, 0x0020000fU, 0x00200011U, 0x00200008U, 0x00000010U, 0x00210010U, 0x001f0010U}) { Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x8009e05c, bcr);
        rejects([&] { g.w(CHCR, 0x01000201U); }, (bcr & 0xffffU) != 0x10U ? "block size" : "remaining upload words", "BCR " + boot::h8(bcr)); }
    { Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x8009e05e, 0x00200010U); rejects([&] { g.w(CHCR, 0x01000201U); }, "not word aligned", "unaligned MADR"); }
    { Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x001ffff0, 0x00200010U); rejects([&] { g.w(CHCR, 0x01000201U); }, "outside main RAM", "source runs past 2 MiB"); }
    { Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x00200000, 0x00200010U); rejects([&] { g.w(CHCR, 0x01000201U); }, "outside main RAM", "source starts beyond RAM"); }
    for (u32 chcr : {0x01000200U, 0x01000203U, 0x11000201U, 0x01000601U, 0x01000211U, 0x81000201U}) {
        Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x8009e05c, 0x00200010U);
        rejects([&] { g.w(CHCR, chcr); }, "not modelled", "unexpected CHCR " + boot::h8(chcr)); }
    { Rig g; g.begin(0, 0x00200020U); g.dmaSetup(0x8009e05c, 0x00200010U); rejects([&] { g.hw.mmioWrite(CHCR, 0x01000201U, 2); }, "not modelled", "CHCR halfword write"); }
    // --- upload 3: 512x512 at (512,0), 131072 words, one DMA2 block transfer ---------------------------------------------------------------
    { Rig g; std::uint64_t h = 0xcbf29ce484222325ULL;
      for (u32 i = 0; i < 131072U; ++i) { const u32 v = i * 2654435761U + 12345U; g.c.ram.write(0x8009e05cU + i * 4U, v, 4); h = fnv(h, v); }
      g.begin(0x00000200U, 0x02000200U); require(g.hw.upRemaining == 131072U, "upload 3: 131072 words expected");
      g.dmaSetup(0x8009e05c, 0x20000010U);
      g.w(DICR, 0x00ff0000U); const u32 dicrBefore = g.r(DICR); const auto istatBefore = g.hw.istat;
      g.w(CHCR, 0x01000201U);
      require(g.r(CHCR) == 0x00000201U, "upload 3: CHCR reads back 00000201 (bit 24 clear, transfer already finished)");
      require(g.r(MADR) == 0x0009e05cU + 131072U * 4U, "upload 3: MADR advanced past the source");
      require(g.hw.upState == boot::Hardware::UpState::Idle && g.hw.uploadsCompleted == 1 && g.hw.dma2BlockUploads == 1, "upload 3: Idle, one DMA upload");
      const auto& u = g.hw.uploads.at(0);
      require(u.x == 512 && u.y == 0 && u.w == 512 && u.h == 512 && u.totalWords == 131072U && u.pioWords == 0 && u.dmaWords == 131072U && g.hw.uploadWordsDma == 131072U, "upload 3: rectangle and accounting");
      require(u.hash == h, "upload 3: hash over the RAM source words");
      require(g.r(DICR) == dicrBefore && g.hw.istat == istatBefore && g.hw.dicrFlags == 0, "upload 3: no DMA IRQ and no DICR flag");
      rejects([&] { g.w(CHCR, 0x01000201U); }, "without a pending", "a second block start after completion"); }
    // --- mixed PIO + DMA: 17x2 = 34 pixels = 17 words = 1 PIO + one 16-word block ---------------------------------------------------------------
    { Rig g; std::uint64_t h = 0xcbf29ce484222325ULL;
      g.begin(0x00050003U, 0x00020011U); require(g.hw.upRemaining == 17, "17 words expected");
      g.w(GP0, 0xdeadbeefU); h = fnv(h, 0xdeadbeefU);
      for (u32 i = 0; i < 16; ++i) { const u32 v = 0x10000000U + i; g.c.ram.write(0x80100000U + i * 4U, v, 4); h = fnv(h, v); }
      g.dmaSetup(0x80100000U, 0x00010010U); g.w(CHCR, 0x01000201U);
      require(g.hw.upState == boot::Hardware::UpState::Idle && g.hw.uploads.at(0).pioWords == 1 && g.hw.uploads.at(0).dmaWords == 16 && g.hw.uploads.at(0).hash == h, "mixed upload: PIO then DMA, ordered hash");
      require(g.r(MADR) == 0x00100040U && g.r(CHCR) == 0x201U, "mixed upload: MADR/CHCR"); }
    // --- linked-list DMA regressions (packet words keep their existing handling) ------------------------------------------------------------
    { Rig g;   // node 0 at 0x1000: 2 words {E1000000, 00000000} -> node 1 at 0x1010: 1 word {E2000000} -> end
      g.c.ram.write(0x80001000U, (2U << 24) | 0x1010U, 4); g.c.ram.write(0x80001004U, 0xe1000000U, 4); g.c.ram.write(0x80001008U, 0x00000000U, 4);
      g.c.ram.write(0x80001010U, (1U << 24) | 0x00ffffffU, 4); g.c.ram.write(0x80001014U, 0xe2000000U, 4);
      g.w(MADR, 0x1000); g.w(BCR, 0); g.w(CHCR, 0x01000401U);
      require(g.r(CHCR) == 0x00000401U && g.hw.counts["gp0 GP0_STATE"] == 2 && g.hw.uploadsCompleted == 0, "linked-list DMA still completes and clears bits 24/28"); }
    { Rig g;   // ClearImage inside a linked list is unchanged
      g.c.ram.write(0x80001000U, (3U << 24) | 0x00ffffffU, 4); g.c.ram.write(0x80001004U, 0x02000000U, 4); g.c.ram.write(0x80001008U, 0x00000000U, 4); g.c.ram.write(0x8000100cU, 0x01e00280U, 4);
      g.w(MADR, 0x1000); g.w(BCR, 0); g.w(CHCR, 0x01000401U);
      require(g.hw.gp0FillWh == 0x01e00280U && g.hw.counts["gp0 GP0_FILL_RECT"] == 1, "linked-list ClearImage unchanged"); }
    { Rig g;   // an A0 word inside a linked list is still not modelled
      g.c.ram.write(0x80001000U, (1U << 24) | 0x00ffffffU, 4); g.c.ram.write(0x80001004U, 0xa0000000U, 4);
      g.w(MADR, 0x1000); g.w(BCR, 0);
      rejects([&] { g.w(CHCR, 0x01000401U); }, "linked-list GP0 command is not modelled", "A0 inside a linked list"); }
    // --- existing generic CHCR configuration writes are unchanged ---------------------------------------------------------------------------------
    { Rig g; g.w(CHCR, 0x00000401U); require(g.r(CHCR) == 0x401U, "CHCR sync-mode-2 configuration write unchanged"); g.w(CHCR, 0x00000201U); require(g.r(CHCR) == 0x201U, "CHCR 00000201 configuration write unchanged"); }
    // --- DMA6/OTC: only the observed PAL CHCR clear is modelled -------------------------------------------------------------------------------
    { Rig g;
      const auto before = g.hw.counts["mmio-w D6_CHCR"];
      g.w(D6CHCR, 0U);
      require(g.hw.counts["mmio-w D6_CHCR"] == before + 1U, "DMA6 CHCR 00000000 word write accepted and logged"); }
    { Rig g; rejects([&] { g.hw.mmioWrite(D6CHCR, 0U, 2); }, "not modelled", "DMA6 CHCR zero halfword write"); }
    for (u32 bad : {0x00000002U, 0x01000000U, 0x10000000U, 0x40000000U, 0x11000002U, 0xffffffffU}) {
        Rig g; rejects([&] { g.w(D6CHCR, bad); }, "not modelled", "unobserved DMA6 CHCR " + boot::h8(bad));
    }
    // --- GP0 80h MoveImage inside a DMA2 linked list (the PAL's (0,0,512,512) -> (512,0) copy) ------------------------------------------------
    const auto listWith = [](Rig& g, std::vector<u32> packet) {
        g.c.ram.write(0x80001000U, (u32(packet.size()) << 24) | 0x00ffffffU, 4);
        for (std::size_t i = 0; i < packet.size(); ++i) g.c.ram.write(0x80001004U + 4U * u32(i), packet[i], 4);
        g.w(MADR, 0x1000); g.w(BCR, 0);
    };
    { Rig g; listWith(g, {0x80000000U, 0x00000000U, 0x00000200U, 0x02000200U}); g.w(CHCR, 0x01000401U);
      require(g.hw.gp0MoveImages == 1 && g.hw.moves.at(0).sx == 0 && g.hw.moves.at(0).dx == 512 && g.hw.moves.at(0).w == 512 && g.hw.moves.at(0).h == 512, "MoveImage (0,0,512,512)->(512,0) accepted and recorded");
      require(g.r(CHCR) == 0x00000401U && g.hw.uploadsCompleted == 0 && g.hw.upState == boot::Hardware::UpState::Idle, "MoveImage list completes and starts no upload"); }
    { Rig g; listWith(g, {0xe1000000U, 0x80000000U, 0x00010002U, 0x00030004U, 0x00050006U, 0xe2000000U}); g.w(CHCR, 0x01000401U);
      require(g.hw.gp0MoveImages == 1 && g.hw.moves.at(0).sx == 2 && g.hw.moves.at(0).sy == 1 && g.hw.moves.at(0).dx == 4 && g.hw.moves.at(0).dy == 3 && g.hw.moves.at(0).w == 6 && g.hw.moves.at(0).h == 5 && g.hw.counts["gp0 GP0_STATE"] == 2, "MoveImage between state words: fields decoded, neighbours still handled"); }
    { Rig g; listWith(g, {0x80000000U, 0x00000000U, 0x00000200U}); rejects([&] { g.w(CHCR, 0x01000401U); }, "truncated GP0 80h", "MoveImage packet with 2 parameter words"); }
    { Rig g; listWith(g, {0x80000001U, 0, 0, 0x00010001U}); rejects([&] { g.w(CHCR, 0x01000401U); }, "linked-list GP0 command is not modelled", "80h with payload bits"); }
    for (auto p : {std::array<u32, 3>{0, 0x00000200U, 0x00000200U},          // w = 512, h = 0
                   std::array<u32, 3>{0, 0x00000200U, 0x02000000U},          // w = 0
                   std::array<u32, 3>{0, 0x00000200U, 0x02010200U},          // h = 513
                   std::array<u32, 3>{0, 0x00000200U, 0x02000401U},          // w = 1025
                   std::array<u32, 3>{0x00000201U, 0x00000200U, 0x02000200U}, // source x + w = 1025 would wrap
                   std::array<u32, 3>{0x00010000U, 0x00000200U, 0x02000200U}, // source y + h = 513
                   std::array<u32, 3>{0, 0x00000201U, 0x02000200U},          // destination x + w = 1025
                   std::array<u32, 3>{0, 0x02000200U, 0x02000200U},          // destination y + h = 1024
                   std::array<u32, 3>{0x04000000U, 0, 0x00010001U},          // source x = 1024... as y (y = 0x0400)
                   std::array<u32, 3>{0, 0x00000400U, 0x00010001U}}) {       // destination x = 1024
        Rig g; listWith(g, {0x80000000U, p[0], p[1], p[2]});
        rejects([&] { g.w(CHCR, 0x01000401U); }, "MoveImage", "invalid MoveImage " + boot::h8(p[0]) + " " + boot::h8(p[1]) + " " + boot::h8(p[2])); }
    { Rig g; g.begin(0, 0x00010004U); listWith(g, {0x80000000U, 0, 0x00000200U, 0x00010001U}); rejects([&] { g.w(CHCR, 0x01000401U); }, "incomplete", "MoveImage list while an upload is pending"); }
    std::cout << "gpu upload: " << checks << " checks passed (GP0 01h, A0h PIO/odd/payload-as-data, rectangle validation, DMA2 block shapes, upload 3, mixed, linked-list regressions)\n";
}
