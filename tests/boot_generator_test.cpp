// Phase 4: synthetic (no game data) generator test for the opt-in boot harness features of the Direct TITLE emitter:
// probe hook + redirect, noreturn roots, manifest-pinned callback sets, extended ADDI, and that the default (no probe) output
// keeps its shape. Writes the probe unit to argv[1] and its function map to argv[2] for tests/boot_test.cpp.
#include "../tools/recomp/closure_emit.hpp"
#include "boot_fixtures.hpp"
#include <fstream>
#include <iostream>

namespace {
using namespace recomp_tool;
using namespace bfx;
int checks = 0;
void require(bool ok, const std::string& what) { ++checks; if (!ok) throw std::runtime_error("FAILED: " + what); }
bool contains(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }
constexpr u32 PIN_SITE = E_PINNED + 8;
struct Built { closure::Result result; closure_emit::Unit unit; std::string source, map; };
Built build(bool probe, bool pinned, bool noreturn, bool card = true) {
    auto p = program();
    std::vector<Seed> seeds;
    for (const auto& t : p.seeds) seeds.push_back({std::get<0>(t), std::get<1>(t), std::get<2>(t)});
    closure::Extras e; e.trapBreak = e.biosHle = e.callbacks = e.bootBios = e.bootIsa = true; e.bootCard = card;
    if (pinned) e.pinnedSets[PIN_SITE] = {{PT0, PT1}, "synthetic: the only two callbacks the fixture registers"};
    if (noreturn) e.noReturn.insert(E_NORETURN);
    Built b;
    b.result = closure::closureDiscover(p.img.bytes(), seeds, {}, closure::TextRange{A, END_TEXT}, 1024, e);
    b.unit = closure_emit::buildUnit(p.img.bytes(), b.result, "synthetic boot unit", probe);
    b.source = generate(b.unit.program, "executeBfx", true);
    b.map = closure_emit::functionMap(b.unit.report, b.result.discovery);
    return b;
}
bool generated(const Built& b, u32 entry) { return std::binary_search(b.unit.report.entries.begin(), b.unit.report.entries.end(), entry); }
}
int main(int argc, char** argv) {
    try {
        if (argc != 3) throw std::runtime_error("Usage: BootGeneratorTest OUT_CPP OUT_MAP");
        const auto full = build(true, true, true);
        for (const auto& n : full.unit.report.notGenerated) std::cerr << "not generated " << hex(n.first) << ": " << n.second << "\n";
        for (auto e : {E_OK, E_GP1BAD, E_DMA_CFG, E_SPIN, E_ADDI, E_PINNED, E_NORETURN, E_CARD, SETJMP, GPU_INIT, IRQ_INIT, ISR, WAIT, PT0, PT1})
            require(generated(full, e), "generated " + hex(e));
        // Phase 5: the only boundary stub is the libcard-shaped kernel patch routine (inline B0:56 call, not a supported form)
        require(full.unit.report.stubs == 1 && full.unit.report.notGenerated.size() == 1 && full.unit.report.notGenerated.count(CARD_PATCH) == 1,
                "exactly one boundary stub: the inline-BIOS-call patch routine");
        require(!generated(full, CARD_PATCH), "the inline B0:56 call routine is not generated");
        require(full.unit.report.biosThunks == 3 && full.unit.report.setGuarded == 1, "three BIOS thunks (incl. InitCARD with --boot-card), one pinned set");
        require(contains(full.source, "c.probe(c, pc)") && contains(full.source, "c.redirectPending"), "probe + redirect emitted");
        require(contains(full.source, "if (c.redirectPending) { c.redirectPending = false; pc = c.redirectPc;"), "BIOS dispatch honours the redirect");
        require(contains(full.source, "Guest ADDI overflow"), "extended ADDI traps on signed overflow");
        const auto& set = full.result.proofs.sets.at(PIN_SITE);
        require(set.kind == "manifest-set" && set.assumed && set.targets == std::vector<u32>({PT0, PT1}), "pinned set recorded as assumed manifest-set");
        // Phase 5 opt-in: without --boot-card the InitCARD thunk is not an implemented boundary (Phase 4 shape)
        const auto nocard = build(true, true, true, false);
        require(nocard.unit.report.biosThunks == 2, "without --boot-card B0:4a is not resolved as a BIOS thunk");
        require(nocard.unit.report.notGenerated.count(TH_INITCARD) == 1 && !generated(nocard, TH_INITCARD), "InitCARD thunk stays an explicit boundary stub without --boot-card");
        require(nocard.result.discovery.bootCard == false && full.result.discovery.bootCard == true, "discovery records the bootCard opt-in");
        // determinism
        const auto again = build(true, true, true);
        require(again.source == full.source && again.map == full.map, "deterministic generation (source and map)");
        // default shape: no probe, no redirect, otherwise the same code
        const auto plain = build(false, true, true);
        require(!contains(plain.source, "c.probe") && !contains(plain.source, "redirectPending"), "default output has no probe/redirect");
        // refusal paths: without the pinned set the unknown callback site is not generated; without the noreturn root the BREAK is not a trap root
        const auto nopin = build(true, false, true);
        require(!generated(nopin, E_PINNED), "no pinned set: the unproven jalr stays unresolved (function not generated)");
        require(nopin.unit.report.notGenerated.count(E_PINNED) == 1, "reported as not generated");
        const auto noret = build(true, true, false);
        require(noret.unit.report.entries.size() <= full.unit.report.entries.size(), "no-noreturn unit never gains functions");
        { std::ofstream out(argv[1], std::ios::binary); out << full.source; if (!out) throw std::runtime_error("cannot write unit"); }
        { std::ofstream out(argv[2], std::ios::binary); out << full.map; if (!out) throw std::runtime_error("cannot write map"); }
        std::cout << "boot generator tests passed (" << checks << " checks)\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
