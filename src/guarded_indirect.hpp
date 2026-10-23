#pragma once
#include "ps1_memory.hpp"
#include <array>
#include <iomanip>
#include <sstream>

namespace moyle::detail {
struct GuardedSlot {
    std::uint32_t baseGlobal, expectedBase, offset, expectedTarget;
    constexpr std::uint32_t address() const { return expectedBase + offset; }
};
// PAL libgpu evidence only. Absence of observed writes is not immutability.
inline constexpr std::array<GuardedSlot,3> libgpuSlots{{
    {0x800678ccU,0x8006788cU,0x08,0x80053718U},
    {0x800678ccU,0x8006788cU,0x10,0x80053604U},
    {0x800678ccU,0x8006788cU,0x3c,0x80053d78U}
}};
inline constexpr const char* guardedConfidence = "likely-invariant";
inline constexpr const char* guardedProvenance =
    "PAL libgpu verified three-slot allowlist; CFG load provenance; runtime RAM validation required";
inline const GuardedSlot* allowedSlot(std::uint32_t global, std::uint32_t base,
                                    std::uint32_t offset, std::uint32_t target) {
    for(const auto& s:libgpuSlots)
        if(s.baseGlobal==global && s.expectedBase==base && s.offset==offset && s.expectedTarget==target) return &s;
    return nullptr;
}
// Called at the JALR instruction, BEFORE its delay slot. capturedTarget is the
// actual source register before retiring a pending load. A RAM match alone must
// never replace a different captured guest target. Single-threaded guest only.
inline std::uint32_t validateGuardedTarget(Ps1Memory& ram, std::uint32_t site,
                                         const GuardedSlot& s, std::uint32_t capturedTarget) {
    const bool allowed=allowedSlot(s.baseGlobal,s.expectedBase,s.offset,s.expectedTarget)!=nullptr;
    const auto base=allowed?ram.read(s.baseGlobal,4):0;
    const auto target=allowed&&base==s.expectedBase?ram.read(s.address(),4):0;
    if(!allowed || base!=s.expectedBase || target!=s.expectedTarget || capturedTarget!=s.expectedTarget) {
        std::ostringstream message;
        message<<"resolved-indirect-guarded validation failed at 0x"<<std::hex<<site
               <<" (base=0x"<<base<<", slot=0x"<<target<<", captured=0x"<<capturedTarget
               <<"); dynamic dispatch is not enabled for this guarded edge";
        throw std::runtime_error(message.str());
    }
    return s.expectedTarget;
}
}
