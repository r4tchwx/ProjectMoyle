#pragma once
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace moyle::detail::recomp::overlay {
// Internal compatibility metadata, not public runtime API or executable code.
struct Metadata {
    const char* name;
    std::uint32_t base, size;
    const char* maskedSha1;
    std::uint32_t runtimeWord0;
    std::array<std::uint32_t,6> patchSites;
    std::uint16_t initialPatchHigh;
    // Only other high half the guest setter writes. Runtime state must be uniform.
    std::uint16_t alternatePatchHigh;
};
inline constexpr Metadata palTitle{
    "PAL TITLE type-2",0x80010200,0x42b4,
    "8039efc0f86388d94659c8fb29cef0f9b67eae84",0x8006b340,
    {0x800103a4,0x80010460,0x80010530,0x800105ec,0x800106b4,0x8001077c},0x1840,0x1c40
};
// PAL LANGUAGE type-2 (decoded 0x42B8 bytes, raw SHA-1 1763c9af...). Same engine code as TITLE: the code words differ
// only in 12 table/data base immediates (+4), because a 4-byte pad word at 0x80012B54 shifts every table and data word
// after the code by 4 (see overlay_unit.hpp palLanguageTableShift). Same base, runtime word0, six sites and patch states.
// The masked digest uses the T1 mask over the whole 0x42B8 bytes; the guest-resident image matched the file word for
// word except word0 (masked) at the first-boot boundary.
inline constexpr Metadata palLanguage{
    "PAL LANGUAGE type-2",0x80010200,0x42b8,
    "d5ccba9cc741fc82e3e87360de8aad18d391be87",0x8006b340,
    {0x800103a4,0x80010460,0x80010530,0x800105ec,0x800106b4,0x8001077c},0x1840,0x1c40
};
// RuntimeSetterEntry: entry into the cull setter, which rewrites all six sites;
// it tolerates a per-site mix of the two valid states (the setter restores a
// uniform state) but nothing else.
enum class LoadPhase { InitialImage, RuntimeLoaded, RuntimeSetterEntry };
class RecognitionError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
// Hashing is read-only identity calculation, NOT load validation. Mask word0
// and each site's high half; retain every other byte, including low halves.
std::string fingerprint(const Metadata&,const std::vector<std::uint8_t>& image);
// Shared metadata-driven validator; permits synthetic descriptors in tests.
// InitialImage requires every site at the initial high half; word0 is not part
// of identity. RuntimeLoaded additionally requires the loader word0 and accepts
// either uniform patch state (all initial or all alternate); a mixed or unknown
// state is fatal. Accepting a state is not executing it: patch semantics are T4.
void validateInitialLoad(const Metadata&,std::uint32_t base,
                         const std::vector<std::uint8_t>& image,LoadPhase);
// Production recognition accepts only the two compiled PAL descriptors, selected by exact size (0x42B8 = LANGUAGE,
// anything else is validated against TITLE, so unknown sizes keep the TITLE diagnostic). No fallback, runtime
// registration, loader writes, code dispatch or invalidation is provided.
const Metadata& recognize(std::uint32_t base,const std::vector<std::uint8_t>& image,LoadPhase);
}
