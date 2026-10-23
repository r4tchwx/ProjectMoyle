#pragma once
// Runtime selector for the PAL type-2 overlay at 0x80010200 (first boot). It is the DynamicRegistry backend for the five
// public overlay entries that EXE code calls with JAL (--external-entry): the registry routes such a call here, after the
// caller's delay slot, with the shared Context. The selector identifies the live RAM image against the compiled
// descriptors it is given (masked T1 fingerprint, src/overlay_recognition.hpp) and runs the matching generated executor
// on the same Context. The executor itself then revalidates identity, runtime word0 and the patch state at entry.
// Fail closed: a pending probe redirect, an address that is not one of the five public entries, an image that matches
// no descriptor (or more than one). There is no fallback executor, interpreter or copy of guest state.
#include "overlay_unit.hpp"
#include "recomp_dispatch.hpp"
#include <initializer_list>

namespace moyle::detail::recomp::overlay {
struct Backend {const Metadata* identity;RecompFunction execute;};
inline const Backend& selectBackend(const Context& c,std::uint32_t entry,std::initializer_list<Backend> backends) {
    if(c.redirectPending)throw unitError(entry,"overlay entry while a probe redirect is pending");
    std::uint32_t canonical=0;
    try{canonical=canonicalCodeAddress(entry);}catch(const std::out_of_range&){throw unitError(entry,"overlay entry is not a mapped RAM code address");}
    if(!publicEntry(canonical))throw unitError(entry,"not one of the five public overlay entries");
    const Backend* match=nullptr;
    for(const auto& b:backends){
        if(!b.identity||!b.execute)throw unitError(entry,"invalid overlay backend");
        const auto offset=Ps1Memory::offset(b.identity->base,4);
        if(offset>c.ram.bytes.size()||b.identity->size>c.ram.bytes.size()-offset)throw unitError(entry,"overlay image outside RAM");
        const std::vector<std::uint8_t> image(c.ram.bytes.begin()+offset,c.ram.bytes.begin()+offset+b.identity->size);
        if(fingerprint(*b.identity,image)!=b.identity->maskedSha1)continue;
        if(match)throw unitError(entry,"live overlay image matches more than one compiled descriptor");
        match=&b;
    }
    if(!match)throw unitError(entry,"live overlay image at 0x80010200 matches no compiled descriptor (unknown overlay)");
    return *match;
}
// Registry backend body: the generated executor runs until the caller's return address (c.r[31] = JAL + 8).
inline void selectAndExecute(Context& c,std::uint32_t entry,std::uint64_t budget,std::initializer_list<Backend> backends) {
    selectBackend(c,entry,backends).execute(c,entry,budget);
}
}
