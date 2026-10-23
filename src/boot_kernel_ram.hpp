#pragma once
// Phase 5: kernel RAM provenance guard (opt-in, installed by the boot harness through Ps1Memory::guard).
//
// PS1 kernel RAM (physical 0x00000000..0x0000ffff) is initialised by the BIOS, whose image is not part of this project. The
// guest memory model zero-fills all RAM ("PROJECT POLICY: deterministic zero initialization, not a hardware reset claim"), which
// is fine for BSS-like game data but would silently invent BIOS contents the moment the PAL reads kernel RAM. This guard makes
// that impossible: a byte in the window may be READ only after the guest (the PAL's own code) has WRITTEN it. A read of a byte
// nobody wrote is a fatal KernelRamFault with the exact address. Writes are always accepted (they are the PAL's own data) and
// recorded, so the report lists exactly which kernel RAM the PAL touched. The guard never changes data.
#include "boot_harness.hpp"
#include <map>

namespace moyle::detail::recomp::boot {
class KernelRamGuard : public MemoryGuard {
public:
    Trace* trace=nullptr;
    const Context* ctx=nullptr;
    static constexpr unsigned logCap=12;
    std::uint64_t reads=0,writes=0;
    std::array<bool,MemoryGuard::window> written{};
    std::map<u32,u32> readWords;      // aligned word address -> number of reads (only words that were fully written)
    void guardRead(u32 address,unsigned width,u32 laneMask) override {
        const auto physical=address&0x1fffffffU;
        for(unsigned n=0;n<width;++n)
            if((width!=4||((laneMask>>(8*n))&0xffU))&&!written[physical+n])
                throw KernelRamFault(address,width,false,"byte "+h8(physical+n)+" was never written by the guest; the harness has no kernel image, so its content is unknown");
        ++reads;++readWords[physical&~3U];
        note("kmem-r",address,width);
    }
    void guardWrite(u32 address,unsigned width,u32 laneMask) override {
        const auto physical=address&0x1fffffffU;
        for(unsigned n=0;n<width;++n)
            if(width==4?((laneMask>>(8*n))&0xffU)==0xffU:true)written[physical+n]=true;
        ++writes;
        note("kmem-w",address,width);
    }
    // Maximal runs of written bytes, as [begin,end) pairs in ascending order.
    std::vector<std::pair<u32,u32>> writtenRanges() const {
        std::vector<std::pair<u32,u32>> out;u32 begin=0;bool open=false;
        for(u32 a=0;a<=MemoryGuard::window;++a){
            const bool w=a<MemoryGuard::window&&written[a];
            if(w&&!open){begin=a;open=true;}
            else if(!w&&open){out.emplace_back(begin,a);open=false;}
        }
        return out;
    }
    bool touched() const {return reads||writes;}
private:
    std::map<std::string,unsigned> seen;
    void note(const char* kind,u32 address,unsigned width) {
        if(!trace)return;
        auto& n=seen[kind];++n;
        if(n>logCap+1)return;
        if(n==logCap+1){trace->add(kind,"further kernel RAM accesses suppressed (totals in the report)");return;}
        trace->add(kind,h8(address)+" w"+std::to_string(width));
    }
};
}
