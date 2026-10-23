#pragma once
// Minimal BIOS boundary for the Direct TITLE closure unit. This is NOT a BIOS emulator: it implements exactly the three
// kernel function-table entries the PAL loader path reaches (tools/recomp discovery: `biosHleSupported`), with the
// semantics that path observes, and every other (table, function) pair is a controlled fatal diagnostic.
//
// What the repository proves about the three call sites (SLES_017.26, see docs/direct-title-runtime.md):
//   B0:0x35 (external reference name "write"): called from the buffered putchar (0x8004f1f4) and the flush (0x8004f2f0)
//       as (a0=1, a1=0x80070210 buffer, a2=byte count). The callers never read v0 or any other register afterwards and
//       the only guest-visible effect is the console stream. HLE: fd must be 1, the buffer must be readable RAM; the bytes
//       are appended to Device::console and v0 = byte count (the documented return of write()).
//   B0:0x5b (external name "ChangeClearPad"): called once from the VSync timeout path (0x8004da50) with a0=0. No caller
//       reads a result. HLE: the argument is recorded in Device::clearPad; there is no pad IRQ in this unit to consume it.
//   C0:0x0a (external name "ChangeClearRCnt"): same path, a0=3, a1=0. HLE: recorded in Device::clearRCnt[a0]; a0 > 3 is
//       fatal (there are only four root counters), there is no counter IRQ in this unit to consume it.
// The names are external psx-spx knowledge and are NOT evidence; the argument/return/effect facts above are.
// Registers other than v0 (write only) are left untouched; the kernel would clobber caller-saved registers, which the
// compiled callers do not rely on across a call.
#include "recomp_context.hpp"
#include <array>
#include <string>
#include <vector>

namespace moyle::detail::recomp::bios {
struct Call {std::uint32_t site,table,function,a0,a1,a2;};
struct Device {
    std::string console;                         // bytes written to fd 1 by B0:0x35, in order
    std::uint32_t clearPad=0;                    // last ChangeClearPad argument (recorded, not consumed)
    bool clearPadSeen=false;
    std::array<std::uint32_t,4> clearRCnt{};     // last ChangeClearRCnt flag per root counter (recorded, not consumed)
    std::array<bool,4> clearRCntSeen{};
    std::vector<Call> calls;                     // every BIOS call in order (diagnostics / tests)
};
inline constexpr std::uint32_t maxWrite=0x10000U; // sanity bound for one write(); the PAL buffer is 32 bytes
[[noreturn]] inline void fail(std::uint32_t site,std::uint32_t table,std::uint32_t function,const std::string& why) {
    std::ostringstream out;
    out<<"BIOS boundary at 0x"<<std::hex<<site<<" (table 0x"<<table<<", function 0x"<<function<<"): "<<why;
    throw std::runtime_error(out.str());
}
// The policy installed in Context::biosPolicy. Requires Context::biosDevice.
inline void minimalPolicy(Context& c,std::uint32_t site,std::uint32_t table,std::uint32_t function) {
    auto* device=c.biosDevice;
    if(!device)fail(site,table,function,"no BIOS device attached");
    const auto a0=c.r[4],a1=c.r[5],a2=c.r[6];
    device->calls.push_back({site,table,function,a0,a1,a2});
    if(table==0xb0U&&function==0x35U) {
        if(a0!=1U)fail(site,table,function,"write() to a descriptor other than 1 is not implemented");
        if(a2>maxWrite)fail(site,table,function,"write() length exceeds the sanity bound");
        std::string bytes;bytes.reserve(a2);
        try{ // host read of guest RAM: no guest read effects are logged (the kernel, not the program, reads the buffer)
            for(std::uint32_t n=0;n<a2;++n)bytes.push_back(char(c.ram.bytes[Ps1Memory::offset(a1+n,1)]));
        }catch(const std::out_of_range&){fail(site,table,function,"write() buffer is not readable RAM");}
        device->console+=bytes;
        c.r[2]=a2;
        return;
    }
    if(table==0xb0U&&function==0x5bU) {device->clearPad=a0;device->clearPadSeen=true;return;}
    if(table==0xc0U&&function==0x0aU) {
        if(a0>3U)fail(site,table,function,"root counter index out of range");
        device->clearRCnt[a0]=a1;device->clearRCntSeen[a0]=true;return;
    }
    fail(site,table,function,"kernel function is not implemented");
}
inline bool supported(std::uint32_t table,std::uint32_t function) {
    return (table==0xb0U&&function==0x35U)||(table==0xb0U&&function==0x5bU)||(table==0xc0U&&function==0x0aU);
}
}
