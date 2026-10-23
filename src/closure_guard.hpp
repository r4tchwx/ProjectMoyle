#pragma once
// Runtime helpers for Direct TITLE closure units (tools/recomp/closure_emit.hpp). A closure unit contains many guest
// functions in one generated dispatch loop, so `jr $ra` is validated: the target must be the entry return sentinel or the
// continuation (call site + 8) of a call the unit contains. Anything else, including a corrupted return address that
// happens to point at other generated code, is a controlled fatal diagnostic.
#include "recomp_dispatch.hpp"

namespace moyle::detail::recomp {
[[noreturn]] inline void closureReturnRejected(std::uint32_t site,std::uint32_t target) {
    std::ostringstream out;
    out<<"Direct TITLE return at 0x"<<std::hex<<site<<" to 0x"<<target
       <<": not the entry return sentinel and not the continuation of a call in the unit";
    throw std::runtime_error(out.str());
}
inline std::uint32_t closureReturnCanonical(std::uint32_t site,std::uint32_t target) {
    try{return canonicalCodeAddress(target);}
    catch(const std::out_of_range&){closureReturnRejected(site,target);}
}
}
