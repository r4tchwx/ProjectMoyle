#pragma once
#include "recomp_context.hpp"
#include <map>
#include <sstream>

namespace moyle::detail::recomp {
// Only the same 2 MiB/alignment/segments accepted by Ps1Memory; no BIOS/overlays.
inline std::uint32_t canonicalCodeAddress(std::uint32_t address) {
    return 0x80000000U | static_cast<std::uint32_t>(Ps1Memory::offset(address,4));
}
inline std::uint32_t codeAlias(std::uint32_t address,std::uint32_t pc) {
    return (canonicalCodeAddress(address)&0x1fffffffU)|(pc&0xe0000000U);
}
using RecompFunction=void(*)(Context&,std::uint32_t,std::uint64_t);
struct DynamicTarget {std::uint32_t guest=0;RecompFunction function=nullptr;};
inline std::runtime_error dispatchError(std::uint32_t site,std::uint32_t target,const char* reason) {
    std::ostringstream out;
    out<<"dynamic jalr at 0x"<<std::hex<<site<<", target 0x"<<target<<": "<<reason;
    return std::runtime_error(out.str());
}
class DynamicRegistry {
    std::map<std::uint32_t,RecompFunction> functions;
public:
    void add(std::uint32_t guest,RecompFunction host) {
        if(!host)throw std::invalid_argument("Null recomp backend");
        const auto key=canonicalCodeAddress(guest);
        if(key==0x80000000U)throw std::invalid_argument("Null physical recomp entry");
        if(!functions.emplace(key,host).second)throw std::invalid_argument("Duplicate recomp entry/alias");
    }
    DynamicTarget lookup(std::uint32_t site,std::uint32_t guest) const {
        std::uint32_t key;
        try{key=canonicalCodeAddress(guest);}catch(const std::out_of_range&){
            throw dispatchError(site,guest,"unaligned or unmapped RAM code address");
        }
        if(key==0x80000000U)throw dispatchError(site,guest,"null guest function pointer");
        const auto found=functions.find(key);
        if(found==functions.end())throw dispatchError(site,guest,"unregistered recomp target");
        return {guest,found->second}; // Preserve virtual alias, including nested RA values.
    }
};
inline DynamicTarget lookupDynamic(Context& c,std::uint32_t site,std::uint32_t guest) {
    if(!c.registry)throw dispatchError(site,guest,"no recomp registry installed");
    return c.registry->lookup(site,guest);
}
// Invoked after the caller's delay slot. The backend receives the shared guest
// state, including pending loads; no invented ABI saves/restores or native fallback.
inline void dispatchDynamic(Context& c,DynamicTarget target,std::uint32_t site,
                            std::uint32_t continuation,std::uint64_t budget) {
    if(!target.function)throw dispatchError(site,target.guest,"missing backend");
    if(c.dynamicDepth>=64)throw dispatchError(site,target.guest,"nested call depth exceeded");
    struct Depth {unsigned& value;explicit Depth(unsigned& v):value(v){++value;}~Depth(){--value;}} depth(c.dynamicDepth);
    const auto start=c.steps;++c.dynamicCalls;c.pc=target.guest;
    c.dynamicTrace.push_back({site,target.guest,c.r[31]});
    target.function(c,target.guest,budget);
    if(c.steps-start>budget)throw dispatchError(site,target.guest,"backend exceeded instruction budget");
    if(c.pc!=continuation)throw dispatchError(site,target.guest,"backend returned to unexpected guest PC");
}
}
