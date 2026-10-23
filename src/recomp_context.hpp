#pragma once
#include "ps1_memory.hpp"
#include "ps1_gte.hpp"
#include <array>

namespace moyle::detail::recomp {
class DynamicRegistry;
namespace cdhle {struct CdDrive;}
namespace bios {struct Device;}
struct Branch { std::uint32_t pc; bool taken; };
struct DynamicCall {std::uint32_t site,target,returnAddress;};
struct TableTransfer {std::uint32_t site,target,returnAddress;bool call;std::uint32_t index=0;};
struct Context;
// Phase 4 execution probe (only units generated with the explicit probe option call it; null = no probe). Invoked at the
// start of every guest instruction iteration with the guest PC about to execute (delay slots included). It may throw to
// stop execution. It must not modify guest state other than through explicit, documented harness mechanisms.
using ProbeHook=void(*)(Context&,std::uint32_t pc);
// Explicit SYSCALL policy hook. The generator only recognizes SYSCALL and routes it here;
// the real BIOS policy is a separate tranche. Invoked at the guest PC of the SYSCALL (the
// executing alias) with the 20-bit code field; any pending load has already retired. When it
// returns, guest execution resumes at PC+4. Exceptions propagate with guest state visible.
using SyscallPolicy=void(*)(Context&,std::uint32_t pc,std::uint32_t code);
// Explicit BIOS function-table boundary (Direct TITLE closure units only). Invoked after the delay slot of a proven
// `jr $t2` thunk (`$t2` = 0xA0/0xB0/0xC0 kernel table, `$t1` = function number) with the guest PC of that JR; when it
// returns, the unit continues at the thunk's caller ($ra), exactly like the kernel routine returning. Null (default)
// makes every BIOS call a controlled fatal diagnostic. src/bios_boundary.hpp has the minimal verified policy.
using BiosPolicy=void(*)(Context&,std::uint32_t site,std::uint32_t table,std::uint32_t function);
struct Context {
    Ps1Memory ram;
    Gte gte;
    std::array<std::uint32_t,32> r{};
    std::uint32_t hi=0,lo=0;
    std::uint32_t cop0Status=0; // boot-only COP0 Status shadow; IRQ delivery remains host-device state
    unsigned loadRegister = 0;
    std::uint32_t loadValue = 0;
    std::uint64_t steps = 0, calls = 0;
    std::vector<Branch> branches;
    // Internal execution state; the public runtime API never sees guest addresses.
    const DynamicRegistry* registry = nullptr;
    std::uint32_t pc = 0;
    unsigned dynamicDepth = 0;
    std::uint64_t dynamicCalls = 0;
    std::vector<DynamicCall> dynamicTrace;
    std::vector<TableTransfer> tableTrace;
    // Host device state used by HLE library entries (null = no device attached).
    cdhle::CdDrive* cd = nullptr;
    // Null (default) makes any executed SYSCALL a controlled fatal diagnostic.
    SyscallPolicy syscallPolicy = nullptr;
    // BIOS boundary policy and its host-side device state (both null = every BIOS call is fatal).
    BiosPolicy biosPolicy = nullptr;
    bios::Device* biosDevice = nullptr;
    // Optional per-instruction probe (see ProbeHook) and its host-side state.
    ProbeHook probe = nullptr;
    void* probeState = nullptr;
    // Phase 4 harness mechanism (probe units only): when set by the probe or by a BIOS policy call the generated loop continues at
    // redirectPc instead of the next sequential/return instruction. Used for interrupt entry and ReturnFromException only.
    bool redirectPending = false;
    std::uint32_t redirectPc = 0;
    // Sources are captured BEFORE this retirement, then current instruction
    // writes win. Loads schedule a new result for the next instruction.
    void retireLoad() {
        if(loadRegister) r[loadRegister]=loadValue;
        loadRegister=0;
    }
};
inline void dispatchSyscall(Context& c,std::uint32_t pc,std::uint32_t code) {
    if(!c.syscallPolicy) {
        std::ostringstream out;
        out<<"Guest SYSCALL at 0x"<<std::hex<<pc<<" (code 0x"<<code<<"): no SYSCALL policy installed";
        throw std::runtime_error(out.str());
    }
    c.syscallPolicy(c,pc,code);
}
// The compiler's divide-by-zero guard (`break 7`) reached at runtime. Never resumable: the unit stops with the guest PC
// and BREAK code in the diagnostic. Also usable as a typed exception by tests and harnesses.
struct GuestBreak : std::runtime_error {
    std::uint32_t pc, word, code, rawCode;
    GuestBreak(std::uint32_t atPc, std::uint32_t breakWord)
        : std::runtime_error(describe(atPc, breakWord)), pc(atPc), word(breakWord), code((breakWord >> 16) & 0x3ffU),
          rawCode((breakWord >> 6) & 0xfffffU) {}
    static std::string describe(std::uint32_t atPc, std::uint32_t breakWord) {
        std::ostringstream out;
        if(((breakWord>>16)&0x3ffU)==7U)
            out<<"Guest BREAK at 0x"<<std::hex<<atPc<<" (code 0x"<<((breakWord>>16)&0x3ffU)<<", word 0x"<<breakWord
               <<"): compiler divide-by-zero guard reached with a zero divisor; execution stopped";
        else
            out<<"Guest BREAK at 0x"<<std::hex<<atPc<<" (raw code 0x"<<((breakWord>>6)&0xfffffU)<<", word 0x"<<breakWord
               <<"): terminal trap of a non-returning root reached; execution stopped";
        return out.str();
    }
};
[[noreturn]] inline void dispatchBreak(Context&,std::uint32_t pc,std::uint32_t word) { throw GuestBreak(pc,word); }
inline void dispatchBios(Context& c,std::uint32_t site,std::uint32_t table,std::uint32_t function) {
    if(!c.biosPolicy) {
        std::ostringstream out;
        out<<"Guest BIOS call at 0x"<<std::hex<<site<<" (table 0x"<<table<<", function 0x"<<function<<"): no BIOS policy installed";
        throw std::runtime_error(out.str());
    }
    c.biosPolicy(c,site,table,function);
}
inline constexpr std::uint32_t counterEntry=0x8002f984U;
inline constexpr std::uint32_t counterLow=0x80010047U, counterHigh=0x8001013cU;
inline constexpr std::uint32_t hostReturn=0x00000080U;
void execute(Context&,std::uint32_t entry,std::uint64_t budget=100000);
}
