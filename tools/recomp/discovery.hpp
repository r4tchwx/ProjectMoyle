#pragma once
#include "generator.hpp"
#include "../../src/guarded_indirect.hpp"
#include "../../src/bios_table.hpp"
#include <deque>
#include <limits>
#include <tuple>

namespace recomp_tool {
struct Image {
    const std::vector<std::uint8_t>& bytes;
    std::uint32_t base, size;
    explicit Image(const std::vector<std::uint8_t>& b):bytes(b),base(0),size(0) {
        if(b.size()<0x800 || std::string(b.begin(),b.begin()+8)!="PS-X EXE") throw std::runtime_error("Not a PS-X EXE");
        base=word(b,0x18); size=word(b,0x1c);
        if((base&3)||(size&3)||!size||std::uint64_t(base)+size>0x100000000ULL||std::uint64_t(size)+0x800>b.size())
            throw std::runtime_error("Invalid/truncated EXE mapping");
    }
    bool contains(std::uint64_t pc) const {return !(pc&3)&&pc>=base&&pc+4<=std::uint64_t(base)+size;}
    std::uint32_t at(std::uint32_t pc) const {
        if(!contains(pc)) throw std::runtime_error("Address outside payload");
        return word(bytes,0x800+std::size_t(pc-base));
    }
    void range(Region r) const {
        if(!r.words||!contains(r.entry)||std::uint64_t(r.entry)+4ULL*r.words>std::uint64_t(base)+size)
            throw std::runtime_error("Invalid scan/seed range");
    }
};
struct Seed {std::uint32_t entry; std::string confidence; std::uint32_t words;};
// Phase 2C closure proofs. They are produced by tools/recomp/closure.hpp from the executable itself and are
// only consumed here: a proof applies to its exact site and register, nothing else is ever inferred.
// SwitchProof: a bounded static jump table (index bound + table words verified by the v2 matcher).
// CellProof: a call through a fixed guest cell (or one object field) whose static writers are all constants.
// A CellProof is a *guarded* static set: the runtime must still check captured target == live RAM cell and
// membership in `targets` (src/indirect_cells.hpp); it is not a claim that the cell is immutable.
struct SwitchProof {std::uint32_t site=0,rs=0,table=0,count=0,defaultTarget=0;std::vector<std::uint32_t> targets;
    std::uint32_t load=0; // load: the guest LW that fetches the table word (emission only; not part of the JSON)
    std::string evidence;}; // non-empty: the table extent was pinned by --table-host (HostTrap: the runtime table guard enforces the bound)
struct CellProof {std::uint32_t site=0,rs=0,cell=0,offset=0;bool field=false;std::uint32_t initial=0;
    std::vector<std::uint32_t> targets;std::vector<std::pair<std::uint32_t,std::uint32_t>> writers;
    // Phase 3: `empty` = no static writer and a null initial value, i.e. the proven target set is empty and any
    // non-null callback is fatal at runtime. `assumptions` lists what the closed-world claim leans on (escapes).
    bool empty=false;std::vector<std::string> assumptions;};
// SetProof (Phase 3): a call whose callback value is not a fixed cell but whose complete candidate set is proven from the
// executable: kind "param" (every in-unit caller passes a provable value) or "ring-registry" (one writer stores a
// provable value into an indexed callback array). The runtime guard is membership-only (validateTargetSet): the
// captured target must be one of `targets`; there is no live-cell comparison because the value is not in a fixed cell.
struct SetProof {std::uint32_t site=0,rs=0,function=0;std::string kind,origin;std::vector<std::uint32_t> targets;
    std::vector<std::string> assumptions;
    bool assumed=false;}; // true when a source set relied on an escape assumption (an object pointer leaked to a callee)
struct ClosureProofs {std::map<std::uint32_t,SwitchProof> switches;std::map<std::uint32_t,CellProof> cells;
    std::map<std::uint32_t,SetProof> sets;};
// Explicit discovery opt-in. extendedIsa teaches the structural CFG the Phase 2A EXE ISA
// (variable shifts, HI/LO ops, generic JR/JALR, SYSCALL). It is deliberately separate from
// the generator's gteEnabled switch: extended discovery never admits COP2/GTE words.
// closure (requires extendedIsa) additionally applies the proofs above and raises the analysis-bound word
// budget of derived entries to derivedWords (an analysis bound, not evidence; flow still stops at the next entry).
// `proofs` is borrowed and must outlive the call; null means no proofs. The type stays literal and default-off.
struct DiscoveryOptions {
    bool extendedIsa=false;
    bool closure=false;
    std::uint32_t derivedWords=256;
    const ClosureProofs* proofs=nullptr;
    // Phase 3 opt-ins (closure mode only; default off keeps every Phase 2C number):
    //  trapBreak: the exact compiler divide-by-zero idiom `divu; bne rt,zero,+2; nop; break 7` becomes a terminal trap.
    //  biosHle:   a BIOS function-table thunk whose (table, function) the runtime implements is a resolved boundary.
    bool trapBreak=false;
    bool biosHle=false;
    // Phase 4 (requires biosHle): the larger boot BIOS set of src/bios_table.hpp `bootTable` is also a resolved boundary.
    bool bootBios=false;
    // Phase 5 (requires bootBios): the libcard InitCARD call (src/bios_table.hpp cardTable) is also a resolved boundary.
    bool bootCard=false;
    // Phase 4 (requires extendedIsa): ADDI (signed overflow is a fatal guest exception) joins the decodable forms. Default off keeps
    // ADDI an unsupported form, exactly as in Phase 2B/2C/3.
    bool bootIsa=false;
    bool bootGte=false;
    // Phase 4: entries explicitly designated non-returning roots (the PS-X EXE startup stub and the program's main). Such an
    // extent needs no structural path to `jr ra`; every block must still stay inside the extent, and any BREAK in it is a
    // terminal fatal trap (never a fall-through). Default empty keeps every earlier result byte-identical.
    const std::set<std::uint32_t>* noReturn=nullptr;   // borrowed; null = none (keeps the type literal)
    // Opt-in (--halt-loops). An unconditional `j <itself>` whose delay slot is a NOP is a hang: the block has no successor other
    // than itself and can never fall through (the compiler's "assert(0); for(;;);" idiom). It is accepted as a structural exit of
    // the extent (like a fatal BREAK trap); the emitted code is the faithful infinite loop, which the harness bounds by its
    // instruction budget. It does not prove the function returns, only that this dead end does not fall through anywhere.
    bool haltLoops=false;
    // Opt-in (--dead-gap ENTRY BEGIN END): unreachable word runs inside a function's extent (dead compiler output, e.g. a `jr ra`
    // after an exhaustive switch). The declaration is verified: the set of declared words must equal the set of words the
    // discovery did not reach, exactly; any other gap keeps failing as "noncontiguous-body". Borrowed; null = none.
    const std::map<std::uint32_t,std::vector<std::pair<std::uint32_t,std::uint32_t>>>* deadGaps=nullptr;
    // Opt-in (--external-entry ENTRY EVIDENCE): a JAL whose encoded target is exactly one of these entries, outside the
    // payload, is a registry-dispatched call into another unit (the PAL type-2 overlay) instead of an unresolved
    // "direct-call-outside-payload" issue. Null/empty keeps every earlier result byte-identical.
    const std::map<std::uint32_t,std::string>* externalEntries=nullptr;
    // Opt-in (--shared-delay-slots). A direct non-link branch or J may target the delay-slot instruction of a *different*
    // direct non-link branch/J of the same function: that word then executes once as the owner's slot and, on the other
    // path, as an ordinary instruction falling through to slot+4. Everything else in a slot stays rejected (calls, table/
    // cell/set targets, entries, control/terminal/SYSCALL slots, a branch into its own slot). Default off keeps every
    // earlier result byte-identical.
    bool sharedDelaySlots=false;
};
struct Evidence {std::uint32_t site,target; bool operator<(const Evidence& b) const {return std::tie(site,target)<std::tie(b.site,b.target);}};
struct Issue {std::uint32_t site; std::string reason; bool operator<(const Issue& b) const {return std::tie(site,reason)<std::tie(b.site,b.reason);}};
// Structural decoder only: additional formats do not enable C++ emission.
inline Instruction decodeFlow(std::uint32_t pc, std::uint32_t w, bool extendedIsa=false, bool trapBreak=false, bool bootIsa=false, bool bootGte=false) {
    const auto op=w>>26, fn=w&63, sh=(w>>6)&31;
    // The one BREAK word the compiler emits for a divide-by-zero check. Idiom validation happens in discoverBody.
    if(trapBreak&&extendedIsa&&(w==0x0007000dU||(bootIsa&&w==0x0006000dU))){Instruction b{pc,w,0,0,w==0x0007000dU?"break 0x7":"break 0x6",""};b.terminal=true;return b;}
    // T5 enables emission in verified regions, not automatic qualification of
    // new COP2 paths. Keep the existing discovery census/provenance boundary.
    if((op==18||op==50||op==58)&&!bootGte)throw std::runtime_error("COP2 path requires explicit verification");
    Instruction i{pc,w,(w>>21)&31,(w>>16)&31,"",""};
    if(op==2) {
        i.control=i.direct=true;i.target=((pc+4)&0xf0000000U)|((w&0x3ffffffU)<<2);
        i.text="j";return i;
    }
    if(op==4||((op==6||op==7||op==1)&&i.rt==0)) {
        const auto u=w&65535;
        i.control=i.direct=true;i.target=pc+4+(u<32768?u:(u|0xffff0000U))*4U;
        i.text=op==4?"beq":op==6?"blez":op==7?"bgtz":"bltz";return i;
    }
    switch(op) {
    case 32:i.text="lb";break;
    case 33:i.text="lh";break;
    case 37:i.text="lhu";break;
    case 10:i.text="slti";break;
    case 11:i.text="sltiu";break;
    case 13:i.text="ori";break;
    case 14:i.text="xori";break;
    default:break;
    }
    if(!i.text.empty())return i;
    if(op==0&&sh==0) {
        switch(fn) {
        case 36:i.text="and";break;
        case 38:i.text="xor";break;
        case 39:i.text="nor";break;
        case 42:i.text="slt";break;
        default:break;
        }
        if(!i.text.empty())return i;
    }
    if(op==0&&i.rs==0&&fn==3) {i.text="sra";return i;}
    // Arguments are (extendedMemory, gteEnabled, extendedIsa). GTE stays explicitly off: the
    // COP2 guard above rejects those words before this fallback in every discovery mode.
    return decode(pc,w,true,bootGte,extendedIsa,bootIsa);
}
// Extended-ISA evidence. Only populated when DiscoveryOptions::extendedIsa is set.
struct RegisterSite {std::uint32_t site,rs,rd; bool operator<(const RegisterSite& b) const {return std::tie(site,rs,rd)<std::tie(b.site,b.rs,b.rd);}};
struct SyscallSite {std::uint32_t site,code; bool operator<(const SyscallSite& b) const {return std::tie(site,code)<std::tie(b.site,b.code);}};
// BIOS function-table thunk: JR/JALR through a register that is provably 0xA0/0xB0/0xC0.
// function is the $t1 call number when it is a proven constant after the delay slot, else -1.
struct BiosSite {std::uint32_t site,table; std::int32_t function; bool call;
    bool operator<(const BiosSite& b) const {return std::tie(site,table,function,call)<std::tie(b.site,b.table,b.function,b.call);}};
// Per-site classification (closure mode only); deterministic, ordered by site.
struct IndirectSiteReport {
    std::uint32_t site=0,function=0,rs=0,rd=0;bool jump=false;
    std::string kind,status,detail,reason;
    std::vector<std::uint32_t> targets;
    bool operator<(const IndirectSiteReport& b) const {return site<b.site;}
};
// External PS1 kernel knowledge (psx-spx / Psy-Q), NOT verified against repository code. Only the calls
// the PAL loader boundary needs are named; anything else stays anonymous.
// The (table, function) pairs src/bios_boundary.hpp implements. Anything else stays an explicit boundary.
inline bool biosHleSupported(std::uint32_t table,std::int32_t function,bool boot=false,bool card=false) {
    if(function<0)return false;
    if(boot)return moyle::detail::recomp::bios::findBootEntry(table,static_cast<std::uint32_t>(function),card)!=nullptr;
    return (table==0xb0U&&function==0x35)||(table==0xb0U&&function==0x5b)||(table==0xc0U&&function==0x0a);
}
inline const char* biosName(std::uint32_t table,std::int32_t function,bool boot=false,bool card=false) {
    if(function<0)return nullptr;
    if(boot){const auto* e=moyle::detail::recomp::bios::findBootEntry(table,static_cast<std::uint32_t>(function),card);return e?e->name:nullptr;}
    if(table==0xb0U&&function==0x35)return "write";
    if(table==0xb0U&&function==0x5b)return "ChangeClearPad";
    if(table==0xc0U&&function==0x0a)return "ChangeClearRCnt";
    return nullptr;
}
struct Function {
    Seed seed; bool resolved=false; std::uint64_t end=0;
    std::set<std::uint32_t> body, returns, delaySlots;
    std::set<Evidence> calls, jumps, tailJumps, unresolvedJumps;
    std::set<Issue> unresolved;
    std::map<std::uint32_t,moyle::detail::GuardedSlot> guarded;
    std::set<RegisterSite> indirectJumps, indirectCalls;
    std::set<SyscallSite> syscalls;
    std::set<BiosSite> biosCalls;
    std::map<std::uint32_t,std::string> unsupportedForms;
    std::map<std::uint32_t,SwitchProof> switchSites; // closure mode: proven bounded-table jumps
    std::map<std::uint32_t,CellProof> cellCalls;     // closure mode: proven guarded fixed-cell calls
    // Phase 3 (only populated by the matching DiscoveryOptions):
    std::map<std::uint32_t,SetProof> setCalls;       // membership-guarded callback sets
    std::map<std::uint32_t,std::uint32_t> breakTraps; // pc -> BREAK word (divide-by-zero guard idiom)
    std::set<std::uint32_t> haltLoops;               // pc of `j self` + NOP hangs accepted as terminal (DiscoveryOptions::haltLoops)
    std::map<std::uint32_t,BiosSite> biosHle;        // BIOS thunks the runtime implements (tail transfer = call + return)
    std::vector<std::pair<std::uint32_t,std::uint32_t>> gaps; // verified dead word runs [begin,end) inside the extent (--dead-gap)
    std::set<Evidence> externalCalls;                // JAL -> pinned external entry (DiscoveryOptions::externalEntries)
    std::set<std::uint32_t> sharedSlots;             // accepted shared delay slots (DiscoveryOptions::sharedDelaySlots)
};
struct Discovery {
    bool extendedIsa=false;
    bool closure=false;
    std::uint32_t derivedWords=256;
    unsigned closureRounds=0;
    bool trapBreak=false,biosHle=false,callbacks=false; // Phase 3 opt-ins that produced this result
    bool bootBios=false,bootIsa=false,bootCard=false,bootGte=false;    // Phase 4: boot BIOS set (src/bios_table.hpp bootTable), ADDI; Phase 5: InitCARD
    std::set<std::uint32_t> noReturn;                    // Phase 4: designated non-returning roots
    bool phase3() const {return closure&&(trapBreak||biosHle||callbacks||!noReturn.empty());}
    std::vector<IndirectSiteReport> indirectReport;
    std::uint32_t base,size;
    std::vector<Region> scans;
    std::set<Evidence> evidence;
    std::map<std::uint32_t,Function> functions;
};
inline bool controlWord(std::uint32_t w) {
    const auto op=w>>26;
    return op==1||op==2||op==3||(op>=4&&op<=7)||(op==0&&((w&63)==8||(w&63)==9));
}
inline std::string unsupported(std::uint32_t w,bool extendedIsa=false) {
    const auto op=w>>26;
    if(extendedIsa&&op==0){
        // With the extended ISA a JR/JALR/shift/HI-LO word only fails to decode when a reserved field is set.
        const auto fn=w&63;
        if(fn==8||fn==9)return "reserved-indirect-jump-encoding";
        if(fn==3||fn==4||fn==6||fn==7||fn==16||fn==18||fn==24||fn==25||fn==27)return "reserved-extended-isa-encoding";
    }
    if(op==0 && (w&63)==9) return "indirect-call-jalr";
    if(op==0 && (w&63)==8) return "indirect-jump-jr";
    if(op==18||op==50||op==58) return "cop2-gte";
    if(op>=16&&op<=19) return "coprocessor-control-or-operation";
    if(controlWord(w)) return "unsupported-branch";
    return "unsupported-or-reserved-instruction";
}
inline bool isLoadWord(std::uint32_t w) {const auto op=w>>26;return op>=32&&op<=38;}
// Operation class only (no operands) so remaining-blocker reports carry no game bytes.
inline std::string opcodeForm(std::uint32_t w) {
    const auto op=w>>26,rs=(w>>21)&31,rt=(w>>16)&31,fn=w&63;
    const auto h=[](std::uint32_t n){std::ostringstream o;o<<"0x"<<std::hex<<std::setfill('0')<<std::setw(2)<<n;return o.str();};
    std::string form="op="+h(op);
    if(op==0)form+=" funct="+h(fn);
    else if(op==1)form+=" rt="+h(rt);
    else if(op>=16&&op<=19){form+=" rs="+h(rs);if(rs>=16)form+=" funct="+h(fn);}
    return form;
}
// Abstract values describe the load provenance, not immutable RAM contents.
struct FlowValue {
    enum Kind { Unknown, Constant, Base, Target } kind=Unknown;
    std::uint32_t value=0;
    bool operator==(const FlowValue& b) const {return kind==b.kind&&value==b.value;}
};
struct FlowState {
    std::array<FlowValue,32> r{};
    std::array<FlowValue,32> pending{};
    std::array<bool,32> hasPending{};
};
// Abstract rs at a generic JR/JALR site, and $t1 after its delay slot (extended ISA only).
struct FlowSite {FlowValue target, t1;};
struct FlowResult {
    std::map<std::uint32_t,moyle::detail::GuardedSlot> guarded;
    std::map<std::uint32_t,FlowSite> sites;
};
inline bool signedDivideGuard(const Image& image,std::uint32_t pc,std::uint32_t entry) {
    const auto divRegs=[&](std::uint32_t at,std::uint32_t& dividend,std::uint32_t& divisor){
        if(at<entry||!image.contains(at))return false;
        const auto w=image.at(at);if((w&0xfc00ffffU)!=0x0000001aU)return false;
        dividend=(w>>21)&31U;divisor=(w>>16)&31U;return true;
    };
    if(image.at(pc)==0x0007000dU){
        if(pc<entry+12U)return false;std::uint32_t dividend=0,divisor=0;if(!divRegs(pc-12U,dividend,divisor))return false;
        return image.at(pc-8U)==(0x14000002U|(divisor<<21))&&image.at(pc-4U)==0U;
    }
    if(image.at(pc)==0x0006000dU){
        if(pc<entry+36U)return false;std::uint32_t dividend=0,divisor=0;if(!divRegs(pc-36U,dividend,divisor))return false;
        return image.at(pc-32U)==(0x14000002U|(divisor<<21))&&image.at(pc-28U)==0U&&image.at(pc-24U)==0x0007000dU&&image.at(pc-20U)==0x2401ffffU&&image.at(pc-16U)==(0x14010004U|(divisor<<21))&&image.at(pc-12U)==0x3c018000U&&image.at(pc-8U)==(0x14010002U|(dividend<<21))&&image.at(pc-4U)==0U;
    }
    return false;
}
inline FlowResult flowAnalysis(const Image& image,Seed seed,std::uint64_t ceiling,bool extendedIsa,bool trapBreak=false,bool bootIsa=false,bool bootGte=false) {
    using V=FlowValue;
    std::map<std::uint32_t,FlowState> states;
    std::deque<std::uint32_t> queue;
    auto valid=[&](std::uint64_t p){return p>=seed.entry&&p+4<=ceiling&&image.contains(p);};
    auto merge=[&](std::uint32_t pc,FlowState s){
        if(!valid(pc))return;
        s.r[0]={V::Constant,0};s.pending[0]={};s.hasPending[0]=false;
        auto inserted=states.emplace(pc,s);bool changed=inserted.second;
        if(!inserted.second)for(unsigned n=0;n<32;++n){
            auto join=[&](V& a,V b){if(!(a==b)&&a.kind!=V::Unknown){a={};changed=true;}};
            auto& old=inserted.first->second;
            join(old.r[n],s.r[n]);
            if(old.hasPending[n]!=s.hasPending[n]){
                if(!old.hasPending[n]||old.pending[n].kind!=V::Unknown)changed=true;
                old.hasPending[n]=true;old.pending[n]={};
            }else join(old.pending[n],s.pending[n]);
        }
        if(changed)queue.push_back(pc);
    };
    // Sources precede retirement; current writes win over the preceding load.
    auto step=[&](FlowState& s,std::uint32_t w){
        const auto op=w>>26,rs=(w>>21)&31,rt=(w>>16)&31,rd=(w>>11)&31;
        const auto a=s.r[rs],b=s.r[rt];
        if(op==0&&(w&63)==12){ // SYSCALL: the policy/handler may rewrite any register.
            for(unsigned n=1;n<32;++n)s.r[n]={};
            s.pending={};s.hasPending={};return;
        }
        for(unsigned n=1;n<32;++n)if(s.hasPending[n])s.r[n]=s.pending[n];
        s.pending={};s.hasPending={};
        const auto u=w&65535,imm=u<32768?u:u|0xffff0000U;
        V result;unsigned dest=0;
        if(op==15){dest=rt;result={V::Constant,u<<16};}
        else if(op==9||op==13){dest=rt;if(a.kind==V::Constant)result={V::Constant,op==9?a.value+imm:a.value|u};}
        else if(op==35){
            dest=rt;
            if(a.kind==V::Constant&&a.value+imm==moyle::detail::libgpuSlots[0].baseGlobal)
                result={V::Base,moyle::detail::libgpuSlots[0].expectedBase};
            else if(a.kind==V::Base)for(unsigned n=0;n<moyle::detail::libgpuSlots.size();++n)
                if(imm==moyle::detail::libgpuSlots[n].offset)result={V::Target,n};
            s.pending[dest]=result;s.hasPending[dest]=true;dest=0;
        } else if(op==32||op==33||op==36||op==37){
            s.pending[rt]={};s.hasPending[rt]=true;
        } else if(op==0){
            dest=rd;
            if(((w&63)==33||(w&63)==37)&&b.kind==V::Constant&&b.value==0)result=a;
            else if(((w&63)==33||(w&63)==37)&&a.kind==V::Constant&&a.value==0)result=b;
        } else if(op>=40&&op<=43) { /* stores do not change registers */ }
        else dest=rt; // All other supported data operations lose provenance.
        if(dest)s.r[dest]=result;
        s.r[0]={V::Constant,0};s.pending[0]={};s.hasPending[0]=false;
    };
    merge(seed.entry,{});
    while(!queue.empty()){
        const auto pc=queue.front();queue.pop_front();auto s=states.at(pc);
        const auto w=image.at(pc),op=w>>26;
        const bool jalr=(w&0xfc1fffffU)==0x0000f809U;
        const bool genericJalr=extendedIsa&&op==0&&(w&63)==9;
        Instruction i;
        try{if(!jalr)i=decodeFlow(pc,w,extendedIsa,trapBreak,bootIsa,bootGte);}catch(const std::runtime_error&){continue;}
        if(!jalr&&!i.control){step(s,w);if(!i.terminal)merge(pc+4,s);continue;}
        if(!valid(std::uint64_t(pc)+4))continue;
        const auto slot=image.at(pc+4);
        try{const auto si=decodeFlow(pc+4,slot,extendedIsa,trapBreak,bootIsa,bootGte);if(si.control||si.syscall||si.terminal)continue;}catch(const std::runtime_error&){continue;}
        // Control instructions retire the preceding load before their slot.
        for(unsigned n=1;n<32;++n)if(s.hasPending[n])s.r[n]=s.pending[n];
        s.pending={};s.hasPending={};
        if(jalr||op==3)s.r[31]={V::Constant,pc+8};
        step(s,slot);
        if(jalr||op==3||(genericJalr&&((w>>11)&31)!=0)){merge(pc+8,{});continue;} // no ABI preservation assumption
        if(w==0x03e00008U)continue;
        if(extendedIsa&&op==0&&((w&63)==8||genericJalr))continue; // generic JR / JALR rd=0: target unknown
        merge(i.target,s);
        if(op!=2)merge(pc+8,s);
    }
    FlowResult flow;
    auto& result=flow.guarded;
    if(extendedIsa)for(const auto& p:states){
        const auto w=image.at(p.first);
        if((w>>26)!=0||((w&63)!=8&&(w&63)!=9))continue;
        if(!valid(std::uint64_t(p.first)+4))continue;
        try{
            decodeFlow(p.first,w,true,trapBreak,bootIsa,bootGte);
            const auto slot=image.at(p.first+4);
            const auto si=decodeFlow(p.first+4,slot,true,trapBreak,bootIsa,bootGte);
            if(si.control||si.syscall||si.terminal)continue;
            auto s=p.second;FlowSite site;site.target=s.r[(w>>21)&31];
            for(unsigned n=1;n<32;++n)if(s.hasPending[n])s.r[n]=s.pending[n];
            s.pending={};s.hasPending={};
            step(s,slot);
            site.t1=s.hasPending[9]?FlowValue{}:s.r[9];
            flow.sites.emplace(p.first,site);
        }catch(const std::runtime_error&){}
    }
    for(const auto& p:states){
        const auto w=image.at(p.first);
        if((w&0xfc1fffffU)!=0x0000f809U)continue;
        const auto source=p.second.r[(w>>21)&31];
        if(source.kind!=V::Target)continue;
        const auto& slot=moyle::detail::libgpuSlots[source.value];
        if(image.contains(slot.baseGlobal)&&image.contains(slot.address())&&image.contains(slot.expectedTarget)&&
           image.at(slot.baseGlobal)==slot.expectedBase&&image.at(slot.address())==slot.expectedTarget)
            result.emplace(p.first,slot);
    }
    return flow;
}
inline std::map<std::uint32_t,moyle::detail::GuardedSlot> guardedProvenance(
    const Image& image,Seed seed,std::uint64_t ceiling) {
    return flowAnalysis(image,seed,ceiling,false).guarded;
}
// Exact GCC divide-by-zero guard: `divu rs,rt ; bne rt,zero,pc+4 ; nop ; break 7`. The BREAK is the first word that is
// only reached when the divisor is zero. Nothing else is a trap: any other BREAK word or shape stays unsupported.
inline bool divideByZeroGuard(const Image& image,std::uint32_t pc,std::uint32_t entry) {
    if(pc<entry+12U||!image.contains(pc-12U)||image.at(pc)!=0x0007000dU)return false;
    const auto divu=image.at(pc-12U),bne=image.at(pc-8U),slot=image.at(pc-4U);
    if((divu&0xfc00ffffU)!=0x0000001bU)return false;                       // divu rs,rt (rd=0, sa=0)
    const auto divisor=(divu>>16)&31U;
    if(!divisor||slot!=0U)return false;                                      // nop in the branch slot
    // bne divisor,zero,+2 words: taken target is pc+4 (the word after the break)
    return (bne>>26)==5U&&((bne>>21)&31U)==divisor&&((bne>>16)&31U)==0U&&(bne&0xffffU)==2U;
}
inline Function discoverBody(const Image& image,Seed seed,const std::map<std::uint32_t,Seed>& entries,const DiscoveryOptions& options) {
    const bool extendedIsa=options.extendedIsa;
    Function f; f.seed=seed;
    std::uint64_t ceiling=std::min(std::uint64_t(image.base)+image.size,std::uint64_t(seed.entry)+4ULL*seed.words);
    const auto next=entries.upper_bound(seed.entry);
    if(next!=entries.end()) ceiling=std::min(ceiling,std::uint64_t(next->first));
    const auto flow=flowAnalysis(image,seed,ceiling,extendedIsa,options.trapBreak,options.bootIsa,options.bootGte);
    const auto& guarded=flow.guarded;
    std::deque<std::uint32_t> queue{seed.entry};
    std::set<std::uint32_t> starts,slots,sharedCandidates;
    std::map<std::uint32_t,std::set<std::uint32_t>> successors;
    const auto issue=[&](std::uint32_t pc,const std::string& why){f.unresolved.insert({pc,why});};
    const bool noReturnRoot=(options.noReturn&&options.noReturn->count(seed.entry)!=0);
    const auto valid=[&](std::uint64_t pc){return image.contains(pc)&&pc>=seed.entry&&pc+4<=ceiling;};
    while(!queue.empty()) {
        const auto pc=queue.front();queue.pop_front();
        if(!valid(pc)){issue(pc,"flow-crosses-entry-or-analysis-bound");continue;}
        if(!starts.insert(pc).second)continue;
        if(slots.count(pc)){
            if(!options.sharedDelaySlots){issue(pc,"flow-enters-delay-slot");continue;}
            sharedCandidates.insert(pc); // validated after the walk; the word is processed as an ordinary instruction
        }
        f.body.insert(pc);
        const auto w=image.at(pc);
        Instruction i;
        try{
            if(guarded.count(pc)){i={pc,w,(w>>21)&31,0,"jalr guarded",""};i.control=true;}
            else if(noReturnRoot&&extendedIsa&&(w&0xfc00003fU)==0x0000000dU){i={pc,w,0,0,"break (non-returning root)",""};i.terminal=true;}
            else i=decodeFlow(pc,w,extendedIsa,options.trapBreak,options.bootIsa,options.bootGte);
        }catch(const std::runtime_error&){
            issue(pc,unsupported(w,extendedIsa));
            if(extendedIsa)f.unsupportedForms[pc]=opcodeForm(w);
            continue;
        }
        auto enqueue=[&](std::uint64_t dest){
            if(dest>0xffffffffULL||!valid(dest)){issue(pc,"flow-crosses-entry-or-analysis-bound");return;}
            const auto target=static_cast<std::uint32_t>(dest);
            successors[pc].insert(target);queue.push_back(target);
        };
        if(!i.control){
            // SYSCALL falls through to PC+4; it is recorded as a policy/HLE boundary, not a CFG edge.
            if(i.syscall)f.syscalls.insert({pc,(w>>6)&0xfffffU});
            if(i.terminal){
                // Only the exact compiler divide-by-zero guard is accepted; any other BREAK stays unsupported.
                if(noReturnRoot||divideByZeroGuard(image,pc,seed.entry)||(options.bootIsa&&signedDivideGuard(image,pc,seed.entry)))f.breakTraps.emplace(pc,w);
                else{issue(pc,unsupported(w,extendedIsa));f.unsupportedForms[pc]=opcodeForm(w);}
                continue;
            }
            enqueue(std::uint64_t(pc)+4);continue;
        }
        if(image.contains(std::uint64_t(pc)+4))f.delaySlots.insert(pc+4);
        if(!valid(std::uint64_t(pc)+4)){issue(pc,"missing-delay-slot");continue;}
        const auto slot=pc+4;
        slots.insert(slot);f.delaySlots.insert(slot);f.body.insert(slot);
        if(entries.count(slot)||(starts.count(slot)&&!options.sharedDelaySlots)){issue(slot,"entry-or-flow-in-delay-slot");continue;}
        if(starts.count(slot))sharedCandidates.insert(slot); // validated after the walk
        bool safeSlot=true;
        try{
            const auto slotInstruction=decodeFlow(slot,image.at(slot),extendedIsa,options.trapBreak,options.bootIsa,options.bootGte);
            if(slotInstruction.control||slotInstruction.terminal)safeSlot=false;
            else if(slotInstruction.syscall){issue(slot,"syscall-in-delay-slot");continue;}
        }catch(const std::runtime_error&){safeSlot=false;}
        if(!safeSlot){issue(slot,"unsupported-or-control-delay-slot");continue;}
        if(guarded.count(pc)) {
            f.guarded.emplace(pc,guarded.at(pc));enqueue(std::uint64_t(pc)+8);
        } else if((w>>26)==3) {
            if(!image.contains(i.target)){
                if(options.externalEntries&&options.externalEntries->count(i.target))f.externalCalls.insert({pc,i.target});
                else issue(pc,"direct-call-outside-payload-overlay-or-external");
            }
            else if(i.target==slot)issue(pc,"call-target-in-delay-slot");
            else f.calls.insert({pc,i.target});
            enqueue(std::uint64_t(pc)+8); // Structural extent assumes normal call return.
        } else if((w>>26)==2) {
            if(!image.contains(i.target)){f.unresolvedJumps.insert({pc,i.target});issue(pc,"direct-jump-outside-payload-overlay-or-external");}
            else if(i.target!=seed.entry&&entries.count(i.target)) {
                f.tailJumps.insert({pc,i.target});
            } else if(valid(i.target)) {
                if(options.haltLoops&&i.target==pc&&image.at(slot)==0U)f.haltLoops.insert(pc);
                f.jumps.insert({pc,i.target});enqueue(i.target);
            } else {f.unresolvedJumps.insert({pc,i.target});issue(pc,"direct-jump-unknown-entry-or-analysis-bound");}
        } else if(w==0x03e00008U) f.returns.insert(pc);
        else if(extendedIsa&&(w>>26)==0&&((w&63)==8||(w&63)==9)) {
            // Generic JR/JALR: the target is a register, so no successor is invented for it.
            const std::uint32_t rs=(w>>21)&31,rd=(w>>11)&31;
            const bool call=(w&63)==9&&rd!=0; // JALR rd=0 discards the link: a jump, not a call
            const auto site=flow.sites.find(pc);
            const bool bios=site!=flow.sites.end()&&site->second.target.kind==FlowValue::Constant&&
                (site->second.target.value==0xa0U||site->second.target.value==0xb0U||site->second.target.value==0xc0U);
            const SwitchProof* switchProof=nullptr;const CellProof* cellProof=nullptr;const SetProof* setProof=nullptr;
            if(options.closure&&options.proofs) {
                const auto s=options.proofs->switches.find(pc);if(s!=options.proofs->switches.end())switchProof=&s->second;
                const auto c=options.proofs->cells.find(pc);if(c!=options.proofs->cells.end())cellProof=&c->second;
                const auto t=options.proofs->sets.find(pc);if(t!=options.proofs->sets.end())setProof=&t->second;
            }
            const bool switchOk=!call&&(w&63)==8&&switchProof&&switchProof->rs==rs&&!isLoadWord(image.at(slot));
            const bool cellOk=call&&(w&63)==9&&rd==31&&cellProof&&cellProof->rs==rs;
            const bool setOk=call&&(w&63)==9&&rd==31&&setProof&&setProof->rs==rs;
            if(!bios&&switchOk) {
                // Bounded table verified by the v2 matcher: successors are exactly its (already validated) words.
                f.switchSites.emplace(pc,*switchProof);
                for(auto target:switchProof->targets)enqueue(target);
            } else if(!bios&&cellOk) {
                f.cellCalls.emplace(pc,*cellProof); // normal call return; targets become entries in discover()
            } else if(!bios&&setOk) {
                f.setCalls.emplace(pc,*setProof);   // membership-guarded callback set; targets become entries too
            } else if(bios) {
                // Fixed PS1 kernel function-table vectors; the call number is whatever $t1 provably holds.
                const auto& t1=site->second.t1;
                const BiosSite bs{pc,site->second.target.value,t1.kind==FlowValue::Constant?std::int32_t(t1.value&0x7fffffffU):-1,call};
                f.biosCalls.insert(bs);
                // A tail transfer into a kernel function the runtime implements is a resolved boundary: the kernel
                // routine returns to this function's caller, exactly like `jr ra`. Everything else stays a boundary.
                if(options.biosHle&&!call&&bs.function>=0&&biosHleSupported(bs.table,bs.function,options.bootBios,options.bootCard)&&!isLoadWord(image.at(slot)))
                    f.biosHle.emplace(pc,bs);
                else issue(pc,"bios-call-boundary");
            } else if(call) {
                f.indirectCalls.insert({pc,rs,rd});issue(pc,"indirect-call-jalr");
            } else {
                f.indirectJumps.insert({pc,rs,rd});issue(pc,(w&63)==9?"indirect-jump-jalr":"indirect-jump-jr");
            }
            // The generator rejects a load in a JR delay slot (JALR allows it), so say so up front.
            if(!call&&isLoadWord(image.at(slot)))issue(slot,"load-in-indirect-jump-delay-slot");
            if(call)enqueue(std::uint64_t(pc)+8); // normal call return, as for JAL
        }
        else {enqueue(i.target);enqueue(std::uint64_t(pc)+8);}
    }
    // Every block needs a structural exit: return or transfer to a known entry.
    // This does not prove the callee returns, terminates or preserves the ABI.
    auto reachesReturn=f.returns;
    for(auto e:f.tailJumps)reachesReturn.insert(e.site);
    for(const auto& e:f.biosHle)reachesReturn.insert(e.first);   // kernel routine returns to our caller
    for(const auto& e:f.breakTraps)reachesReturn.insert(e.first); // fatal trap: no successor, never falls through
    for(auto pc:f.haltLoops)reachesReturn.insert(pc);             // `j self` + NOP: a hang, never falls through
    bool changed=true;
    while(changed){changed=false;for(const auto& edge:successors)for(auto dest:edge.second)
        if(reachesReturn.count(dest)&&reachesReturn.insert(edge.first).second)changed=true;}
    if(!noReturnRoot&&reachesReturn.size()!=starts.size())issue(seed.entry,"no-proven-path-to-return");
    // Shared delay slots (opt-in): the owner and every flow edge into the word must be direct non-link branches/J of this
    // function, no edge may come from the owner itself, and the word must be a safe ordinary instruction with slot+4 in
    // the walk. Anything else keeps the slot conflict as an issue.
    for(auto s:sharedCandidates){
        const auto directFlow=[&](std::uint32_t at){
            const auto w=image.at(at),op=w>>26,rt=(w>>16)&31;
            return op==2||(op>=4&&op<=7)||(op==1&&rt!=0x10&&rt!=0x11);
        };
        std::string why;
        if(entries.count(s))why="entry";
        else if(!slots.count(s)||!starts.count(s)||!directFlow(s-4))why="owner is not a direct non-link branch or J";
        else if(!starts.count(s+4))why="no ordinary fallthrough to slot+4";
        else{
            try{const auto si=decodeFlow(s,image.at(s),extendedIsa,options.trapBreak,options.bootIsa,options.bootGte);
                if(si.control||si.terminal||si.syscall)why="control, terminal or SYSCALL slot";}
            catch(const std::runtime_error&){why="unsupported slot instruction";}
            for(const auto& edge:successors){
                if(!edge.second.count(s)||!why.empty())continue;
                if(edge.first==s-4)why="branch into its own delay slot";
                else if(!directFlow(edge.first))why="edge from "+hex(edge.first)+" is not a direct non-link branch or J";
            }
        }
        if(why.empty())f.sharedSlots.insert(s);else issue(s,"shared-delay-slot-rejected ("+why+")");
    }
    if(!f.body.empty()) {
        const auto end=std::uint64_t(*f.body.rbegin())+4;
        if((end-seed.entry)/4!=f.body.size()){
            bool verified=false;
            if(options.deadGaps){
                const auto declaredRuns=options.deadGaps->find(seed.entry);
                if(declaredRuns!=options.deadGaps->end()){
                    std::set<std::uint64_t> declared,unvisited;
                    for(const auto& g:declaredRuns->second)for(std::uint64_t a=g.first;a<g.second;a+=4)declared.insert(a);
                    for(std::uint64_t a=seed.entry;a<end;a+=4)if(!f.body.count(static_cast<std::uint32_t>(a)))unvisited.insert(a);
                    if(declared==unvisited){f.gaps=declaredRuns->second;std::sort(f.gaps.begin(),f.gaps.end());verified=true;}
                }
            }
            if(!verified)issue(seed.entry,"noncontiguous-body");
        }
        if(f.unresolved.empty()&&(!f.returns.empty()||!f.tailJumps.empty()||!f.biosHle.empty()||noReturnRoot)){f.resolved=true;f.end=end;}
    }
    return f;
}
inline Function discoverBody(const Image& image,Seed seed,const std::map<std::uint32_t,Seed>& entries,bool extendedIsa=false) {
    DiscoveryOptions options;options.extendedIsa=extendedIsa;
    return discoverBody(image,seed,entries,options);
}
inline Discovery discover(const std::vector<std::uint8_t>& bytes,const std::vector<Seed>& seeds,std::vector<Region> scans,
                          DiscoveryOptions options={}) {
    const Image image(bytes);
    if(seeds.empty())throw std::runtime_error("At least one manifest seed required");
    Discovery d;d.base=image.base;d.size=image.size;d.extendedIsa=options.extendedIsa;
    d.closure=options.extendedIsa&&options.closure;d.derivedWords=options.derivedWords;
    d.bootBios=d.closure&&options.bootBios;d.bootIsa=d.closure&&options.bootIsa;d.bootGte=d.closure&&options.bootGte;d.bootCard=d.closure&&options.bootBios&&options.bootCard;
    d.noReturn=(d.closure&&options.noReturn)?*options.noReturn:std::set<std::uint32_t>();
    d.trapBreak=d.closure&&options.trapBreak;d.biosHle=d.closure&&options.biosHle;d.callbacks=d.closure&&options.proofs&&!options.proofs->sets.empty();
    if(!options.derivedWords)throw std::runtime_error("Invalid derived word budget");
    std::map<std::uint32_t,Seed> entries;
    for(auto seed:seeds){
        image.range({seed.entry,seed.words});
        if(seed.confidence!="confirmed"&&seed.confidence!="tentative"&&seed.confidence!="unknown"&&seed.confidence!="derived")throw std::runtime_error("Invalid seed confidence");
        if(!entries.emplace(seed.entry,seed).second)throw std::runtime_error("Duplicate seed");
    }
    std::sort(scans.begin(),scans.end(),[](Region a,Region b){return std::tie(a.entry,a.words)<std::tie(b.entry,b.words);});
    d.scans=scans;
    for(auto r:scans){image.range(r);for(std::uint32_t n=0;n<r.words;++n){
        const auto pc=r.entry+n*4,w=image.at(pc);
        if((w>>26)!=3)continue;
        const auto target=decode(pc,w).target;
        // Linear scan evidence is kept separate from reachable caller edges.
        if(image.contains(target))d.evidence.insert({pc,target});
    }}
    auto derive=[&](Evidence e){
        d.evidence.insert(e);
        const auto remaining=(std::uint64_t(image.base)+image.size-e.target)/4;
        return entries.emplace(e.target,Seed{e.target,"derived",static_cast<std::uint32_t>(std::min<std::uint64_t>(remaining,options.derivedWords))}).second;
    };
    // Raw scan matches are evidence only; never promote unreachable data into entries.
    bool changed=true;
    while(changed){
        changed=false;d.functions.clear();
        for(const auto& entry:entries)d.functions.emplace(entry.first,discoverBody(image,entry.second,entries,options));
        std::set<std::uint32_t> knownSlots;
        for(const auto& pair:d.functions)knownSlots.insert(pair.second.delaySlots.begin(),pair.second.delaySlots.end());
        for(const auto& pair:d.functions)for(auto e:pair.second.calls)
            if(!knownSlots.count(pair.first)&&!knownSlots.count(e.site)&&!knownSlots.count(e.target)&&derive(e))changed=true;
        for(const auto& pair:d.functions)for(const auto& e:pair.second.guarded){
            if(knownSlots.count(pair.first)||knownSlots.count(e.first)||knownSlots.count(e.second.expectedTarget))continue;
            const auto target=e.second.expectedTarget;
            const auto remaining=(std::uint64_t(image.base)+image.size-target)/4;
            if(entries.emplace(target,Seed{target,"derived",static_cast<std::uint32_t>(std::min<std::uint64_t>(remaining,options.derivedWords))}).second)changed=true;
        }
        // Proven callback sets (Phase 3): same rule as the fixed-cell calls.
        for(const auto& pair:d.functions)for(const auto& e:pair.second.setCalls){
            if(knownSlots.count(pair.first)||knownSlots.count(e.first))continue;
            for(auto target:e.second.targets){
                if(knownSlots.count(target)||!image.contains(target))continue;
                const auto remaining=(std::uint64_t(image.base)+image.size-target)/4;
                if(entries.emplace(target,Seed{target,"derived",static_cast<std::uint32_t>(std::min<std::uint64_t>(remaining,options.derivedWords))}).second)changed=true;
            }
        }
        // Proven fixed-cell calls: every non-null proven target is a certified-by-proof entry candidate.
        for(const auto& pair:d.functions)for(const auto& e:pair.second.cellCalls){
            if(knownSlots.count(pair.first)||knownSlots.count(e.first))continue;
            for(auto target:e.second.targets){
                if(knownSlots.count(target)||!image.contains(target))continue;
                const auto remaining=(std::uint64_t(image.base)+image.size-target)/4;
                if(entries.emplace(target,Seed{target,"derived",static_cast<std::uint32_t>(std::min<std::uint64_t>(remaining,options.derivedWords))}).second)changed=true;
            }
        }
    }
    // Entry discovery is monotonic; re-analysis above applies all new boundaries.
    std::map<std::uint32_t,std::uint32_t> owners;
    std::set<std::uint32_t> allSlots;
    for(const auto& pair:d.functions)allSlots.insert(pair.second.delaySlots.begin(),pair.second.delaySlots.end());
    for(auto& pair:d.functions){
        auto& f=pair.second;
        for(auto it=f.tailJumps.begin();it!=f.tailJumps.end();) {
            if(allSlots.count(it->target)){f.unresolved.insert({it->site,"jump-target-in-delay-slot"});f.unresolvedJumps.insert(*it);it=f.tailJumps.erase(it);}
            else ++it;
        }
        if(allSlots.count(pair.first))f.unresolved.insert({pair.first,"entry-in-another-function-delay-slot"});
        if(d.extendedIsa) {
            for(auto e:f.syscalls)if(allSlots.count(e.site))f.unresolved.insert({e.site,"syscall-in-delay-slot"});
            for(auto e:f.indirectCalls)if(allSlots.count(e.site))f.unresolved.insert({e.site,"indirect-site-in-delay-slot"});
            for(auto e:f.indirectJumps)if(allSlots.count(e.site))f.unresolved.insert({e.site,"indirect-site-in-delay-slot"});
            for(auto e:f.biosCalls)if(allSlots.count(e.site))f.unresolved.insert({e.site,"indirect-site-in-delay-slot"});
        }
        for(auto it=f.cellCalls.begin();it!=f.cellCalls.end();){
            bool bad=allSlots.count(it->first)||allSlots.count(pair.first);
            for(auto target:it->second.targets)if(allSlots.count(target))bad=true;
            if(bad){f.unresolved.insert({it->first,"cell-call-source-or-target-in-delay-slot"});it=f.cellCalls.erase(it);}
            else ++it;
        }
        for(auto it=f.setCalls.begin();it!=f.setCalls.end();){
            bool bad=allSlots.count(it->first)||allSlots.count(pair.first);
            for(auto target:it->second.targets)if(allSlots.count(target))bad=true;
            if(bad){f.unresolved.insert({it->first,"set-call-source-or-target-in-delay-slot"});it=f.setCalls.erase(it);}
            else ++it;
        }
        for(auto it=f.biosHle.begin();it!=f.biosHle.end();){
            if(allSlots.count(it->first)||allSlots.count(pair.first)){f.unresolved.insert({it->first,"bios-site-or-entry-in-delay-slot"});it=f.biosHle.erase(it);}
            else ++it;
        }
        for(auto it=f.breakTraps.begin();it!=f.breakTraps.end();){
            if(allSlots.count(it->first)){f.unresolved.insert({it->first,"break-in-delay-slot"});it=f.breakTraps.erase(it);}
            else ++it;
        }
        for(auto it=f.switchSites.begin();it!=f.switchSites.end();){
            bool bad=allSlots.count(it->first)||allSlots.count(pair.first);
            for(auto target:it->second.targets)if(allSlots.count(target))bad=true;
            if(bad){f.unresolved.insert({it->first,"switch-site-or-target-in-delay-slot"});it=f.switchSites.erase(it);}
            else ++it;
        }
        for(auto it=f.guarded.begin();it!=f.guarded.end();){
            if(allSlots.count(it->second.expectedTarget)||allSlots.count(it->first)||allSlots.count(pair.first)){
                f.unresolved.insert({it->first,"guarded-call-source-or-target-in-delay-slot"});it=f.guarded.erase(it);
            }else ++it;
        }
        for(auto it=f.calls.begin();it!=f.calls.end();){
            if(allSlots.count(it->target)||allSlots.count(it->site)||allSlots.count(pair.first)){f.unresolved.insert({it->site,"call-source-or-target-in-delay-slot"});it=f.calls.erase(it);}
            else ++it;
        }
        if(!f.unresolved.empty()){f.resolved=false;f.end=0;}
    }
    for(auto& pair:d.functions)for(auto pc:pair.second.body){
        auto result=owners.emplace(pc,pair.first);
        if(!result.second){
            auto& other=d.functions.at(result.first->second);
            pair.second.unresolved.insert({pc,"overlapping-function-body"});other.unresolved.insert({pc,"overlapping-function-body"});
            pair.second.resolved=other.resolved=false;pair.second.end=other.end=0;
        }
    }
    return d;
}
inline std::string noReturnJson(const Discovery& d) {
    if(d.noReturn.empty())return std::string();
    std::string s=", \"no_return_roots\": [";bool first=true;
    for(auto e:d.noReturn){if(!first)s+=", ";first=false;s+="\""+hex(e)+"\"";}
    return s+"]";
}
inline std::string discoveryJson(const Discovery& d) {
    std::ostringstream o;
    o<<"{\n  \"schema\": "<<(d.closure?5:d.extendedIsa?4:3)<<",\n"<<(d.extendedIsa?"  \"extended_isa\": true,\n":"")<<(d.closure?"  \"closure\": true,\n":"")
     <<(d.phase3()?std::string("  \"phase3\": {\"trap_break\": ")+(d.trapBreak?"true":"false")+", \"bios_hle\": "+(d.biosHle?"true":"false")+", \"callbacks\": "+(d.callbacks?"true":"false")+noReturnJson(d)+"},\n":std::string())
     <<"  \"load_address\": \""<<hex(d.base)<<"\",\n  \"payload_bytes\": "<<d.size<<",\n  \"scan_ranges\": [";
    bool first=true;for(auto r:d.scans){if(!first)o<<",";first=false;o<<"{\"entry\":\""<<hex(r.entry)<<"\",\"words\":"<<r.words<<"}";}
    o<<"],\n  \"jal_evidence\": [";first=true;
    for(auto e:d.evidence){if(!first)o<<",";first=false;o<<"{\"site\":\""<<hex(e.site)<<"\",\"target\":\""<<hex(e.target)<<"\"}";}
    o<<"],\n  \"functions\": [\n";first=true;
    for(const auto& pair:d.functions){const auto& f=pair.second;if(!first)o<<",\n";first=false;
        o<<"    {\"entry\":\""<<hex(pair.first)<<"\",\"confidence\":\""<<f.seed.confidence<<"\",\"status\":\""<<(f.resolved?"resolved":"unresolved")<<"\",\"end_exclusive\":";
        if(f.resolved)o<<f.end;else o<<"null";
        o<<",\"visited_words\":"<<f.body.size();
        if(!f.gaps.empty()){o<<",\"dead_gaps\":[";for(std::size_t n=0;n<f.gaps.size();++n)o<<(n?",":"")<<"[\""<<hex(f.gaps[n].first)<<"\",\""<<hex(f.gaps[n].second)<<"\"]";o<<"]";}
        if(!f.externalCalls.empty()){o<<",\"external_calls\":[";bool c2=false;
            for(auto e:f.externalCalls){if(c2)o<<",";c2=true;o<<"{\"site\":\""<<hex(e.site)<<"\",\"entry\":\""<<hex(e.target)<<"\"}";}o<<"]";}
        if(!f.sharedSlots.empty()){o<<",\"shared_delay_slots\":[";bool c3=false;
            for(auto s:f.sharedSlots){if(c3)o<<",";c3=true;o<<"\""<<hex(s)<<"\"";}o<<"]";}
        o<<",\"direct_calls\":[";bool comma=false;
        for(auto e:f.calls){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(e.site)<<"\",\"callee\":\""<<hex(e.target)<<"\"}";}
        o<<"],\"direct_jumps\":[";comma=false;
        for(auto e:f.jumps){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(e.site)<<"\",\"target\":\""<<hex(e.target)<<"\",\"kind\":\"internal\"}";}
        for(auto e:f.tailJumps){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(e.site)<<"\",\"target\":\""<<hex(e.target)<<"\",\"kind\":\"other-entrypoint\"}";}
        for(auto e:f.unresolvedJumps){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(e.site)<<"\",\"target\":\""<<hex(e.target)<<"\",\"kind\":\"unresolved\"}";}
        o<<"],\"guarded_indirect_calls\":[";comma=false;
        for(const auto& e:f.guarded){if(comma)o<<",";comma=true;const auto& s=e.second;
            o<<"{\"kind\":\"resolved-indirect-guarded\",\"jalr_site\":\""<<hex(e.first)
             <<"\",\"base_global\":\""<<hex(s.baseGlobal)<<"\",\"expected_base\":\""<<hex(s.expectedBase)
             <<"\",\"slot_address\":\""<<hex(s.address())<<"\",\"slot_offset\":\""<<hex(s.offset)
             <<"\",\"expected_target\":\""<<hex(s.expectedTarget)<<"\",\"confidence\":\""<<moyle::detail::guardedConfidence
             <<"\",\"provenance\":\""<<moyle::detail::guardedProvenance<<"\"}";
        }
        o<<"]";
        if(d.extendedIsa) {
            o<<",\"syscalls\":[";comma=false;
            for(auto e:f.syscalls){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(e.site)<<"\",\"code\":"<<e.code<<"}";}
            o<<"],\"indirect_calls\":[";comma=false;
            for(auto e:f.indirectCalls){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(e.site)<<"\",\"rs\":"<<e.rs<<",\"rd\":"<<e.rd<<"}";}
            o<<"],\"indirect_jumps\":[";comma=false;
            for(auto e:f.indirectJumps){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(e.site)<<"\",\"rs\":"<<e.rs<<",\"rd\":"<<e.rd<<"}";}
            o<<"],\"bios_calls\":[";comma=false;
            for(auto e:f.biosCalls){if(comma)o<<",";comma=true;
                o<<"{\"site\":\""<<hex(e.site)<<"\",\"table\":\""<<hex(e.table)<<"\",\"function\":";
                if(e.function>=0)o<<e.function;else o<<"null";
                if(d.closure){const auto* name=biosName(e.table,e.function,d.bootBios,d.bootCard);
                    if(name)o<<",\"name\":\""<<name<<"\",\"name_source\":\"external-reference-not-verified-in-repo\"";}
                o<<",\"call\":"<<(e.call?"true":"false")<<"}";}
            o<<"],\"unsupported_forms\":[";comma=false;
            for(const auto& e:f.unsupportedForms){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(e.first)<<"\",\"form\":\""<<e.second<<"\"}";}
            o<<"]";
            if(d.closure) {
                o<<",\"switch_calls\":[";comma=false;
                for(const auto& e:f.switchSites){if(comma)o<<",";comma=true;const auto& s=e.second;
                    o<<"{\"kind\":\"resolved-indirect-static-table\",\"site\":\""<<hex(e.first)<<"\",\"rs\":"<<s.rs<<",\"table\":\""<<hex(s.table)
                     <<"\",\"count\":"<<s.count<<",\"default\":\""<<hex(s.defaultTarget)<<"\",\"targets\":[";
                    for(std::size_t n=0;n<s.targets.size();++n)o<<(n?",":"")<<"\""<<hex(s.targets[n])<<"\"";
                    o<<"]}";}
                o<<"],\"cell_guarded_calls\":[";comma=false;
                for(const auto& e:f.cellCalls){if(comma)o<<",";comma=true;const auto& s=e.second;
                    o<<"{\"kind\":\"resolved-indirect-cell-guarded\",\"site\":\""<<hex(e.first)<<"\",\"rs\":"<<s.rs
                     <<",\"location\":\""<<(s.field?"field":"cell")<<"\",\"cell\":\""<<hex(s.cell)<<"\",\"offset\":\""<<hex(s.offset)
                     <<"\",\"initial\":\""<<hex(s.initial)<<"\",\"targets\":[";
                    for(std::size_t n=0;n<s.targets.size();++n)o<<(n?",":"")<<"\""<<hex(s.targets[n])<<"\"";
                    o<<"],\"writers\":[";
                    for(std::size_t n=0;n<s.writers.size();++n)o<<(n?",":"")<<"{\"pc\":\""<<hex(s.writers[n].first)<<"\",\"value\":\""<<hex(s.writers[n].second)<<"\"}";
                    o<<"],\"runtime_guard\":\"captured target == live RAM and member of targets; unknown/null/misaligned fatal\"}";}
                o<<"]";
                if(d.phase3()) {
                    o<<",\"set_guarded_calls\":[";comma=false;
                    for(const auto& e:f.setCalls){if(comma)o<<",";comma=true;const auto& s=e.second;
                        o<<"{\"kind\":\"resolved-indirect-set-guarded\",\"site\":\""<<hex(e.first)<<"\",\"rs\":"<<s.rs<<",\"set_kind\":\""<<s.kind
                         <<"\",\"origin\":\""<<s.origin<<"\",\"targets\":[";
                        for(std::size_t n=0;n<s.targets.size();++n)o<<(n?",":"")<<"\""<<hex(s.targets[n])<<"\"";
                        o<<"],\"assumptions\":[";
                        for(std::size_t n=0;n<s.assumptions.size();++n)o<<(n?",":"")<<"\""<<s.assumptions[n]<<"\"";
                        o<<"],\"runtime_guard\":\"captured target is a member of targets; unknown/null/misaligned fatal\"}";}
                    o<<"],\"break_traps\":[";comma=false;
                    for(const auto& e:f.breakTraps){if(comma)o<<",";comma=true;
                        o<<"{\"site\":\""<<hex(e.first)<<"\",\"word\":\""<<hex(e.second)<<"\",\"kind\":\"divide-by-zero-guard\",\"runtime\":\"fatal\"}";}
                    o<<"],\"bios_hle\":[";comma=false;
                    for(const auto& e:f.biosHle){if(comma)o<<",";comma=true;
                        o<<"{\"site\":\""<<hex(e.first)<<"\",\"table\":\""<<hex(e.second.table)<<"\",\"function\":"<<e.second.function<<"}";}
                    o<<"]";
                }
            }
        }
        o<<",\"returns\":[";comma=false;for(auto pc:f.returns){if(comma)o<<",";comma=true;o<<"\""<<hex(pc)<<"\"";}
        o<<"],\"unresolved\":[";comma=false;
        for(const auto& issue:f.unresolved){if(comma)o<<",";comma=true;o<<"{\"site\":\""<<hex(issue.site)<<"\",\"reason\":\""<<issue.reason<<"\"}";}
        o<<"]}";
    }
    o<<"\n  ]";
    if(d.closure) {
        o<<",\n  \"closure_rounds\": "<<d.closureRounds<<",\n  \"derived_words\": "<<d.derivedWords<<",\n  \"indirect_sites\": [";
        first=true;
        for(const auto& s:d.indirectReport){if(!first)o<<",";first=false;
            o<<"\n    {\"site\":\""<<hex(s.site)<<"\",\"function\":\""<<hex(s.function)<<"\",\"op\":\""<<(s.jump?"jr":"jalr")<<"\",\"rs\":"<<s.rs
             <<",\"rd\":"<<s.rd<<",\"kind\":\""<<s.kind<<"\",\"status\":\""<<s.status<<"\",\"detail\":\""<<s.detail<<"\",\"targets\":[";
            for(std::size_t n=0;n<s.targets.size();++n)o<<(n?",":"")<<"\""<<hex(s.targets[n])<<"\"";
            o<<"],\"reason\":\""<<s.reason<<"\"}";}
        o<<"\n  ]";
    }
    o<<"\n}\n";return o.str();
}
inline std::string discoveryMarkdown(const Discovery& d) {
    std::ostringstream o;std::size_t calls=0,resolved=0;
    for(const auto& p:d.functions){calls+=p.second.calls.size();resolved+=p.second.resolved;}
    o<<"# Function discovery\n\nFunctions: "<<d.functions.size()<<"; resolved extents: "<<resolved<<"; direct call sites: "<<calls<<".\n\n";
    o<<"Structural analysis only; normal call return assumed. Derived entries are evidence, not verified code.\n\n";
    if(d.extendedIsa) {
        std::size_t sys=0,ic=0,ij=0,bios=0;
        for(const auto& p:d.functions){sys+=p.second.syscalls.size();ic+=p.second.indirectCalls.size();ij+=p.second.indirectJumps.size();bios+=p.second.biosCalls.size();}
        o<<"Extended ISA discovery: SYSCALL sites "<<sys<<"; generic indirect calls "<<ic<<"; generic indirect jumps "<<ij<<"; BIOS table calls "<<bios<<".\n"
         <<"Generic JR/JALR targets are never guessed; SYSCALL and BIOS table calls are runtime policy/HLE boundaries.\n\n";
    }
    for(const auto& p:d.functions){const auto& f=p.second;o<<"- "<<hex(p.first)<<" ("<<f.seed.confidence<<", "<<(f.resolved?"resolved":"unresolved")<<")\n";
        for(auto e:f.calls)o<<"  - "<<hex(e.site)<<": -> "<<hex(e.target)<<"\n";
        for(const auto& e:f.guarded){const auto& s=e.second;
            o<<"  - "<<hex(e.first)<<": resolved-indirect-guarded -> "<<hex(s.expectedTarget)
             <<"; base global "<<hex(s.baseGlobal)<<" == "<<hex(s.expectedBase)<<"; slot "<<hex(s.address())
             <<" (+"<<hex(s.offset)<<"); confidence="<<moyle::detail::guardedConfidence
             <<"; provenance="<<moyle::detail::guardedProvenance<<"\n";
        }
        for(auto e:f.jumps)o<<"  - "<<hex(e.site)<<": internal jump -> "<<hex(e.target)<<"\n";
        for(auto e:f.tailJumps)o<<"  - "<<hex(e.site)<<": other-entrypoint jump -> "<<hex(e.target)<<"\n";
        for(auto e:f.unresolvedJumps)o<<"  - "<<hex(e.site)<<": unresolved jump -> "<<hex(e.target)<<"\n";
        for(auto e:f.syscalls)o<<"  - "<<hex(e.site)<<": syscall code "<<e.code<<" (policy boundary)\n";
        for(const auto& e:f.cellCalls){const auto& s=e.second;
            o<<"  - "<<hex(e.first)<<": resolved-indirect-cell-guarded via "<<(s.field?"field ":"cell ")<<hex(s.cell)<<(s.field?" +"+hex(s.offset):std::string())<<" -> {";
            for(std::size_t n=0;n<s.targets.size();++n)o<<(n?", ":"")<<hex(s.targets[n]);
            o<<"}; runtime guard required\n";}
        for(const auto& e:f.setCalls){const auto& s=e.second;
            o<<"  - "<<hex(e.first)<<": resolved-indirect-set-guarded ("<<s.kind<<") -> {";
            for(std::size_t n=0;n<s.targets.size();++n)o<<(n?", ":"")<<hex(s.targets[n]);
            o<<"}; membership guard required\n";}
        for(const auto& e:f.breakTraps)o<<"  - "<<hex(e.first)<<": BREAK 7 divide-by-zero guard (fatal trap)\n";
        for(const auto& e:f.biosHle)o<<"  - "<<hex(e.first)<<": BIOS table "<<hex(e.second.table)<<" function 0x"<<std::hex<<e.second.function<<std::dec<<" (HLE boundary, returns to caller)\n";
        for(const auto& e:f.switchSites){const auto& s=e.second;
            o<<"  - "<<hex(e.first)<<": resolved-indirect-static-table "<<hex(s.table)<<" x"<<s.count<<" -> "<<s.targets.size()<<" distinct internal targets\n";}
        for(auto e:f.indirectCalls)o<<"  - "<<hex(e.site)<<": indirect call (jalr r"<<e.rd<<",r"<<e.rs<<"), target unresolved\n";
        for(auto e:f.indirectJumps)o<<"  - "<<hex(e.site)<<": indirect jump (r"<<e.rs<<"), target unresolved\n";
        for(auto e:f.biosCalls){o<<"  - "<<hex(e.site)<<": BIOS table "<<hex(e.table)<<" function ";
            if(e.function>=0)o<<"0x"<<std::hex<<e.function<<std::dec;else o<<"unknown";
            o<<(e.call?" (call)":" (tail transfer)")<<"\n";}
        for(const auto& i:f.unresolved)o<<"  - "<<hex(i.site)<<": "<<i.reason<<"\n";
    }return o.str();
}
// Baseline (legacy) vs extended discovery. regressions are hard failures: every function the
// legacy run resolved must stay resolved with identical extent, calls, jumps, guarded sites and
// returns. Anything else lost in an unresolved function is only reported as `lost`.
struct Comparison {std::vector<std::string> regressions, lost; std::string report;};
inline Comparison compareDiscovery(const Discovery& legacy,const Discovery& extended) {
    Comparison c;
    const auto count=[](const Discovery& d,std::size_t& resolved,std::size_t& calls,std::size_t& jumps,std::size_t& unresolvedJumps,
                         std::size_t& guarded,std::size_t& indirect) {
        resolved=calls=jumps=unresolvedJumps=guarded=indirect=0;
        for(const auto& p:d.functions){const auto& f=p.second;resolved+=f.resolved;calls+=f.calls.size();
            jumps+=f.jumps.size()+f.tailJumps.size();unresolvedJumps+=f.unresolvedJumps.size();guarded+=f.guarded.size();
            for(const auto& i:f.unresolved)if(i.reason.compare(0,9,"indirect-")==0)++indirect;}
    };
    std::size_t r0,c0,j0,u0,g0,i0,r1,c1,j1,u1,g1,i1;
    count(legacy,r0,c0,j0,u0,g0,i0);count(extended,r1,c1,j1,u1,g1,i1);
    const auto sameSet=[](const auto& a,const auto& b){
        return a.size()==b.size()&&std::equal(a.begin(),a.end(),b.begin(),[](const auto& x,const auto& y){return !(x<y)&&!(y<x);});
    };
    for(const auto& p:legacy.functions) {
        const auto found=extended.functions.find(p.first);
        if(found==extended.functions.end()){c.regressions.push_back(hex(p.first)+": entry lost");continue;}
        const auto& a=p.second;const auto& b=found->second;
        if(a.resolved){
            if(!b.resolved||b.end!=a.end){
                // Typically a newly understood path of another function now overlaps this certified one.
                std::string why;
                for(const auto& i:b.unresolved)why+=(why.empty()?"":", ")+hex(i.site)+" "+i.reason;
                c.regressions.push_back(hex(p.first)+": legacy-resolved extent changed or unresolved"+(why.empty()?std::string():" ("+why+")"));
            }
            else if(!sameSet(a.body,b.body)||!sameSet(a.delaySlots,b.delaySlots)||!sameSet(a.returns,b.returns)||!sameSet(a.calls,b.calls)||
                    !sameSet(a.jumps,b.jumps)||!sameSet(a.tailJumps,b.tailJumps)||!sameSet(a.unresolvedJumps,b.unresolvedJumps)||
                    a.guarded.size()!=b.guarded.size()||a.seed.confidence!=b.seed.confidence)
                c.regressions.push_back(hex(p.first)+": legacy-resolved function evidence changed");
            else for(const auto& g:a.guarded){const auto other=b.guarded.find(g.first);
                if(other==b.guarded.end()||other->second.expectedTarget!=g.second.expectedTarget)
                    c.regressions.push_back(hex(p.first)+": guarded site changed");}
        } else {
            for(auto e:a.calls)if(!b.calls.count(e))c.lost.push_back(hex(p.first)+": call "+hex(e.site)+" -> "+hex(e.target)+" no longer reported");
            for(auto e:a.jumps)if(!b.jumps.count(e))c.lost.push_back(hex(p.first)+": jump "+hex(e.site)+" -> "+hex(e.target)+" no longer reported");
            for(auto pc:a.body)if(!b.body.count(pc)){c.lost.push_back(hex(p.first)+": body word "+hex(pc)+" no longer reached");break;}
        }
    }
    std::ostringstream o;
    o<<"# Extended ISA discovery comparison\n\n| metric | legacy | extended |\n|---|---|---|\n"
     <<"| functions | "<<legacy.functions.size()<<" | "<<extended.functions.size()<<" |\n"
     <<"| resolved extents | "<<r0<<" | "<<r1<<" |\n| direct call sites | "<<c0<<" | "<<c1<<" |\n"
     <<"| accepted J sites | "<<j0<<" | "<<j1<<" |\n| unresolved J sites | "<<u0<<" | "<<u1<<" |\n"
     <<"| guarded indirect calls | "<<g0<<" | "<<g1<<" |\n| indirect-* unresolved reasons | "<<i0<<" | "<<i1<<" |\n";
    if(extended.closure) {
        std::size_t cells0=0,cells1=0,sw0=0,sw1=0;
        for(const auto& p:legacy.functions){cells0+=p.second.cellCalls.size();sw0+=p.second.switchSites.size();}
        for(const auto& p:extended.functions){cells1+=p.second.cellCalls.size();sw1+=p.second.switchSites.size();}
        o<<"| cell-guarded indirect calls | "<<cells0<<" | "<<cells1<<" |\n| static-table switch sites | "<<sw0<<" | "<<sw1<<" |\n";
    }
    o<<"\n";
    o<<"Regressions of legacy-resolved extents: "<<c.regressions.size()<<"\n";
    for(const auto& r:c.regressions)o<<"- "<<r<<"\n";
    o<<"\n## New entries (reached only through newly understood instructions)\n";
    for(const auto& p:extended.functions)if(!legacy.functions.count(p.first))
        o<<"- "<<hex(p.first)<<" ("<<p.second.seed.confidence<<", "<<(p.second.resolved?"resolved":"unresolved")<<", visited "<<p.second.body.size()
         <<" words"<<(p.second.resolved?", end "+hex(static_cast<std::uint32_t>(p.second.end)):std::string())<<")\n";
    o<<"\n## Newly resolved extents\n";
    for(const auto& p:extended.functions){
        const auto old=legacy.functions.find(p.first);
        if(p.second.resolved&&(old==legacy.functions.end()||!old->second.resolved))
            o<<"- "<<hex(p.first)<<" -> end "<<hex(static_cast<std::uint32_t>(p.second.end))<<" ("<<p.second.body.size()<<" words, was "
             <<(old==legacy.functions.end()?"absent":"unresolved")<<")\n";
    }
    o<<"\n## Newly reached address ranges (existing entries; CFG-reachable words not visited by legacy)\n";
    for(const auto& p:extended.functions){
        const auto old=legacy.functions.find(p.first);if(old==legacy.functions.end())continue;
        std::vector<std::uint32_t> added;
        for(auto pc:p.second.body)if(!old->second.body.count(pc))added.push_back(pc);
        if(added.empty())continue;
        o<<"- "<<hex(p.first)<<":";
        for(std::size_t n=0;n<added.size();){std::size_t m=n;while(m+1<added.size()&&added[m+1]==added[m]+4)++m;
            o<<" ["<<hex(added[n])<<","<<hex(added[m]+4)<<")";n=m+1;}
        o<<"\n";
    }
    o<<"\n## Remaining blockers (unresolved reasons)\n";
    std::map<std::string,std::vector<std::uint32_t>> reasons;
    for(const auto& p:extended.functions)for(const auto& i:p.second.unresolved)reasons[i.reason].push_back(i.site);
    for(const auto& r:reasons){o<<"- "<<r.first<<": "<<r.second.size()<<" (";
        for(std::size_t n=0;n<r.second.size()&&n<16;++n)o<<(n?", ":"")<<hex(r.second[n]);
        if(r.second.size()>16){o<<", ...";}
        o<<")\n";}
    o<<"\n## Remaining unsupported instruction forms (operation class only)\n";
    std::map<std::string,std::vector<std::uint32_t>> forms;
    for(const auto& p:extended.functions)for(const auto& e:p.second.unsupportedForms)forms[e.second].push_back(e.first);
    for(const auto& f:forms){o<<"- "<<f.first<<": "<<f.second.size()<<" (";
        for(std::size_t n=0;n<f.second.size()&&n<16;++n)o<<(n?", ":"")<<hex(f.second[n]);
        if(f.second.size()>16){o<<", ...";}
        o<<")\n";}
    o<<"\n## Runtime boundaries exposed\n";
    for(const auto& p:extended.functions){
        for(auto e:p.second.syscalls)o<<"- SYSCALL code "<<e.code<<" at "<<hex(e.site)<<" in "<<hex(p.first)<<"\n";
        for(auto e:p.second.biosCalls){o<<"- BIOS table "<<hex(e.table)<<" function ";
            if(e.function>=0)o<<"0x"<<std::hex<<e.function<<std::dec;else o<<"unknown";
            o<<(e.call?" call":" tail transfer")<<" at "<<hex(e.site)<<" in "<<hex(p.first)<<"\n";}
        for(auto e:p.second.indirectCalls)o<<"- generic indirect call (jalr r"<<e.rd<<",r"<<e.rs<<") at "<<hex(e.site)<<" in "<<hex(p.first)<<"\n";
        for(auto e:p.second.indirectJumps)o<<"- generic indirect jump (r"<<e.rs<<") at "<<hex(e.site)<<" in "<<hex(p.first)<<"\n";
    }
    o<<"\nLost in unresolved legacy functions: "<<c.lost.size()<<"\n";
    for(const auto& l:c.lost)o<<"- "<<l<<"\n";
    c.report=o.str();return c;
}
}
