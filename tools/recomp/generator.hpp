#pragma once
#include "../../src/guarded_indirect.hpp"
#include "../../src/ps1_gte.hpp"
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace recomp_tool {
struct Region { std::uint32_t entry, words; };
// IndirectCall: generic (unannotated) JALR, only produced with the extended ISA enabled.
// CellGuarded / SetGuarded / TableSwitch / BiosVector / ReturnGuarded are Phase 3 closure kinds. They are only ever
// attached by tools/recomp/closure_emit.hpp from Phase 2C/3 proofs; the default decoder never produces them.
enum class CallKind { None, Direct, Guarded, DynamicRuntime, StaticTableTailJump, StaticTableCall, IndirectCall,
                      CellGuarded, SetGuarded, TableSwitch, BiosVector, ReturnGuarded };
inline std::string hex(std::uint32_t n) {
    std::ostringstream s; s << "0x" << std::hex << std::setfill('0') << std::setw(8) << n; return s.str();
}
inline std::uint32_t word(const std::vector<std::uint8_t>& b, std::size_t p) {
    if (p > b.size() || b.size()-p < 4) throw std::runtime_error("Truncated word");
    return b[p] | (std::uint32_t(b[p+1])<<8) | (std::uint32_t(b[p+2])<<16) | (std::uint32_t(b[p+3])<<24);
}
struct Instruction {
    std::uint32_t pc, bits, rs, rt;
    std::string text, code;
    bool control = false, direct = false, load = false;
    std::uint32_t target = 0;
    CallKind callKind=CallKind::None;
    bool syscall=false;
    // Phase 3: a terminal instruction never falls through and never reaches a successor (fatal BREAK trap, boundary
    // stub). It is only produced on an explicit opt-in path, never by the default decoder.
    bool terminal=false;
};
// extendedIsa (default OFF) enables the Phase 2A additions: SRA, SLLV, SRLV, SRAV, MULT, MULTU,
// DIVU, MFHI, MFLO, BLTZ, BLEZ, BGTZ, generic JR, generic JALR and SYSCALL. It is opt-in so the
// reviewed subsets used by the overlay and static-table generators stay byte-for-byte unchanged.
inline Instruction decode(std::uint32_t pc, std::uint32_t w, bool extendedMemory=true,
                          bool gteEnabled=false, bool extendedIsa=false, bool bootIsa=false) {
    const auto op=w>>26, rs=(w>>21)&31, rt=(w>>16)&31, rd=(w>>11)&31, sh=(w>>6)&31, fn=w&63;
    const auto u=w&65535;
    const auto imm = u < 32768 ? std::int32_t(u) : std::int32_t(u)-65536;
    const auto ext=static_cast<std::uint32_t>(imm);
    Instruction i{pc,w,rs,rt,"",""};
    const auto reg=[](unsigned r){return "r"+std::to_string(r);};
    const auto write=[](unsigned r,const std::string& value){return "c.r["+std::to_string(r)+"] = "+value+";";};
    const auto fail=[&](){throw std::runtime_error("Unsupported/reserved opcode at "+hex(pc)+": "+hex(w));};
    // Existing certified extents keep their execution boundaries. Only callers
    // explicitly opting into the T5 subset may emit these instructions.
    if((op==18||op==50||op==58)&&!gteEnabled)fail();
    if (op==18) {
        if(rs>=16){
            if(!moyle::detail::recomp::Gte::supports(w))fail();
            i.text="GTE command";i.code="(void)c.gte.execute("+hex(w)+"U);";
        }else{
            if((w&2047)||(rs!=0&&rs!=2&&rs!=4&&rs!=6))fail();
            const auto index=std::to_string(rd);
            i.rs=0;
            if(rs==0||rs==2){i.text=rs==0?"mfc2":"cfc2";i.code=write(rt,"c.gte."+std::string(rs==0?"readData":"readControl")+"("+index+")");}
            else{i.text=rs==4?"mtc2":"ctc2";i.code="c.gte."+std::string(rs==4?"writeData":"writeControl")+"("+index+",b);";}
        }
    } else if(op==50||op==58){
        const auto index=std::to_string(rt),address="a+"+hex(ext)+"U";
        if(op==50){i.text="lwc2";i.code="c.gte.writeData("+index+",c.ram.read("+address+",4));";}
        else{i.text="swc2";i.code="c.ram.write("+address+",c.gte.readData("+index+"),4);";}
    } else if (op==0) {
        if (fn==0 || fn==2) {
            if (rs) fail();
            const std::string name=fn==0?"sll":"srl";
            i.text=w==0?"nop":name+" "+reg(rd)+","+reg(rt)+","+std::to_string(sh);
            i.code=write(rd,"b "+std::string(fn==0?"<<":" >>")+" "+std::to_string(sh));
        } else if (fn==0x24 || fn==0x26 || fn==0x2a || fn==0x2b) {
            if(sh)fail();
            i.text=(fn==0x24?"and ":fn==0x26?"xor ":fn==0x2b?"sltu ":"slt ")+reg(rd)+","+reg(rs)+","+reg(rt);
            i.code=write(rd,fn==0x24?"a & b":fn==0x26?"a ^ b":fn==0x2b?"(a < b)":"((a ^ 0x80000000U) < (b ^ 0x80000000U))");
        } else if (fn==0x20) {
            if(sh)fail();
            i.text="add "+reg(rd)+","+reg(rs)+","+reg(rt);
            i.code="const auto sum = a + b; if (((~(a ^ b) & (a ^ sum)) & 0x80000000U) != 0) throw std::runtime_error(\"Guest ADD overflow\"); "+write(rd,"sum");
        } else if (fn==0x22 && extendedIsa && bootIsa && gteEnabled) {
            // SUB (second-stage boot ISA: requires --boot-isa AND --boot-gte so every pinned --boot-isa unit stays unchanged): like ADD, signed overflow is a fatal guest exception, never a silent wrap.
            if(sh)fail();
            i.text="sub "+reg(rd)+","+reg(rs)+","+reg(rt);
            i.code="const auto diff = a - b; if ((((a ^ b) & (a ^ diff)) & 0x80000000U) != 0) throw std::runtime_error(\"Guest SUB overflow\"); "+write(rd,"diff");
        } else if (fn==0x21 || fn==0x23 || fn==0x25) {
            if (sh) fail();
            const std::string name=fn==0x21?"addu":fn==0x23?"subu":"or";
            i.text=name+" "+reg(rd)+","+reg(rs)+","+reg(rt);
            i.code=write(rd,"a "+std::string(fn==0x21?"+":fn==0x23?"-":"|")+" b");
        } else if (fn==8) {
            // Default: only verified returns. Extended ISA: any JR rs; the target is dispatched
            // through the generated PC switch, so a destination outside the extents is a fatal.
            if (extendedIsa ? (rt || rd || sh) : (rs!=31 || rt || rd || sh)) fail();
            i.text="jr "+reg(rs); i.control=true; i.code="following = a;";
        } else if (extendedIsa && fn==9) {
            // Generic JALR: target is rs captured before the link write (so rd==rs is defined here),
            // link PC+8 goes to rd (rd==0 discards it). Executes inside the generated PC space.
            if (rt || sh) fail();
            i.text="jalr "+reg(rd)+","+reg(rs); i.control=true; i.callKind=CallKind::IndirectCall;
            i.code="following = a; "+(rd?write(rd,"pc + 8U")+" ":std::string())+"++c.calls;";
        } else if (extendedIsa && fn==0x27) {
            // NOR (extended ISA): the Direct TITLE closure extents contain it (bitwise complement idiom).
            if (sh) fail();
            i.text="nor "+reg(rd)+","+reg(rs)+","+reg(rt);
            i.code=write(rd,"~(a | b)");
        } else if (extendedIsa && fn==3) {
            if (rs) fail();
            i.text="sra "+reg(rd)+","+reg(rt)+","+std::to_string(sh);
            i.code=write(rd,sh?"(b >> "+std::to_string(sh)+") | ((b & 0x80000000U) ? "+hex(0xffffffffU<<(32-sh))+"U : 0U)":std::string("b"));
        } else if (extendedIsa && (fn==4 || fn==6 || fn==7)) {
            if (sh) fail();
            i.text=std::string(fn==4?"sllv ":fn==6?"srlv ":"srav ")+reg(rd)+","+reg(rt)+","+reg(rs);
            i.code=write(rd,fn==4?"b << (a & 31U)":fn==6?"b >> (a & 31U)":
                "(b >> (a & 31U)) | ((b & 0x80000000U) ? ~(0xffffffffU >> (a & 31U)) : 0U)");
        } else if (extendedIsa && (fn==0x10 || fn==0x12)) {
            if (rs || rt || sh) fail();
            i.text=std::string(fn==0x10?"mfhi ":"mflo ")+reg(rd);
            i.code=write(rd,fn==0x10?"c.hi":"c.lo");
        } else if (extendedIsa && (fn==0x18 || fn==0x19 || fn==0x1b || (bootIsa && fn==0x1a))) {
            // HI/LO are updated immediately (no R3000 multiplier/divider latency is modeled).
            if (rd || sh) fail();
            i.text=std::string(fn==0x18?"mult ":fn==0x19?"multu ":fn==0x1a?"div ":"divu ")+reg(rs)+","+reg(rt);
            if (fn==0x1b) i.code="if (b != 0U) { c.lo = a / b; c.hi = a % b; } else { c.lo = 0xffffffffU; c.hi = a; }";
            else if (fn==0x1a) i.code="if (b == 0U) { c.lo = (a & 0x80000000U) ? 1U : 0xffffffffU; c.hi = a; } else { const auto sa = static_cast<std::int64_t>(static_cast<std::int32_t>(a)); const auto sb = static_cast<std::int64_t>(static_cast<std::int32_t>(b)); c.lo = static_cast<std::uint32_t>(sa / sb); c.hi = static_cast<std::uint32_t>(sa % sb); }";
            else if (fn==0x19) i.code="const std::uint64_t product = std::uint64_t(a) * b; c.hi = std::uint32_t(product >> 32); c.lo = std::uint32_t(product);";
            else i.code="const std::uint64_t product = std::uint64_t(a) * b; std::uint32_t high = std::uint32_t(product >> 32); "
                        "if ((a & 0x80000000U) != 0U) high -= b; if ((b & 0x80000000U) != 0U) high -= a; "
                        "c.hi = high; c.lo = std::uint32_t(product);";
        } else if (extendedIsa && fn==12) {
            const auto sysCode=(w>>6)&0xfffffU;
            i.text="syscall "+hex(sysCode); i.syscall=true;
            i.code="dispatchSyscall(c, pc, "+hex(sysCode)+"U);";
        } else fail();
    } else if (extendedIsa && bootIsa && op==16) {
        if((w&2047U)||rd!=12U||(rs!=0U&&rs!=4U))fail();
        i.rs=0;i.text=rs==0?"mfc0 status":"mtc0 status";
        if(rs==0)i.code=write(rt,"c.cop0Status");else i.code="c.cop0Status = b;";
    } else if (extendedIsa && bootIsa && op==8) {
        // ADDI (Phase 4 boot ISA opt-in, requires extendedIsa): like ADD, signed overflow is a fatal guest exception, never a silent wrap.
        i.text="addi "+reg(rt)+","+reg(rs)+","+std::to_string(imm);
        i.code="const auto sum = a + "+hex(ext)+"U; if (((~(a ^ "+hex(ext)+"U) & (a ^ sum)) & 0x80000000U) != 0) throw std::runtime_error(\"Guest ADDI overflow\"); "+write(rt,"sum");
    } else if (op==9) {
        i.text="addiu "+reg(rt)+","+reg(rs)+","+std::to_string(imm);
        i.code=write(rt,"a + "+hex(ext)+"U");
    } else if (op==10||op==11) {
        i.text=(op==10?"slti ":"sltiu ")+reg(rt)+","+reg(rs)+","+std::to_string(imm);
        i.code=write(rt,op==10?"((a ^ 0x80000000U) < ("+hex(ext)+"U ^ 0x80000000U))":"(a < "+hex(ext)+"U)");
    } else if (op==13) {
        i.text="ori "+reg(rt)+","+reg(rs)+","+hex(u);i.code=write(rt,"a | "+hex(u)+"U");
    } else if (extendedIsa && op==14) {
        // XORI (extended ISA): zero-extended immediate, like ORI/ANDI.
        i.text="xori "+reg(rt)+","+reg(rs)+","+hex(u);i.code=write(rt,"a ^ "+hex(u)+"U");
    } else if (op==12) {
        i.text="andi "+reg(rt)+","+reg(rs)+","+hex(u);
        i.code=write(rt,"a & "+hex(u)+"U");
    } else if (op==15) {
        if (rs) fail();
        i.text="lui "+reg(rt)+","+hex(u); i.code=write(rt,hex(u<<16)+"U");
    } else if (op==4 || op==5 || (op==1 && rt==1) || (extendedIsa && (op==1 || op==6 || op==7) && rt==0)) {
        i.control=i.direct=true; i.target=pc+4+ext*4U;
        const std::string condition=op==4?"a == b":op==5?"a != b":op==6?"((a & 0x80000000U) != 0U || a == 0U)":
            op==7?"((a & 0x80000000U) == 0U && a != 0U)":rt==0?"(a & 0x80000000U) != 0":"(a & 0x80000000U) == 0";
        const std::string name=op==4?"beq ":op==5?"bne ":op==6?"blez ":op==7?"bgtz ":rt==0?"bltz ":"bgez ";
        i.text=name+reg(rs)+(op==4||op==5?","+reg(rt):std::string())+","+hex(i.target);
        i.code="const bool taken = "+condition+"; following = taken ? "+hex(i.target)+"U : "+hex(pc+8)+"U; c.branches.push_back({"+hex(pc)+"U,taken});";
    } else if (op==2) {
        i.control=i.direct=true;i.target=((pc+4)&0xf0000000U)|((w&0x3ffffffU)<<2);
        i.text="j "+hex(i.target);i.code="following = "+hex(i.target)+"U;";
    } else if (op==3) {
        i.callKind=CallKind::Direct;
        i.control=i.direct=true; i.target=((pc+4)&0xf0000000U)|((w&0x3ffffffU)<<2);
        i.text="jal "+hex(i.target);
        i.code=write(31,hex(pc+8)+"U")+" following = "+hex(i.target)+"U; ++c.calls;";
    } else if (extendedMemory&&(op==34||op==38||op==42||op==46)) {
        const std::string name=op==34?"lwl":op==38?"lwr":op==42?"swl":"swr";
        i.text=name+" "+reg(rt)+","+std::to_string(imm)+"("+reg(rs)+")";
        i.load=op==34||op==38;
        const auto addr="a + "+hex(ext)+"U";
        if(i.load)i.code="c.loadValue = c.ram."+std::string(op==34?"loadLeft":"loadRight")+"("+addr+",merge); c.loadRegister = "+std::to_string(rt)+";";
        else i.code="c.ram."+std::string(op==42?"storeLeft":"storeRight")+"("+addr+",b);";
    } else if (op==32 || (extendedMemory&&op==33) || op==35 || op==36 || op==37 || op==40 || op==41 || op==43) {
        const unsigned width=op==32||op==36||op==40?1:op==33||op==37||op==41?2:4;
        const std::string name=op==32?"lb":op==33?"lh":op==35?"lw":op==36?"lbu":op==37?"lhu":op==40?"sb":op==41?"sh":"sw";
        i.text=name+" "+reg(rt)+","+std::to_string(imm)+"("+reg(rs)+")";
        const auto addr="a + "+hex(ext)+"U";
        i.load=op==32||op==33||op==35||op==36||op==37;
        if(i.load) i.code="c.loadValue = c.ram.read("+addr+","+std::to_string(width)+"); c.loadRegister = "+std::to_string(rt)+";";
        else i.code="c.ram.write("+addr+",b,"+std::to_string(width)+");";
        if(op==32)i.code+=" c.loadValue = (c.loadValue ^ 128U) - 128U;";
        if(op==33)i.code+=" c.loadValue = (c.loadValue ^ 32768U) - 32768U;";
    } else fail();
    return i;
}
using GuardedCalls=std::map<std::uint32_t,moyle::detail::GuardedSlot>;
struct Program {
    std::map<std::uint32_t,Instruction> instructions;
    std::vector<Region> regions; GuardedCalls guarded;
    std::set<std::uint32_t> dynamic;
    std::uint32_t fragmentExit=0;
    // Optional local declarations supplied by the validated static-table pass.
    std::string tablePrelude;
    std::string extraIncludes;
    std::string sourceDescription="verified external PS-X EXE extents";
    // Phase 3 closure units (all empty for every legacy program, which keeps legacy output byte-identical):
    std::string closurePrelude;  // function-scope declarations placed before the loop (cell/set sites, return-site guard)
    std::string loopLocals;      // locals declared next to pc/next (e.g. the armed BIOS call)
    std::string iterationLocals; // sampled at the start of each iteration (before the instruction runs)
    std::string postSlot;        // statements run at the end of each iteration; guard with the sampled iterationLocals
    bool closure=false;          // forces the runtime backend
};
inline Program analyze(const std::vector<std::uint8_t>& bytes, const std::vector<Region>& regions,
                       const GuardedCalls& guarded={},const std::set<std::uint32_t>& dynamic={},
                       std::uint32_t fragmentExit=0,bool extendedIsa=false,
                       const std::map<std::uint32_t,Instruction>& overrides={},bool bootIsa=false,bool gteEnabled=false,
                       const std::set<std::uint32_t>& sharedSlots={}) {
    if(bytes.size()<0x800 || std::string(bytes.begin(),bytes.begin()+8)!="PS-X EXE") throw std::runtime_error("Not a PS-X EXE");
    const auto base=word(bytes,0x18), size=word(bytes,0x1c);
    if((base&3) || std::uint64_t(base)+size>0x100000000ULL || std::uint64_t(size)+0x800>bytes.size()) throw std::runtime_error("Invalid/truncated EXE mapping");
    if(regions.empty()) throw std::runtime_error("No verified regions supplied");
    Program p; p.regions=regions;p.guarded=guarded;p.dynamic=dynamic;p.fragmentExit=fragmentExit;
    if(fragmentExit && ((fragmentExit&3)||dynamic.empty()))throw std::runtime_error("Invalid dynamic fragment exit");
    for(auto pc:dynamic)if(guarded.count(pc))throw std::runtime_error("Conflicting indirect classifications");
    for(auto r:regions) {
        if((r.entry&3)||!r.words||r.entry<base||std::uint64_t(r.entry-base)+std::uint64_t(r.words)*4>size) throw std::runtime_error("Extent outside executable");
        for(std::uint32_t n=0;n<r.words;++n) {
            const auto pc=r.entry+n*4;
            const auto w=word(bytes,0x800+std::size_t(pc-base));
            Instruction instruction;
            if(guarded.count(pc)){
                const auto& s=guarded.at(pc);
                if((w&0xfc1fffffU)!=0x0000f809U||
                   !moyle::detail::allowedSlot(s.baseGlobal,s.expectedBase,s.offset,s.expectedTarget))
                    throw std::runtime_error("Invalid guarded JALR metadata");
                instruction={pc,w,(w>>21)&31,0,"resolved-indirect-guarded",""};
                instruction.control=instruction.direct=true;instruction.target=s.expectedTarget;
                instruction.callKind=CallKind::Guarded;
                instruction.code="following = moyle::detail::validateGuardedTarget(c.ram,"+hex(pc)+"U,{"+
                    hex(s.baseGlobal)+"U,"+hex(s.expectedBase)+"U,"+hex(s.offset)+"U,"+hex(s.expectedTarget)+
                    "U},a); c.r[31] = "+hex(pc+8)+"U; ++c.calls;";
            }else if(dynamic.count(pc)){
                if((w&0xfc1fffffU)!=0x0000f809U)throw std::runtime_error("Dynamic site is not supported JALR rd=ra");
                instruction={pc,w,(w>>21)&31,0,"resolved-indirect-dynamic-runtime",""};
                instruction.control=true;instruction.callKind=CallKind::DynamicRuntime;
                instruction.code="pending = lookupDynamic(c,pc,a); pendingSite = pc; continuation = pc + 8U; "
                    "c.r[31] = continuation; following = continuation; waiting = true; ++c.calls;";
            }else if(overrides.count(pc)){
                instruction=overrides.at(pc);
                if(instruction.pc!=pc||instruction.bits!=w)throw std::runtime_error("Override does not match the executable word at "+hex(pc));
            }else instruction=decode(pc,w,true,gteEnabled,extendedIsa,bootIsa);
            if(!p.instructions.emplace(pc,instruction).second) throw std::runtime_error("Overlapping extents");
        }
    }
    for(const auto& edge:guarded)if(!p.instructions.count(edge.first))throw std::runtime_error("Guarded site outside extents");
    for(auto pc:dynamic)if(!p.instructions.count(pc))throw std::runtime_error("Dynamic site outside extents");
    if(fragmentExit && (p.instructions.count(fragmentExit)||fragmentExit<8||!dynamic.count(fragmentExit-8)))
        throw std::runtime_error("Fragment must end immediately after an explicit dynamic call slot");
    std::set<std::uint32_t> slots;
    for(const auto& pair:p.instructions) {
        const auto& i=pair.second;
        if(i.control) {
            const auto delay=p.instructions.find(i.pc+4);
            if(delay==p.instructions.end()||delay->second.control) throw std::runtime_error("Missing/unsupported control delay slot");
            // A load in a return slot crosses the host boundary: deliberately unsupported.
            if(!i.direct && i.callKind!=CallKind::DynamicRuntime && i.callKind!=CallKind::IndirectCall &&
               i.callKind!=CallKind::CellGuarded && i.callKind!=CallKind::SetGuarded && delay->second.load) throw std::runtime_error("Load in return delay slot unsupported");
            if(delay->second.terminal) throw std::runtime_error("Terminal trap in delay slot unsupported");
            slots.insert(i.pc+4);
            if(i.direct && !p.instructions.count(i.target)) throw std::runtime_error("Unresolved direct branch/call target");
        }
    }
    for(auto r:regions) if(slots.count(r.entry)) throw std::runtime_error("Entry in delay slot");
    // Shared delay slots (discovery opt-in): a real slot whose word also falls through as an ordinary instruction.
    for(auto s:sharedSlots)if(!slots.count(s)||!p.instructions.count(s)||!p.instructions.count(s+4)||p.instructions.at(s).control||
                               p.instructions.at(s).terminal||p.instructions.at(s).syscall)throw std::runtime_error("Invalid shared delay slot "+hex(s));
    for(const auto& pair:p.instructions) if(pair.second.syscall && slots.count(pair.first)) throw std::runtime_error("SYSCALL in delay slot unsupported");
    for(const auto& pair:p.instructions) {
        const auto& i=pair.second;
        if(i.direct && slots.count(i.target)) {
            // Only a direct non-link branch/J into a declared shared slot that is not its own slot is admitted.
            const auto op=i.bits>>26,rt=(i.bits>>16)&31;
            const bool directFlow=op==2||(op>=4&&op<=7)||(op==1&&rt!=0x10&&rt!=0x11);
            if(!sharedSlots.count(i.target)||!directFlow||i.target==i.pc+4) throw std::runtime_error("Branch/call into delay slot unsupported");
        }
        if(!i.control && !i.terminal && !slots.count(i.pc) && !p.instructions.count(i.pc+4)) throw std::runtime_error("Fallthrough outside extents");
        if(i.direct && (i.bits>>26)!=2 && !p.instructions.count(i.pc+8)) throw std::runtime_error("Missing branch fallthrough / call continuation");
        if(i.callKind==CallKind::DynamicRuntime && !p.instructions.count(i.pc+8) && i.pc+8!=fragmentExit)
            throw std::runtime_error("Missing dynamic call continuation");
        if((i.callKind==CallKind::IndirectCall||i.callKind==CallKind::CellGuarded||i.callKind==CallKind::SetGuarded) &&
           !p.instructions.count(i.pc+8)) throw std::runtime_error("Missing indirect call continuation");
    }
    return p;
}
inline std::string disassembly(const Program& p) {
    std::ostringstream out;
    for(const auto& pair:p.instructions) {const auto& i=pair.second;out<<hex(i.pc)<<"  "<<hex(i.bits)<<"  "<<i.text<<'\n';}
    return out.str();
}
inline std::string generate(const Program& p, const std::string& name="execute",bool runtimeBackend=false) {
    const bool runtime=runtimeBackend||p.closure||!p.dynamic.empty()||!p.tablePrelude.empty();
    if(runtime)for(const auto& pair:p.instructions)
        if(pair.first<0x80000000U||pair.first>=0x80200000U)throw std::runtime_error("Runtime backend requires KSEG0 source extents");
    std::ostringstream out;
    out<<"// Automatically generated from "<<p.sourceDescription<<". Do not edit.\n"
       <<"#include \"recomp_context.hpp\"\n";
    out<<p.extraIncludes;
    if(!p.guarded.empty())out<<"#include \"guarded_indirect.hpp\"\n";
    if(runtime)out<<"#include \"recomp_dispatch.hpp\"\n";
    if(!p.tablePrelude.empty())out<<"#include \"static_table.hpp\"\n";
    out<<"namespace moyle::detail::recomp {\n"
       <<"void "<<name<<"(Context& c, std::uint32_t entry, std::uint64_t budget) {\n"
       <<(runtime?"switch (canonicalCodeAddress(entry)) {\n":"switch (entry) {\n");
    for(auto r:p.regions) out<<"case "<<hex(r.entry)<<"U: break;\n";
    out<<"default: throw std::runtime_error(\"Unverified entry\"); }\n";
    out<<p.tablePrelude;
    if(p.fragmentExit)out<<"const auto stop = codeAlias("<<hex(p.fragmentExit)<<"U,entry);\n";
    else out<<"const auto stop = c.r[31];\n";
    out<<p.closurePrelude;
    out<<"if ((stop & 3U) != 0) throw std::runtime_error(\"Unaligned return\");\n";
    if(runtime)out<<"if (entry == stop) throw std::runtime_error(\"Entry equals return sentinel\");\nif (!c.dynamicDepth) {\nswitch (canonicalCodeAddress(stop)) {\n";
    else out<<"switch (stop) {\n";
    for(const auto& pair:p.instructions) out<<"case "<<hex(pair.first)<<"U:\n";
    out<<"throw std::runtime_error(\"Return sentinel overlaps code\"); default: break; }\n";
    if(runtime)out<<"}\nconst auto startSteps = c.steps;\nc.pc = entry;\n";
    if(!p.dynamic.empty())out<<"DynamicTarget pending; bool waiting = false; std::uint32_t pendingSite = 0, continuation = 0;\n";
    out<<p.loopLocals;
    out<<"std::uint32_t pc = entry, next = entry + 4U;\n"
       <<(runtime?"while (pc != stop) {\n":"for (std::uint64_t steps = 0; pc != stop; ++steps) {\n")
       <<(runtime?"if (c.steps - startSteps >= budget)":"if (steps >= budget)")
       <<" throw std::runtime_error(\"Instruction budget exceeded\");\n";
    if(!p.dynamic.empty())out<<"const bool dispatchAfterSlot = waiting;\n";
    out<<p.iterationLocals;
    out<<"++c.steps; c.r[0] = 0; std::uint32_t following = next + 4U;\n"
       <<(runtime?"switch (canonicalCodeAddress(pc)) {\n":"switch (pc) {\n");
    for(const auto& pair:p.instructions) {
        const auto& i=pair.second;
        auto code=i.code;
        if(runtime&&i.direct){
            const auto replace=[&](const std::string& from,const std::string& to){std::size_t pos=0;while((pos=code.find(from,pos))!=std::string::npos){code.replace(pos,from.size(),to);pos+=to.size();}};
            if(i.callKind==CallKind::Guarded){
                const auto& s=p.guarded.at(i.pc);
                code="following = moyle::detail::validateGuardedTarget(c.ram,pc,{"+hex(s.baseGlobal)+"U,"+
                    hex(s.expectedBase)+"U,"+hex(s.offset)+"U,"+hex(s.expectedTarget)+
                    "U},a); c.r[31] = pc + 8U; ++c.calls;";
            }else{
                replace(hex(i.pc+8)+"U","(pc + 8U)");
                replace(hex(i.target)+"U","codeAlias("+hex(i.target)+"U,pc)");
                replace(hex(i.pc)+"U","pc");
            }
        }
        out<<"case "<<hex(i.pc)<<"U: { // "<<i.text<<"\n"
           <<"[[maybe_unused]] const auto a = c.r["<<i.rs<<"], b = c.r["<<i.rt<<"];\n";
        if((i.bits>>26)==34||(i.bits>>26)==38)
            out<<"const auto merge = ("<<i.rt<<"U != 0 && c.loadRegister == "<<i.rt<<"U) ? c.loadValue : b;\n";
        out<<"c.retireLoad(); "<<code<<" break; }\n";
    }
    out<<"default: throw std::runtime_error(\"Unresolved guest PC\");\n}\n"
       <<"c.r[0] = 0; pc = next; next = following;\n";
    if(runtime)out<<"c.pc = pc;\n";
    out<<p.postSlot;
    if(!p.dynamic.empty())out<<"if (dispatchAfterSlot) { waiting = false; dispatchDynamic(c,pending,pendingSite,continuation,budget-(c.steps-startSteps)); pc = c.pc; next = pc + 4U; }\n";
    out<<"}\n}\n}\n";
    return out.str();
}
}
