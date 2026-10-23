#pragma once
// Phase 4: host harness for the generated Direct TITLE unit. This is NOT an emulator. It contains exactly:
//   * a verified PS-X EXE loader and the startup register state the header defines (parsePsxExe / bootState / loadExe),
//   * a deterministic low-noise checkpoint trace (Trace),
//   * an execution probe that records first function entries and keeps an approximate shadow call chain (Probe),
//   * the failure report every unsupported boundary must produce (describeFailure / runBoot),
//   * the MMIO bus entry point (Hardware : MmioHandler, src/boot_hardware.hpp supplies the narrow device models).
// Everything unknown is fatal with a diagnostic; nothing is silently ignored.
#include "bios_boot.hpp"
#include "recomp_context.hpp"
#include <algorithm>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace moyle::detail::recomp::boot {
using u32=std::uint32_t;
inline std::string h8(u32 v){std::ostringstream s;s<<"0x"<<std::hex<<std::setfill('0')<<std::setw(8)<<v;return s.str();}
inline std::string hn(u32 v){std::ostringstream s;s<<"0x"<<std::hex<<v;return s.str();}

// ---------------------------------------------------------------------------------------------------------------------
// PS-X EXE
// ---------------------------------------------------------------------------------------------------------------------
struct PsxExe {
    u32 initialPc=0,gp=0,load=0,textSize=0,dataAddress=0,dataSize=0,bssAddress=0,bssSize=0,stackBase=0,stackOffset=0;
    static constexpr std::size_t headerSize=0x800;
    u32 stackTop() const {return stackBase+stackOffset;}
    u32 imageEnd() const {return load+textSize;}
};
[[noreturn]] inline void exeError(const std::string& why){throw std::runtime_error("PS-X EXE rejected: "+why);}
inline u32 le32(const std::vector<std::uint8_t>& b,std::size_t at){
    if(at+4>b.size())exeError("truncated header");
    return b[at]|(u32(b[at+1])<<8)|(u32(b[at+2])<<16)|(u32(b[at+3])<<24);
}
// Header layout (the PS-X EXE container, 0x800-byte header): +0x00 "PS-X EXE", +0x10 initial PC, +0x14 initial GP,
// +0x18 load address, +0x1c text size, +0x20/+0x24 data address/size, +0x28/+0x2c bss address/size, +0x30 stack base,
// +0x34 stack offset. The data/bss fields are accepted only when zero (the PAL EXE has none); nothing is guessed.
inline PsxExe parsePsxExe(const std::vector<std::uint8_t>& file) {
    static const char magic[8]={'P','S','-','X',' ','E','X','E'};
    if(file.size()<PsxExe::headerSize)exeError("smaller than the 0x800-byte header");
    for(int n=0;n<8;++n)if(file[n]!=std::uint8_t(magic[n]))exeError("bad magic");
    PsxExe e;
    e.initialPc=le32(file,0x10);e.gp=le32(file,0x14);e.load=le32(file,0x18);e.textSize=le32(file,0x1c);
    e.dataAddress=le32(file,0x20);e.dataSize=le32(file,0x24);e.bssAddress=le32(file,0x28);e.bssSize=le32(file,0x2c);
    e.stackBase=le32(file,0x30);e.stackOffset=le32(file,0x34);
    if(!e.textSize||(e.textSize&3U))exeError("text size is zero or not word aligned");
    if(file.size()-PsxExe::headerSize<e.textSize)exeError("file is shorter than header + text size");
    if((e.load&3U)||e.load<0x80010000U||std::uint64_t(e.load)+e.textSize>0x80200000ULL)exeError("load range is not word-aligned KSEG0 RAM above the kernel area");
    if((e.initialPc&3U)||e.initialPc<e.load||e.initialPc>=e.imageEnd())exeError("initial PC is outside the loaded text");
    if(e.dataSize||e.bssSize||e.dataAddress||e.bssAddress)exeError("data/bss header fields are not supported (the PAL EXE has none)");
    if(!e.stackBase)exeError("no stack base in the header (a default would be a guess)");
    const auto top=std::uint64_t(e.stackBase)+e.stackOffset;
    if(top&3U)exeError("initial stack pointer is not word aligned");
    if(top>0x80200000ULL||top<std::uint64_t(e.imageEnd())+0x100U)exeError("initial stack pointer is outside RAM or inside the image");
    if(e.gp&3U)exeError("initial GP is not word aligned");
    return e;
}
struct BootState {u32 pc,sp,gp,ra;};
inline BootState bootState(const PsxExe& e){return {e.initialPc,e.stackTop(),e.gp,hostReturn};}
inline void loadExe(Context& c,const PsxExe& e,const std::vector<std::uint8_t>& file) {
    for(u32 n=0;n<e.textSize;++n)c.ram.bytes[Ps1Memory::offset(e.load+n,1)]=file[PsxExe::headerSize+n];
}
inline void applyBootState(Context& c,const BootState& s) {
    c.r.fill(0);c.hi=c.lo=0;c.loadRegister=0;c.loadValue=0;
    c.r[28]=s.gp;c.r[29]=s.sp;c.r[30]=s.sp;c.r[31]=s.ra;c.pc=s.pc;
}

// ---------------------------------------------------------------------------------------------------------------------
// Deterministic trace: one line per high-value checkpoint, never per instruction.
// ---------------------------------------------------------------------------------------------------------------------
struct Trace {
    std::vector<std::string> lines;
    const Context* ctx=nullptr;
    std::size_t limit=20000; // hard cap; exceeding it is itself a recorded, deterministic event
    bool truncated=false;
    void add(const std::string& kind,const std::string& detail) {
        if(lines.size()>=limit){truncated=true;return;}
        std::ostringstream s;
        s<<std::setw(10)<<std::setfill('0')<<(ctx?ctx->steps:0)<<' '<<kind<<(detail.empty()?"":" ")<<detail;
        lines.push_back(s.str());
    }
    std::string text() const {
        std::string out;for(const auto& l:lines){out+=l;out+='\n';}
        if(truncated)out+="-- trace truncated at "+std::to_string(limit)+" lines\n";
        return out;
    }
};

inline void traceExeEntry(Trace& trace,const PsxExe& exe,const BootState& state) {
    trace.add("exe-entry","pc="+h8(state.pc)+" sp="+h8(state.sp)+" gp="+h8(state.gp)+" ra="+h8(state.ra)+" load="+h8(exe.load)+" text="+hn(exe.textSize));
}

// ---------------------------------------------------------------------------------------------------------------------
// Function map (generated by DirectTitleGenerator: "entry end G|S" lines)
// ---------------------------------------------------------------------------------------------------------------------
struct FunctionRange {u32 entry,end;char kind;};
struct FunctionMap {
    std::vector<FunctionRange> ranges; // ascending by entry
    static FunctionMap parse(const std::string& text) {
        FunctionMap m;std::istringstream in(text);std::string a,b,k;
        while(in>>a>>b>>k){
            if(k.size()!=1||(k[0]!='G'&&k[0]!='S'))throw std::runtime_error("Bad function map line");
            m.ranges.push_back({u32(std::stoul(a,nullptr,0)),u32(std::stoul(b,nullptr,0)),k[0]});
        }
        if(!std::is_sorted(m.ranges.begin(),m.ranges.end(),[](const FunctionRange& x,const FunctionRange& y){return x.entry<y.entry;}))
            throw std::runtime_error("Function map is not sorted");
        return m;
    }
    const FunctionRange* find(u32 pc) const {
        const auto canon=(pc&0x1fffffffU)|0x80000000U;
        auto it=std::upper_bound(ranges.begin(),ranges.end(),canon,[](u32 v,const FunctionRange& r){return v<r.entry;});
        if(it==ranges.begin())return nullptr;
        --it;
        return canon<it->end?&*it:nullptr;
    }
    bool isEntry(u32 pc) const {const auto* r=find(pc);return r&&r->entry==((pc&0x1fffffffU)|0x80000000U);}
};

// ---------------------------------------------------------------------------------------------------------------------
// Probe: first-entry checkpoints, approximate shadow call chain, call budget, explicit stop address.
// ---------------------------------------------------------------------------------------------------------------------
struct StopRequested : std::runtime_error {
    u32 pc;
    StopRequested(u32 at,const std::string& why):std::runtime_error(why),pc(at){}
};
struct CallBudgetExceeded : std::runtime_error {using std::runtime_error::runtime_error;};
struct Probe {
    Trace* trace=nullptr;
    const FunctionMap* map=nullptr;
    std::vector<std::uint8_t> flags=std::vector<std::uint8_t>(0x200000/4);
    static constexpr std::uint8_t entry=1,seen=2,stopHere=4,logEveryEntry=8;
    struct Frame {u32 entry,ra,sp;};
    std::vector<Frame> chain;
    std::map<u32,std::string> names;      // optional human names for checkpoints
    std::uint64_t callBudget=~0ULL;       // maximum Context::calls
    std::uint64_t entries=0;
    std::function<void(Context&,u32 entry)> onFirstEntry; // harness hook for domain checkpoints
    std::function<void(Context&,u32 pc)> onStop;
    std::function<bool(Context&,u32 pc)> beforeInstruction;   // interrupt entry hook; true = Context::redirectPending was set
    static std::size_t index(u32 pc){return (pc&0x1fffffU)>>2;}
    void watchEntries(const FunctionMap& m){
        map=&m;
        for(const auto& r:m.ranges)if(r.kind=='G'||r.kind=='S')flags[index(r.entry)]|=entry;
    }
    void stopAt(u32 pc){flags[index(pc)]|=stopHere;}
    void logAllEntries(u32 pc){flags[index(pc)]|=logEveryEntry;}
    std::string nameOf(u32 pc) const {auto n=names.find(pc);return n==names.end()?std::string():" "+n->second;}
    static void hook(Context& c,u32 pc){static_cast<Probe*>(c.probeState)->visit(c,pc);}
    std::size_t seenBiosCalls=0;
    static constexpr std::size_t biosTraceLimit=64;
    void traceBiosCalls(Context& c) {
        const auto& calls=c.biosDevice->calls;
        for(;seenBiosCalls<calls.size();++seenBiosCalls){
            const auto& k=calls[seenBiosCalls];
            if(!trace)continue;
            if(seenBiosCalls<biosTraceLimit){
                std::ostringstream o;o<<std::hex<<"bios "<<(k.table==0xa0?"A0":k.table==0xb0?"B0":"C0")<<':'<<std::setw(2)<<std::setfill('0')<<k.function
                                      <<" site="<<h8(k.site)<<" a0="<<h8(k.a0)<<" a1="<<h8(k.a1)<<" a2="<<h8(k.a2);
                trace->add("bios",o.str().substr(5));
            }else if(seenBiosCalls==biosTraceLimit)trace->add("bios","further BIOS calls not traced (full list in the report)");
        }
    }
    void visit(Context& c,u32 pc) {
        if(beforeInstruction&&beforeInstruction(c,pc))return;
        if(c.biosDevice&&c.biosDevice->calls.size()!=seenBiosCalls)traceBiosCalls(c);
        if(c.calls>callBudget)throw CallBudgetExceeded("Call budget exceeded");
        auto& f=flags[index(pc)];
        if(!chain.empty()&&chain.back().ra==pc&&c.r[29]>=chain.back().sp)chain.pop_back();
        if(!f)return;
        if(f&stopHere){if(onStop)onStop(c,pc);throw StopRequested(pc,"stop requested at "+h8(pc));}
        if(f&entry){
            ++entries;
            chain.push_back({pc,c.r[31],c.r[29]});
            if(chain.size()>4096)chain.erase(chain.begin(),chain.begin()+2048);
            if(!(f&seen)){
                f|=seen;
                if(trace)trace->add("enter",h8(pc)+nameOf(pc)+" ra="+h8(c.r[31])+" sp="+h8(c.r[29]));
                if(onFirstEntry)onFirstEntry(c,pc);
            } else if(f&logEveryEntry){
                if(trace)trace->add("enter*",h8(pc)+nameOf(pc)+" ra="+h8(c.r[31])+" a0="+h8(c.r[4]));
            }
        }
    }
    void attach(Context& c){c.probe=&Probe::hook;c.probeState=this;}
};

// ---------------------------------------------------------------------------------------------------------------------
// Failure report
// ---------------------------------------------------------------------------------------------------------------------
struct MmioFault : std::runtime_error {
    u32 address,value;unsigned width;bool write;
    MmioFault(u32 a,unsigned w,bool wr,u32 v,const std::string& why)
        :std::runtime_error(describe(a,w,wr,v,why)),address(a),value(v),width(w),write(wr){}
    static std::string describe(u32 a,unsigned w,bool wr,u32 v,const std::string& why) {
        std::ostringstream o;
        o<<"MMIO "<<(wr?"write":"read")<<" at "<<h8(a)<<" width "<<w;
        if(wr)o<<" value "<<h8(v);
        o<<": "<<why;
        return o.str();
    }
};
// Phase 5: a guest access to the kernel RAM window that no evidence supports (src/boot_kernel_ram.hpp).
struct KernelRamFault : std::runtime_error {
    u32 address;unsigned width;bool write;
    KernelRamFault(u32 a,unsigned w,bool wr,const std::string& why)
        :std::runtime_error(describe(a,w,wr,why)),address(a),width(w),write(wr){}
    static std::string describe(u32 a,unsigned w,bool wr,const std::string& why) {
        std::ostringstream o;o<<"Kernel RAM "<<(wr?"write":"read")<<" at "<<h8(a)<<" width "<<w<<": "<<why;return o.str();
    }
};
enum class Outcome {Returned,Stopped,Fault};
struct BootResult {
    Outcome outcome=Outcome::Fault;
    std::string boundaryType;   // classification of the stopping boundary
    std::string message;        // exception text
    std::string report;         // multi-line deterministic diagnostic
};
inline std::string classify(const std::exception& e) {
    const std::string m=e.what();
    if(dynamic_cast<const StopRequested*>(&e))return "requested-stop";
    if(dynamic_cast<const CallBudgetExceeded*>(&e))return "call-budget";
    if(dynamic_cast<const MmioFault*>(&e))return "mmio";
    if(dynamic_cast<const KernelRamFault*>(&e))return "kernel-ram";
    if(dynamic_cast<const GuestBreak*>(&e))return "guest-break";
    if(m.find("Instruction budget exceeded")!=std::string::npos)return "instruction-budget";
    if(m.find("MMIO not implemented")!=std::string::npos)return "mmio";
    if(m.find("BIOS boundary")!=std::string::npos||m.find("BIOS call")!=std::string::npos)return "bios";
    if(m.find("SYSCALL")!=std::string::npos)return "syscall";
    if(m.find("is not generated")!=std::string::npos)return "ungenerated-function";
    if(m.find("Direct TITLE return")!=std::string::npos)return "return-guard";
    if(m.find("Unresolved guest PC")!=std::string::npos)return "unresolved-pc";
    if(m.find("Fatal libcd HLE")!=std::string::npos)return "libcd";
    if(m.find("indirect")!=std::string::npos||m.find("callback")!=std::string::npos||m.find("cell")!=std::string::npos||m.find("table")!=std::string::npos)return "indirect-guard";
    return "other";
}
inline std::string describeFailure(const Context& c,const std::exception& e,const FunctionMap* map,const Probe* probe,
                                   std::uint64_t startSteps,std::uint64_t budget,const std::string& boundaryType) {
    std::ostringstream o;
    o<<"boundary: "<<boundaryType<<"\n"
     <<"message: "<<e.what()<<"\n"
     <<"guest pc: "<<h8(c.pc)<<"\n";
    if(map){
        const auto* f=map->find(c.pc);
        if(f)o<<"containing function: "<<h8(f->entry)<<".."<<h8(f->end)<<(f->kind=='S'?" (boundary stub)":" (generated)")<<"\n";
        else o<<"containing function: none (pc is outside every generated extent)\n";
    }
    if(const auto* m=dynamic_cast<const MmioFault*>(&e))
        o<<"mmio: "<<(m->write?"write":"read")<<" address "<<h8(m->address)<<" width "<<m->width<<(m->write?" value "+h8(m->value):"")<<"\n";
    if(const auto* k=dynamic_cast<const KernelRamFault*>(&e))
        o<<"kernel ram: "<<(k->write?"write":"read")<<" address "<<h8(k->address)<<" width "<<k->width<<"\n";
    if(const auto* b=dynamic_cast<const GuestBreak*>(&e))o<<"break: word "<<h8(b->word)<<" raw code "<<hn(b->rawCode)<<"\n";
    static const char* names[32]={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7",
                                  "s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","fp","ra"};
    o<<"registers:";
    for(int n=0;n<32;++n){if(n%4==0)o<<"\n  ";o<<names[n]<<"="<<h8(c.r[n])<<' ';}
    o<<"\n  hi="<<h8(c.hi)<<" lo="<<h8(c.lo)<<" pending-load r"<<c.loadRegister<<"="<<h8(c.loadValue)<<"\n";
    const auto used=c.steps-startSteps;
    o<<"instructions executed this run: "<<used<<", remaining budget: "<<(budget>used?budget-used:0)<<"\n"
     <<"calls (transfers): "<<c.calls<<"\n";
    if(probe){
        o<<"call depth (approximate shadow chain, innermost last): "<<probe->chain.size()<<"\n";
        const std::size_t from=probe->chain.size()>12?probe->chain.size()-12:0;
        for(std::size_t n=from;n<probe->chain.size();++n)o<<"  "<<h8(probe->chain[n].entry)<<" ra="<<h8(probe->chain[n].ra)<<" sp="<<h8(probe->chain[n].sp)<<"\n";
    }
    return o.str();
}

// ---------------------------------------------------------------------------------------------------------------------
// Run driver: executes the unit once and converts every non-return into a deterministic BootResult.
// ---------------------------------------------------------------------------------------------------------------------
using ExecuteFn=void(*)(Context&,u32,std::uint64_t);
inline BootResult runBoot(Context& c,ExecuteFn execute,u32 entry,std::uint64_t budget,const FunctionMap* map,Probe* probe) {
    BootResult r;const auto startSteps=c.steps;
    try{
        execute(c,entry,budget);
        r.outcome=Outcome::Returned;r.boundaryType="returned";r.message="the unit returned to the host sentinel";
        r.report="boundary: returned\nguest pc: "+h8(c.pc)+"\n";
    }catch(const StopRequested& e){
        r.outcome=Outcome::Stopped;r.boundaryType="requested-stop";r.message=e.what();
        r.report=describeFailure(c,e,map,probe,startSteps,budget,r.boundaryType);
    }catch(const std::exception& e){
        r.outcome=Outcome::Fault;r.boundaryType=classify(e);r.message=e.what();
        r.report=describeFailure(c,e,map,probe,startSteps,budget,r.boundaryType);
    }
    return r;
}
}
