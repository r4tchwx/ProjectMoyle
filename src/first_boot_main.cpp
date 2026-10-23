// Phase 4 opt-in harness: boots the real SLES_017.26 through the generated Direct TITLE unit.
// Usage: direct_title_boot EXE MAP --disc FILE [--budget N] [--call-budget N] [--trace FILE] [--stop PC]... [--boot-card]
// The EXE and any TITLE image are read-only external inputs; nothing proprietary is written except the trace text.
#include "boot_hardware.hpp"
#include "boot_kernel_ram.hpp"
#include "first_boot.hpp"
#include "first_boot_cd.hpp"
#include <fstream>
#include <iostream>
#include <iterator>

namespace moyle::detail::recomp {void executeDirectTitle(Context&,std::uint32_t,std::uint64_t);}
using namespace moyle::detail::recomp;
#ifdef MOYLE_PAL_LANGUAGE_UNIT
// The PAL type-2 overlay: the five public entries reached by --external-entry JALs go through the selector, which runs the
// executor generated locally from the user's external LANGUAGE image (build/generated, never committed). Without this
// build option no overlay entry is registered and such a JAL is a fatal "unregistered recomp target".
#include "overlay_dispatch.hpp"
#include <map>
namespace moyle::detail::recomp {void executePalLanguage(Context&,std::uint32_t,std::uint64_t);}
namespace {
struct OverlayStats {
    std::uint64_t calls=0,returns=0,firstSteps=0;std::uint32_t firstEntry=0,firstContinuation=0,lastEntry=0,lastContinuation=0;
    std::map<std::uint32_t,std::uint64_t> perEntry;
} overlayStats;
void palOverlay(Context& c,std::uint32_t entry,std::uint64_t budget){
    const auto continuation=c.r[31];
    if(!overlayStats.calls){overlayStats.firstEntry=entry;overlayStats.firstContinuation=continuation;overlayStats.firstSteps=c.steps;}
    ++overlayStats.calls;++overlayStats.perEntry[canonicalCodeAddress(entry)];overlayStats.lastEntry=entry;overlayStats.lastContinuation=continuation;
    overlay::selectAndExecute(c,entry,budget,{{&overlay::palLanguage,executePalLanguage}});
    ++overlayStats.returns;
}
}
#endif

namespace {
std::vector<std::uint8_t> slurp(const std::string& path){
    std::ifstream in(path,std::ios::binary);if(!in)throw std::runtime_error("Cannot read "+path);
    return {std::istreambuf_iterator<char>(in),{}};
}
}
int main(int argc,char** argv){
    try{
        if(argc<3)throw std::runtime_error("Usage: direct_title_boot EXE MAP --disc FILE [--budget N] [--call-budget N] [--trace FILE] [--stop PC]... [--peek ADDR WORDS]... [--boot-card]");
        std::uint64_t budget=50000000ULL,callBudget=~0ULL;std::string traceFile,discFile;std::vector<std::uint32_t> stops;bool card=true;std::vector<std::pair<std::uint32_t,std::uint32_t>> peeks;
        for(int i=3;i<argc;){const std::string o=argv[i++];
            if(o=="--budget"&&i<argc)budget=std::stoull(argv[i++],nullptr,0);
            else if(o=="--call-budget"&&i<argc)callBudget=std::stoull(argv[i++],nullptr,0);
            else if(o=="--trace"&&i<argc)traceFile=argv[i++];
            else if(o=="--disc"&&i<argc)discFile=argv[i++];
            else if(o=="--boot-card")card=true;
            else if(o=="--stop"&&i<argc)stops.push_back(std::uint32_t(std::stoul(argv[i++],nullptr,0)));
            else if(o=="--peek"&&i+1<argc){const auto a=std::uint32_t(std::stoul(argv[i],nullptr,0));const auto n=std::uint32_t(std::stoul(argv[i+1],nullptr,0));i+=2;peeks.emplace_back(a,n);}
            else throw std::runtime_error("Invalid arguments");
        }
        if(discFile.empty())throw std::runtime_error("--disc FILE (raw 2352-byte Mode 2 disc image) is required");
        const auto file=slurp(argv[1]);
        const auto mapText=slurp(argv[2]);
        const auto map=boot::FunctionMap::parse(std::string(mapText.begin(),mapText.end()));
        const auto exe=boot::parsePsxExe(file);
        auto context=std::make_unique<Context>();auto& c=*context;
        boot::Trace trace;trace.ctx=&c;
        firstboot::Device device;device.cardInitEnabled=card;device.bringupTrace=&trace;boot::Hardware hardware;hardware.trace=&trace;hardware.ctx=&c;
        c.ram.recordEffects=false;c.ram.mmio=&hardware;
        boot::KernelRamGuard kernelRam;kernelRam.trace=&trace;kernelRam.ctx=&c;
        if(card)c.ram.guard=&kernelRam; // card variant only: Phase 4 behaviour is untouched
        c.biosPolicy=firstboot::biosPolicy;c.syscallPolicy=bios::bootSyscall;c.biosDevice=&device;
        // Host CD: read-only raw disc, the existing libcd drive state, and a registry that only knows the DataReady callback backend.
        moyle::detail::cd::DiscImage disc(discFile,moyle::detail::cd::ImageLayout::Raw2352Mode2Form1);
        cdhle::CdDrive drive;drive.source=&disc;c.cd=&drive;
        DynamicRegistry registry;registry.add(0x800410dcU,executeDirectTitle);c.registry=&registry;
#ifdef MOYLE_PAL_LANGUAGE_UNIT
        for(auto e:overlay::entries)registry.add(e,palOverlay);
#endif
        boot::loadExe(c,exe,file);
        const auto state=boot::bootState(exe);boot::applyBootState(c,state);
        boot::Probe probe;probe.trace=&trace;probe.watchEntries(map);probe.callBudget=callBudget;probe.attach(c);
        for(auto s:stops)probe.stopAt(s);
        boot::InterruptEntry irq;irq.hw=&hardware;irq.trace=&trace;irq.probe=&probe;irq.map=&map;
        firstboot::Policy bringup; bringup.trace=&trace;
        firstboot::CdPolicy cdp;cdp.trace=&trace;cdp.probe=&probe;cdp.execute=executeDirectTitle;
        probe.beforeInstruction=[&](Context& cc,std::uint32_t pc){
            if(cdp.before(cc,pc))return true;
            if(bringup.before(cc,pc))return true;
            if(cdp.callbackActive(cc))return false;
            return irq.poll(cc,pc);
        };
        boot::traceExeEntry(trace,exe,state);
        const auto result=boot::runBoot(c,executeDirectTitle,state.pc,budget,&map,&probe);
        trace.add("end",result.boundaryType);
        for(const auto& call:device.calls)(void)call;
        if(!traceFile.empty()){std::ofstream out(traceFile,std::ios::binary);out<<trace.text();}
        else std::cout<<trace.text();
        std::cout<<"---\n"<<result.report;
        if(card)std::cout<<"card init: calls="<<device.cardInit.calls<<" pad_enable="<<device.cardInit.padEnable<<"\n";
        if(card){
            std::cout<<"kernel ram: reads="<<kernelRam.reads<<" writes="<<kernelRam.writes<<" written-ranges:";
            for(const auto& r:kernelRam.writtenRanges())std::cout<<" ["<<boot::h8(r.first)<<","<<boot::h8(r.second)<<")";
            std::cout<<"\n";
            for(const auto& kv:kernelRam.readWords)std::cout<<"  kernel-ram read word "<<boot::h8(kv.first)<<" x"<<kv.second<<"\n";
        }
        std::cout<<"interrupts: entered="<<device.interruptsEntered<<" returned="<<device.interruptsReturned<<" vblank-edges="<<hardware.edgesSeen<<"\n";
        for(const auto& kv:hardware.counts)std::cout<<"  mmio-count "<<kv.first<<" = "<<kv.second<<"\n";
        std::cout<<"gpu uploads: completed="<<hardware.uploadsCompleted<<" pio-words="<<hardware.uploadWordsPio<<" dma-words="<<hardware.uploadWordsDma
                 <<" dma2-block-uploads="<<hardware.dma2BlockUploads<<" gp0-80-move-images="<<hardware.gp0MoveImages<<" gp0-01-nops="<<hardware.gp0ResetNops<<" pending="<<(hardware.upState!=boot::Hardware::UpState::Idle?"yes":"no")<<"\n";
        for(const auto& u:hardware.uploads)std::cout<<"  upload rect("<<u.x<<","<<u.y<<","<<u.w<<","<<u.h<<") words="<<u.totalWords<<" pio="<<u.pioWords<<" dma="<<u.dmaWords<<" hash="<<boot::h8(std::uint32_t(u.hash>>32))<<boot::h8(std::uint32_t(u.hash)).substr(2)<<"\n";
        std::cout<<"spu dma: transfers="<<hardware.spuDmaTransfers<<" bytes="<<hardware.spuDmaBytes<<" dma4-interrupts="<<hardware.dma4Interrupts<<"\n";
        for(const auto& t:hardware.spuDmas)std::cout<<"  spu-dma ram="<<boot::h8(t.madr)<<" spu="<<boot::h8(t.spuAddress)<<" bytes="<<t.bytes<<" hash="<<boot::h8(std::uint32_t(t.hash>>32))<<boot::h8(std::uint32_t(t.hash)).substr(2)<<"\n";
        for(const auto& m:hardware.moves)std::cout<<"  move-image ("<<m.sx<<","<<m.sy<<") -> ("<<m.dx<<","<<m.dy<<") "<<m.w<<"x"<<m.h<<"\n";
        std::cout<<"cd: reads="<<cdp.readsStarted<<" delivered="<<drive.delivered<<" consumed="<<drive.consumed<<" overrun="<<drive.overrun
                 <<" callbacks-returned="<<cdp.callbacksReturned<<" gate-blocked="<<cdp.gateBlocked<<" commands="<<cdp.commandsHandled
                 <<" reading="<<drive.reading<<" next-lba="<<drive.next<<" due="<<cdp.due<<" interval="<<cdp.interval<<"\n";
        std::cout<<"bios console: ["<<device.console<<"]\n";
#ifdef MOYLE_PAL_LANGUAGE_UNIT
        std::cout<<"overlay (PAL LANGUAGE unit): calls="<<overlayStats.calls<<" returned="<<overlayStats.returns;
        if(overlayStats.calls)std::cout<<" first-entry="<<boot::h8(overlayStats.firstEntry)<<" first-continuation="<<boot::h8(overlayStats.firstContinuation)
                                       <<" first-at-steps="<<overlayStats.firstSteps<<" last-entry="<<boot::h8(overlayStats.lastEntry)
                                       <<" last-continuation="<<boot::h8(overlayStats.lastContinuation);
        std::cout<<"\n";
        for(const auto& kv:overlayStats.perEntry)std::cout<<"  overlay-entry "<<boot::h8(kv.first)<<" calls="<<kv.second<<"\n";
#endif
        // Diagnostic only: read-only dump of RAM words at the stop (--peek ADDR WORDS); never changes the run.
        for(const auto& pk:peeks){
            for(std::uint32_t n=0;n<pk.second&&n<4096U;++n){
                const auto a=pk.first+4U*n;
                if(n%4==0)std::cout<<"peek "<<boot::h8(a)<<":";
                std::cout<<" "<<boot::h8(c.ram.read(a,4)).substr(2);
                if(n%4==3||n+1==pk.second)std::cout<<"\n";
            }
        }
        return result.outcome==boot::Outcome::Fault?2:0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}



