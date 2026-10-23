#pragma once
// First-boot paced libcd adapter (Stage A+B). It sits in front of the existing cdhle::CdDrive / cdhle::control /
// cdhle::cdGetSector / cdhle::invokeGuestCallback and adds only what the proven PAL contract needs on top of them:
//   * strict (command, return address) guards on the four libcd entries the loader(78) path reaches,
//   * the status cell M[0x8005FDB8] and the guest return (cdhle::hleReturn only sets Context::pc),
//   * sector timing on a fixed deadline grid (one sector per safe point at most, never ahead of the grid),
//   * the nested guest DataReady callback with first-boot state (IRQ gate, Probe shadow chain, redirect) wrapped around it.
// cdhle::pump / cdStatus / cdReadCallback / registerPalLibcd / cdSync are deliberately NOT used. Everything unexpected is fatal.
#include "boot_harness.hpp"
#include "libcd_hle.hpp"
#include <sstream>

namespace moyle::detail::recomp::firstboot {
struct CdPolicy {
    // Wiring (set by the harness).
    boot::Trace* trace=nullptr;
    boot::Probe* probe=nullptr;
    boot::ExecuteFn execute=nullptr;
    // Pacing state; cdhle::CdDrive itself stays unchanged.
    std::uint64_t due=0,interval=0;
    unsigned readsStarted=0;
    // Diagnostics.
    std::uint64_t commandsHandled=0,gateBlocked=0,callbacksReturned=0;

    static constexpr std::uint32_t cdControlB=0x800469d4U,cdControl=0x80046764U,cdSync=0x800466fcU,cdGetSector=0x80046b40U;
    static constexpr std::uint32_t cdStatusPc=0x800465b8U,pollHead=0x800448a4U;
    static constexpr std::uint32_t statusCell=0x8005fdb8U,readyCell=0x8005fdb0U,resultBuffer=0x80069588U,callbackPc=0x800410dcU;
    // Resources the loader (0x800415E0) requests. The loader walks the PAL's own resource table: 113 entries of 16 bytes at tableBase,
    // filled by 0x80040EF4 from the static array at staticArray (8 bytes each: logical LBA, size in bytes; CdIntToPos adds the 150 sector
    // lead-in to form the entry's CdlLOC at +12, the size lands at +8). The loader's s0 holds the entry when it issues SeekL (ra 0x8004181C).
    // A SeekL is accepted only if s0 is exactly one of the 113 entries and the PAL's own data agree: the SeekL position equals the static
    // array's LBA, the entry's +8 size equals the static size, and the window is [LBA, LBA + ceil(size/2048) - 1]. Proven by real runs for
    // entries 78, 79, 80, 1 (each read as N-1 sectors plus one continuation ReadN at the last sector, all inside the window). Every other
    // request shape (other tuples, unknown entry, mismatching data, a read outside the window) stays fatal.
    struct Resource{std::uint32_t index=0,start=0,last=0;};
    static constexpr std::uint32_t tableBase=0x8005f248U,staticArray=0x8005eec0U,tableEntries=113U;
    Resource currentResource;
    const Resource* current=nullptr;   // resource of the last accepted SeekL
    bool sought=false;                  // a SeekL was accepted and its first ReadN has not started yet
    static constexpr std::uint64_t doubleSpeed=112896ULL,singleSpeed=225792ULL,nestedBudget=1000000ULL;

    bool callbackActive(const Context& c) const {return c.cd&&c.cd->inCallback;}

    bool before(Context& c,std::uint32_t pc) {
        switch(pc){
        case cdControlB:return command(c,pc,true);
        case cdControl:return command(c,pc,false);
        case cdSync:return sync(c,pc);
        case cdGetSector:return getSector(c,pc);
        case cdStatusPc:
        case pollHead:pump(c,pc);return false;   // CdStatus stays generated code after the pump
        default:return false;
        }
    }

private:
    struct Tuple{std::uint32_t command,ra;bool callbackOnly;};
    static bool allowed(const Tuple* t,std::size_t n,std::uint32_t command,std::uint32_t ra,bool inCallback) {
        for(std::size_t i=0;i<n;++i)if(t[i].command==command&&t[i].ra==ra)return t[i].callbackOnly==inCallback;
        return false;
    }
    static bios::BootDevice& device(Context& c,std::uint32_t pc) {
        auto* d=static_cast<bios::BootDevice*>(c.biosDevice);
        if(!d)cdhle::hleFail(pc,"no BIOS device attached");
        return *d;
    }
    void note(const std::string& text) const {if(trace)trace->add("first-boot-cd",text);}
    static void redirectToCaller(Context& c) {c.redirectPending=true;c.redirectPc=c.r[31];}
    // Every handled CD call: keep the status cell in step with the drive and return to the guest caller.
    static void finish(Context& c,cdhle::CdDrive& d,std::uint32_t value) {
        c.ram.write(statusCell,d.status(),1);
        cdhle::hleReturn(c,value);
        redirectToCaller(c);
    }
    // SeekL: the loader's s0 must hold a table entry and the PAL's own static data must agree with the SeekL position and the entry size.
    const Resource* seekResource(Context& c,std::uint32_t pc,std::uint32_t setloc) {
        const auto entry=c.r[16];
        const std::uint32_t span=16U*tableEntries;
        if(entry<tableBase||entry-tableBase>=span||((entry-tableBase)&15U)!=0U){
            std::ostringstream s;s<<"SeekL (LBA "<<setloc<<") from s0=0x"<<std::hex<<entry<<" is not an entry of the PAL resource table";
            cdhle::hleFail(pc,s.str());
        }
        const auto index=(entry-tableBase)/16U;
        const auto lba=c.ram.read(staticArray+8U*index,4),staticSize=c.ram.read(staticArray+8U*index+4U,4),size=c.ram.read(entry+8U,4);
        const std::uint64_t sectors=(std::uint64_t(size)+2047U)/2048U;
        if(setloc!=lba||size!=staticSize||sectors==0U){
            std::ostringstream s;s<<"resource "<<index<<": SeekL LBA "<<setloc<<" / table size 0x"<<std::hex<<size<<" disagree with the PAL static array (LBA "
                                  <<std::dec<<lba<<", size 0x"<<std::hex<<staticSize<<")";
            cdhle::hleFail(pc,s.str());
        }
        currentResource.index=index;currentResource.start=setloc;currentResource.last=std::uint32_t(std::uint64_t(setloc)+sectors-1U);
        return &currentResource;
    }

    bool command(Context& c,std::uint32_t pc,bool blocking) {
        auto& d=cdhle::drive(c,pc);
        auto& dev=device(c,pc);
        if(dev.interruptDepth)cdhle::hleFail(pc,"CD command inside an interrupt service routine");
        c.retireLoad();
        static constexpr Tuple viaControlB[]={{0x0eU,0x8004178cU,false},{0x01U,0x800417f0U,false},{0x15U,0x8004181cU,false}};
        static constexpr Tuple viaControl[]={{0x06U,0x80041268U,false},{0x09U,0x80040f20U,false},{0x09U,0x800411d0U,true}};
        const auto cmd=c.r[4],ra=c.r[31];
        const bool ok=blocking?allowed(viaControlB,3,cmd,ra,d.inCallback):allowed(viaControl,3,cmd,ra,d.inCallback);
        if(!ok){
            std::ostringstream s;
            s<<(blocking?"CdControlB":"CdControl")<<" tuple is not part of the loader(78) contract: command 0x"<<std::hex<<cmd
             <<", ra 0x"<<ra<<(d.inCallback?" (inside the callback)":"");
            cdhle::hleFail(pc,s.str());
        }
        std::uint64_t newInterval=0;
        if(cmd==cdhle::Setmode){
            const auto param=c.r[5];
            if(!param)cdhle::hleFail(pc,"Setmode without parameter");
            const auto mode=c.ram.read(param,1);
            if(mode==0x80U)newInterval=doubleSpeed;
            else if(mode==0x00U)newInterval=singleSpeed;
            else{std::ostringstream s;s<<"Setmode value 0x"<<std::hex<<mode<<" is neither 0x80 nor 0x00";cdhle::hleFail(pc,s.str());}
        }else if(cmd==cdhle::SeekL){
            if(d.reading)cdhle::hleFail(pc,"SeekL while a read is active");
        }else if(cmd==cdhle::ReadN){
            if(d.reading)cdhle::hleFail(pc,"ReadN while a read is already active");
            if(d.sectorReady)cdhle::hleFail(pc,"ReadN with an unconsumed sector latch");
            if(!d.source)cdhle::hleFail(pc,"ReadN without a disc");
            if(!interval)cdhle::hleFail(pc,"ReadN before Setmode: the sector interval is unknown");
            if(!current)cdhle::hleFail(pc,"ReadN without a SeekL to a proven resource");
        }
        cdhle::control(c,pc,blocking);
        ++commandsHandled;
        std::ostringstream o;o<<std::dec;
        if(cmd==cdhle::Setmode){
            interval=newInterval;
            o<<"Setmode mode=0x"<<std::hex<<unsigned(d.mode)<<std::dec<<" interval="<<interval;
        }else if(cmd==cdhle::Getstat){
            o<<"Getstat status=0x"<<std::hex<<unsigned(d.status());
        }else if(cmd==cdhle::SeekL){
            current=seekResource(c,pc,d.setloc);sought=true;
            o<<"SeekL lba="<<d.setloc<<" resource="<<current->index<<" window="<<current->start<<".."<<current->last;
        }else if(cmd==cdhle::ReadN){
            if((sought&&d.next!=current->start)||d.next<current->start||d.next>current->last){
                std::ostringstream s;s<<"ReadN begins at LBA "<<d.next<<", outside resource "<<current->index<<" window "<<current->start<<".."<<current->last
                                      <<(sought?" (the first read must start at the SeekL position)":"");
                cdhle::hleFail(pc,s.str());
            }
            sought=false;
            ++readsStarted;
            due=c.steps+interval;
            o<<"ReadN armed read="<<readsStarted<<" lba="<<d.next<<" due="<<due<<" interval="<<interval;
        }else{ // Pause
            o<<"Pause"<<(d.inCallback?" (inside callback)":"")<<" delivered="<<d.delivered<<" consumed="<<d.consumed;
        }
        note(o.str());
        finish(c,d,1U);
        return true;
    }

    // Guarded replacement for cdhle::cdSync (which ignores the mode and the caller): mode 1, result into the loader's buffer.
    bool sync(Context& c,std::uint32_t pc) {
        auto& d=cdhle::drive(c,pc);
        auto& dev=device(c,pc);
        c.retireLoad();
        if(dev.interruptDepth||d.inCallback||c.r[4]!=1U||c.r[5]!=resultBuffer||c.r[31]!=0x80040f34U){
            std::ostringstream s;
            s<<"CdSync tuple is not part of the loader(78) contract: mode 0x"<<std::hex<<c.r[4]<<", result 0x"<<c.r[5]<<", ra 0x"<<c.r[31];
            cdhle::hleFail(pc,s.str());
        }
        c.ram.write(resultBuffer,d.status(),1);
        finish(c,d,cdhle::complete);
        return true;
    }

    bool getSector(Context& c,std::uint32_t pc) {
        auto& d=cdhle::drive(c,pc);
        c.retireLoad();
        const auto ra=c.r[31],dest=c.r[4],words=c.r[5];
        if(!d.inCallback)cdhle::hleFail(pc,"CdGetSector outside the DataReady callback");
        if(ra!=0x80041110U&&ra!=0x8004115cU){std::ostringstream s;s<<"CdGetSector from unexpected ra 0x"<<std::hex<<ra;cdhle::hleFail(pc,s.str());}
        if(words!=512U)cdhle::hleFail(pc,"CdGetSector word count is not 512");
        if(d.sectorCursor!=0U)cdhle::hleFail(pc,"CdGetSector with a partially consumed latch");
        if(dest&3U)cdhle::hleFail(pc,"CdGetSector destination is not 4-byte aligned");
        const auto route=Ps1Memory::route(dest);
        if(route.region!=MemoryRegion::Ram||route.offset+cd::userBytes>c.ram.bytes.size())cdhle::hleFail(pc,"CdGetSector destination is outside RAM");
        const std::uint64_t before=d.consumed;const std::uint32_t lba=d.sectorLba;
        cdhle::cdGetSector(c,pc,0);
        if(d.sectorReady||d.consumed!=before+1)cdhle::hleFail(pc,"CdGetSector did not consume the latch");
        std::ostringstream o;o<<"CdGetSector consumed lba="<<std::dec<<lba<<" dest=0x"<<std::hex<<dest;
        note(o.str());
        finish(c,d,1U);
        return true;
    }

    // Safe point: deliver at most one sector, only on or after its deadline and only when the guest could take the interrupt.
    void pump(Context& c,std::uint32_t pc) {
        auto& d=cdhle::drive(c,pc);
        if(!d.reading||c.steps<due)return;
        auto& dev=device(c,pc);
        if(!dev.irqEnabled||dev.interruptDepth||d.inCallback||c.redirectPending){++gateBlocked;return;}
        if(pc==cdStatusPc&&c.r[31]!=0x80041864U&&c.r[31]!=0x800448d0U){
            std::ostringstream s;s<<"CdStatus polled from unexpected ra 0x"<<std::hex<<c.r[31]<<" while a read is active";cdhle::hleFail(pc,s.str());
        }
        if(!current)cdhle::hleFail(pc,"a sector is due without a proven resource");
        const auto last=current->last;
        if(d.next>last){
            std::ostringstream s;s<<"sector LBA "<<d.next<<" is due beyond the read window ending at LBA "<<last;cdhle::hleFail(pc,s.str());
        }
        if(d.sectorReady){
            std::ostringstream s;s<<"CD overrun: LBA "<<d.next<<" is due while LBA "<<d.sectorLba<<" is still unconsumed";cdhle::hleFail(pc,s.str());
        }
        const auto cell=c.ram.read(readyCell,4);
        if(cell!=callbackPc){
            std::ostringstream s;s<<"ready callback cell holds 0x"<<std::hex<<cell<<" while reading, expected 0x"<<callbackPc;cdhle::hleFail(pc,s.str());
        }
        if(!execute||lookupDynamic(c,cdhle::callbackReturn,callbackPc).function!=execute)
            cdhle::hleFail(pc,"the DataReady callback backend is not the Direct TITLE unit");
        d.sector=d.source->read(d.next);d.sectorLba=d.next++;d.sectorReady=true;d.sectorCursor=0;++d.delivered;
        std::ostringstream o;o<<"deliver lba="<<std::dec<<d.sectorLba<<" at pc=0x"<<std::hex<<pc<<std::dec<<" steps="<<c.steps<<" due="<<due;
        note(o.str());
        runCallback(c,pc,dev,d);
        due+=interval;
    }

    void runCallback(Context& c,std::uint32_t pc,bios::BootDevice& dev,cdhle::CdDrive& d) {
        struct Busy{bool& flag;explicit Busy(bool& f):flag(f){flag=true;}~Busy(){flag=false;}} busy(d.inCallback);
        const bool irq=dev.irqEnabled;
        const auto depth=dev.interruptDepth;
        const auto frames=dev.frames.size();
        const auto mark=probe?probe->chain.size():std::size_t(0);
        const bool redirect=c.redirectPending;
        const auto redirectPc=c.redirectPc;
        dev.irqEnabled=false;   // the guest callback runs as interrupt context
        cdhle::invokeGuestCallback(c,callbackPc,1U,resultBuffer,nestedBudget);
        if(c.redirectPending)cdhle::hleFail(pc,"a redirect was left pending after the DataReady callback");
        if(dev.interruptDepth!=depth||dev.frames.size()!=frames)cdhle::hleFail(pc,"the DataReady callback changed the interrupt frame state");
        dev.irqEnabled=irq;
        if(probe&&probe->chain.size()>mark)probe->chain.resize(mark);   // the sentinel return is never visited: drop the callback's frame
        c.redirectPending=redirect;c.redirectPc=redirectPc;
        ++callbacksReturned;
    }
};
}
