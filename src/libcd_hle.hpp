#pragma once
#include "cd_backing.hpp"
#include "recomp_dispatch.hpp"
#include <array>
#include <vector>

// Minimal HLE of the PsyQ libcd entries used by the PAL loader path A
// (CdControlB/CdControl/CdReadCallback/CdGetSector/CdStatus/CdSync).
// Commands complete immediately; data sectors are delivered on demand only.
namespace moyle::detail::recomp::cdhle {
enum Command:std::uint8_t{Getstat=0x01,Setloc=0x02,ReadN=0x06,Pause=0x09,Setmode=0x0e,SeekL=0x15};
inline constexpr std::uint8_t statusStandby=0x02,statusRead=0x20;
inline constexpr std::uint32_t complete=2; // CdlComplete
struct CommandRecord{std::uint8_t command;bool blocking;};
struct CdDrive {
    const cd::SectorSource* source=nullptr;
    std::uint8_t mode=0;
    std::uint32_t setloc=0,next=0;      // LBA of the last Setloc/SeekL and of the next ReadN sector
    bool reading=false;
    std::uint32_t readCallback=0;       // guest function registered by CdReadCallback
    bool sectorReady=false;
    cd::Sector sector{};
    std::uint32_t sectorLba=0,sectorCursor=0;
    std::uint64_t delivered=0,consumed=0,overrun=0;
    bool inCallback=false;
    std::vector<CommandRecord> commands;
    std::uint8_t status() const noexcept{return static_cast<std::uint8_t>(statusStandby|(reading?statusRead:0));}
};
[[noreturn]] inline void hleFail(std::uint32_t entry,const std::string& what){
    std::ostringstream s;s<<"Fatal libcd HLE at 0x"<<std::hex<<entry<<": "<<what;throw std::runtime_error(s.str());
}
inline CdDrive& drive(Context& c,std::uint32_t entry){if(!c.cd)hleFail(entry,"no CD drive attached");return *c.cd;}
inline void hleReturn(Context& c,std::uint32_t value){c.retireLoad();c.r[2]=value;c.pc=c.r[31];}
inline std::uint32_t readLoc(Context& c,std::uint32_t entry,std::uint32_t loc){
    if(!loc)hleFail(entry,"CdlLOC pointer is null");
    try{return cd::msfToLba({static_cast<std::uint8_t>(c.ram.read(loc,1)),static_cast<std::uint8_t>(c.ram.read(loc+1,1)),
                             static_cast<std::uint8_t>(c.ram.read(loc+2,1))});}
    catch(const cd::CdError& e){hleFail(entry,e.what());}
}
inline void control(Context& c,std::uint32_t entry,bool blocking){
    auto& d=drive(c,entry);
    const auto command=static_cast<std::uint8_t>(c.r[4]);const auto param=c.r[5],result=c.r[6];
    d.commands.push_back({command,blocking});
    switch(command){
    case Getstat:break;
    case Setloc:d.setloc=readLoc(c,entry,param);break;
    case SeekL:d.setloc=readLoc(c,entry,param);d.reading=false;break;
    case Setmode:if(!param)hleFail(entry,"Setmode without parameter");d.mode=static_cast<std::uint8_t>(c.ram.read(param,1));break;
    case ReadN:
        if(!d.source)hleFail(entry,"ReadN without a sector source");
        if(param)d.setloc=readLoc(c,entry,param);
        d.reading=true;d.next=d.setloc;d.sectorReady=false;break;
    case Pause:d.reading=false;break;
    default:{std::ostringstream s;s<<"unsupported CD command 0x"<<std::hex<<unsigned(command);hleFail(entry,s.str());}
    }
    if(result)c.ram.write(result,d.status(),1);
}
// CdControlB / CdControl (int com, u_char* param, u_char* result) -> 1
inline void cdControlB(Context& c,std::uint32_t entry,std::uint64_t){control(c,entry,true);hleReturn(c,1);}
inline void cdControl(Context& c,std::uint32_t entry,std::uint64_t){control(c,entry,false);hleReturn(c,1);}
// CdReadCallback(func) -> previous func
inline void cdReadCallback(Context& c,std::uint32_t entry,std::uint64_t){
    auto& d=drive(c,entry);const auto previous=d.readCallback;d.readCallback=c.r[4];hleReturn(c,previous);
}
// CdGetSector(void* dest, int words) -> 1; copies from the delivered sector.
inline void cdGetSector(Context& c,std::uint32_t entry,std::uint64_t){
    auto& d=drive(c,entry);const auto dest=c.r[4],words=c.r[5];
    if(!d.sectorReady)hleFail(entry,"CdGetSector without a delivered sector");
    if(words>(cd::userBytes-d.sectorCursor)/4)hleFail(entry,"CdGetSector beyond the 2048-byte sector");
    for(std::uint32_t n=0;n<words*4;++n)c.ram.write(dest+n,d.sector[d.sectorCursor+n],1);
    d.sectorCursor+=words*4;
    if(d.sectorCursor==cd::userBytes){d.sectorReady=false;++d.consumed;}
    hleReturn(c,1);
}
// CdSync(mode, result) -> CdlComplete: every command completes immediately.
inline void cdSync(Context& c,std::uint32_t entry,std::uint64_t){
    auto& d=drive(c,entry);if(c.r[5])c.ram.write(c.r[5],d.status(),1);hleReturn(c,complete);
}
inline constexpr std::uint8_t dataReady=1;          // CdlDataReady, first callback argument
inline constexpr std::uint32_t callbackReturn=0x00000084U; // host sentinel RA, never guest code
// Interrupt-style call of a guest callback through the dynamic registry. The
// interrupted guest state (GPRs, HI/LO, pending load, PC) is restored afterwards.
// An unregistered callback is fatal: no host substitute is invented.
inline void invokeGuestCallback(Context& c,std::uint32_t target,std::uint32_t a0,std::uint32_t a1,std::uint64_t budget){
    const auto r=c.r;const auto hi=c.hi,lo=c.lo,pc=c.pc;const auto loadRegister=c.loadRegister;const auto loadValue=c.loadValue;
    c.loadRegister=0;c.r[4]=a0;c.r[5]=a1;c.r[31]=callbackReturn;
    const auto callee=lookupDynamic(c,callbackReturn,target);
    callee.function(c,callee.guest,budget);
    if(c.pc!=callbackReturn){std::ostringstream s;s<<"guest callback 0x"<<std::hex<<target<<" did not return";throw std::runtime_error(s.str());}
    c.r=r;c.hi=hi;c.lo=lo;c.pc=pc;c.loadRegister=loadRegister;c.loadValue=loadValue;
}
// One DataReady event of an active ReadN: read the next sector from the source
// on demand and run the registered read callback. Never runs re-entrantly and
// never reads ahead; a sector not fully taken by CdGetSector counts as overrun.
inline bool pump(Context& c,std::uint64_t budget){
    if(!c.cd)throw std::runtime_error("Fatal libcd HLE: pump without a CD drive");
    auto& d=*c.cd;
    if(!d.reading||!d.readCallback||d.inCallback)return false;
    if(d.sectorReady)++d.overrun;
    d.sector=d.source->read(d.next);d.sectorLba=d.next++;d.sectorReady=true;d.sectorCursor=0;++d.delivered;
    struct Busy{bool& flag;explicit Busy(bool& f):flag(f){flag=true;}~Busy(){flag=false;}} busy(d.inCallback);
    invokeGuestCallback(c,d.readCallback,dataReady,0,budget);
    return true;
}
// CdStatus() -> status byte (no shell-open bit). It is also the pump point the
// loader's header wait (0x8004185C) and BZZ helper (every 0xFFFF spins) reach.
inline void cdStatus(Context& c,std::uint32_t entry,std::uint64_t budget){drive(c,entry);pump(c,budget);hleReturn(c,c.cd->status());}

struct Entry{std::uint32_t guest;const char* name;RecompFunction function;};
// PAL SLES_017.26 libcd addresses on the loader path (CONFIRMED from the executable).
inline constexpr std::array<Entry,6> palEntries={{{0x800469d4,"CdControlB",cdControlB},{0x80046764,"CdControl",cdControl},
    {0x80046750,"CdReadCallback",cdReadCallback},{0x80046b40,"CdGetSector",cdGetSector},
    {0x800465b8,"CdStatus",cdStatus},{0x800466fc,"CdSync",cdSync}}};
inline void registerPalLibcd(DynamicRegistry& registry){for(const auto& e:palEntries)registry.add(e.guest,e.function);}
}
