#pragma once
#include "overlay_recognition.hpp"
#include "static_table.hpp"
#include <set>

namespace moyle::detail::recomp::overlay {
inline constexpr std::array<std::uint32_t,5> entries={0x80010204,0x80010258,0x8001020c,0x80012ae4,0x80012ab0};
// load: the table LW feeding the JR (B/D: in a branch delay slot, two paths join).
// minIndex: guest domain. B/D receive byte offsets 0x08..0x1C from their callers.
// elementRegister: register holding the element pointer at A/C dispatch (0 = none).
struct JumpTable {std::uint32_t site,load,base,count,minIndex;const char* name;unsigned elementRegister;};
inline constexpr std::array<JumpTable,4> tables={{{0x80010dec,0x80010de4,0x80012b54,22,0,"JT_A",4},
    {0x80011a94,0x80011a54,0x80012ba4,8,2,"JT_B",0},{0x80010368,0x80010360,0x80012bc4,20,0,"JT_C",4},
    {0x80010928,0x800108fc,0x80012c14,8,2,"JT_D",0}}};
inline constexpr std::uint32_t deadBegin=0x80010930,deadEnd=0x80010ba4,codeEnd=0x80012b54;
// LANGUAGE layout (palLanguage): identical code, entries, sites and table load/JR sites; one pad word at codeEnd moves
// every table base (and all data after the code) by +4. TITLE is shift 0. No other layout is accepted.
inline constexpr std::uint32_t palLanguageTableShift=4;
inline bool publicEntry(std::uint32_t canonical) {
    for(auto e:entries)if(e==canonical)return true;
    return false;
}
// RingSpaceWait (entry 800129B4) runs normally while ring space is >= 0x800.
// Only its wait branch is withheld: [pollPoint,pollEnd) is the spin body and
// pollPoint is the future VBlank/CD poll point. No scheduler exists yet.
inline constexpr std::uint32_t ringSpaceWait=0x800129b4,ringSpacePollPoint=0x80012a04,ringSpacePollEnd=0x80012a2c;
// Shared BREAK 1 trap targeted by unsupported table types; 80012AA4 (j self) is never emitted.
inline constexpr std::uint32_t breakTrap=0x80012aa0;
inline bool deadAddress(std::uint32_t pc) {return pc>=deadBegin&&pc<deadEnd;}
inline bool codeAddress(std::uint32_t pc) {
    return !(pc&3)&&pc>=0x80010204&&pc<codeEnd&&
        !deadAddress(pc)&&!(pc>=0x80012aa4&&pc<0x80012ab0);
}
inline std::runtime_error unitError(std::uint32_t pc,const std::string& reason) {
    std::ostringstream s;s<<"Fatal PAL overlay unit at 0x"<<std::hex<<pc<<": "<<reason;return std::runtime_error(s.str());
}
// Diagnostic only: reports the table dispatch that reached the trap, if any.
inline std::runtime_error breakError(const Context& c,std::uint32_t pc,std::uint32_t code,std::uint32_t lowCode) {
    std::ostringstream s;s<<"guest BREAK "<<std::dec<<code;
    if(lowCode)s<<","<<lowCode;
    const JumpTable* table=nullptr;
    if(!c.tableTrace.empty()&&canonicalCodeAddress(c.tableTrace.back().target)==canonicalCodeAddress(pc))
        for(const auto& t:tables)if(canonicalCodeAddress(c.tableTrace.back().site)==t.site)table=&t;
    if(table){
        const auto& t=c.tableTrace.back();
        s<<" via "<<table->name<<" dispatcher 0x"<<std::hex<<t.site<<", index "<<std::dec<<t.index
         <<", byte offset 0x"<<std::hex<<4*t.index;
        if(table->elementRegister)s<<", element type 0x"<<4*t.index<<", element pointer 0x"<<c.r[table->elementRegister];
    }else s<<" (not reached through an overlay table dispatch)";
    return unitError(pc,s.str());
}
inline void validateImage(Context& c,const Metadata& m,bool setterEntry=false) {
    const auto offset=Ps1Memory::offset(m.base,4);
    if(offset>c.ram.bytes.size()||m.size>c.ram.bytes.size()-offset)throw unitError(m.base,"image outside RAM");
    const std::vector<std::uint8_t> image(c.ram.bytes.begin()+offset,c.ram.bytes.begin()+offset+m.size);
    validateInitialLoad(m,m.base,image,setterEntry?LoadPhase::RuntimeSetterEntry:LoadPhase::RuntimeLoaded);
}
inline std::uint32_t jump(std::uint32_t pc,std::uint32_t target,std::uint32_t stop,const std::set<std::uint32_t>& slots) {
    if(target==stop)return target;
    const auto canonical=canonicalCodeAddress(target);
    if(deadAddress(canonical))throw unitError(pc,"JR target in dead range 80010930-80010BA3");
    if(!codeAddress(canonical)||slots.count(canonical))throw unitError(pc,"JR target outside code or in delay slot");
    return target;
}
// All checks precede the guest read: no adjacent table/data word is ever loaded.
// tableShift is the layout's table offset (0 = TITLE, palLanguageTableShift = LANGUAGE); it is emitted only when non-zero.
inline std::uint32_t loadTable(Context& c,TableTicket& ticket,const StaticTable& table,unsigned id,std::uint32_t site,std::uint32_t address,
                               std::uint32_t tableShift=0) {
    ticket={};
    if(id>=tables.size())throw unitError(site,"unknown overlay jump table");
    if(tableShift!=0&&tableShift!=palLanguageTableShift)throw unitError(site,"unknown overlay table layout");
    auto meta=tables[id];meta.base+=tableShift;
    if(canonicalCodeAddress(table.base)!=meta.base||table.targets.size()!=meta.count)throw unitError(site,"jump table descriptor mismatch");
    if(address&3)throw unitError(site,std::string(meta.name)+" index not aligned to 4 (AdEL)");
    if(Ps1Memory::route(address).region!=MemoryRegion::Ram)throw unitError(site,std::string(meta.name)+" index out of bounds");
    const auto actual=canonicalCodeAddress(address);
    if(actual<meta.base||std::uint64_t(actual)>=std::uint64_t(meta.base)+4ULL*meta.count)
        throw unitError(site,std::string(meta.name)+" index out of bounds");
    const auto index=(actual-meta.base)/4;
    if(index<meta.minIndex)throw unitError(site,std::string(meta.name)+" index out of bounds of guest domain");
    tableIndex(ticket,table,site,index);
    return tableLoad(c,ticket,table,site,address);
}
// T4 cull patch. The setter rewrites only the high halfword of each site; the
// branch reads that halfword from guest RAM every time it executes (no cache).
inline constexpr std::uint32_t cullSetter=0x8001020c;
inline bool patchSite(std::uint32_t pc) {
    for(auto site:palTitle.patchSites)if(pc==site)return true;
    return false;
}
// Semantics are decoded from the RAM halfword, restricted to the two specified
// states (initial 1840 = BLEZ, alternate 1C40 = BGTZ, both on the captured rs).
inline bool patchedBranch(const Context& c,std::uint32_t pc,std::uint32_t value) {
    const auto offset=Ps1Memory::offset(pc,4);
    const std::uint32_t high=c.ram.bytes.at(offset+2)|(std::uint32_t(c.ram.bytes.at(offset+3))<<8);
    if(!patchSite(canonicalCodeAddress(pc))||(high!=palTitle.initialPatchHigh&&high!=palTitle.alternatePatchHigh)){
        std::ostringstream s;s<<"unknown cull patch high half 0x"<<std::hex<<high<<" (expected 0x"<<palTitle.initialPatchHigh
            <<" BLEZ or 0x"<<palTitle.alternatePatchHigh<<" BGTZ)";
        throw unitError(pc,s.str());
    }
    const auto op=high>>10;
    return op==6?(value==0||(value&0x80000000U)):(value!=0&&!(value&0x80000000U));
}
// Data-driven whitelist, not generic SMC: inside the unit image only a halfword
// store to one of the six site+2 addresses is permitted. Other RAM is normal.
inline void store(Context& c,std::uint32_t pc,std::uint32_t address,std::uint32_t value,unsigned width) {
    // Word0 and code [80010200,80012B54); tables and data after the code stay writable.
    const auto physical=address&0x1fffffffU,base=palTitle.base&0x1fffffffU;
    if(std::uint64_t(physical)+width>base&&physical<(codeEnd&0x1fffffffU)){
        bool allowed=false;
        if(width==2)for(auto site:palTitle.patchSites)allowed=allowed||physical==(site&0x1fffffffU)+2;
        if(!allowed){
            std::ostringstream s;s<<"overlay code write to 0x"<<std::hex<<address<<" width "<<std::dec<<width
                <<" (only halfword stores to the six cull patch site+2 addresses are allowed)";
            throw unitError(pc,s.str());
        }
    }
    c.ram.write(address,value,width);
}
}
