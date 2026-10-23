#pragma once
#include "generator.hpp"
#include "../../src/overlay_unit.hpp"

namespace recomp_tool::overlay_unit {
using namespace moyle::detail::recomp::overlay;
inline Instruction trap(std::uint32_t pc,std::uint32_t w,const char* reason) {
    return {pc,w,0,0,reason,"throw overlay::unitError(pc,\""+std::string(reason)+"\");"};
}
inline Instruction cpu(std::uint32_t pc,std::uint32_t w) {
    const auto op=w>>26,rs=(w>>21)&31,rt=(w>>16)&31,rd=(w>>11)&31,sh=(w>>6)&31,fn=w&63;
    if(patchSite(pc)){
        // Low half (target) comes from the verified image; the high half is
        // re-read from guest RAM at every execution by overlay::patchedBranch.
        if((w>>16)!=palTitle.initialPatchHigh)throw std::runtime_error("Patch site lacks the initial branch at "+hex(pc));
        Instruction i{pc,w,(w>>21)&31,0,"cull patch branch (BLEZ/BGTZ from RAM high half)",""};
        i.control=i.direct=true;i.target=pc+4+static_cast<std::uint32_t>(static_cast<std::int16_t>(w&65535))*4;
        i.code="const bool taken=overlay::patchedBranch(c,pc,a); following=taken?"+hex(i.target)+"U:"+hex(pc+8)+"U; c.branches.push_back({pc,taken});";
        return i;
    }
    // Wait branch only: the RingSpaceWait prologue/space test/return run normally.
    if(pc>=ringSpacePollPoint&&pc<ringSpacePollEnd)
        return trap(pc,w,"RingSpaceWait spin requires future poll support (poll point 0x80012a04)");
    if(pc==breakTrap||(op==0&&fn==13))
        return {pc,w,0,0,"guest BREAK","throw overlay::breakError(c,pc,"+std::to_string((w>>16)&1023)+"U,"+std::to_string((w>>6)&1023)+"U);"};
    Instruction i{pc,w,rs,rt,"overlay CPU",""};
    const auto set=[&](unsigned r,const std::string& value){return "c.r["+std::to_string(r)+"] = "+value+";";};
    if(op==0&&fn==8&&!rt&&!rd&&!sh){i.control=true;i.code="following = overlay::jump(pc,a,stop,unitSlots);";return i;}
    if(op==0&&fn==34&&!sh){i.code="const auto value=a-b; if (((a^b)&(a^value)&0x80000000U)!=0) throw overlay::unitError(pc,\"guest SUB overflow\"); "+set(rd,"value");return i;}
    if(op==0&&fn==3&&!rs){i.code=set(rd,"(b >> "+std::to_string(sh)+") | ((b & 0x80000000U) ? "+hex(sh?0xffffffffU<<(32-sh):0)+"U : 0U)");return i;}
    if(op==0&&(fn==16||fn==18)&&!rs&&!rt&&!sh){i.code=set(rd,fn==16?"c.hi":"c.lo");return i;}
    if(op==0&&(fn==17||fn==19)&&!rd&&!rt&&!sh){i.code=std::string(fn==17?"c.hi":"c.lo")+" = a;";return i;}
    if(((op==6||op==7)&&!rt) || (op==1&&rt==0)){
        i.control=i.direct=true;i.target=pc+4+static_cast<std::uint32_t>(static_cast<std::int16_t>(w))*4;
        const std::string condition=op==6?"(a==0 || (a&0x80000000U))":op==7?"(a!=0 && !(a&0x80000000U))":"(a&0x80000000U)";
        i.code="const bool taken="+condition+"; following=taken?"+hex(i.target)+"U:"+hex(pc+8)+"U; c.branches.push_back({pc,taken});";return i;
    }
    try{i=decode(pc,w,true,true);}catch(const std::exception&){return trap(pc,w,op==18?"unsupported GTE instruction":"unsupported integer instruction");}
    if(op==40||op==41||op==43||op==58){const auto start=i.code.find("c.ram.write(");i.code.replace(start,12,"overlay::store(c,pc,");}
    if(op==42||op==46)return trap(pc,w,"unaligned overlay store not admitted in T3");
    return i;
}
inline bool writes(std::uint32_t w,unsigned reg) {
    const auto op=w>>26,fn=w&63;
    if(op==0)return fn!=8&&((w>>11)&31)==reg;
    if(op==3)return reg==31;
    return op>=8&&op<=38&&((w>>16)&31)==reg;
}
// The declared LW must be the only producer of the JR source: every path from
// it stays inside (load,site], never redefines the register, contains no call
// or indirect transfer, retires the load before the JR, and no edge enters the
// region except through the LW (directly or as a branch delay slot).
template<class Word> void verifyTableLoad(const Program& p,const Word& at,const JumpTable& t,unsigned reg) {
    const auto fail=[&](const std::string& why){throw std::runtime_error("Overlay JR lacks verified retired table LW at "+hex(t.site)+": "+why);};
    const auto load=t.load,w=at(load);
    if(!p.instructions.count(load)||(w>>26)!=35||((w>>16)&31)!=reg||load>=t.site||t.site-load>0x80)fail("declared load is not LW of the JR source");
    std::vector<std::uint32_t> work;
    const auto owner=p.instructions.find(load-4);
    if(owner!=p.instructions.end()&&owner->second.control){
        if(!owner->second.direct||owner->second.callKind!=CallKind::None)fail("load in a call/indirect delay slot");
        work.push_back(owner->second.target);if((owner->second.bits>>26)!=2)work.push_back(load+4);
    }else work.push_back(load+4);
    for(auto next:work)if(next==t.site)fail("load not retired before JR");
    std::set<std::uint32_t> seen;
    while(!work.empty()){
        const auto pc=work.back();work.pop_back();
        if(pc==t.site||!seen.insert(pc).second)continue;
        if(pc<=load||pc>t.site||!p.instructions.count(pc))fail("path leaves dispatch region at "+hex(pc));
        const auto& i=p.instructions.at(pc);
        if(writes(at(pc),reg))fail("JR source redefined at "+hex(pc));
        if(!i.control){work.push_back(pc+4);continue;}
        if(!i.direct||i.callKind!=CallKind::None)fail("call or indirect transfer at "+hex(pc));
        if(pc+4>=t.site||writes(at(pc+4),reg))fail("delay slot at "+hex(pc+4));
        seen.insert(pc+4);work.push_back(i.target);if((i.bits>>26)!=2)work.push_back(pc+8);
    }
    for(const auto& [pc,i]:p.instructions)
        if(i.direct&&i.target>load&&i.target<=t.site&&(pc+4<load||pc>=t.site))fail("edge from "+hex(pc)+" enters dispatch region");
}
// tableShift selects the proven table layout: 0 = TITLE (size 0x42B4), palLanguageTableShift = LANGUAGE (size 0x42B8,
// one pad word before the tables). Code range, entries, dead ranges, sites and table load/JR sites are shared.
inline Program build(const std::vector<std::uint8_t>& image,const Metadata& identity=palTitle,std::uint32_t tableShift=0,
                     const char* unitName="PAL TITLE unit") {
    if(identity.base!=palTitle.base||identity.patchSites!=palTitle.patchSites||
       identity.runtimeWord0!=palTitle.runtimeWord0||identity.initialPatchHigh!=palTitle.initialPatchHigh||
       identity.alternatePatchHigh!=palTitle.alternatePatchHigh||
       !((tableShift==0&&identity.size==palTitle.size)||(tableShift==palLanguageTableShift&&identity.size==palLanguage.size)))
        throw std::runtime_error("Incompatible overlay unit geometry");
    // Both patch states must be BLEZ/BGTZ on the same rs with rt=0.
    if((palTitle.initialPatchHigh>>10)!=6||(palTitle.alternatePatchHigh>>10)!=7||(palTitle.initialPatchHigh&31)||
       ((palTitle.initialPatchHigh^palTitle.alternatePatchHigh)&0x3ff))throw std::runtime_error("Unsupported cull patch states");
    validateInitialLoad(identity,palTitle.base,image,LoadPhase::InitialImage);
    Program p;p.extraIncludes="#include \"overlay_unit.hpp\"\n";
    p.sourceDescription="a validated overlay unit descriptor";
    const auto at=[&](std::uint32_t pc){return word(image,pc-palTitle.base);};
    std::set<std::uint32_t> slots;
    for(std::uint32_t pc=0x80010204;pc<0x80012b54;pc+=4)if(codeAddress(pc)){
        const auto w=at(pc),op=w>>26,fn=w&63;
        // Include slots of unsupported controls too: they trap if reached, but
        // their delay instruction must never become an independent entry/target.
        auto i=cpu(pc,w);if(i.control||(op>=1&&op<=7)||(op==0&&(fn==8||fn==9)))slots.insert(pc+4);p.instructions.emplace(pc,i);
    }
    for(auto pc:entries){if(slots.count(pc))throw std::runtime_error("Overlay entry in delay slot");p.regions.push_back({pc,1});}
    std::ostringstream pre;
    pre<<"const overlay::Metadata identity{\""<<unitName<<"\",0x80010200U,0x"<<std::hex<<identity.size<<std::dec<<"U,\""<<identity.maskedSha1<<"\",0x8006b340U,{";
    for(auto pc:palTitle.patchSites)pre<<hex(pc)<<"U,";
    pre<<"},0x1840,0x1c40}; overlay::validateImage(c,identity,canonicalCodeAddress(entry)==overlay::cullSetter);\nconst std::set<std::uint32_t> unitSlots{";
    for(auto pc:slots)pre<<hex(pc)<<"U,";pre<<"};\n";
    for(unsigned n=0;n<tables.size();++n){auto t=tables[n];t.base+=tableShift;const auto transfer=at(t.site),reg=(transfer>>21)&31;
        if((transfer&0xfc1fffffU)!=8||reg==31)throw std::runtime_error("Overlay table site is not JR");
        verifyTableLoad(p,at,t,reg);const auto load=t.load;
        const auto name="overlayTable"+std::to_string(n),ticket="overlayTicket"+std::to_string(n);
        pre<<"const StaticTable "<<name<<"{"<<hex(t.base)<<"U,{";
        for(unsigned index=0;index<t.count;++index){const auto target=at(t.base+4*index),canonical=moyle::detail::recomp::canonicalCodeAddress(target);
            if(deadAddress(canonical))throw std::runtime_error("Overlay table target outside live code: dead range 80010930-80010BA3");
            if(!codeAddress(canonical)||slots.count(canonical))throw std::runtime_error("Overlay table target outside live code");
            pre<<hex(target)<<"U,";
        }
        pre<<"}}; TableTicket "<<ticket<<";\n";
        auto& lw=p.instructions.at(load);const auto immediate=static_cast<std::uint32_t>(static_cast<std::int16_t>(lw.bits&65535));
        lw.code="c.loadValue = overlay::loadTable(c,"+ticket+","+name+","+std::to_string(n)+"U,pc,a+"+hex(immediate)+"U"+
            (tableShift?","+std::to_string(tableShift)+"U":std::string())+"); c.loadRegister="+std::to_string(reg)+";";
        auto& jr=p.instructions.at(t.site);jr.callKind=CallKind::StaticTableTailJump;
        jr.code="following = tableTransfer(c,"+ticket+",pc,a,TableKind::TailJump);";
    }
    for(const auto& [pc,i]:p.instructions){
        if(i.control){if(!p.instructions.count(pc+4)||p.instructions.at(pc+4).control)throw std::runtime_error("Invalid overlay delay slot at "+hex(pc));}
        if(i.direct&&deadAddress(i.target))throw std::runtime_error("Overlay direct edge into dead range 80010930-80010BA3 at "+hex(pc));
        if(i.direct&&(!codeAddress(i.target)||slots.count(i.target)))throw std::runtime_error("Overlay direct edge outside live code");
    }
    p.tablePrelude=pre.str();return p;
}
}
