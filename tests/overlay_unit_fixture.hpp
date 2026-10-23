#pragma once
#include "../src/overlay_unit.hpp"

// Hand-authored test programs, not instructions extracted from TITLE.
namespace overlay_fixture {
using namespace moyle::detail::recomp;
inline std::uint32_t imm(unsigned op,unsigned rs,unsigned rt,int value) {
    return (op<<26)|(rs<<21)|(rt<<16)|(static_cast<unsigned>(value)&65535);
}
inline std::uint32_t reg(unsigned rs,unsigned rt,unsigned rd,unsigned fn) {
    return (rs<<21)|(rt<<16)|(rd<<11)|fn;
}
inline void put(std::vector<std::uint8_t>& v,std::uint32_t pc,std::uint32_t w) {
    for(unsigned k=0;k<4;++k)v.at(pc-overlay::palTitle.base+k)=static_cast<std::uint8_t>(w>>(8*k));
}
inline std::vector<std::uint8_t> image() {
    std::vector<std::uint8_t> v(overlay::palTitle.size,0);
    for(auto pc=0x80010204U;pc<0x80012b54U;pc+=4)if(overlay::codeAddress(pc))put(v,pc,13); // BREAK unused code
    const auto sequence=[&](std::uint32_t pc,std::initializer_list<std::uint32_t> words){for(auto w:words){put(v,pc,w);pc+=4;}};
    // Entry dispatch uses a deliberately non-ABI register, and captures before slot.
    for(auto pc:{0x80010204U,0x80010258U})sequence(pc,{reg(4,0,0,8),imm(9,20,20,1)});
    put(v,0x8001025c,reg(0,0,4,33)); // clobber captured JR source in delay slot
    for(auto t:overlay::tables){
        if(t.load==t.site-8)sequence(t.load,{imm(35,5,8,0),0,reg(8,0,0,8),imm(9,21,21,1)});
        else{ // LW in an always-taken branch slot; the skipped word and the join path reach the JR.
            sequence(t.load-4,{imm(1,0,1,2),imm(35,5,8,0),imm(9,13,13,1)});
            for(auto pc=t.load+8;pc<t.site;pc+=4)put(v,pc,0);
            sequence(t.site,{reg(8,0,0,8),imm(9,21,21,1)});
        }
        for(unsigned k=0;k<t.count;++k)put(v,t.base+4*k,0x80012000U);
    }
    // Specified unsupported-type entries share the BREAK 1 trap (A: 0x18, C: 0x10/0x44).
    put(v,overlay::breakTrap,0x0001000dU);
    put(v,overlay::tables[0].base+0x18,overlay::breakTrap);
    for(auto type:{0x10U,0x44U})put(v,overlay::tables[2].base+type,overlay::breakTrap);
    // RingSpaceWait-shaped program: return when r8 >= 0x800, else reach the poll point.
    sequence(overlay::ringSpaceWait,{imm(10,8,1,0x800),imm(4,1,0,28),0,
        (2U<<26)|((overlay::ringSpacePollPoint>>2)&0x3ffffff),0});
    sequence(overlay::ringSpacePollEnd,{reg(31,0,0,8),imm(9,19,19,1)});
    sequence(0x80012000,{imm(9,22,22,1),reg(31,0,0,8),imm(35,6,9,0)}); // pending load crosses return
    sequence(0x80012020,{reg(10,11,12,32),reg(31,0,0,8),0}); // ADD
    sequence(0x80012030,{reg(10,11,12,34),reg(31,0,0,8),0}); // SUB
    sequence(0x80012040,{imm(4,10,11,2),imm(9,23,23,1),imm(9,24,24,1),reg(31,0,0,8),0});
    // Internal JAL plus a non-RA JR continuation: all registers remain shared.
    sequence(0x80012060,{reg(31,0,26,33),(3U<<26)|((0x80012090U>>2)&0x3ffffff),imm(9,27,27,1),
        reg(26,0,31,33),reg(31,0,0,8),imm(9,25,25,1)});
    sequence(0x80012090,{reg(31,0,15,33),reg(0,0,16,16),reg(0,0,17,18),reg(15,0,0,8),imm(9,1,1,7)});
    sequence(0x800120b0,{0x4a000012U}); // MVMVA is outside the T5 GTE subset
    sequence(0x800120c0,{imm(43,5,10,0),reg(31,0,0,8),0}); // code write guard
    // S10-shaped programs express packet/OT semantics, not the original code.
    sequence(0x80012ae4,{(2U<<26)|((0x80012100U>>2)&0x3ffffff),0});
    sequence(0x80012ab0,{(2U<<26)|((0x80012200U>>2)&0x3ffffff),0});
    std::uint32_t pc=0x80012100;
    const auto emit=[&](std::uint32_t w){put(v,pc,w);pc+=4;};
    emit(imm(35,5,8,0x14));emit(0); // OT pointer from scratch context
    emit(imm(35,8,9,0x180));emit(imm(15,0,10,0x0500));
    emit(reg(9,10,9,37));emit(imm(43,4,9,0));
    emit(imm(15,0,10,0x2a00));emit(reg(6,10,9,37));emit(imm(43,4,9,4));
    unsigned off=8;
    for(auto w:{0xff88ff00U,0xff880100U,0x0078ff00U,0x00780100U}){
        emit(imm(15,0,9,w>>16));emit(imm(13,9,9,w&65535));emit(imm(43,4,9,off));off+=4;
    }
    emit(imm(15,0,10,0x00ff));emit(imm(13,10,10,0xffff));emit(reg(4,10,9,36));
    emit(imm(43,8,9,0x180));emit(reg(31,0,0,8));emit(imm(9,4,2,0x18));
    pc=0x80012200;
    emit(imm(35,5,8,0x14));emit(0);emit(imm(35,8,9,0));emit(imm(15,0,10,0x0100));
    emit(reg(9,10,9,37));emit(imm(43,4,9,0));
    emit(imm(15,0,9,0xe100));emit(imm(13,9,9,0x620));emit(imm(43,4,9,4));
    emit(imm(15,0,10,0x00ff));emit(imm(13,10,10,0xffff));emit(reg(4,10,9,36));
    emit(imm(43,8,9,0));emit(reg(31,0,0,8));emit(imm(9,4,2,8));
    // Cull sites: BLEZ v0 (initial state) to site+16; not-taken path marks r23,
    // taken path marks r24. Both return to the caller.
    for(auto site:overlay::palTitle.patchSites)
        sequence(site,{0x18400003U,0,reg(31,0,0,8),imm(9,23,23,1),reg(31,0,0,8),imm(9,24,24,1)});
    // Hand-written setter shape: six SH of a0 to site+2, the sixth in the JR slot.
    std::uint32_t setterPc=overlay::cullSetter;
    const auto emitAt=[&](std::uint32_t w){put(v,setterPc,w);setterPc+=4;};
    emitAt(imm(15,0,8,0x8001));
    for(unsigned n=0;n<6;++n){
        if(n==5)emitAt(reg(31,0,0,8));
        emitAt(imm(41,8,4,static_cast<int>(overlay::palTitle.patchSites[n]+2-0x80010000U)));
    }
    // Setter then a cull site in one invocation: the second read must see the new RAM.
    sequence(0x80012300,{reg(31,0,26,33),imm(13,0,4,0x1c40),(3U<<26)|((overlay::cullSetter>>2)&0x3ffffff),0,
        reg(26,0,31,33),(2U<<26)|((overlay::palTitle.patchSites[0]>>2)&0x3ffffff),0});
    // Unknown high half stored by the guest, then executed.
    sequence(0x80012340,{imm(13,0,10,0x1234),imm(15,0,9,0x8001),imm(41,9,10,0x3a6),
        (2U<<26)|((overlay::palTitle.patchSites[0]>>2)&0x3ffffff),0});
    sequence(0x800120d0,{imm(41,5,10,0),reg(31,0,0,8),0}); // SH r10,0(r5)
    sequence(0x800120e0,{imm(40,5,10,0),reg(31,0,0,8),0}); // SB r10,0(r5)
    sequence(0x800120f0,{imm(58,5,24,0),reg(31,0,0,8),0}); // SWC2 MAC0,0(r5)
    return v;
}
// LANGUAGE-shaped synthetic image (still hand-authored, not LANGUAGE code): the same program with one zero pad word at
// codeEnd, so every table and all data after the code move by palLanguageTableShift; 0x42B8 bytes like palLanguage.
inline std::vector<std::uint8_t> languageImage() {
    auto v=image();
    v.insert(v.begin()+(overlay::codeEnd-overlay::palTitle.base),overlay::palLanguageTableShift,std::uint8_t(0));
    return v;
}
// First instruction of the synthetic dispatch sequence for a table.
inline std::uint32_t dispatch(const overlay::JumpTable& t) {return t.load==t.site-8?t.load:t.load-4;}
inline void install(Context& c,bool language=false) {
    const auto v=language?languageImage():image();std::copy(v.begin(),v.end(),c.ram.bytes.begin()+0x10200);
    c.ram.write(overlay::palTitle.base,overlay::palTitle.runtimeWord0,4);
    c.r[31]=hostReturn;
}
}
