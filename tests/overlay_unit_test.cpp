#include "overlay_unit_fixture.hpp"
#include <iostream>
#include <tuple>
using namespace moyle::detail::recomp;
namespace moyle::detail::recomp {void executeSyntheticTitle(Context&,std::uint32_t,std::uint64_t);}
static unsigned checks=0;
void require(bool v,const char* why){++checks;if(!v)throw std::runtime_error(why);}
template<class F> void rejects(F f,const char* text){try{f();}catch(const std::exception& e){require(std::string(e.what()).find(text)!=std::string::npos,e.what());return;}throw std::runtime_error("Expected rejection");}
void run(Context& c,std::uint32_t target,std::uint32_t entry=0x80010204){c.r[4]=target;executeSyntheticTitle(c,entry,500);}
int main(){try{
    for(auto alias:{0U,0x80000000U,0xa0000000U})for(auto t:overlay::tables){
        Context c;overlay_fixture::install(c);c.r[5]=((t.base+4*t.minIndex)&0x1fffffff)|alias;c.r[6]=0x80150000;c.r[9]=7;
        c.ram.write(c.r[6],0xabcdef01,4);c.r[18]=0x11223344;c.hi=13;c.lo=17;
        run(c,(overlay_fixture::dispatch(t)&0x1fffffff)|alias,(0x10204|alias));
        require(c.pc==hostReturn&&c.r[31]==hostReturn,"Table tail jump RA/PC");
        require(c.r[20]==1&&c.r[21]==1&&c.r[22]==1,"Delay slots exactly once");
        require(c.r[18]==0x11223344&&c.hi==13&&c.lo==17,"Guest state preserved");
        require(c.r[9]==7&&c.loadRegister==9&&c.loadValue==0xabcdef01,"Pending load at return");
        require(c.tableTrace.size()==1&&!c.tableTrace[0].call&&c.tableTrace[0].index==t.minIndex,"Tail table trace");
    }
    for(auto entry:{0x80010204U,0x80010258U}){Context c;overlay_fixture::install(c);run(c,0x80012060,entry);
        require(c.r[15]==0x8001206c&&c.r[26]==hostReturn&&c.r[31]==hostReturn,"Internal non-o32 linkage");
        require(c.r[27]==1&&c.r[25]==1&&c.r[1]==7&&c.pc==hostReturn,"Internal JAL/JR slots/state");
        if(entry==0x80010258)require(c.r[4]==0,"JR source captured before slot");}
    {Context c;overlay_fixture::install(c);c.loadRegister=4;c.loadValue=0x80012aa0;run(c,0x80012060);
        require(c.r[4]==0x80012aa0&&c.pc==hostReturn,"JR uses source before pending-load retirement");}
    for(auto target:{0x80012aa0U,0x800120b0U,overlay::ringSpacePollPoint}){Context c;overlay_fixture::install(c);
        rejects([&]{run(c,target);},target==0x80012aa0?"BREAK":target==0x800120b0?"GTE":"poll point");}
    // ---- T4: cull setter and patched branches (no NCLIP; v0 is a synthetic MAC0).
    const auto& sites=overlay::palTitle.patchSites;
    const auto setAll=[&](Context& c,std::uint32_t high){for(auto site:sites)c.ram.write(site+2,high,2);};
    const auto codeWrites=[&](const Context& c){
        std::vector<std::pair<std::uint32_t,std::uint32_t>> w;
        for(const auto& e:c.ram.effects){
            const auto physical=e.address&0x1fffffffU;
            if(e.kind==moyle::detail::EffectKind::Write&&physical>=0x10200&&physical<0x12b54)w.push_back({e.address,e.value});
        }
        return w;
    };
    for(auto value:{0x1840U,0x1c40U})for(unsigned start=0;start<3;++start){
        Context c;overlay_fixture::install(c);
        if(start==1)setAll(c,0x1c40);
        if(start==2)for(std::size_t n=0;n<sites.size();++n)c.ram.write(sites[n]+2,n&1?0x1c40U:0x1840U,2); // alternating
        const auto before=c.ram.bytes;const auto regs=c.r;c.ram.effects.clear();
        c.r[4]=value;executeSyntheticTitle(c,overlay::cullSetter,500);
        require(c.pc==hostReturn&&c.r[31]==hostReturn&&c.r[4]==value&&c.r[8]==0x80010000U,"Setter PC/RA/registers");
        for(unsigned r=1;r<32;++r)if(r!=4&&r!=8)require(c.r[r]==regs[r],"Setter clobbered a register");
        for(auto site:sites)require(c.ram.read(site+2,2)==value&&c.ram.read(site,2)==3,"Setter site state");
        require(c.ram.read(sites[5]+2,2)==value,"Sixth (delay-slot) store");
        const auto writes=codeWrites(c);require(writes.size()==6,"Exactly six code stores");
        for(std::size_t n=0;n<6;++n)require(writes[n].first==sites[n]+2&&writes[n].second==value,"Store order/address");
        bool otherBytes=true;
        for(std::size_t n=0x10200;n<0x10200+overlay::palTitle.size;++n){bool site=false;
            for(auto s:sites)site=site||n==((s+2)&0x1fffffffU)||n==((s+3)&0x1fffffffU);
            otherBytes=otherBytes&&(site||c.ram.bytes[n]==before[n]);}
        require(otherBytes,"Setter changed other image bytes");
    }
    {Context c;overlay_fixture::install(c);c.ram.write(sites[2]+2,0x1234,2);c.r[4]=0x1840;
        rejects([&]{executeSyntheticTitle(c,overlay::cullSetter,500);},"runtime patch high half");}
    for(auto mode:{0x1840U,0x1c40U})for(auto mac0:{0U,1U,0xffffffffU,0x80000000U,0x7fffffffU})for(auto site:sites){
        Context c;overlay_fixture::install(c);setAll(c,mode);c.r[2]=mac0;run(c,site);
        const bool positive=mac0&&!(mac0&0x80000000U),taken=mode==0x1840U?!positive:positive;
        require(c.r[24]==(taken?1U:0U)&&c.r[23]==(taken?0U:1U)&&c.pc==hostReturn,"BLEZ/BGTZ selection from RAM");
        require(!c.branches.empty()&&c.branches.back().pc==site&&c.branches.back().taken==taken,"Branch trace");}
    {Context c;overlay_fixture::install(c);c.r[2]=1;run(c,sites[3]);require(c.r[23]==1,"BLEZ not taken for v0=1");
        setAll(c,0x1c40);c.r[23]=c.r[24]=0;run(c,sites[3]);require(c.r[24]==1,"No cache: second dispatch must follow RAM");
        setAll(c,0x1840);c.r[23]=c.r[24]=0;run(c,sites[3]);require(c.r[23]==1,"No cache after restore");}
    {Context c;overlay_fixture::install(c);c.r[2]=1;run(c,0x80012300);
        require(c.r[24]==1&&c.r[23]==0&&c.pc==hostReturn,"Setter then site in one invocation");
        for(auto site:sites)require(c.ram.read(site+2,2)==0x1c40,"In-invocation setter state");}
    {Context c;overlay_fixture::install(c);c.r[2]=1;rejects([&]{run(c,0x80012340);},"unknown cull patch high half 0x1234");}
    // Code-write whitelist: exactly SH to the six site+2 (any RAM alias); everything else in code is fatal.
    for(auto site:sites)for(auto alias:{0U,0x80000000U,0xa0000000U}){Context c;overlay_fixture::install(c);
        c.r[5]=((site+2)&0x1fffffffU)|alias;c.r[10]=0x1c40;run(c,0x800120d0);require(c.ram.read(site+2,2)==0x1c40,"Allowed site+2 SH");}
    for(auto site:sites)for(const auto& bad:{std::pair{0x800120d0U,site},std::pair{0x800120e0U,site+1},std::pair{0x800120e0U,site+2},
                                             std::pair{0x800120e0U,site+3},std::pair{0x800120c0U,site}}){
        Context c;overlay_fixture::install(c);c.r[5]=bad.second;c.r[10]=0x1c40;const auto before=c.ram.bytes;
        rejects([&]{run(c,bad.first);},"overlay code write");require(c.ram.bytes==before,"Rejected code write changed RAM");}
    for(auto address:{0x80012022U,0x80010202U,0x80010200U,0x80012b52U}){Context c;overlay_fixture::install(c);
        c.r[5]=address;rejects([&]{run(c,0x800120d0);},"overlay code write");}
    for(auto address:{0x80012b56U,0x80150000U,0x1f800010U}){Context c;overlay_fixture::install(c);c.r[5]=address;c.r[10]=0xbeef;
        run(c,0x800120d0);require(c.ram.read(address,2)==0xbeef,"Data store outside code must stay normal");}
    {Context c;overlay_fixture::install(c);c.r[5]=sites[0];c.gte.writeData(24,0x12345678);const auto before=c.ram.bytes;
        rejects([&]{run(c,0x800120f0);},"overlay code write");require(c.ram.bytes==before,"SWC2 bypassed code whitelist");
        c.r[5]=0x80150000;run(c,0x800120f0);require(c.ram.read(c.r[5],4)==0x12345678,"SWC2 outside code");}
    for(auto target:{0x80012b54U,0x80010930U,0x80012008U,0x80012aa4U}){Context c;overlay_fixture::install(c);
        rejects([&]{run(c,target);},"JR target");}
    // N5: the dead range is an explicit fatal from every dynamic transfer.
    for(auto target:{0x80010930U,0x80010a00U,0x80010ba0U,0xa0010930U}){Context c;overlay_fixture::install(c);
        rejects([&]{run(c,target);},"dead range");}
    // RingSpaceWait: proceed with space >= 0x800; stop only at the spin/poll point.
    for(auto space:{0x800U,0x801U,0x7fffffffU}){Context c;overlay_fixture::install(c);c.r[8]=space;run(c,overlay::ringSpaceWait);
        require(c.pc==hostReturn&&c.r[19]==1&&c.r[20]==1,"RingSpaceWait with space must return");}
    for(auto space:{0x7ffU,0U,0xffffffffU}){Context c;overlay_fixture::install(c);c.r[8]=space;
        rejects([&]{run(c,overlay::ringSpaceWait);},"poll point 0x80012a04");
        require(c.r[19]==0&&c.pc==overlay::ringSpacePollPoint,"Spin branch must stop at poll point");}
    // BREAK: fatal diagnostic, never the j-self at 80012AA4.
    {Context c;overlay_fixture::install(c);rejects([&]{run(c,overlay::breakTrap);},"guest BREAK 1 (not reached through an overlay table dispatch)");
        require(c.pc==overlay::breakTrap,"BREAK continued");}
    // N1-N3 synthetic analogues: unsupported types reach BREAK through their dispatcher.
    for(const auto& row:{std::tuple{2U,0x10U,"JT_C dispatcher 0x80010368, index 4, byte offset 0x10, element type 0x10, element pointer 0x80010360"},
                         std::tuple{2U,0x44U,"JT_C dispatcher 0x80010368, index 17, byte offset 0x44, element type 0x44, element pointer 0x80010360"},
                         std::tuple{0U,0x18U,"JT_A dispatcher 0x80010dec, index 6, byte offset 0x18, element type 0x18, element pointer 0x80010de4"}}){
        const auto type=std::get<1>(row);const char* text=std::get<2>(row);
        const auto t=overlay::tables[std::get<0>(row)];Context c;overlay_fixture::install(c);c.r[5]=t.base+type;
        rejects([&]{run(c,overlay_fixture::dispatch(t));},text);
        require(c.pc==overlay::breakTrap&&c.tableTrace.size()==1&&c.tableTrace[0].index==type/4,"BREAK table diagnostic state");}
    // Runtime patch state: uniform 1840/1C40 accepted at entry, mixed state fatal.
    for(bool mixed:{false,true}){Context c;overlay_fixture::install(c);
        for(std::size_t n=0;n<overlay::palTitle.patchSites.size();++n)
            c.ram.write(overlay::palTitle.patchSites[n]+2,(mixed&&n==3)?0x1840U:0x1c40U,2);
        c.r[10]=10;c.r[11]=3;
        if(mixed)rejects([&]{run(c,0x80012020);},"mixed runtime patch state");
        else{run(c,0x80012020);require(c.r[12]==13,"Uniform 1C40 runtime state rejected");}}
    for(bool taken:{false,true}){Context c;overlay_fixture::install(c);c.r[10]=1;c.r[11]=taken?1:2;run(c,0x80012040);
        require(c.r[23]==1&&c.r[24]==(taken?0U:1U),"Branch delay/fallthrough");}
    for(bool sub:{false,true}){Context c;overlay_fixture::install(c);c.r[10]=sub?0x80000000:0x7fffffff;c.r[11]=1;c.r[12]=99;
        rejects([&]{run(c,sub?0x80012030:0x80012020);},"overflow");require(c.r[12]==99,"Overflow wrote destination");
        overlay_fixture::install(c);c.r[10]=10;c.r[11]=3;run(c,sub?0x80012030:0x80012020);require(c.r[12]==(sub?7U:13U),"Integer result");}
    {Context c;overlay_fixture::install(c);c.r[5]=0xa0010204;rejects([&]{run(c,0x800120c0);},"code write");}
    // N4: range, alignment and guest domain are checked before any table read.
    // Specified domains: A 22 and C 20 entries from 0; B/D byte offsets 0x08..0x1C.
    const std::array<std::array<std::uint32_t,3>,4> domain={{{0,22,0},{8,8,2},{0,20,0},{8,8,2}}};
    for(unsigned id=0;id<overlay::tables.size();++id){const auto t=overlay::tables[id];
        require(t.count==domain[id][1]&&t.minIndex==domain[id][2],"Jump table domain metadata");
        for(auto offset:{domain[id][0],4*domain[id][1]-4}){Context c;overlay_fixture::install(c);c.r[5]=t.base+offset;
            run(c,overlay_fixture::dispatch(t));require(c.tableTrace.size()==1&&c.tableTrace[0].index==offset/4,"Domain boundary accepted");}
        std::vector<std::uint32_t> bad={t.base+4*t.count,t.base-4,t.base+1,t.base+4*t.count+2,0x1f800000U,0xbfc00000U};
        for(std::uint32_t offset=0;offset<domain[id][0];offset+=4)bad.push_back(t.base+offset);
        for(auto address:bad){Context c;overlay_fixture::install(c);c.r[5]=address;c.ram.effects.clear();
            rejects([&]{run(c,overlay_fixture::dispatch(t));},(address&3)?"not aligned to 4 (AdEL)":
                (address>=t.base&&address<t.base+domain[id][0])?"guest domain":"out of bounds");
            for(const auto& e:c.ram.effects)require(!(e.kind==moyle::detail::EffectKind::Read&&(e.address&~3U)==(address&~3U)),"Rejected table slot was read");
            require(c.tableTrace.empty(),"Rejected index transferred");}
        Context c;overlay_fixture::install(c);
        StaticTable table{t.base,std::vector<std::uint32_t>(t.count,0x80012000U)};TableTicket ticket;
        c.ram.write(t.base+4*t.minIndex,0x80012020,4);rejects([&]{overlay::loadTable(c,ticket,table,id,t.site,t.base+4*t.minIndex);},"target");
        rejects([&]{overlay::loadTable(c,ticket,StaticTable{t.base,{0x80012000U}},id,t.site,t.base+4*t.minIndex);},"descriptor mismatch");
        rejects([&]{overlay::loadTable(c,ticket,table,7,t.site,t.base+4*t.minIndex);},"unknown overlay jump table");}
    {Context c;overlay_fixture::install(c);rejects([&]{executeSyntheticTitle(c,0x80012000,100);},"Unverified entry");}
    {Context c;overlay_fixture::install(c);c.ram.write(0x80012d00,1,4);rejects([&]{run(c,0x80012000);},"SHA-1");}
    // S10 semantic packet expectations from the specification; synthetic instructions only.
    {Context c;overlay_fixture::install(c);constexpr auto ring=0x80100000U,ot=0x80120000U,ctx=0x1f800000U;
        for(unsigned k=0;k<=0x60;++k)c.ram.write(ot+4*k,k?(ot+4*(k-1))&0xffffff:0xffffff,4);
        c.ram.write(ctx+0x18,ot,4);c.r[4]=ring;c.r[5]=ctx+4;c.r[6]=0x123456;
        executeSyntheticTitle(c,0x80012ae4,500);require(c.r[2]==ring+0x18,"F4 return");
        c.r[4]=c.r[2];executeSyntheticTitle(c,0x80012ab0,500);require(c.r[2]==ring+0x20,"E1 return");
        // Compute from this test's OT and rectangle; no oracle-derived golden.
        const auto xy=[](int x,int y){return (static_cast<std::uint32_t>(y)&65535)<<16 | (static_cast<std::uint32_t>(x)&65535);};
        unsigned off=0;for(auto w:{(5U<<24)|((ot+4*(0x60-1))&0xffffff), (0x2aU<<24)|0x123456,
            xy(-256,-120),xy(256,-120),xy(-256,120),xy(256,120),(1U<<24)|0xffffff,0xe1000620U}){
            require(c.ram.read(ring+off,4)==w,"S10 packet word");off+=4;}
        require(c.ram.read(ot+0x180,4)==(ring&0xffffff)&&c.ram.read(ot,4)==((ring+0x18)&0xffffff),"S10 OT links");}
    std::cout<<"Overlay unit runtime: "<<checks<<" checks passed (synthetic S10, no proprietary input)\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
