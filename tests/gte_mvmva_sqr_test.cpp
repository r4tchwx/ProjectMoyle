// MVMVA (rotation matrix x V0..V2 or the IR vector, no translation) and SQR. These two commands are NOT covered by the 79 T5 hardware-derived
// vectors; the expectations below are computed here from the published command definitions with plain 64-bit arithmetic
// (independent of the class under test), so they check the implementation against the spec text, not against a real GTE.
#include "../src/ps1_gte.hpp"
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
using moyle::detail::recomp::Gte;
static unsigned checks=0;
static void require(bool value,const std::string& why){++checks;if(!value)throw std::runtime_error(why);}
static std::uint32_t pack(int lo,int hi){return (std::uint32_t(lo)&0xffffU)|(std::uint32_t(hi)<<16);}
static std::uint32_t mvmva(unsigned sf,unsigned mx,unsigned v,unsigned cv,unsigned lm){
    return 0x4a000012U|(sf<<19)|(mx<<17)|(v<<15)|(cv<<13)|(lm<<10);
}
static std::int64_t sar(std::int64_t v,unsigned n){return v>=0?v>>n:-((-v+((1LL<<n)-1))>>n);}
int main(){try{
    const int rt[3][3]={{0x1000,-0x0800,0x0123},{0x0456,0x0c00,-0x0789},{-0x0abc,0x0222,0x0f00}};
    const int vert[3][3]={{100,-200,300},{-1234,567,-89},{32767,-32768,1}};
    for(unsigned vs=0;vs<3;++vs)for(unsigned sf=0;sf<2;++sf)for(unsigned lm=0;lm<2;++lm){
        Gte g;
        g.writeControl(0,pack(rt[0][0],rt[0][1]));g.writeControl(1,pack(rt[0][2],rt[1][0]));g.writeControl(2,pack(rt[1][1],rt[1][2]));
        g.writeControl(3,pack(rt[2][0],rt[2][1]));g.writeControl(4,std::uint32_t(rt[2][2]));
        g.writeData(2*vs,pack(vert[vs][0],vert[vs][1]));g.writeData(2*vs+1,std::uint32_t(vert[vs][2]));
        // Translation registers hold values that would show up if cv=3 wrongly used them.
        g.writeControl(5,0x1111);g.writeControl(6,0x2222);g.writeControl(7,0x3333);g.writeControl(13,0x4444);
        require(Gte::supports(mvmva(sf,0,vs,3,lm)),"MVMVA RT cv=3 supported");
        require(g.execute(mvmva(sf,0,vs,3,lm)),"MVMVA executes");
        std::uint32_t flag=0;
        for(unsigned row=0;row<3;++row){
            std::int64_t sum=0;for(unsigned col=0;col<3;++col)sum+=std::int64_t(rt[row][col])*vert[vs][col];
            const auto mac=sar(sum,sf*12);
            require(std::int64_t(std::int32_t(g.readData(25+row)))==mac,"MVMVA MAC"+std::to_string(row+1));
            const std::int64_t lo=lm?0:-32768,hi=32767;
            const auto irv=mac<lo?lo:mac>hi?hi:mac;
            if(mac<lo||mac>hi)flag|=1U<<(24-row);
            require(std::int64_t(std::int32_t(g.readData(9+row)))==irv,"MVMVA IR"+std::to_string(row+1));
        }
        require(g.flagRaw()==flag,"MVMVA FLAG vs="+std::to_string(vs)+" sf="+std::to_string(sf)+" lm="+std::to_string(lm));
    }
    // ---- MVMVA RT x IR (v=3, cv=3): the forms at 0x8004F8C0/0x80037A54 (sf=0) and 0x8004F8E0/0x80037A78 (sf=1).
    // Bits 20..24 (the libgte command-number field) are not decoded by the GTE; the PAL words carry 0x04 there.
    const std::uint32_t ignored=31U<<20;
    require((0x4a41e012U&~ignored)==mvmva(0,0,3,3,0)&&(0x4a49e012U&~ignored)==mvmva(1,0,3,3,0),"PAL v=3 opcodes decode to mx=0 v=3 cv=3 lm=0");
    require(Gte::supports(0x4a41e012U)&&Gte::supports(0x4a49e012U),"PAL v=3 opcodes supported");
    // Reference: old IR snapshot, 44-bit sums (no overflow possible from 16-bit operands), arithmetic shift, 32-bit MAC,
    // IR saturated from the 32-bit MAC (the existing machinery), FLAG bits 24/23/22 per lane, summary over 30..23/18..13.
    const auto setRt=[](Gte& g,const int m[3][3]){
        g.writeControl(0,pack(m[0][0],m[0][1]));g.writeControl(1,pack(m[0][2],m[1][0]));g.writeControl(2,pack(m[1][1],m[1][2]));
        g.writeControl(3,pack(m[2][0],m[2][1]));g.writeControl(4,std::uint32_t(m[2][2]));};
    const auto checkIr=[&](const int m[3][3],const int in[3],unsigned sf,unsigned lm,const std::string& id){
        Gte g;setRt(g,m);
        // Distinct V0..V2, translation and MAC0 values: any wrong source or stray write shows up.
        g.writeData(0,pack(11,-22));g.writeData(1,33);g.writeData(2,pack(-44,55));g.writeData(3,66);g.writeData(4,pack(77,-88));g.writeData(5,99);
        g.writeControl(5,0x1111);g.writeControl(6,0x2222);g.writeControl(7,0x3333);g.writeData(24,0x12345678);g.writeData(7,0x4321);
        for(unsigned n=0;n<3;++n)g.writeData(9+n,std::uint32_t(in[n]));
        g.writeControl(31,0x7ffff000); // stale FLAG must be cleared by the command
        std::uint32_t before[64];for(unsigned r=0;r<32;++r){before[r]=g.readData(r);before[32+r]=g.readControl(r);}
        require(g.execute(mvmva(sf,0,3,3,lm)),id+": executes");
        std::uint32_t flag=0;
        for(unsigned row=0;row<3;++row){
            std::int64_t sum=0;for(unsigned col=0;col<3;++col)sum+=std::int64_t(m[row][col])*in[col];
            const auto mac=std::int32_t(std::uint32_t(sar(sum,sf*12)));
            require(std::int32_t(g.readData(25+row))==mac,id+": MAC"+std::to_string(row+1));
            const std::int64_t lo=lm?0:-32768,hi=32767;
            const auto irv=mac<lo?lo:mac>hi?hi:mac;
            if(mac<lo||mac>hi)flag|=1U<<(24-row);
            require(std::int64_t(std::int32_t(g.readData(9+row)))==irv,id+": IR"+std::to_string(row+1));
        }
        require(g.flagRaw()==flag,id+": FLAG lanes");
        require((g.readControl(31)>>31)==((flag&0x7f87e000U)?1U:0U),id+": FLAG summary");
        bool untouched=true;
        for(unsigned r=0;r<32;++r){
            const bool written=(r>=9&&r<=11)||(r>=25&&r<=27)||r==28||r==29; // IR, MAC and the IRGB/ORGB views of IR
            if(!written&&g.readData(r)!=before[r])untouched=false;
            if(r!=31&&g.readControl(r)!=before[32+r])untouched=false;
        }
        require(untouched,id+": other data/control registers untouched");
    };
    const int asym[3][3]={{0x0800,-0x1000,0x0300},{0x7fff,0x0001,-0x0200},{-0x0400,0x0123,0x7fff}};
    for(unsigned sf=0;sf<2;++sf)for(unsigned lm=0;lm<2;++lm){
        const int in1[3]={1000,-2000,300};checkIr(asym,in1,sf,lm,"asym sf="+std::to_string(sf)+" lm="+std::to_string(lm));
        const int in2[3]={-32768,32767,-1};checkIr(asym,in2,sf,lm,"extremes sf="+std::to_string(sf)+" lm="+std::to_string(lm));
    }
    {   // Snapshot: IR1 is written first; rows 2 and 3 must still see the old IR1 (a permutation matrix makes it visible).
        const int perm[3][3]={{0,1,0},{1,0,0},{1,1,1}};const int in[3]={5,7,11};
        Gte g;setRt(g,perm);for(unsigned n=0;n<3;++n)g.writeData(9+n,std::uint32_t(in[n]));
        require(g.execute(0x4a41e012U),"aliasing executes");
        require(g.readData(9)==7&&g.readData(10)==5&&g.readData(11)==23,"IR source snapshotted before IR/MAC writes");
        checkIr(perm,in,0,0,"aliasing reference");
    }
    {   // IR saturation boundaries (sf=0, lm=0): 32767 / -32768 exact, 32768 / -32769 saturate; lane bits 24, 23, 22.
        const int m[3][3]={{1,1,0},{1,1,0},{0,1,1}};
        const int at[3]={32766,1,-32768};checkIr(m,at,0,0,"boundary exact");    // 32767, 32767, -32767
        const int over[3]={32767,1,-32768};checkIr(m,over,0,0,"boundary over"); // 32768 (IR1, IR2 flags), -32767
        const int under[3]={-32768,-1,-32768};checkIr(m,under,0,0,"boundary under"); // -32769 (IR1, IR2), -32769 (IR3: no summary)
        Gte g;setRt(g,m);g.writeData(9,std::uint32_t(-32768));g.writeData(10,std::uint32_t(-1));g.writeData(11,std::uint32_t(-32768));
        g.execute(0x4a41e012U);require(g.flagRaw()==((1U<<24)|(1U<<23)|(1U<<22))&&(g.readControl(31)>>31)==1U,"lane bits and summary");
        const int m3[3][3]={{0,0,0},{0,0,0},{0,0,1}};
        Gte h;setRt(h,m3);h.writeData(11,std::uint32_t(-32768));h.writeData(9,0);h.writeData(10,0);
        const int mneg[3][3]={{0,0,0},{0,0,0},{0,-1,-1}};setRt(h,mneg);h.writeData(10,std::uint32_t(-32768));
        h.execute(0x4a41e012U);require(h.flagRaw()==(1U<<22)&&(h.readControl(31)>>31)==0U&&std::int32_t(h.readData(11))==32767,"IR3-only saturation: bit 22 set, not in the summary");
    }
    {   // Signed 32-bit MAC wrap (sf=0): 3 x 32767 x 32767 exceeds 2^31; MAC1 wraps, IR1 saturates from the wrapped MAC.
        const int big[3][3]={{0x7fff,0x7fff,0x7fff},{-0x8000,-0x8000,-0x8000},{0,0,0}};
        const int in[3]={32767,32767,32767};checkIr(big,in,0,0,"MAC wrap");
        Gte g;setRt(g,big);for(unsigned n=0;n<3;++n)g.writeData(9+n,32767);g.execute(0x4a41e012U);
        require(std::int32_t(g.readData(25))<0&&std::int32_t(g.readData(26))>0,"MAC wraps to the opposite sign");
    }
    // Forms that stay unsupported must not mutate state: translation vectors, other matrices, far-colour (cv=2), every
    // non-RT or translated IR-vector form, and the PAL 0x80056E74 form (mx=2, v=3, cv=1, lm=1, sf=1 = 0x4A4DA412).
    require((0x4a4da412U&~ignored)==mvmva(1,2,3,1,1),"0x4A4DA412 is mx=2 v=3 cv=1 lm=1 sf=1");
    for(auto pal:{0x4a41e012U,0x4a49e012U}){ // the exact PAL words behave exactly like the field-built opcode
        const int in[3]={1234,-567,8901};Gte a,b;setRt(a,asym);setRt(b,asym);
        for(unsigned n=0;n<3;++n){a.writeData(9+n,std::uint32_t(in[n]));b.writeData(9+n,std::uint32_t(in[n]));}
        a.execute(pal);b.execute(pal&~ignored);bool same=a.flagRaw()==b.flagRaw();
        for(unsigned r=0;r<32;++r)same=same&&a.readData(r)==b.readData(r);
        require(same,"exact PAL opcode == field-built opcode");
    }
    for(auto w:{mvmva(1,0,0,0,0),mvmva(1,0,0,1,0),mvmva(1,0,0,2,0),mvmva(1,1,0,3,0),mvmva(1,2,0,3,0),mvmva(1,3,0,3,0),
                mvmva(1,1,3,3,0),mvmva(1,2,3,3,0),mvmva(1,3,3,3,0),mvmva(1,0,3,0,0),mvmva(1,0,3,1,0),mvmva(1,0,3,2,0),0x4a4da412U,0x4a000012U}){
        Gte g;g.writeControl(31,0x7ffff000);const auto before=g.readControl(31);g.writeData(9,5);
        require(!Gte::supports(w)&&!g.execute(w)&&g.readControl(31)==before&&g.readData(9)==5,"unsupported MVMVA form mutated state");
    }
    // SQR.
    const int irs[3]={3,-4,100};
    for(unsigned sf=0;sf<2;++sf)for(unsigned lm=0;lm<2;++lm){
        Gte g;for(unsigned n=0;n<3;++n)g.writeData(9+n,std::uint32_t(irs[n]));
        const std::uint32_t w=0x4a000028U|(sf<<19)|(lm<<10);
        require(Gte::supports(w)&&g.execute(w),"SQR executes");
        for(unsigned n=0;n<3;++n){
            const auto mac=sar(std::int64_t(irs[n])*irs[n],sf*12);
            require(std::int32_t(g.readData(25+n))==mac,"SQR MAC");
            require(std::int32_t(g.readData(9+n))==(mac>32767?32767:mac),"SQR IR");
        }
        require(g.flagRaw()==0,"SQR no flag");
    }
    {   // Saturation: 300^2 = 90000 > 32767 -> IR1 clamps to 32767 and FLAG bit 24 (IR1 saturated) is set; MAC keeps the value.
        Gte g;g.writeData(9,300);g.writeData(10,2);g.writeData(11,static_cast<std::uint32_t>(-181));
        require(g.execute(0x4a000428U),"SQR saturating");
        require(g.readData(25)==90000&&g.readData(9)==32767,"SQR IR1 saturates");
        require(g.readData(26)==4&&g.readData(10)==4&&g.readData(27)==32761&&g.readData(11)==32761,"SQR other lanes");
        require(g.flagRaw()==(1U<<24),"SQR FLAG");
        require(g.readControl(31)==((1U<<24)|0x80000000U)||g.readControl(31)==(1U<<24),"SQR FLAG read");
    }
    std::cout<<"GTE MVMVA(rt,cv=3)/SQR: spec-derived expectations (no hardware vectors); "<<checks<<" checks passed\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
