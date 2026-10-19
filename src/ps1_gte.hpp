#pragma once
#include <algorithm>
#include <array>
#include <cstdint>

namespace moyle::detail::recomp {
// Synchronous architectural GTE subset. No host floating point, timing or PC
// specializations. Register storage is private: transfers always use PS1 views.
class Gte {
    std::array<std::uint32_t,32> data_{}, control_{};
    using Wide = std::int64_t;
    static constexpr Wide signed16(std::uint32_t v) { return Wide(v&0x7fff)-Wide(v&0x8000); }
    static constexpr Wide signed32(std::uint32_t v) { return Wide(v&0x7fffffff)-Wide(v&0x80000000); }
    // Defined arithmetic right shift, including on C++17 targets.
    static constexpr Wide shift(Wide v,unsigned n) { return v>=0?v/(Wide(1)<<n):-1-((-1-v)/(Wide(1)<<n)); }
    static Wide clamp(Wide v,Wide lo,Wide hi) { return std::min(hi,std::max(lo,v)); }
    void flag(unsigned bit) { control_[31]|=std::uint32_t(1)<<bit; }
    Wide saturate(Wide v,Wide lo,Wide hi,unsigned bit) {
        if(v<lo||v>hi)flag(bit);
        return clamp(v,lo,hi);
    }
    Wide accumulator(unsigned lane,Wide v) {
        if(v>=(Wide(1)<<43))flag(31-lane);
        if(v<-(Wide(1)<<43))flag(28-lane);
        const auto bits=static_cast<std::uint64_t>(v)&((std::uint64_t(1)<<44)-1);
        return Wide(bits&((std::uint64_t(1)<<43)-1))-Wide(bits&(std::uint64_t(1)<<43));
    }
    Wide mac0(Wide v) {
        if(v>0x7fffffffLL)flag(16);
        if(v<-0x80000000LL)flag(15);
        return v;
    }
    Wide ir(unsigned lane,Wide v,bool lm) { return saturate(v,lm?0:-32768,32767,25-lane); }
    void macIr(unsigned lane,Wide v,unsigned sf,bool lm) {
        data_[24+lane]=static_cast<std::uint32_t>(shift(v,sf));
        data_[8+lane]=static_cast<std::uint32_t>(ir(lane,signed32(data_[24+lane]),lm));
    }
    void pushScreen(std::uint32_t v) { data_[12]=data_[13];data_[13]=data_[14];data_[14]=v; }
    void pushColour(std::uint32_t v) { data_[20]=data_[21];data_[21]=data_[22];data_[22]=v; }
    std::uint32_t divide(std::uint32_t h,std::uint32_t z) {
        if(h>=2*z){flag(17);return 0x1ffff;}
        unsigned leading=0;
        while((z<<leading)<0x8000)++leading;
        const std::uint64_t n=std::uint64_t(h)<<leading;
        const auto d=z<<leading,index=(d-0x7fc0)>>7;
        // 257-entry PS1 UNR table formula, integer division only for the table.
        const auto table=std::max(0,int((0x40000/(index+0x100)+1)/2)-0x101);
        const std::uint32_t u=std::uint32_t(table)+0x101;
        const auto first=(0x2000080-d*u)>>8,reciprocal=(0x80+first*u)>>8;
        return static_cast<std::uint32_t>(std::min<std::uint64_t>(0x1ffff,(n*reciprocal+0x8000)>>16));
    }
    void project(unsigned vertex,unsigned sf,bool lm,bool last) {
        const std::array<Wide,3> v={signed16(data_[2*vertex]),signed16(data_[2*vertex]>>16),signed16(data_[2*vertex+1])};
        std::array<Wide,3> acc{};
        for(unsigned row=0;row<3;++row){
            auto sum=accumulator(row+1,signed32(control_[5+row])*4096);
            for(unsigned col=0;col<3;++col){
                const auto element=3*row+col;
                sum=accumulator(row+1,sum+signed16(control_[element/2]>>(16*(element%2)))*v[col]);
            }
            acc[row]=sum;
        }
        macIr(1,acc[0],sf,lm);macIr(2,acc[1],sf,lm);
        data_[27]=static_cast<std::uint32_t>(shift(acc[2],sf));
        const auto z=shift(acc[2],12);
        (void)ir(3,z,false); // IR3 FLAG source ignores sf and lm.
        data_[11]=static_cast<std::uint32_t>(clamp(signed32(data_[27]),lm?0:-32768,32767));
        data_[16]=data_[17];data_[17]=data_[18];data_[18]=data_[19];
        data_[19]=static_cast<std::uint32_t>(saturate(z,0,65535,18));
        const Wide q=divide(control_[26]&65535,data_[19]);
        const auto x=saturate(shift(mac0(q*signed16(data_[9])+signed32(control_[24])),16),-1024,1023,14);
        const auto y=saturate(shift(mac0(q*signed16(data_[10])+signed32(control_[25])),16),-1024,1023,13);
        pushScreen((static_cast<std::uint32_t>(x)&65535)|(static_cast<std::uint32_t>(y)<<16));
        if(last){
            const auto depth=mac0(q*signed16(control_[27])+signed32(control_[28]));
            data_[24]=static_cast<std::uint32_t>(depth);
            data_[8]=static_cast<std::uint32_t>(saturate(shift(depth,12),0,4096,12));
        }
    }
    void depthCue(std::uint32_t colour,unsigned sf,bool lm) {
        std::uint32_t result=data_[6]&0xff000000;
        for(unsigned lane=1;lane<=3;++lane){
            const Wide base=Wide((colour>>(8*(lane-1)))&255)*65536;
            const auto diff=accumulator(lane,signed32(control_[20+lane])*4096-base);
            const auto intermediate=ir(lane,signed32(static_cast<std::uint32_t>(shift(diff,sf))),false);
            macIr(lane,accumulator(lane,base+intermediate*signed16(data_[8])),sf,lm);
            result|=static_cast<std::uint32_t>(saturate(shift(signed32(data_[24+lane]),4),0,255,22-lane))<<(8*(lane-1));
        }
        pushColour(result);
    }
public:
    std::uint32_t flagRaw() const { return control_[31]; }
    std::uint32_t readControl(unsigned r) const {
        if(r==31)return control_[31]|((control_[31]&0x7f87e000)?0x80000000U:0U);
        return control_.at(r);
    }
    void writeControl(unsigned r,std::uint32_t v) {
        if(r==31)v&=0x7ffff000;
        else if(r==4||r==12||r==20||r==26||r==27||r==29||r==30)v=static_cast<std::uint32_t>(signed16(v));
        control_.at(r)=v;
    }
    std::uint32_t readData(unsigned r) const {
        if(r==15)return data_[14];
        if(r==28||r==29){
            std::uint32_t packed=0;
            for(unsigned lane=1;lane<=3;++lane)packed|=static_cast<std::uint32_t>(clamp(shift(signed16(data_[8+lane]),7),0,31))<<(5*(lane-1));
            return packed;
        }
        return data_.at(r);
    }
    void writeData(unsigned r,std::uint32_t v) {
        if(r==15){pushScreen(v);return;}
        if(r==28){for(unsigned lane=1;lane<=3;++lane)data_[8+lane]=((v>>(5*(lane-1)))&31)<<7;return;}
        if(r==29||r==31)return;
        if(r==1||r==3||r==5||(r>=8&&r<=11))v=static_cast<std::uint32_t>(signed16(v));
        else if(r==7||(r>=16&&r<=19))v&=65535;
        if(r==30){
            auto bits=(v&0x80000000)?~v:v;
            unsigned count=0;while(count<32&&!(bits&0x80000000)){++count;bits<<=1;}
            data_[31]=count;
        }
        data_.at(r)=v;
    }
    static bool supports(std::uint32_t w) {
        if((w&0xfe000000U)!=0x4a000000U)return false;
        switch(w&63){case 1:case 6:case 16:case 42:case 45:case 46:case 48:return true;default:return false;}
    }
    // Unsupported instructions do not mutate state; the caller supplies the PC diagnostic.
    bool execute(std::uint32_t w) {
        if(!supports(w))return false;
        control_[31]=0;
        const unsigned sf=(w&(1U<<19))?12:0;const bool lm=(w&(1U<<10))!=0;
        switch(w&63){
        case 1:project(0,sf,lm,true);break;
        case 48:for(unsigned v=0;v<3;++v)project(v,sf,lm,v==2);break;
        case 6:{
            Wide area=0;
            for(unsigned v=0;v<3;++v)area+=signed16(data_[12+v])*(signed16(data_[12+(v+1)%3]>>16)-signed16(data_[12+(v+2)%3]>>16));
            data_[24]=static_cast<std::uint32_t>(mac0(area));break;
        }
        case 45:case 46:{
            const bool four=(w&63)==46;
            Wide sum=0;for(unsigned r=four?16:17;r<=19;++r)sum+=data_[r];
            const auto product=mac0(sum*signed16(control_[four?30:29]));
            data_[24]=static_cast<std::uint32_t>(product);
            data_[7]=static_cast<std::uint32_t>(saturate(shift(product,12),0,65535,18));break;
        }
        case 16:depthCue(data_[6],sf,lm);break;
        case 42:for(unsigned n=0;n<3;++n)depthCue(data_[20],sf,lm);break;
        }
        return true;
    }
};
}
