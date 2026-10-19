#include "../src/ps1_gte.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
using moyle::detail::recomp::Gte;
unsigned checks=0;
void require(bool value,const std::string& why){++checks;if(!value)throw std::runtime_error(why);}
int main(int argc,char** argv){try{
    require(argc==2,"Expected converted T5 vector file");
    std::ifstream input(argv[1]);unsigned count=0;input>>count;require(count==79,"T5 vector count");
    const auto number=[&](){std::string s;input>>s;require(bool(input),"Truncated T5 vectors");return static_cast<std::uint32_t>(std::stoul(s,nullptr,0));};
    for(unsigned n=0;n<count;++n){
        Gte g;std::string id;unsigned steps=0;input>>id;const auto encoding=number();input>>steps;
        for(unsigned s=0;s<steps;++s){std::string op;unsigned reg;input>>op>>reg;const auto v=number();
            if(op=="mtc2")g.writeData(reg,v);else if(op=="ctc2")g.writeControl(reg,v);
            else {require(op=="exec",id+": unknown operation");require(g.execute(v),id+": unsupported setup command");}}
        if(encoding)require(g.execute(encoding),id+": unsupported command");
        for(unsigned bank=0;bank<2;++bank)for(unsigned r=0;r<32;++r){
            const auto expected=number(),actual=bank?g.readControl(r):g.readData(r);
            if(actual!=expected){std::cerr<<id<<" encoding 0x"<<std::hex<<encoding<<" "<<(bank?"cfc2":"mfc2")<<std::dec<<r
                <<" expected 0x"<<std::hex<<expected<<" actual 0x"<<actual<<'\n';}
            require(actual==expected,id+": architectural mismatch");
        }
        require(g.flagRaw()==number(),id+": raw FLAG");
        require(g.readControl(31)==number(),id+": FLAG read");
        require((g.readControl(31)>>31)==number(),id+": FLAG summary");
    }
    std::string trailing;require(!(input>>trailing),"Unexpected trailing vector data");
    // Architectural transfer registers omitted by the supplied 79 cases.
    Gte g;g.writeData(28,0x7fff);require(g.readData(9)==3968&&g.readData(10)==3968&&g.readData(11)==3968,"IRGB unpack");
    require(g.readData(28)==0x7fff&&g.readData(29)==0x7fff,"ORGB/IRGB readback");
    g.writeData(29,0);require(g.readData(29)==0x7fff,"ORGB readonly");
    for(auto row:{std::pair{0U,32U},std::pair{0xffffffffU,32U},std::pair{0x80000000U,1U},std::pair{1U,31U}}){
        g.writeData(30,row.first);g.writeData(31,99);require(g.readData(30)==row.first&&g.readData(31)==row.second,"LZCS/LZCR");}
    g.writeControl(31,0x7ffff000);const auto before=g.readControl(31);
    require(!g.execute(0x4a000012)&&g.readControl(31)==before,"Unsupported GTE mutated state");
    std::cout<<"GTE: 79/79 synthetic vectors, all 32+32 architectural registers and FLAG views; "<<checks<<" checks passed\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
