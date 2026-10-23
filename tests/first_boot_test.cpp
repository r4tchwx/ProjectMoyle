#include "first_boot.hpp"
#include <iostream>
#include <memory>
using namespace moyle::detail::recomp;
int main(){
    auto ctx=std::make_unique<Context>();auto& c=*ctx;bios::BootDevice d;c.biosDevice=&d;
    firstboot::Policy p;boot::Trace trace;trace.ctx=&c;p.trace=&trace;
    auto check=[](bool x){if(!x)throw std::runtime_error("first-boot policy regression");};
    d.cardInitEnabled=true;c.r[31]=0x8005a30c;c.ram.write(0x8005a814,0x240a00b0,4);c.ram.write(0x8005a818,0x01400008,4);c.ram.write(0x8005a81c,0x2409004a,4);
    check(p.before(c,0x8005a814));check(d.cardInit.calls==1&&c.redirectPc==c.r[31]);
    c.redirectPending=false;c.r[31]=0x8005a31c;c.r[2]=123;
    check(p.before(c,0x8005a920));check(c.r[2]==123&&c.redirectPc==c.r[31]);
    for(int kind=0;kind<3;++kind){
        c.r[31]=kind==0?0x8005a320:0x8005a31c;d.irqEnabled=kind==1;d.interruptDepth=kind==2;
        bool failed=false;try{p.before(c,0x8005a920);}catch(const std::runtime_error&){failed=true;}check(failed);
    }
    check(!p.before(c,0x80012340));
    std::cout<<"first-boot policy: init, preservation, return, caller/IRQ/depth guards passed\n";
}
