#pragma once
#include "boot_harness.hpp"
namespace moyle::detail::recomp::firstboot {

struct Device : bios::BootDevice {
    std::array<std::uint32_t,bios::BootDevice::maxEvents> callbackHandlers{};
    boot::Trace* bringupTrace=nullptr;

    struct IntRpState {
        bool active=false;
        std::uint32_t node=0;
        std::uint32_t fn0=0;
        std::uint32_t fn1=0;
    };
    std::array<IntRpState,4> intRp{};
};

inline void biosPolicy(
    Context& c,
    std::uint32_t site,
    std::uint32_t table,
    std::uint32_t function
) {
    auto* device=static_cast<Device*>(c.biosDevice);
    if(!device)
        throw std::runtime_error("first-boot BIOS policy: no device");

    // PAL libcard opens exactly eight callback-mode events here.
    if(table==0xb0U && function==0x08U && c.r[6]==0x1000U) {
        struct Expected {
            std::uint32_t ret;
            std::uint32_t cls;
            std::uint32_t spec;
            std::uint32_t handler;
        };

        static constexpr Expected expected[]={
            {0x8005ce14U,0xf4000001U,0x00000004U,0x8005cd14U},
            {0x8005ce38U,0xf4000001U,0x00008000U,0x8005cd28U},
            {0x8005ce5cU,0xf4000001U,0x00000100U,0x8005cd3cU},
            {0x8005ce80U,0xf4000001U,0x00002000U,0x8005cd50U},
            {0x8005cea4U,0xf0000011U,0x00000004U,0x8005cd64U},
            {0x8005cec8U,0xf0000011U,0x00008000U,0x8005cd78U},
            {0x8005ceecU,0xf0000011U,0x00000100U,0x8005cd8cU},
            {0x8005cf10U,0xf0000011U,0x00002000U,0x8005cda0U},
        };

        if(site!=0x8004e648U ||
           device->interruptDepth ||
           device->irqEnabled)
            throw std::runtime_error(
                "first-boot card OpenEvent: site/state guard failed"
            );

        const Expected* match=nullptr;
        for(const auto& e:expected)
            if(e.ret==c.r[31]) {
                match=&e;
                break;
            }

        if(!match ||
           c.r[4]!=match->cls ||
           c.r[5]!=match->spec ||
           c.r[7]!=match->handler)
            throw std::runtime_error(
                "first-boot card OpenEvent: PAL tuple guard failed"
            );

        for(std::uint32_t n=0;n<bios::BootDevice::maxEvents;++n) {
            if(device->events[n].used)
                continue;

            device->events[n]={
                c.r[4],
                c.r[5],
                c.r[6],
                0x1000U,
                true
            };

            device->callbackHandlers[n]=c.r[7];
            ++device->eventsOpened;
            c.r[2]=bios::BootDevice::eventHandleBase+n;

            if(device->bringupTrace) {
                std::ostringstream o;
                o<<"callback OpenEvent handle=0x"<<std::hex<<c.r[2]
                 <<" class=0x"<<c.r[4]
                 <<" spec=0x"<<c.r[5]
                 <<" handler=0x"<<c.r[7];
                device->bringupTrace->add("first-boot-hle",o.str());
            }

            return;
        }

        throw std::runtime_error(
            "first-boot card OpenEvent: event table full"
        );
    }

    // Do not silently approximate callback delivery.
    // Registration/EnableEvent is enough for bring-up until card activity
    // actually attempts to fire one of these handlers.
    if(table==0xb0U && function==0x07U) {
        for(std::uint32_t n=0;n<bios::BootDevice::maxEvents;++n) {
            const auto& e=device->events[n];

            if(e.used &&
               e.mode==0x1000U &&
               e.status==0x2000U &&
               e.cls==c.r[4] &&
               e.spec==c.r[5]) {
                throw std::runtime_error(
                    "first-boot card callback delivery reached; "
                    "guest callback execution is not implemented yet"
                );
            }
        }
    }

    bios::bootPolicy(c,site,table,function);
}

// Explicit opt-in bring-up policy. The original boot harness and its pinned tests stay unchanged.
struct Policy {
    boot::Trace* trace=nullptr;
    bool before(Context& c,std::uint32_t pc) {
        if(pc==0x80045de8U) {
            auto* device=static_cast<bios::BootDevice*>(c.biosDevice);
            if(!device || device->interruptDepth || c.r[4]!=0U || c.r[31]!=0x80044e90U || c.ram.read(0x8005fbc4U,4)!=0x40000001U || c.ram.read(0x8005fc48U,4)!=0x60000000U || c.ram.read(0x80060984U,2)==0U)
                throw std::runtime_error("first-boot MDEC init: caller/state guard failed");
            c.retireLoad();
            const auto dpcr=c.ram.read(0x1f8010f0U,4);
            c.ram.write(0x1f8010f0U,dpcr|0x88U,4);
            if(trace)trace->add("first-boot-hle","MDEC reset/table load bypassed; DMA0 completed synchronously; decode unavailable");
            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }

        if(pc==0x80050aa4U) {
            auto* device=static_cast<bios::BootDevice*>(c.biosDevice);
            const auto savedRa=c.ram.read(0x80062354U,4);
            if(!device || device->interruptDepth || !device->irqEnabled || c.r[31]!=0x8004f6fcU || (savedRa!=0x80056184U && savedRa!=0x80044e18U))
                throw std::runtime_error("first-boot _patch_gte: caller/state guard failed");
            c.retireLoad();
            c.ram.write(0x80070230U,c.r[31],4);
            ++device->flushCache;
            device->irqEnabled=true;
            if(trace)trace->add("first-boot-hle","_patch_gte BIOS handler patch bypassed; host GTE/runtime owns execution");
            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }
        if(pc==0x80047d94U) {
            auto* device=static_cast<firstboot::Device*>(c.biosDevice);
            const auto savedRa=c.ram.read(c.r[29]+0x10U,4);
            if(!device || device->interruptDepth || c.r[31]!=0x80047d88U || savedRa!=0x80046508U || c.ram.read(0x80060070U,4)!=0x1f801800U)
                throw std::runtime_error("first-boot CDINIT remainder: caller/state guard failed");
            c.retireLoad();
            c.ram.write(0x80060088U,2U,1);
            c.ram.write(0x80060089U,0U,1);
            c.ram.write(0x8006008aU,0U,1);
            c.r[2]=0U;
            c.r[31]=savedRa;
            c.r[29]+=0x18U;
            if(trace)trace->add("first-boot-hle","CDINIT remainder bypassed; host libcd owns CD controller");
            c.redirectPending=true;
            c.redirectPc=savedRa;
            return true;
        }

        if(pc==0x80047bdcU) {
            auto* device=static_cast<firstboot::Device*>(c.biosDevice);
            if(!device || device->interruptDepth || c.r[31]!=0x80046518U)
                throw std::runtime_error("first-boot CD post-init: caller/state guard failed");
            c.retireLoad();
            c.r[2]=0U;
            if(trace)trace->add("first-boot-hle","CD post-init hardware reset bypassed; host CD/SPU own devices");
            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }
        if(pc==0x8005c6fcU) {
            auto* device=static_cast<firstboot::Device*>(c.biosDevice);

            if(!device ||
               device->interruptDepth!=1U ||
               device->irqEnabled ||
               c.r[31]!=0x8004e2a4U)
                throw std::runtime_error("first-boot VSYNC7: interrupt/caller guard failed");

            const auto q=c.ram.read(0x80067e64U,4);
            const auto cb44=c.ram.read(0x80076554U,4);

            if((q&0x80000000U)==0U || cb44!=0U)
                throw std::runtime_error("first-boot VSYNC7: card state left idle path");

            const auto count50=c.ram.read(0x80076560U,4);
            const auto count54=c.ram.read(0x80076564U,4);

            c.ram.write(0x80076560U,count50+1U,4);
            c.ram.write(0x80076564U,count54+1U,4);

            c.retireLoad();
            c.r[2]=0x80076510U;
            c.r[3]=count54+1U;

            if(trace) {
                std::ostringstream o;
                o<<"VSYNC7 idle-card path"
                 <<" count50="<<std::dec<<(count50+1U)
                 <<" count54="<<(count54+1U);
                trace->add("first-boot-hle",o.str());
            }

            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }

        if(pc==0x80058404U || pc==0x80058414U) {
            auto* device=static_cast<firstboot::Device*>(c.biosDevice);

            if(!device ||
               device->interruptDepth ||
               device->irqEnabled)
                throw std::runtime_error(
                    "first-boot SysEnqIntRP/SysDeqIntRP: interrupt-state guard failed"
                );

            const bool enq=(pc==0x80058404U);

            // Current PAL boot path:
            //   SysDeqIntRP(2, 0x800761e8) -> RA 0x800579b0
            //   SysEnqIntRP(2, 0x800761e8) -> RA 0x800579bc
            if(c.r[4]!=2U ||
               c.r[5]!=0x800761e8U ||
               c.r[31]!=(enq ? 0x800579bcU : 0x800579b0U))
                throw std::runtime_error(
                    "first-boot SysEnqIntRP/SysDeqIntRP: PAL tuple guard failed"
                );

            // Verify the PAL interrupt-procedure element we already audited.
            const auto fn0=c.ram.read(0x800761ecU,4);
            const auto fn1=c.ram.read(0x800761f0U,4);

            if(fn0!=0x800577e0U || fn1!=0x80057778U)
                throw std::runtime_error(
                    "first-boot SysEnqIntRP/SysDeqIntRP: node function guard failed"
                );

            auto& slot=device->intRp[2];
            slot.node=0x800761e8U;
            slot.fn0=fn0;
            slot.fn1=fn1;
            slot.active=enq;

            if(device->bringupTrace) {
                std::ostringstream o;
                o<<(enq ? "SysEnqIntRP" : "SysDeqIntRP")
                 << " priority=2 node=0x800761e8"
                 << " fn0=0x"<<std::hex<<fn0
                 << " fn1=0x"<<fn1;
                device->bringupTrace->add("first-boot-hle",o.str());
            }

            // Both PAL call sites ignore the BIOS return value.
            // Do not fabricate BIOS list pointers or a return result.
            c.retireLoad();
            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }

        if(pc==0x8005a2b4U) {
            auto* device=static_cast<bios::BootDevice*>(c.biosDevice);

            if(!device ||
               device->interruptDepth ||
               !device->cardInit.calls ||
               c.r[31]!=0x8005a284U)
                throw std::runtime_error(
                    "first-boot _bu_init: caller/state guard failed"
                );

            // Temporary first-boot HLE.
            // Caller ignores the return value completely.
            // Do not fabricate memory-card filesystem/kernel state.
            c.retireLoad();

            if(trace)trace->add(
                "first-boot-hle",
                "_bu_init A0:70 accepted; card filesystem unavailable"
            );

            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }

        if(pc==0x8005a824U) {
            auto* device=static_cast<bios::BootDevice*>(c.biosDevice);

            if(!device ||
               device->interruptDepth ||
               device->irqEnabled ||
               !device->cardInit.calls ||
               c.r[31]!=0x8005a36cU)
                throw std::runtime_error(
                    "first-boot StartCARD: caller/state guard failed"
                );

            // Temporary first-boot HLE.
            // Real memory-card I/O is intentionally not implemented yet.
            // PAL StartCARD wrapper observes success as v0 == 0.
            c.retireLoad();
            c.r[2]=0;

            if(trace)trace->add(
                "first-boot-hle",
                "StartCARD B0:4B accepted; memory-card I/O unavailable"
            );

            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }

        if(pc==0x8005a844U) {
            auto* device=static_cast<bios::BootDevice*>(c.biosDevice);
            if(!device || device->irqEnabled || device->interruptDepth ||
               !device->cardInit.calls || c.r[31]!=0x8005a32cU)
                throw std::runtime_error("first-boot libcard info patch: caller/state guard failed");

            // PAL patches BIOS-internal card code here.
            // Native host runtime owns this path; memory-card I/O remains unsupported.
            if(trace)trace->add(
                "first-boot-hle",
                "libcard card-info BIOS patch bypassed; memory-card I/O unavailable"
            );

            c.retireLoad();
            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }

        if(pc==0x8005a9b4U) {
            auto* device=static_cast<bios::BootDevice*>(c.biosDevice);
            if(!device || device->irqEnabled || device->interruptDepth ||
               !device->cardInit.calls || c.r[31]!=0x8005a324U)
                throw std::runtime_error("first-boot libcard second kernel patch: caller/state guard failed");
            // TODO(first-boot): PAL libcard patches BIOS-owned kernel/card code here.
            // Host InterruptEntry owns exception dispatch; memory-card I/O remains unsupported.
            if(trace)trace->add("first-boot-hle","libcard second kernel patch bypassed; memory-card I/O unavailable");
            c.retireLoad();
            c.redirectPending=true;
            c.redirectPc=c.r[31];
            return true;
        }
        if(pc==0x8005a920U) {
            auto* device=static_cast<bios::BootDevice*>(c.biosDevice);
            if(!device || device->irqEnabled || device->interruptDepth || !device->cardInit.calls || c.r[31]!=0x8005a31cU)
                throw std::runtime_error("first-boot libcard patch: caller/state guard failed");
            // TODO(first-boot): no kernel card driver exists to patch. Host InterruptEntry owns exception dispatch.
            // This entry's caller overwrites v0 in the following patch routine; no result is fabricated.
            if(trace)trace->add("first-boot-hle","libcard C0 kernel patch bypassed; memory-card I/O unavailable");
            c.retireLoad();c.redirectPending=true;c.redirectPc=c.r[31];return true;
        }
        if(pc!=0x8005a814U)return false;
        // Use the existing tested InitCARD policy even with the original Phase 4 generated unit.
        if(c.ram.read(pc,4)!=0x240a00b0U || c.ram.read(pc+4,4)!=0x01400008U || c.ram.read(pc+8,4)!=0x2409004aU)
            throw std::runtime_error("first-boot InitCARD thunk byte guard failed");
        c.retireLoad();
        bios::bootPolicy(c,pc+4,0xb0,0x4a);
        if(trace)trace->add("first-boot-hle","InitCARD: existing state-only policy");
        c.redirectPending=true;c.redirectPc=c.r[31];return true;
    }
};
}









