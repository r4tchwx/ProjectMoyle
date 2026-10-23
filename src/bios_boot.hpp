#pragma once
// Phase 4 BIOS boundary for the first real PAL boot (opt-in; src/bios_boundary.hpp is the unchanged Phase 3 policy).
// This is NOT a BIOS emulator. It implements, with the semantics the PAL call sites observe, the kernel function-table entries
// the boot path reaches before the first unsupported boundary (src/bios_table.hpp `bootTable`), delegates the three Phase 3
// functions to bios::minimalPolicy, and keeps every other (table, function) pair a controlled fatal diagnostic.
//   A0:0x39 InitHeap(a0 base, a1 size): called once by the startup stub with 0x800768f4 / 0x00181710. Recorded; no allocator is
//       modelled (the PAL's own allocator is not used by anything reached so far; later code is not verified).
//   A0:0x44 FlushCache: counted. The translated unit has no instruction cache, so there is nothing to flush.
//   A0:0x49 GPU_cw(a0): one GP0 command word, written to GP0 (0x1f801810) so the GPU model decides what is supported.
//   A0:0x72 CdRemove: counted (this unit has no kernel CD handlers to remove).
//   B0:0x07 DeliverEvent / 08 OpenEvent / 0A WaitEvent / 0B TestEvent / 0C EnableEvent: kernel events (class, spec, mode 0x2000,
//       no handler); WaitEvent completes only for a delivered event, otherwise it would block forever and is fatal.
//   B0:0x19 SetCustomExitFromException(a0 = jmp_buf): recorded; boot_hardware.hpp InterruptEntry leaves through it.
//   B0:0x17 ReturnFromException: restores the context saved at interrupt entry (only valid inside a service routine).
// Phase 5 (opt-in, BootDevice::cardInitEnabled; docs/direct-title-libcard.md has the evidence):
//   B0:0x4a InitCARD(a0 = 0|1): STATE ONLY. The PAL calls it exactly once from libcard 0x8005a2c4, inside a critical section, with
//       a0 = the libcard mode cell (only ever 0 or 1) and never reads $v0 afterwards. The harness has no kernel card driver and no
//       SIO0 device, so there is nothing for the call to initialise that anything could observe; every consequence the PAL's own code
//       relies on (the kernel table patches that follow) is NOT modelled here and stays a boundary. Registers and memory are untouched.
// SYSCALL 1/2 are Enter/ExitCriticalSection. Names are external psx-spx knowledge; the argument/return/effect facts are from
// the call sites. Registers other than the documented results are left untouched.
#include "bios_boundary.hpp"
#include "bios_table.hpp"

namespace moyle::detail::recomp::bios {
struct BootDevice : Device {
    struct Heap {bool set=false;std::uint32_t base=0,size=0;};
    std::uint64_t flushCache=0;
    // Kernel event table. Status values follow the kernel convention: 0x1000 opened/disabled, 0x2000 enabled, 0x4000 delivered
    // ("already"). Only mode 0x2000 (no interrupt callback) is implemented: a callback event would need the host to call guest
    // code from DeliverEvent.
    struct Event {std::uint32_t cls=0,spec=0,mode=0,status=0;bool used=false;};
    static constexpr std::uint32_t eventHandleBase=0xf1000000U,maxEvents=64U;
    std::array<Event,maxEvents> events{};
    std::uint32_t eventsOpened=0;
    std::uint64_t gp0Words=0;                    // A0:0x49 calls (each is one 32-bit write to GP0, 0x1f801810)
    std::uint64_t cdRemove=0;                    // A0:0x72 calls
    std::uint32_t customExit=0;                  // B0:0x19 jmp_buf address (0 = none registered)
    bool irqEnabled=false;                       // SYSCALL Enter/ExitCriticalSection state (false until the PAL enables it)
    unsigned interruptDepth=0;                   // >0 while the harness runs an interrupt service routine
    // Context saved by the harness at interrupt entry (the BIOS exception frame) and restored by B0:0x17 ReturnFromException.
    struct Frame {std::uint32_t r[32]{};std::uint32_t hi=0,lo=0,pc=0;bool irqEnabled=false;};
    std::vector<Frame> frames;
    std::uint64_t interruptsEntered=0,interruptsReturned=0;
    std::uint64_t criticalEnters=0,criticalExits=0;   // SYSCALL Enter/ExitCriticalSection counts
    Heap heap;                                   // A0:0x39 InitHeap arguments (recorded, not consumed)
    // Phase 5 opt-in: B0:0x4a InitCARD is accepted as a state-only call. Off by default (Phase 4 behaviour: fatal).
    bool cardInitEnabled=false;
    struct CardInit {std::uint64_t calls=0;std::uint32_t padEnable=0,site=0;};
    CardInit cardInit;
};
// SYSCALL policy (Context::syscallPolicy): only the two documented critical-section calls, selected by $a0. Everything else is
// fatal. EnterCriticalSection (a0=1) disables interrupt delivery and returns the previous enable state in $v0;
// ExitCriticalSection (a0=2) enables it. These are kernel-level calls (external psx-spx knowledge); the PAL call sites
// (0x8004e6b4, 0x8004e6c4) pass exactly these constants.
inline void bootSyscall(Context& c,std::uint32_t pc,std::uint32_t code) {
    auto* device=static_cast<BootDevice*>(c.biosDevice);
    if(!device)throw std::runtime_error("SYSCALL policy: no BIOS device attached");
    std::ostringstream why;why<<"SYSCALL at 0x"<<std::hex<<pc<<" (code 0x"<<code<<", a0 0x"<<c.r[4]<<"): ";
    if(code!=0U)throw std::runtime_error(why.str()+"only code 0 is implemented");
    if(c.r[4]==1U){++device->criticalEnters;c.r[2]=device->irqEnabled?1U:0U;device->irqEnabled=false;return;}
    if(c.r[4]==2U){++device->criticalExits;device->irqEnabled=true;return;}
    throw std::runtime_error(why.str()+"function not implemented");
}
// The policy installed in Context::biosPolicy. Requires Context::biosDevice.
inline void bootPolicy(Context& c,std::uint32_t site,std::uint32_t table,std::uint32_t function) {
    if((table==0xb0U&&function==0x35U)||(table==0xb0U&&function==0x5bU)||(table==0xc0U&&function==0x0aU)){minimalPolicy(c,site,table,function);return;} // Phase 3 functions
    auto* device=static_cast<BootDevice*>(c.biosDevice);
    if(!device)fail(site,table,function,"no BIOS device attached");
    const auto a0=c.r[4],a1=c.r[5],a2=c.r[6];
    device->calls.push_back({site,table,function,a0,a1,a2});
    if(table==0xa0U&&function==0x39U) {
        if(device->heap.set)fail(site,table,function,"InitHeap called twice");
        if((a0&3U)||a0<0x80010000U||a0>=0x80200000U)fail(site,table,function,"InitHeap base is not word-aligned KSEG0 RAM");
        if(!a1||(a1&3U)||std::uint64_t(a0)+a1>0x80200000ULL)fail(site,table,function,"InitHeap size is empty, unaligned or beyond RAM");
        device->heap={true,a0,a1};return;
    }
    if(table==0xb0U&&function>=0x07U&&function<=0x0cU&&function!=0x09U) { // kernel events (the PAL never calls 09/CloseEvent yet)
        auto event=[&](std::uint32_t handle)->BootDevice::Event& {
            const auto index=handle-BootDevice::eventHandleBase;
            if(handle<BootDevice::eventHandleBase||index>=BootDevice::maxEvents||!device->events[index].used)fail(site,table,function,"event handle is not an open event");
            return device->events[index];
        };
        if(function==0x08U) { // OpenEvent(class, spec, mode, handler) -> handle
            if(a2!=0x2000U)fail(site,table,function,"only mode 0x2000 (no interrupt callback) is implemented");
            if(c.r[7]!=0U)fail(site,table,function,"an event handler with mode 0x2000 is not implemented");
            for(std::uint32_t n=0;n<BootDevice::maxEvents;++n)if(!device->events[n].used){
                device->events[n]={a0,a1,a2,0x1000U,true};++device->eventsOpened;c.r[2]=BootDevice::eventHandleBase+n;return;
            }
            fail(site,table,function,"event table is full");
        }
        if(function==0x0cU) {auto& e=event(a0);e.status=0x2000U;c.r[2]=1U;return;}              // EnableEvent
        if(function==0x0bU) {auto& e=event(a0);if(e.status==0x4000U){e.status=0x2000U;c.r[2]=1U;}else c.r[2]=0U;return;} // TestEvent
        if(function==0x0aU) { // WaitEvent: a delivered event completes; otherwise no source exists to deliver it, so waiting would hang
            auto& e=event(a0);
            if(e.status!=0x4000U)fail(site,table,function,"WaitEvent would block: the event is not delivered and the host has no delivery source for it");
            e.status=0x2000U;c.r[2]=1U;return;
        }
        if(function==0x07U) { // DeliverEvent(class, spec): enabled matching events become delivered
            for(auto& e:device->events)if(e.used&&e.cls==a0&&e.spec==a1&&e.status==0x2000U)e.status=0x4000U;
            return;
        }
    }
    if(table==0xa0U&&function==0x49U) { // GP0 command word: a bus write, so the GPU model decides what it supports
        ++device->gp0Words;c.ram.write(0x1f801810U,a0,4);return;
    }
    if(table==0xa0U&&function==0x72U) {++device->cdRemove;return;}
    if(table==0xb0U&&function==0x19U) {
        if((a0&3U)||a0<0x80010000U||std::uint64_t(a0)+0x30U>0x80200000ULL)fail(site,table,function,"jmp_buf is not word-aligned KSEG0 RAM");
        device->customExit=a0;return;
    }
    if(table==0xb0U&&function==0x17U) {
        if(!device->interruptDepth||device->frames.empty())fail(site,table,function,"ReturnFromException outside an interrupt service routine");
        // The BIOS restores the exception frame it saved at interrupt entry and resumes the interrupted instruction.
        const auto frame=device->frames.back();device->frames.pop_back();
        for(unsigned i=0;i<32;++i)c.r[i]=frame.r[i];
        c.hi=frame.hi;c.lo=frame.lo;c.loadRegister=0;
        device->irqEnabled=frame.irqEnabled;--device->interruptDepth;++device->interruptsReturned;
        c.redirectPending=true;c.redirectPc=frame.pc;
        return;
    }
    if(table==0xb0U&&function==0x4aU&&device->cardInitEnabled) { // Phase 5: state only (see the header comment)
        if(a0>1U)fail(site,table,function,"InitCARD argument must be 0 or 1 (the only values the PAL passes)");
        if(device->interruptDepth)fail(site,table,function,"InitCARD inside an interrupt service routine is not supported");
        if(device->irqEnabled)fail(site,table,function,"InitCARD must run inside a critical section (the PAL always calls it with interrupts disabled)");
        ++device->cardInit.calls;device->cardInit.padEnable=a0;device->cardInit.site=site;
        return;
    }
    if(table==0xa0U&&function==0x44U) {++device->flushCache;return;} // no instruction cache exists in the translated unit
    fail(site,table,function,"kernel function is not implemented");
}

inline bool bootSupported(std::uint32_t table,std::uint32_t function,bool card=false) {return findBootEntry(table,function,card)!=nullptr;}
}
