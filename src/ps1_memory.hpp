#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <array>
#include <sstream>

namespace moyle::detail {
enum class EffectKind { Read, Write, Call, Return, Branch };
struct Effect {
    EffectKind kind;
    std::uint32_t address, value, width;
    bool operator==(const Effect& b) const noexcept {
        return kind == b.kind && address == b.address && value == b.value && width == b.width;
    }
};
enum class MemoryRegion { Ram, Scratchpad, Mmio, Unmapped };
// Phase 4: optional narrow device hook for the hardware window 0x1f801000..0x1f802fff. Null (default) keeps the original
// behaviour: every MMIO access is a fatal "MMIO not implemented" fault. A handler receives the exact guest address, width
// and (for writes) the value and decides; unsupported accesses must throw, never be ignored. Masked (lwl/lwr/swl/swr style)
// stores are not delivered to a handler: they stay fatal, because a lane mask has no defined device meaning here.
struct MmioHandler {
    virtual ~MmioHandler()=default;
    virtual std::uint32_t mmioRead(std::uint32_t address,unsigned width)=0;
    virtual void mmioWrite(std::uint32_t address,std::uint32_t value,unsigned width)=0;
};
// Phase 5: optional audit hook for the kernel RAM window (physical 0x00000000..0x0000ffff). Null (default) keeps the original
// behaviour exactly. A guard sees every data access that lands in the window and may throw to refuse it; it never changes
// the data. Masked (lwl/lwr/swl/swr) stores report only the lanes they actually write.
struct MemoryGuard {
    static constexpr std::uint32_t window=0x10000U;
    virtual ~MemoryGuard()=default;
    virtual void guardRead(std::uint32_t address,unsigned width,std::uint32_t laneMask)=0;
    virtual void guardWrite(std::uint32_t address,unsigned width,std::uint32_t laneMask)=0;
};
struct MemoryRoute { MemoryRegion region; std::size_t offset; };
// Data routing is separate from RAM-only code/image offsets. No automatic RAM
// wraparound. MMIO/cache isolation require dedicated policies, never byte fallback.
class Ps1Memory {
public:
    std::vector<std::uint8_t> bytes = std::vector<std::uint8_t>(0x200000);
    // PROJECT POLICY: deterministic zero initialization, not a hardware reset claim.
    std::array<std::uint8_t,1024> scratchpad{};
    std::vector<Effect> effects;
    MmioHandler* mmio=nullptr;
    MemoryGuard* guard=nullptr;
    std::uint32_t readLanes=0xffffffffU; // byte lanes of a 4-byte read the guest actually uses (lwl/lwr use fewer)
    bool recordEffects=true; // Phase 4 harness runs turn this off: a long boot would otherwise log every access
    static MemoryRoute route(std::uint32_t address) noexcept {
        const auto segment=address&0xe0000000U, physical=address&0x1fffffffU;
        if(segment!=0&&segment!=0x80000000U&&segment!=0xa0000000U)
            return {MemoryRegion::Unmapped,0};
        if(physical<0x200000U)return {MemoryRegion::Ram,physical};
        if(physical>=0x1f800000U&&physical<0x1f800400U&&segment!=0xa0000000U)
            return {MemoryRegion::Scratchpad,physical-0x1f800000U};
        if(physical>=0x1f801000U&&physical<0x1f803000U)
            return {MemoryRegion::Mmio,physical-0x1f801000U};
        return {MemoryRegion::Unmapped,0};
    }
    // Retained RAM-only contract for executable images and dispatch targets.
    static std::size_t offset(std::uint32_t address, unsigned width) {
        if (width != 1 && width != 2 && width != 4) throw std::out_of_range("RAM access width");
        const auto segment = address & 0xe0000000U;
        if (segment != 0 && segment != 0x80000000U && segment != 0xa0000000U)
            throw std::out_of_range("Unsupported PS1 segment");
        const auto physical = address & 0x1fffffffU;
        if (physical > 0x200000U - width || (physical & (width - 1U)))
            throw std::out_of_range("Unmapped or unaligned PS1 RAM access");
        return physical;
    }
    void event(EffectKind kind, std::uint32_t address, std::uint32_t value, unsigned width = 0) {
        if(!recordEffects)return;
        effects.push_back({kind,address,value,width});
    }
private:
    [[noreturn]] static void fault(std::uint32_t address,unsigned width,const char* reason) {
        std::ostringstream out;out<<reason<<" at 0x"<<std::hex<<address<<", width "<<std::dec<<width;
        throw std::out_of_range(out.str());
    }
    std::uint8_t* storage(std::uint32_t address,unsigned width,bool store) {
        if(width!=1&&width!=2&&width!=4)fault(address,width,"Invalid access width");
        if(address&(width-1))fault(address,width,store?"AdES: unaligned store":"AdEL: unaligned load");
        const auto r=route(address);
        if(r.region==MemoryRegion::Ram&&r.offset<=bytes.size()-width)return bytes.data()+r.offset;
        if(r.region==MemoryRegion::Scratchpad&&r.offset<=scratchpad.size()-width)return scratchpad.data()+r.offset;
        if(r.region==MemoryRegion::Mmio)fault(address,width,"MMIO not implemented");
        fault(address,width,"Unmapped PS1 data access");
    }
    void auditRead(std::uint32_t address,unsigned width) {
        const auto r=route(address);
        if(r.region==MemoryRegion::Ram&&r.offset<MemoryGuard::window&&!(address&(width-1))&&(width==1||width==2||width==4))guard->guardRead(address,width,readLanes);
    }
    void auditWrite(std::uint32_t address,unsigned width,std::uint32_t laneMask) {
        const auto r=route(address);
        if(r.region==MemoryRegion::Ram&&r.offset<MemoryGuard::window&&!(address&(width-1))&&(width==1||width==2||width==4))guard->guardWrite(address,width,laneMask);
    }
public:
    std::uint32_t read(std::uint32_t address, unsigned width) {
        if(mmio&&route(address).region==MemoryRegion::Mmio) {
            if(width!=1&&width!=2&&width!=4)fault(address,width,"Invalid access width");
            if(address&(width-1))fault(address,width,"AdEL: unaligned load");
            std::uint32_t value=mmio->mmioRead(address,width);
            if(width<4)value&=(1U<<(8*width))-1U;
            event(EffectKind::Read,address,value,width);
            return value;
        }
        if(guard)auditRead(address,width);
        const auto p = storage(address,width,false);
        std::uint32_t value = 0;
        for (unsigned i = 0; i < width; ++i) value |= std::uint32_t(p[i]) << (8*i);
        event(EffectKind::Read,address,value,width);
        return value;
    }
    void write(std::uint32_t address, std::uint32_t value, unsigned width) {
        if(mmio&&route(address).region==MemoryRegion::Mmio) {
            if(width!=1&&width!=2&&width!=4)fault(address,width,"Invalid access width");
            if(address&(width-1))fault(address,width,"AdES: unaligned store");
            if(width<4)value&=(1U<<(8*width))-1U;
            mmio->mmioWrite(address,value,width);
            event(EffectKind::Write,address,value,width);
            return;
        }
        if(guard)auditWrite(address,width,0xffffffffU);
        const auto p = storage(address,width,true);
        if (width < 4) value &= (1U << (8*width)) - 1U;
        for (unsigned i = 0; i < width; ++i) p[i] = static_cast<std::uint8_t>(value >> (8*i));
        event(EffectKind::Write,address,value,width);
    }
    std::uint32_t loadLeft(std::uint32_t address,std::uint32_t prior) {
        const unsigned shift=8*(3-(address&3));
        readLanes=0xffffffffU>>(8*(3-(address&3)));
        const auto word=read(address&~3U,4);readLanes=0xffffffffU;
        return (prior&~(0xffffffffU<<shift))|(word<<shift);
    }
    std::uint32_t loadRight(std::uint32_t address,std::uint32_t prior) {
        const unsigned shift=8*(address&3);
        readLanes=0xffffffffU<<shift;
        const auto word=read(address&~3U,4);readLanes=0xffffffffU;
        return (prior&~(0xffffffffU>>shift))|(word>>shift);
    }
    // One aligned masked-word store, not a bus read plus byte writes. A future
    // MMIO backend must receive the lane mask and define its own side effects.
    void writeMaskedWord(std::uint32_t address,std::uint32_t value,std::uint32_t mask) {
        if(guard)auditWrite(address,4,mask);
        auto p=storage(address,4,true);std::uint32_t old=0;
        for(unsigned n=0;n<4;++n)old|=std::uint32_t(p[n])<<(8*n);
        const auto merged=(old&~mask)|(value&mask);
        for(unsigned n=0;n<4;++n)p[n]=std::uint8_t(merged>>(8*n));
        event(EffectKind::Write,address,merged,4);
    }
    void storeLeft(std::uint32_t address,std::uint32_t value) {
        const unsigned shift=8*(3-(address&3));
        writeMaskedWord(address&~3U,value>>shift,0xffffffffU>>shift);
    }
    void storeRight(std::uint32_t address,std::uint32_t value) {
        const unsigned shift=8*(address&3);
        writeMaskedWord(address&~3U,value<<shift,0xffffffffU<<shift);
    }
};
}
