#pragma once
// Phase 4 minimal device model. Strict by construction: every register that is not modelled below is a fatal MmioFault
// with the exact address/width/value. Each modelled register is justified by a real PAL access observed by the harness;
// docs/direct-title-boot.md lists, per register, the PAL function, direction, observed values, what the caller expects
// afterwards and why the minimal model is sufficient. Nothing here is a general GPU/DMA/timer/interrupt implementation.
#include "boot_harness.hpp"

namespace moyle::detail::recomp::boot {
class Hardware : public MmioHandler {
public:
    Trace* trace=nullptr;
    Context* ctx=nullptr;        // guest instruction count is the only time base (deterministic host clock)
    std::uint64_t accesses=0;
    // --- host clock policy (NOT hardware evidence): one guest instruction = cyclesPerInstruction CPU cycles; a video field is
    // fieldCycles CPU cycles (50 Hz at 33.8688 MHz = 677376) and a scanline is lineCycles. The PAL only observes differences
    // of root counter 1 and the VBlank edge, so these constants decide *when*, never *what*. --------------------------------
    std::uint32_t cyclesPerInstruction=2;
    std::uint64_t fieldCycles=677376,lineCycles=2168;
    std::uint64_t now() const {return ctx?ctx->steps:0;}
    std::uint64_t cycles() const {return now()*cyclesPerInstruction;}
    // First step at which cycle count reaches `cyc` (ceil division).
    std::uint64_t stepOfCycle(std::uint64_t cyc) const {return (cyc+cyclesPerInstruction-1)/cyclesPerInstruction;}
    // --- root counter 1 (0x1f801110 value, 0x1f801114 mode), HBlank clock source, sync mode 3 --------------------------
    bool timer1Configured=false;
    std::uint32_t timer1Mode=0;
    std::uint64_t timer1StartStep=0;   // first VBlank edge after the mode write: counting starts there (sync mode 3)
    std::uint64_t nextEdgeStep() const {
        const auto edge=(cycles()/fieldCycles+1)*fieldCycles;   // next field boundary strictly after now
        return stepOfCycle(edge);
    }
    // --- root counter 2 (0x1f801120 value, 0x1f801124 mode, 0x1f801128 target). libapi SetRCnt(2, 0xffff, RCntMdNOINTR) writes
    // mode=0, target=0xffff, mode=0x0248 (reset at target, system clock / 8, no IRQ enable bits): nothing else is accepted.
    // The counter value register is NOT readable yet (an unmodelled read stays fatal until the guest actually reads it). ------
    bool timer2Configured=false,timer2TargetSet=false;
    std::uint32_t timer2Mode=0;
    std::uint64_t timer2StartStep=0;   // step of the mode write that configured it: the counter restarts at 0 there
    // --- interrupt controller (I_STAT 0x1f801070, I_MASK 0x1f801074) ---------------------------------------------------
    std::uint16_t istat=0,imask=0;
    // --- DMA control (DPCR 0x1f8010f0) --------------------------------------------------------------------------------
    std::uint32_t dpcr=0;
    // --- GPU: GP1 control port (0x1f801814 write) and GPUSTAT (same address, read). Only observed GP1 commands are modelled; the
    // GPU is "infinitely fast" (ready bits constant), there is no VRAM and no rendering. GPUSTAT is unknown until the first
    // GP1(00h) reset, so a read before that is fatal. --------------------------------------------------------------------
    bool gpuReset=false;
    // Environment parameter (not PAL evidence): the GPU revision GP1(10h) index 7 reports. 2 = the later 208-pin GPU found in
    // every console built after the first revisions. Both PAL branches exist; the choice is explicit and recorded in the trace.
    std::uint32_t gpuType=2;
    bool gpuReadValid=false;std::uint32_t gpuRead=0;   // GPUREAD latch, valid only after a modelled GP1(10h)
    std::uint32_t gpuStat=0;                    // stored bits; the ready/DMA-request/parity bits are derived in gpuStatus()
    std::uint64_t gp1Commands=0;
    std::uint32_t gpuStatus() const {
        auto s=gpuStat|0x04000000U|0x10000000U;   // ready to receive command word (26), ready for DMA block (28)
        const auto dir=(s>>29)&3U;
        const bool request=dir==1U?true:dir==2U?true:false; // dir 1: FIFO not full; dir 2: = bit 28; dir 3 (VRAM->CPU): bit 27 is never set
        s=(s&~0x02000000U)|(request?0x02000000U:0U);
        if(s&0x00400000U)s|=((vblankIndex&1U)?0x80000000U:0U);  // field parity only while vertical interlace is on
        return s;
    }
    std::uint64_t vblankIndex=0;
    // --- SPU control/voice register file 0x1f801c00..0x1f801dff (halfword registers). Write-then-read-back storage: a register the
    // PAL never wrote cannot be read (its power-on value is unknown, fatal). SPUCNT (0x1f801daa) is stored and mirrored into the
    // low six bits of SPUSTAT (0x1f801dae, read-only) without delay; SPUCNT transfer-mode bits (4..5) and the IRQ-enable bit (6)
    // are unsupported (no SPU RAM transfer / SPU IRQ is modelled) and fatal. No audio is produced. ---------------------------
    std::array<std::uint16_t,256> spuReg{};
    std::array<bool,256> spuWritten{};
    static bool inSpu(std::uint32_t phys){return phys>=0x1f801c00U&&phys<0x1f801e00U;}
    // SPU RAM and the manual transfer path (SPUCNT transfer mode 1): halfwords written to the data FIFO (0x1f801da8) are queued
    // and committed at the transfer address register (0x1f801da6, units of 8 bytes) when SPUCNT selects manual write. The
    // transfer is instantaneous (SPUSTAT busy never set). DMA transfer modes (2, 3) are unsupported and fatal.
    std::vector<std::uint8_t> spuRam=std::vector<std::uint8_t>(512*1024);
    std::vector<std::uint16_t> spuFifo;
    std::uint64_t spuRamWrites=0;
    void spuFlush(std::uint32_t address,unsigned width,std::uint32_t value) {
        const std::uint32_t base=std::uint32_t(spuReg[(0x1f801da6U-0x1f801c00U)/2])*8U;
        if(std::uint64_t(base)+spuFifo.size()*2>spuRam.size())throw MmioFault(address,width,true,value,"SPU RAM transfer beyond 512 KiB");
        for(std::size_t n=0;n<spuFifo.size();++n){spuRam[base+2*n]=std::uint8_t(spuFifo[n]);spuRam[base+2*n+1]=std::uint8_t(spuFifo[n]>>8);}
        spuRamWrites+=spuFifo.size();
        if(trace)trace->add("spu-ram",std::string("manual write ")+std::to_string(spuFifo.size()*2)+" bytes at "+h8(base));
        spuFifo.clear();
    }
    // SPU_DELAY / size register 0x1f801014 (32-bit). The PAL's libspu read-modify-writes it before an SPU DMA write
    // ((v & 0xF0FFFFFF) | 0x20000000, helper 0x8004A6C0). Power-on value 0x200931E1 is an ENVIRONMENT PARAMETER (documented console reset
    // value, there is no BIOS here), not PAL evidence; with it the PAL's write is value-preserving. Any other write is unsupported.
    std::uint32_t spuDelay=0x200931e1U;
    // --- DMA channel 4 (SPU): MADR 0x1f8010c0, BCR 0x1f8010c4, CHCR 0x1f8010c8. Only the libspu RAM -> SPU block transfer is modelled
    // (CHCR 0x01000201, BCR = blocks<<16 | 0x10, SPUCNT transfer mode 2, DPCR channel 4 enabled). The transfer copies the words into
    // the SPU RAM image at (SPU transfer address register 0x1f801da6) * 8 and completes synchronously; completion then raises the
    // DMA4 interrupt exactly like hardware does: DICR flag 28 if DICR enable 20 is set, and I_STAT bit 3 when the DICR master flag
    // rises. Nothing else (read direction, linked list, partial blocks, config-only CHCR writes) is supported. -------------------
    std::uint32_t dma4Madr=0,dma4Bcr=0,dma4Chcr=0;
    struct SpuDmaRecord {std::uint32_t madr=0,spuAddress=0,bytes=0;std::uint64_t hash=0xcbf29ce484222325ULL;};
    std::vector<SpuDmaRecord> spuDmas;                // first uploadsKept completed transfers
    std::uint64_t spuDmaTransfers=0,spuDmaBytes=0,dma4Interrupts=0;
    void dma4Block(std::uint32_t address,std::uint32_t value) {
        const auto fail=[&](const char* why){throw MmioFault(address,4,true,value,why);};
        if(!ctx)fail("DMA4 block transfer: missing context");
        const auto cntIndex=(0x1f801daaU-0x1f801c00U)/2,addrIndex=(0x1f801da6U-0x1f801c00U)/2;
        if(!spuWritten[cntIndex]||((spuReg[cntIndex]>>4)&3U)!=2U)fail("DMA4 block transfer while SPUCNT is not in DMA write mode (2)");
        if(!spuWritten[addrIndex])fail("DMA4 block transfer before the SPU transfer address was written");
        if(!(dpcr&0x00080000U))fail("DMA4 block transfer while DPCR channel 4 is disabled");
        if(!spuFifo.empty())fail("DMA4 block transfer with queued manual-write halfwords");
        if((dma4Madr&3U)!=0U)fail("DMA4 block transfer: MADR is not word aligned");
        if((dma4Bcr&0xffffU)!=0x10U)fail("DMA4 block transfer: BCR block size is not 16 words");
        const std::uint32_t blocks=dma4Bcr>>16;
        if(blocks==0U)fail("DMA4 block transfer: zero blocks");
        const std::uint64_t bytes=std::uint64_t(blocks)*64U;
        if(std::uint64_t(dma4Madr)+bytes>0x00200000ULL)fail("DMA4 block transfer: source range is outside main RAM");
        const std::uint64_t base=std::uint64_t(spuReg[addrIndex])*8U;
        if(base+bytes>spuRam.size())fail("DMA4 block transfer: destination runs past the 512 KiB SPU RAM");
        SpuDmaRecord rec;rec.madr=dma4Madr;rec.spuAddress=std::uint32_t(base);rec.bytes=std::uint32_t(bytes);
        for(std::uint64_t i=0;i<bytes/4;++i){
            const auto word=ctx->ram.read(0x80000000U|std::uint32_t(dma4Madr+i*4U),4);
            for(unsigned b=0;b<4;++b){const auto byte=std::uint8_t(word>>(8*b));spuRam[std::size_t(base+i*4U+b)]=byte;rec.hash^=byte;rec.hash*=0x100000001b3ULL;}
        }
        ++spuDmaTransfers;spuDmaBytes+=bytes;if(spuDmas.size()<uploadsKept)spuDmas.push_back(rec);
        dma4Madr=std::uint32_t(dma4Madr+bytes);
        dma4Chcr=value&~0x01000000U;                   // finished before the CHCR write retires: busy bit clear
        note("mmio-w",address,4,value,"D4_CHCR_BLOCK_TO_SPU");
        if(trace)trace->add("spu-dma","RAM "+h8(rec.madr)+" -> SPU RAM "+h8(rec.spuAddress)+" "+std::to_string(bytes)+" bytes");
        // completion interrupt (hardware: flag only when the channel enable bit is set; I_STAT bit 3 on the master flag's rising edge)
        if(dicrEnable&0x00100000U){
            const bool before=(dicrValue()&0x80000000U)!=0U;
            dicrFlags|=0x10000000U;
            if(!before&&(dicrValue()&0x80000000U)){istat|=0x8U;++dma4Interrupts;}
        }
    }
    std::uint16_t spuStat() const {return std::uint16_t(spuReg[(0x1f801daaU-0x1f801c00U)/2]&0x3fU);}
    // --- DMA channel 2 (GPU): MADR 0x1f8010a0, BCR 0x1f8010a4, CHCR 0x1f8010a8. Configuration registers only; a CHCR write that
    // would start a transfer (bit 24 or bit 28) is fatal until a real PAL transfer is observed and modelled. ---------------
    std::uint32_t dma2Madr=0,dma2Bcr=0,dma2Chcr=0;
    // --- DMA interrupt control (DICR 0x1f8010f4): channel enables (bits 16..22), master enable (bit 23), channel flags
    // (bits 24..30, set only by a device completion, cleared by writing 1) and the derived master flag (bit 31). Bits 0..15
    // (unused / force-IRQ) are not supported: a write with any of them set is fatal. -----------------------------------
    std::uint32_t dicrEnable=0,dicrFlags=0;       // enable = bits 16..23 as written; flags = bits 24..30
    std::uint32_t dicrValue() const {
        const bool master=(dicrEnable&0x800000U)&&((dicrEnable>>16)&dicrFlags>>24&0x7fU);
        return dicrEnable|dicrFlags|(master?0x80000000U:0U);
    }
    std::set<std::uint32_t> touched;   // first-touch trace gate
    // Per register name: the first logCap events are traced, then one "suppressed" marker; the totals stay available in `counts`.
    static constexpr unsigned logCap=12;
    std::map<std::string,std::uint64_t> counts;
    void note(const char* kind,std::uint32_t address,unsigned width,std::uint32_t value,const char* name) {
        const auto key=std::string(kind)+" "+name;
        const auto total=++counts[key];
        if(!trace)return;
        // writes are configuration events: logged (up to logCap per register); reads only on the first touch of the register
        if(std::string(kind)=="mmio-r"&&!touched.insert(address).second)return;
        if(total>logCap+1)return;
        if(total==logCap+1){trace->add(kind,std::string(name)+" "+h8(address)+" further events suppressed (totals in the report)");return;}
        trace->add(kind,std::string(name)+" "+h8(address)+" w"+std::to_string(width)+" "+h8(value));
    }
    // --- VBlank (host clock, see fieldCycles): edge n happens at CPU cycle n*fieldCycles; I_STAT bit 0 latches on every edge
    // regardless of I_MASK (hardware behaviour) and stays set until the PAL acknowledges it. sync() is a pure function of the
    // guest instruction count. -----------------------------------------------------------------------------------------
    std::uint64_t edgesSeen=0;
    void sync() {
        const auto edges=cycles()/fieldCycles;
        if(edges==edgesSeen)return;
        edgesSeen=edges;vblankIndex=edges;istat|=1U;
        ++counts["vblank edge"];
    }
    std::uint32_t gp1DisplayStart=0,gp1HRange=0,gp1VRange=0,gp1DisplayMode=0,gp1DmaDirection=0;
    std::uint32_t gp0FillColor=0,gp0FillXy=0,gp0FillWh=0;
    // --- GP0 CPU->VRAM upload (command A0h), the only GP0 data transfer modelled. There is NO VRAM: the rectangle is validated,
    // the payload is consumed word by word (PIO through 0x1f801810 and/or one DMA2 block transfer) and folded into a hash plus
    // accounting. In the Data state EVERY GP0 word is payload, even one that looks like a command (A0h, E1h, 01h...). ---------
    enum class UpState {Idle,ExpectXY,ExpectWH,Data};
    struct UploadRecord {
        std::uint32_t x=0,y=0,w=0,h=0;
        std::uint32_t totalWords=0,pioWords=0,dmaWords=0;
        std::uint64_t hash=0xcbf29ce484222325ULL;   // FNV-1a over the little-endian bytes of every payload word, in order
    };
    UpState upState=UpState::Idle;
    UploadRecord upCur;
    std::uint32_t upRemaining=0;
    std::uint32_t upX=0,upY=0;
    std::vector<UploadRecord> uploads;               // completed uploads, bounded (first uploadsKept only)
    static constexpr std::size_t uploadsKept=16;
    std::uint64_t uploadsCompleted=0,uploadWordsPio=0,uploadWordsDma=0,gp0ResetNops=0,dma2BlockUploads=0;
    static constexpr std::uint32_t upMaxWords=1024U*512U/2U;
    // GP0 80h VRAM->VRAM copy (MoveImage), accepted only as a 4-word packet inside a DMA2 linked list. Without a VRAM it is validated
    // (both rectangles inside VRAM, no wrap) and accounted, nothing else. Bounded metadata like the uploads.
    struct MoveRecord {std::uint32_t sx=0,sy=0,dx=0,dy=0,w=0,h=0;};
    std::vector<MoveRecord> moves;
    std::uint64_t gp0MoveImages=0;
    void gp0MoveImage(std::uint32_t srcXy,std::uint32_t dstXy,std::uint32_t wh) {
        MoveRecord m;m.sx=srcXy&0xffffU;m.sy=srcXy>>16;m.dx=dstXy&0xffffU;m.dy=dstXy>>16;m.w=wh&0xffffU;m.h=wh>>16;
        const auto bad=[&](const char* why){throw MmioFault(0x1f801810U,4,true,0x80000000U,why);};
        if(m.w<1U||m.h<1U||m.w>1024U||m.h>512U)bad("GP0 80h MoveImage: invalid rectangle size");
        if(m.sx>=1024U||m.sy>=512U||m.sx+m.w>1024U||m.sy+m.h>512U)bad("GP0 80h MoveImage: source rectangle outside VRAM or wrapping");
        if(m.dx>=1024U||m.dy>=512U||m.dx+m.w>1024U||m.dy+m.h>512U)bad("GP0 80h MoveImage: destination rectangle outside VRAM or wrapping");
        ++gp0MoveImages;if(moves.size()<uploadsKept)moves.push_back(m);
        note("gp0",0x1f801810U,4,0x80000000U,"GP0_80_MOVE_IMAGE");
    }
    void upFold(std::uint32_t word) {
        for(unsigned b=0;b<4;++b){upCur.hash^=(word>>(8*b))&0xffU;upCur.hash*=0x100000001b3ULL;}
    }
    void upFinish() {
        ++uploadsCompleted;
        if(uploads.size()<uploadsKept)uploads.push_back(upCur);
        if(trace)trace->add("gpu-upload","complete rect("+std::to_string(upCur.x)+","+std::to_string(upCur.y)+","+std::to_string(upCur.w)+","+std::to_string(upCur.h)+") words="+std::to_string(upCur.totalWords)+" pio="+std::to_string(upCur.pioWords)+" dma="+std::to_string(upCur.dmaWords)+" hash="+h8(std::uint32_t(upCur.hash>>32))+h8(std::uint32_t(upCur.hash)).substr(2));
        upState=UpState::Idle;upRemaining=0;
    }
    // One word written to GP0 (0x1f801810). Returns false when the word is not part of the modelled set (caller raises the fault).
    bool gp0Write(std::uint32_t address,std::uint32_t value) {
        switch(upState){
        case UpState::ExpectXY: {
            const auto x=value&0xffffU,y=value>>16;
            if(x>=1024U||y>=512U)throw MmioFault(address,4,true,value,"GP0 A0h upload: XY origin outside VRAM");
            upX=x;upY=y;upState=UpState::ExpectWH;note("gp0",address,4,value,"GP0_A0_XY");return true;
        }
        case UpState::ExpectWH: {
            const auto w=value&0xffffU,h=value>>16;
            if(w<1U||h<1U||w>1024U||h>512U||upX+w>1024U||upY+h>512U)throw MmioFault(address,4,true,value,"GP0 A0h upload: invalid or wrapping rectangle size");
            upCur=UploadRecord{};upCur.x=upX;upCur.y=upY;upCur.w=w;upCur.h=h;
            upCur.totalWords=(w*h+1U)/2U;upRemaining=upCur.totalWords;upState=UpState::Data;
            note("gp0",address,4,value,"GP0_A0_WH");return true;
        }
        case UpState::Data:
            upFold(value);++upCur.pioWords;++uploadWordsPio;--upRemaining;
            note("gp0",address,4,value,"GP0_A0_DATA_PIO");
            if(upRemaining==0U)upFinish();
            return true;
        case UpState::Idle:
            break;
        }
        if(gpuReset){   // 01h / A0h exist only after the PAL reset the GPU (GP1(00h)); every other word keeps the pre-existing handling
            if(value==0x01000000U){++gp0ResetNops;note("gp0",address,4,value,"GP0_01_NOP");return true;}
            if(value==0xa0000000U){upState=UpState::ExpectXY;note("gp0",address,4,value,"GP0_A0_BEGIN");return true;}
        }
        return gp0State(address,value);
    }
    // DMA2 sync-mode-1 (block) CPU RAM -> GPU transfer of the pending A0h payload. Completed synchronously; no DMA IRQ, no DICR flag.
    void dma2BlockUpload(std::uint32_t address,std::uint32_t value) {
        const auto fail=[&](const char* why){throw MmioFault(address,4,true,value,why);};
        if(!ctx)fail("DMA2 block upload: missing context");
        if(upState!=UpState::Data)fail("DMA2 block upload without a pending GP0 A0h data phase");
        if(gp1DmaDirection!=2U)fail("DMA2 block upload while GP1(04h) DMA direction is not CPU->GPU (2)");
        if(!(dpcr&0x00000800U))fail("DMA2 block upload while DPCR channel 2 is disabled");
        if((dma2Madr&3U)!=0U)fail("DMA2 block upload: MADR is not word aligned");
        if((dma2Bcr&0xffffU)!=0x10U)fail("DMA2 block upload: BCR block size is not 16 words");
        const std::uint32_t blocks=dma2Bcr>>16;
        const std::uint64_t words=std::uint64_t(blocks)*16U;
        if(blocks==0U||words!=upRemaining)fail("DMA2 block upload: block count does not equal the remaining upload words");
        if(std::uint64_t(dma2Madr)+words*4U>0x00200000ULL)fail("DMA2 block upload: source range is outside main RAM");
        for(std::uint64_t i=0;i<words;++i)upFold(ctx->ram.read(0x80000000U|std::uint32_t(dma2Madr+i*4U),4));
        upCur.dmaWords+=std::uint32_t(words);uploadWordsDma+=words;++dma2BlockUploads;
        dma2Madr=std::uint32_t(dma2Madr+words*4U);
        dma2Chcr=value&~0x01000000U;                     // transfer finished before the CHCR write retires: busy bit clear
        note("mmio-w",address,4,value,"D2_CHCR_BLOCK_UPLOAD");
        upRemaining=0U;upFinish();
    }
    bool gp0State(std::uint32_t address,std::uint32_t value) {
        const auto cmd=value>>24;
        if(cmd==0x00U){note("mmio-w",address,4,value,"GP0_NOP");return true;}
        if(cmd>=0xe1U&&cmd<=0xe6U){note("gp0",address,4,value,"GP0_STATE");return true;}
        return false;
    }
    void dma2LinkedList(std::uint32_t chcrAddress) {
        if(!ctx)throw std::runtime_error("DMA2 linked-list: missing context");
        std::uint32_t node=dma2Madr&0x00fffffcU;
        for(unsigned nodes=0;nodes<1024U;++nodes){
            if(node>0x001ffffcU)throw std::runtime_error("DMA2 linked-list: node outside RAM");
            const auto tag=ctx->ram.read(0x80000000U|node,4);
            const auto words=tag>>24;
            if(words>15U)throw std::runtime_error("DMA2 linked-list: node exceeds 15 words");
            for(std::uint32_t i=0;i<words;++i){
                const auto off=node+4U+i*4U;
                if(off>0x001ffffcU)throw std::runtime_error("DMA2 linked-list: packet crosses RAM");
                const auto word=ctx->ram.read(0x80000000U|off,4);
                if((word>>24)==0x02U){
                    if(word!=0x02000000U)throw std::runtime_error("DMA2 ClearImage: only shipped PAL black fill is modelled");
                    if(i+2U>=words)throw std::runtime_error("DMA2 ClearImage: truncated GP0 fill packet");
                    const auto xyOff=node+4U+(i+1U)*4U,whOff=node+4U+(i+2U)*4U;
                    if(xyOff>0x001ffffcU||whOff>0x001ffffcU)throw std::runtime_error("DMA2 ClearImage: fill packet crosses RAM");
                    const auto xy=ctx->ram.read(0x80000000U|xyOff,4);
                    const auto wh=ctx->ram.read(0x80000000U|whOff,4);
                    const auto x=xy&0xffffU,y=(xy>>16)&0xffffU,w=wh&0xffffU,h=(wh>>16)&0xffffU;
                    if(x>=1024U||y>=512U||w==0U||h==0U||w>1024U||h>512U)throw std::runtime_error("DMA2 ClearImage: implausible PAL fill rectangle");
                    gp0FillColor=word&0x00ffffffU;gp0FillXy=xy;gp0FillWh=wh;
                    note("gp0",0x1f801810U,4,word,"GP0_FILL_RECT");
                    note("gp0",0x1f801810U,4,xy,"GP0_FILL_XY");
                    note("gp0",0x1f801810U,4,wh,"GP0_FILL_WH");
                    i+=2U;
                    continue;
                }
                if(word==0x80000000U){
                    if(i+3U>=words)throw std::runtime_error("DMA2 MoveImage: truncated GP0 80h packet");
                    gp0MoveImage(ctx->ram.read(0x80000000U|(node+4U+(i+1U)*4U),4),ctx->ram.read(0x80000000U|(node+4U+(i+2U)*4U),4),ctx->ram.read(0x80000000U|(node+4U+(i+3U)*4U),4));
                    i+=3U;
                    continue;
                }
                if(!gp0State(0x1f801810U,word))throw MmioFault(0x1f801810U,4,true,word,"DMA2 linked-list GP0 command is not modelled");
            }
            const auto next=tag&0x00ffffffU;
            if(next==0x00ffffffU){dma2Chcr&=~0x11000000U;note("mmio-w",chcrAddress,4,dma2Chcr,"D2_CHCR_LINKED_LIST_DONE");return;}
            if((next&3U)!=0U||next>0x001ffffcU)throw std::runtime_error("DMA2 linked-list: invalid next pointer");
            node=next;
        }
        throw std::runtime_error("DMA2 linked-list: node limit exceeded");
    }
    bool gp1(std::uint32_t address,std::uint32_t value) {
        const auto cmd=value>>24,param=value&0x00ffffffU;
        if(cmd<=0x01U&&upState!=UpState::Idle)throw MmioFault(address,4,true,value,"GP1 reset during an incomplete GP0 A0h upload");
        switch(cmd){
        case 0x00U:
            if(param==0){gpuReset=true;gpuStat=0x00802000U;++gp1Commands;note("gp1",address,4,value,"GP1_RESET");return true;}
            break;
        case 0x01U: if(gpuReset&&param==0){++gp1Commands;note("gp1",address,4,value,"GP1_RESET_FIFO");return true;} break;
        case 0x02U: if(gpuReset&&param==0){++gp1Commands;note("gp1",address,4,value,"GP1_ACK_IRQ");return true;} break;
        case 0x03U: if(gpuReset&&param<=1U){gpuStat=(gpuStat&~0x00800000U)|(param?0x00800000U:0U);++gp1Commands;note("gp1",address,4,value,"GP1_DISPLAY_ENABLE");return true;} break;
        case 0x04U: if(gpuReset&&param<=3U){gp1DmaDirection=param;gpuStat=(gpuStat&~0x60000000U)|(param<<29);++gp1Commands;note("gp1",address,4,value,"GP1_DMA_DIRECTION");return true;} break;
        case 0x05U: if(gpuReset){gp1DisplayStart=param;++gp1Commands;note("gp1",address,4,value,"GP1_DISPLAY_START");return true;} break;
        case 0x06U: if(gpuReset){gp1HRange=param;++gp1Commands;note("gp1",address,4,value,"GP1_H_RANGE");return true;} break;
        case 0x07U: if(gpuReset){gp1VRange=param;++gp1Commands;note("gp1",address,4,value,"GP1_V_RANGE");return true;} break;
        case 0x08U: if(gpuReset&&(param&~0x7fU)==0){gp1DisplayMode=param;++gp1Commands;note("gp1",address,4,value,"GP1_DISPLAY_MODE");return true;} break;
        case 0x10U:
            if(gpuReset&&param==7U){gpuRead=gpuType;gpuReadValid=true;++gp1Commands;note("gp1",address,4,value,"GP1_INFO_TYPE");return true;}
            break;
        default:break;
        }
        return false;
    }
    std::uint32_t mmioRead(std::uint32_t address,unsigned width) override {
        ++accesses;
        const auto phys=address&0x1fffffffU;
        if(inSpu(phys)&&(width==2||(width==4&&!(phys&2U)))){
            std::uint32_t result=0;
            for(unsigned half=0;half<width/2;++half){
                const auto index=(phys-0x1f801c00U)/2+half;
                if(0x1f801c00U+index*2==0x1f801daeU){result|=std::uint32_t(spuStat())<<(16*half);continue;}
                if(!spuWritten[index])throw MmioFault(address,width,false,0,"SPU register read before any PAL write (power-on value unknown)");
                result|=std::uint32_t(spuReg[index])<<(16*half);
            }
            return result;
        }
        switch(phys){
        case 0x1f801070U:if(width==2||width==4){sync();note("mmio-r",address,width,istat,"I_STAT");return istat;}break;
        case 0x1f801074U:if(width==2||width==4){note("mmio-r",address,width,imask,"I_MASK");return imask;}break;
        case 0x1f8010f0U:if(width==4){note("mmio-r",address,width,dpcr,"DPCR");return dpcr;}break;
        case 0x1f801014U:if(width==4){note("mmio-r",address,width,spuDelay,"SPU_DELAY");return spuDelay;}break;
        case 0x1f8010c0U:if(width==4){note("mmio-r",address,width,dma4Madr,"D4_MADR");return dma4Madr;}break;
        case 0x1f8010c4U:if(width==4){note("mmio-r",address,width,dma4Bcr,"D4_BCR");return dma4Bcr;}break;
        case 0x1f8010c8U:if(width==4){note("mmio-r",address,width,dma4Chcr,"D4_CHCR");return dma4Chcr;}break;
        case 0x1f801810U: // GPUREAD: only the latch written by a modelled GP1(10h)
            if(width==4&&gpuReadValid){note("mmio-r",address,width,gpuRead,"GPUREAD");return gpuRead;}
            break;
        case 0x1f801814U:
            if(width==4&&gpuReset){sync();const auto v=gpuStatus();note("mmio-r",address,width,v,"GPUSTAT");return v;}
            break;
        case 0x1f8010a0U:if(width==4){note("mmio-r",address,width,dma2Madr,"D2_MADR");return dma2Madr;}break;
        case 0x1f8010a4U:if(width==4){note("mmio-r",address,width,dma2Bcr,"D2_BCR");return dma2Bcr;}break;
        case 0x1f8010a8U:if(width==4){note("mmio-r",address,width,dma2Chcr,"D2_CHCR");return dma2Chcr;}break;
        case 0x1f8010f4U:if(width==4){const auto v=dicrValue();note("mmio-r",address,width,v,"DICR");return v;}break;
        case 0x1f801110U:
            if(width==4&&timer1Configured){
                const auto n=now();
                const std::uint32_t v=n<timer1StartStep?0U:std::uint32_t(((n-timer1StartStep)*cyclesPerInstruction/lineCycles)&0xffffU);
                note("mmio-r",address,width,v,"RCNT1_COUNT");return v;
            }
            break;
        default:break;
        }
        throw MmioFault(address,width,false,0,"register/width is not modelled");
    }
    void mmioWrite(std::uint32_t address,std::uint32_t value,unsigned width) override {
        ++accesses;
        const auto phys=address&0x1fffffffU;
        if(inSpu(phys)&&(width==2||(width==4&&!(phys&2U)))){
            for(unsigned half=0;half<width/2;++half){
                const auto index=(phys-0x1f801c00U)/2+half;const auto reg=0x1f801c00U+index*2;
                const std::uint16_t v=std::uint16_t(value>>(16*half));
                if(reg==0x1f801daeU)throw MmioFault(address,width,true,value,"SPUSTAT is read-only");
                if(reg==0x1f801daaU){
                    if(v&0x40U)throw MmioFault(address,width,true,value,"SPU IRQ enable is not modelled");
                    const auto mode=(v>>4)&3U;
                    if(mode==3U)throw MmioFault(address,width,true,value,"SPU DMA read transfer mode is not modelled");   // mode 2 (DMA write): stored only
                    if(mode==1U)spuFlush(address,width,value);
                    else if(!spuFifo.empty())throw MmioFault(address,width,true,value,"SPU FIFO holds data but no transfer mode was selected");
                    if(trace)trace->add("mmio-w",std::string("SPUCNT ")+h8(address)+" "+h8(v));
                }
                if(reg==0x1f801da8U){ // data FIFO: queued, not stored as a register
                    if(spuFifo.size()>=32U)throw MmioFault(address,width,true,value,"SPU data FIFO overflow");
                    spuFifo.push_back(v);continue;
                }
                spuReg[index]=v;spuWritten[index]=true;
            }
            return;
        }
        switch(phys){
        case 0x1f801070U: // acknowledge: a written 0 bit clears the pending bit, a 1 bit leaves it
            if(width==2||width==4){sync();istat=std::uint16_t(istat&value);note("mmio-w",address,width,value,"I_STAT");return;}
            break;
        case 0x1f801074U:
            if((width==2||width==4)&&(value&~0x7ffU)==0){imask=std::uint16_t(value);note("mmio-w",address,width,value,"I_MASK");return;}
            break;
        case 0x1f8010f0U:
            if(width==4){dpcr=value;note("mmio-w",address,width,value,"DPCR");return;}
            break;
        case 0x1f801014U: // only the libspu DMA-write pattern: keep every bit except the 0x0F000000 nibble, which becomes 0
            if(width==4&&value==((spuDelay&0xf0ffffffU)|0x20000000U)){spuDelay=value;note("mmio-w",address,width,value,"SPU_DELAY");return;}
            break;
        case 0x1f801814U: // GP1
            if(width==4&&gp1(address,value))return;
            break;
        case 0x1f8010c0U:if(width==4){dma4Madr=value&0x00ffffffU;note("mmio-w",address,width,value,"D4_MADR");return;}break;
        case 0x1f8010c4U:if(width==4){dma4Bcr=value;note("mmio-w",address,width,value,"D4_BCR");return;}break;
        case 0x1f8010c8U:if(width==4&&value==0x01000201U){dma4Block(address,value);return;}break;
        case 0x1f8010a0U:if(width==4){dma2Madr=value&0x00ffffffU;note("mmio-w",address,width,value,"D2_MADR");return;}break;
        case 0x1f8010a4U:if(width==4){dma2Bcr=value;note("mmio-w",address,width,value,"D2_BCR");return;}break;
        case 0x1f8010a8U:
            if(width==4&&value==0x01000401U&&dma2Bcr==0U){if(upState!=UpState::Idle)throw MmioFault(address,width,true,value,"DMA2 linked-list start while a GP0 A0h upload is incomplete");dma2Chcr=value;note("mmio-w",address,width,value,"D2_CHCR_LINKED_LIST_START");dma2LinkedList(address);return;}
            if(width==4&&value==0x01000201U){dma2BlockUpload(address,value);return;}
            if(width==4&&(value&0x11000000U)==0&&(value&~0x71770703U)==0&&((value>>9)&3U)<3U){dma2Chcr=value;note("mmio-w",address,width,value,"D2_CHCR");return;}
            break;
        case 0x1f8010e8U:
            // DMA6/OTC CHCR. The first observed PAL access is a 32-bit clear.
            // It starts no transfer; actual OTC start, MADR/BCR and reads remain unmodelled.
            if(width==4&&value==0U){note("mmio-w",address,width,value,"D6_CHCR");return;}
            break;
        case 0x1f801810U:
            if(width==4&&gp0Write(address,value))return;
            break;
        case 0x1f8010f4U:
            if(width==4&&(value&0x7fffU)==0){
                dicrEnable=value&0x00ff0000U;
                dicrFlags&=~(value&0x7f000000U);                 // write-1-to-clear acknowledge
                note("mmio-w",address,width,value,"DICR");return;
            }
            break;
        case 0x1f801124U: // RCNT2 mode: the reset write (0) and the final SetRCnt value 0x0248 (needs the 0xffff target first)
            if(width==2&&value==0U){timer2Configured=false;timer2Mode=0;note("mmio-w",address,width,value,"RCNT2_MODE");return;}
            if(width==2&&value==0x0248U&&timer2TargetSet){
                timer2Configured=true;timer2Mode=value;timer2StartStep=now();
                note("mmio-w",address,width,value,"RCNT2_MODE");return;
            }
            break;
        case 0x1f801128U: // RCNT2 target: only 0xffff
            if(width==2&&value==0xffffU){timer2TargetSet=true;note("mmio-w",address,width,value,"RCNT2_TARGET");return;}
            break;
        case 0x1f801114U: // only the one mode the PAL writes (sync enable, mode 3, HBlank clock): anything else is unsupported
            if(width==4&&value==0x107U){
                timer1Configured=true;timer1Mode=value;timer1StartStep=nextEdgeStep();
                note("mmio-w",address,width,value,"RCNT1_MODE");return;
            }
            break;
        default:break;
        }
        throw MmioFault(address,width,true,value,"register/width/value is not modelled");
    }
};

// ---------------------------------------------------------------------------------------------------------------------
// Interrupt entry (the BIOS exception path as the PAL configured it). Evidence from the PAL (ResetCallback, 0x8004dc84): it runs
// setjmp (0x8004f4f4, standard jmp_buf: ra,sp,fp,s0..s7,gp) into 0x800609bc, replaces buf.sp by the interrupt stack and registers
// the buffer with B0:19 SetCustomExitFromException. On an interrupt the BIOS exception code saves the interrupted context and
// leaves through that buffer exactly like longjmp(buf,1); the PAL's service routine ends in B0:17 ReturnFromException. This class
// reproduces only that: it never interprets, chooses or calls a handler itself.
// An interrupt is taken at an instruction boundary only when ALL of these hold (otherwise it stays pending, deterministically):
//   a custom exit buffer is registered; interrupts are enabled (ExitCriticalSection) and not already inside the service
//   routine; (I_STAT & I_MASK) != 0; the instruction about to execute is not a branch delay slot and no load is in flight.
// ---------------------------------------------------------------------------------------------------------------------
class InterruptEntry {
public:
    Hardware* hw=nullptr;Trace* trace=nullptr;Probe* probe=nullptr;const FunctionMap* map=nullptr;
    unsigned traceLimit=8;
    std::uint64_t delivered=0;
    std::size_t chainMark=0;bool active=false;
    static bool isBranchOrJump(std::uint32_t w) {
        const auto op=w>>26;
        if(op>=1U&&op<=7U)return true;                       // REGIMM, J, JAL, BEQ, BNE, BLEZ, BGTZ
        if(op==0U){const auto f=w&0x3fU;return f==8U||f==9U;} // JR, JALR
        return false;
    }
    // Returns true when the interrupted context was swapped for the service entry (Context::redirect is set).
    bool poll(Context& c,std::uint32_t pc) {
        auto* d=static_cast<bios::BootDevice*>(c.biosDevice);
        if(active&&d->frames.empty()){   // the service routine returned (B0:17): drop its shadow frames
            active=false;
            if(probe&&probe->chain.size()>chainMark)probe->chain.resize(chainMark);
            if(trace&&delivered<=traceLimit)trace->add("irq-return","resume "+h8(pc)+" sp="+h8(c.r[29]));
        }
        hw->sync();
        if(!d||!d->customExit||!d->irqEnabled||d->interruptDepth||c.loadRegister)return false;
        if(!(hw->istat&hw->imask))return false;
        if(isBranchOrJump(c.ram.read(pc-4U,4)))return false;
        const auto buf=d->customExit;
        Ps1Memory& ram=c.ram;
        const auto ra=ram.read(buf,4);
        if(!map||!map->find(ra)||map->find(ra)->kind!='G')
            throw std::runtime_error("Interrupt entry: custom exit return address "+h8(ra)+" is not inside a generated function");
        bios::BootDevice::Frame f;
        for(unsigned i=0;i<32;++i)f.r[i]=c.r[i];
        f.hi=c.hi;f.lo=c.lo;f.pc=pc;f.irqEnabled=d->irqEnabled;
        d->frames.push_back(f);
        ++d->interruptDepth;++d->interruptsEntered;d->irqEnabled=false;++delivered;
        c.r[31]=ra;c.r[29]=ram.read(buf+4U,4);c.r[30]=ram.read(buf+8U,4);
        for(unsigned i=0;i<8;++i)c.r[16+i]=ram.read(buf+12U+4U*i,4);
        c.r[28]=ram.read(buf+44U,4);c.r[2]=1;
        if(trace&&delivered<=traceLimit)
            trace->add("irq-enter","#"+std::to_string(delivered)+" istat="+h8(hw->istat)+" imask="+h8(hw->imask)+" interrupted="+h8(pc)+" -> "+h8(ra)+" sp="+h8(c.r[29]));
        else if(trace&&delivered==traceLimit+1)trace->add("irq-enter","further interrupt entries not traced (count in the report)");
        chainMark=probe?probe->chain.size():0;active=true;
        c.redirectPending=true;c.redirectPc=ra;
        return true;
    }
};
}


