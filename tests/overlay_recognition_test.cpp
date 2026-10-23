#include "../src/overlay_recognition.hpp"
#include <iostream>
using namespace moyle::detail::recomp::overlay;
namespace {
void require(bool b,const char* why){if(!b)throw std::runtime_error(why);}
template<class F> void rejects(F f,const char* message){
    try{f();}catch(const RecognitionError& e){
        require(std::string(e.what()).find("Fatal overlay recognition:")==0,"Missing fatal diagnostic");
        require(std::string(e.what()).find(message)!=std::string::npos,"Wrong diagnostic");return;
    }
    throw std::runtime_error("Invalid overlay accepted");
}
void put(std::vector<std::uint8_t>& bytes,std::size_t offset,std::uint32_t word){
    for(unsigned n=0;n<4;++n)bytes.at(offset+n)=std::uint8_t(word>>(8*n));
}
}
int main(){try{
    const std::array<std::uint32_t,6> sites={0x800103a4,0x80010460,0x80010530,0x800105ec,0x800106b4,0x8001077c};
    require(palTitle.base==0x80010200&&palTitle.size==0x42b4&&palTitle.runtimeWord0==0x8006b340&&
        palTitle.initialPatchHigh==0x1840&&palTitle.alternatePatchHigh==0x1c40&&palTitle.patchSites==sites&&
        std::string(palTitle.maskedSha1)=="8039efc0f86388d94659c8fb29cef0f9b67eae84","PAL metadata mismatch");
    // Entire image invented here. Digest independently computed with .NET SHA1
    // over byte(i*37+11), after the documented masks; no game input or I/O.
    auto synthetic=palTitle;synthetic.name="synthetic fixture";
    synthetic.maskedSha1="2ee05abecba723e2f15ccb0535d43f13358bbb4b";
    std::vector<std::uint8_t> bytes(synthetic.size);
    for(std::size_t n=0;n<bytes.size();++n)bytes[n]=std::uint8_t(n*37+11);
    put(bytes,0,0);
    for(auto site:sites){const auto off=site-synthetic.base;bytes[off+2]=0x40;bytes[off+3]=0x18;}
    const auto original=bytes;
    require(fingerprint(synthetic,bytes)==synthetic.maskedSha1,"Synthetic fingerprint");
    validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::InitialImage);
    require(bytes==original,"Recognition modified image");
    for(auto w:{0U,0xffffffffU,synthetic.runtimeWord0}){
        put(bytes,0,w);require(fingerprint(synthetic,bytes)==synthetic.maskedSha1,"Word0 not masked");
    }
    validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeLoaded);
    put(bytes,0,0);rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeLoaded);},"runtime word0");
    for(auto site:sites){
        for(auto high:{0U,0x1c40U,0xffffU}){
            bytes=original;const auto off=site-synthetic.base;bytes[off+2]=std::uint8_t(high);bytes[off+3]=std::uint8_t(high>>8);
            require(fingerprint(synthetic,bytes)==synthetic.maskedSha1,"Patch high half not masked");
            rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::InitialImage);},"initial patch high half");
            put(bytes,0,synthetic.runtimeWord0);
            rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeLoaded);},
                high==0x1c40U?"mixed runtime patch state":"runtime patch high half");
        }
        for(unsigned byte=0;byte<2;++byte){bytes=original;bytes[site-synthetic.base+byte]^=1;
            rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::InitialImage);},"unknown masked SHA-1");}
    }
    // Runtime state: uniform 1840 or uniform 1C40 accepted, never at identity time.
    const auto setAll=[&](std::uint32_t high,std::uint32_t word0){
        bytes=original;put(bytes,0,word0);
        for(auto site:sites){const auto off=site-synthetic.base;bytes[off+2]=std::uint8_t(high);bytes[off+3]=std::uint8_t(high>>8);}
    };
    setAll(0x1c40,synthetic.runtimeWord0);
    require(fingerprint(synthetic,bytes)==synthetic.maskedSha1,"Uniform alternate state changes identity");
    validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeLoaded);
    rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::InitialImage);},"initial patch high half");
    setAll(0x1c40,0);
    rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeLoaded);},"runtime word0");
    setAll(0x1840,synthetic.runtimeWord0);
    validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeLoaded);
    for(std::size_t split=1;split<sites.size();++split){ // every mixed prefix/suffix split, both directions
        for(auto lead:{0x1840U,0x1c40U}){
            setAll(lead,synthetic.runtimeWord0);
            for(auto n=split;n<sites.size();++n){const auto off=sites[n]-synthetic.base;const auto other=lead==0x1840U?0x1c40U:0x1840U;
                bytes[off+2]=std::uint8_t(other);bytes[off+3]=std::uint8_t(other>>8);}
            rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeLoaded);},"mixed runtime patch state");
        }
    }
    // Setter entry: per-site mix of the two valid states tolerated, nothing else.
    setAll(0x1840,synthetic.runtimeWord0);
    for(std::size_t n=1;n<sites.size();n+=2){const auto off=sites[n]-synthetic.base;bytes[off+2]=0x40;bytes[off+3]=0x1c;}
    validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeSetterEntry);
    rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeLoaded);},"mixed runtime patch state");
    rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::InitialImage);},"initial patch high half");
    {const auto off=sites[4]-synthetic.base;bytes[off+2]=0x34;bytes[off+3]=0x12;}
    rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeSetterEntry);},"runtime patch high half");
    setAll(0x1c40,0);
    rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::RuntimeSetterEntry);},"runtime word0");
    {auto same=synthetic;same.alternatePatchHigh=same.initialPatchHigh;
        rejects([&]{fingerprint(same,original);},"invalid metadata patch states");}
    for(auto offset:{4U,0x100U,synthetic.size-1}){bytes=original;bytes[offset]^=1;
        rejects([&]{validateInitialLoad(synthetic,synthetic.base,bytes,LoadPhase::InitialImage);},"unknown masked SHA-1");}
    for(auto size:{0U,synthetic.size-1,synthetic.size+1}){bytes=original;bytes.resize(size);
        rejects([&]{recognize(palTitle.base,bytes,LoadPhase::InitialImage);},"unknown size");}
    for(auto base:{0U,0x00010200U,0xa0010200U,palTitle.base+4})
        rejects([&]{recognize(base,original,LoadPhase::InitialImage);},"unknown base");
    rejects([&]{recognize(palTitle.base,original,LoadPhase::InitialImage);},"unknown masked SHA-1");
    rejects([&]{validateInitialLoad(synthetic,synthetic.base,original,static_cast<LoadPhase>(7));},"invalid load phase");
    for(auto badSite:{synthetic.base,synthetic.base+5,synthetic.base+synthetic.size,0xffffffffU}){
        auto bad=synthetic;bad.patchSites[0]=badSite;
        rejects([&]{fingerprint(bad,original);},"invalid metadata patch site");
    }
    auto duplicate=synthetic;duplicate.patchSites[1]=duplicate.patchSites[0];
    rejects([&]{fingerprint(duplicate,original);},"duplicate metadata patch site");
    std::cout<<"Overlay recognition: PAL metadata, independent synthetic hash, masks, six strict initial patches, uniform runtime patch states/mixed rejection, setter-entry mix, runtime word0, unknown identity/extent/base, read-only and metadata bounds passed\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
