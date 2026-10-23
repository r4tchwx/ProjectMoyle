#include "overlay_recognition.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace moyle::detail::recomp::overlay {
namespace {
std::string hex(std::uint32_t n) {
    std::ostringstream s;s<<"0x"<<std::hex<<std::setfill('0')<<std::setw(8)<<n;return s.str();
}
[[noreturn]] void fail(const std::string& reason) {
    throw RecognitionError("Fatal overlay recognition: "+reason);
}
void check(NTSTATUS status,const char* operation) {
    if(status<0)fail(std::string("SHA-1 provider ")+operation+" failed, status "+hex(static_cast<std::uint32_t>(status)));
}
struct Provider {
    BCRYPT_ALG_HANDLE handle=nullptr;
    ~Provider(){if(handle)BCryptCloseAlgorithmProvider(handle,0);}
};
struct Hash {
    BCRYPT_HASH_HANDLE handle=nullptr;
    ~Hash(){if(handle)BCryptDestroyHash(handle);}
};
void checkMetadata(const Metadata& m) {
    if(!m.name||!m.maskedSha1||m.size<4||(m.base&3)||m.base<0x80000000U||
       std::uint64_t(m.base)+m.size>0x80200000ULL)fail("invalid metadata RAM extent");
    const std::string digest=m.maskedSha1;
    if(digest.size()!=40||digest.find_first_not_of("0123456789abcdef")!=std::string::npos)
        fail("invalid metadata SHA-1");
    if(m.initialPatchHigh==m.alternatePatchHigh)fail("invalid metadata patch states");
    for(std::size_t n=0;n<m.patchSites.size();++n){
        const auto p=m.patchSites[n];
        if((p&3)||p<=m.base||std::uint64_t(p)+4>std::uint64_t(m.base)+m.size)
            fail("invalid metadata patch site "+hex(p));
        for(std::size_t k=0;k<n;++k)if(m.patchSites[k]==p)fail("duplicate metadata patch site "+hex(p));
    }
}
std::uint32_t word(const std::vector<std::uint8_t>& image,std::size_t offset) {
    return image[offset]|(std::uint32_t(image[offset+1])<<8)|
           (std::uint32_t(image[offset+2])<<16)|(std::uint32_t(image[offset+3])<<24);
}
}
std::string fingerprint(const Metadata& m,const std::vector<std::uint8_t>& image) {
    checkMetadata(m);
    if(image.size()!=m.size)fail("unknown size at "+hex(m.base)+": expected "+std::to_string(m.size)+", got "+std::to_string(image.size()));
    auto masked=image;
    std::fill_n(masked.begin(),4,0);
    for(auto p:m.patchSites){const auto offset=p-m.base;masked[offset+2]=masked[offset+3]=0;}
    Provider provider;
    check(BCryptOpenAlgorithmProvider(&provider.handle,BCRYPT_SHA1_ALGORITHM,nullptr,0),"open");
    ULONG length=0,written=0;
    check(BCryptGetProperty(provider.handle,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&length),sizeof(length),&written,0),"object size");
    if(written!=sizeof(length)||!length)fail("invalid SHA-1 provider object size");
    std::vector<UCHAR> object(length);
    Hash hash;
    check(BCryptCreateHash(provider.handle,&hash.handle,object.data(),length,nullptr,0,0),"create");
    check(BCryptHashData(hash.handle,masked.data(),static_cast<ULONG>(masked.size()),0),"data");
    std::array<UCHAR,20> result{};
    check(BCryptFinishHash(hash.handle,result.data(),static_cast<ULONG>(result.size()),0),"finish");
    std::ostringstream text;text<<std::hex<<std::setfill('0');
    for(auto byte:result)text<<std::setw(2)<<unsigned(byte);
    return text.str();
}
void validateInitialLoad(const Metadata& m,std::uint32_t base,
                         const std::vector<std::uint8_t>& image,LoadPhase phase) {
    checkMetadata(m);
    if(base!=m.base)fail("unknown base "+hex(base)+", expected "+hex(m.base));
    if(phase!=LoadPhase::InitialImage&&phase!=LoadPhase::RuntimeLoaded&&phase!=LoadPhase::RuntimeSetterEntry)fail("invalid load phase");
    const auto actual=fingerprint(m,image);
    if(actual!=m.maskedSha1)fail(std::string("unknown masked SHA-1 for ")+m.name+" at "+hex(base)+": expected "+m.maskedSha1+", got "+actual);
    if(phase==LoadPhase::InitialImage){
        for(auto p:m.patchSites){
            const auto high=word(image,p-m.base)>>16;
            if(high!=m.initialPatchHigh)fail("initial patch high half at "+hex(p)+": expected "+hex(m.initialPatchHigh)+", got "+hex(high));
        }
        return;
    }
    if(word(image,0)!=m.runtimeWord0)
        fail("runtime word0 at "+hex(base)+": expected "+hex(m.runtimeWord0)+", got "+hex(word(image,0)));
    const auto first=word(image,m.patchSites[0]-m.base)>>16;
    for(auto p:m.patchSites){
        const auto high=word(image,p-m.base)>>16;
        if(high!=m.initialPatchHigh&&high!=m.alternatePatchHigh)
            fail("runtime patch high half at "+hex(p)+": expected "+hex(m.initialPatchHigh)+" or "+hex(m.alternatePatchHigh)+", got "+hex(high));
        if(high!=first&&phase!=LoadPhase::RuntimeSetterEntry)
            fail("mixed runtime patch state at "+hex(p)+": "+hex(high)+" differs from "+hex(first));
    }
}
const Metadata& recognize(std::uint32_t base,const std::vector<std::uint8_t>& image,LoadPhase phase) {
    const Metadata& identity=image.size()==palLanguage.size?palLanguage:palTitle;
    validateInitialLoad(identity,base,image,phase);
    return identity;
}
}
