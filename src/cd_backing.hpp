#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

// Host CD backing for the guest libcd HLE: read-only, sector-granular and on
// demand (nothing is preloaded or cached). Contains no game data.
namespace moyle::detail::cd {
inline constexpr std::size_t userBytes=2048;
using Sector=std::array<std::uint8_t,userBytes>;
class CdError:public std::runtime_error{public:using std::runtime_error::runtime_error;};
[[noreturn]] inline void cdFail(const std::string& what){throw CdError("Fatal CD backing: "+what);}

// CdlLOC fields are BCD; LBA 0 is 00:02:00 (150-sector lead-in).
struct Msf{std::uint8_t minute,second,sector;};
inline unsigned fromBcd(std::uint8_t v){
    if((v>>4)>9||(v&15)>9){std::ostringstream s;s<<"invalid BCD byte 0x"<<std::hex<<unsigned(v);cdFail(s.str());}
    return (v>>4)*10U+(v&15U);
}
inline std::uint8_t toBcd(unsigned v){
    if(v>99)cdFail("BCD value out of range");
    return static_cast<std::uint8_t>(((v/10)<<4)|(v%10));
}
inline std::uint32_t msfToLba(Msf m){
    const auto mm=fromBcd(m.minute),ss=fromBcd(m.second),ff=fromBcd(m.sector);
    if(ss>59||ff>74)cdFail("MSF second/sector out of range");
    const auto absolute=(mm*60U+ss)*75U+ff;
    if(absolute<150)cdFail("MSF inside the lead-in (before 00:02:00)");
    return absolute-150;
}
inline Msf lbaToMsf(std::uint32_t lba){
    if(lba>100U*60U*75U-151U)cdFail("LBA beyond 99:59:74");
    const auto a=lba+150U;
    return {toBcd(a/(60*75)),toBcd(a/75%60),toBcd(a%75)};
}

class SectorSource{
public:
    virtual ~SectorSource()=default;
    // 2048 user-data bytes of one data sector; out-of-range is fatal.
    virtual Sector read(std::uint32_t lba) const=0;
};

namespace detail{
inline std::uint64_t fileSize(std::ifstream& f,const std::filesystem::path& p){
    if(!f)cdFail("cannot open "+p.string());
    f.seekg(0,std::ios::end);const auto size=f.tellg();
    if(size<0)cdFail("cannot size "+p.string());
    return static_cast<std::uint64_t>(size);
}
inline void readAt(std::ifstream& f,std::uint64_t offset,std::uint8_t* out,std::size_t n){
    f.clear();f.seekg(static_cast<std::streamoff>(offset));
    f.read(reinterpret_cast<char*>(out),static_cast<std::streamsize>(n));
    if(static_cast<std::size_t>(f.gcount())!=n)cdFail("short read");
}
}

// Whole disc image. Raw: 2352-byte sectors, Mode 2 Form 1 user data at +24
// (sync, header mode and form are checked on every read). Cooked: 2048 bytes.
enum class ImageLayout{Raw2352Mode2Form1,Cooked2048};
class DiscImage final:public SectorSource{
public:
    DiscImage(std::filesystem::path path,ImageLayout layout):path_(std::move(path)),layout_(layout),
        file_(path_,std::ios::binary){
        const auto size=detail::fileSize(file_,path_);
        if(!size||size%stride())cdFail("image size is not a whole number of sectors: "+path_.string());
        sectors_=size/stride();
    }
    std::uint64_t sectors() const noexcept{return sectors_;}
    Sector read(std::uint32_t lba) const override{
        if(lba>=sectors_){std::ostringstream s;s<<"LBA "<<lba<<" beyond image ("<<sectors_<<" sectors)";cdFail(s.str());}
        Sector out{};
        if(layout_==ImageLayout::Cooked2048){detail::readAt(file_,std::uint64_t(lba)*2048,out.data(),out.size());return out;}
        std::array<std::uint8_t,24> head{};
        detail::readAt(file_,std::uint64_t(lba)*2352,head.data(),head.size());
        static constexpr std::array<std::uint8_t,12> sync={0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0};
        for(std::size_t n=0;n<sync.size();++n)if(head[n]!=sync[n])cdFail("raw sector without sync pattern at LBA "+std::to_string(lba));
        const auto msf=lbaToMsf(lba);
        if(head[12]!=msf.minute||head[13]!=msf.second||head[14]!=msf.sector)cdFail("raw sector header address mismatch at LBA "+std::to_string(lba));
        if(head[15]!=2)cdFail("raw sector is not Mode 2 at LBA "+std::to_string(lba));
        if(head[18]&0x20)cdFail("raw sector is Mode 2 Form 2 at LBA "+std::to_string(lba));
        detail::readAt(file_,std::uint64_t(lba)*2352+24,out.data(),out.size());
        return out;
    }
private:
    std::uint64_t stride() const noexcept{return layout_==ImageLayout::Cooked2048?2048:2352;}
    std::filesystem::path path_;ImageLayout layout_;mutable std::ifstream file_;std::uint64_t sectors_=0;
};

// One extracted disc file mapped at its first LBA (for example a level
// container placed from the executable's level table). The final partial
// sector reads as zero padding; LBAs outside the file are fatal.
class FileAtLba final:public SectorSource{
public:
    FileAtLba(std::filesystem::path path,std::uint32_t firstLba):path_(std::move(path)),first_(firstLba),
        file_(path_,std::ios::binary){
        size_=detail::fileSize(file_,path_);
        if(!size_)cdFail("empty mapped file "+path_.string());
        if(std::uint64_t(first_)+(size_+2047)/2048>100U*60U*75U-150U)cdFail("mapped file beyond 99:59:74");
    }
    std::uint32_t firstLba() const noexcept{return first_;}
    std::uint32_t endLba() const noexcept{return first_+static_cast<std::uint32_t>((size_+2047)/2048);}
    Sector read(std::uint32_t lba) const override{
        if(lba<first_||lba>=endLba()){std::ostringstream s;s<<"LBA "<<lba<<" outside mapped file ["<<first_<<","<<endLba()<<")";cdFail(s.str());}
        Sector out{};const auto offset=std::uint64_t(lba-first_)*2048;
        detail::readAt(file_,offset,out.data(),static_cast<std::size_t>(std::min<std::uint64_t>(2048,size_-offset)));
        return out;
    }
private:
    std::filesystem::path path_;std::uint32_t first_;mutable std::ifstream file_;std::uint64_t size_=0;
};
}

