// Host CD backing: synthetic images written to a temporary directory only.
#include "../src/cd_backing.hpp"
#include <iostream>
#include <vector>
using namespace moyle::detail::cd;
namespace {
unsigned checks=0;
void require(bool v,const char* why){++checks;if(!v)throw std::runtime_error(why);}
template<class F> void rejects(F f,const char* text){
    try{f();}catch(const CdError& e){require(std::string(e.what()).find(text)!=std::string::npos,e.what());return;}
    throw std::runtime_error(std::string("Expected CD failure: ")+text);
}
std::uint8_t pattern(std::uint32_t lba,std::size_t n){return static_cast<std::uint8_t>(lba*7+n*13+1);}
std::vector<std::uint8_t> rawSector(std::uint32_t lba,std::uint8_t submode=0x08){
    std::vector<std::uint8_t> s(2352,0);
    for(int n=1;n<11;++n)s[n]=0xff;
    const auto msf=lbaToMsf(lba);s[12]=msf.minute;s[13]=msf.second;s[14]=msf.sector;s[15]=2;
    s[18]=s[22]=submode;
    for(std::size_t n=0;n<2048;++n)s[24+n]=pattern(lba,n);
    return s;
}
void write(const std::filesystem::path& p,const std::vector<std::uint8_t>& bytes){
    std::ofstream f(p,std::ios::binary|std::ios::trunc);f.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    if(!f)throw std::runtime_error("cannot write temporary image");
}
bool samePattern(const Sector& s,std::uint32_t lba){for(std::size_t n=0;n<s.size();++n)if(s[n]!=pattern(lba,n))return false;return true;}
}
int main(){try{
    // MSF/BCD (CdlLOC): LBA 0 = 00:02:00.
    require(lbaToMsf(0).minute==0&&lbaToMsf(0).second==2&&lbaToMsf(0).sector==0,"LBA 0");
    for(std::uint32_t lba:{0U,1U,74U,75U,4499U,4500U,10383U,449849U}){const auto m=lbaToMsf(lba);require(msfToLba(m)==lba,"MSF round trip");}
    require(lbaToMsf(10383).minute==0x02&&lbaToMsf(10383).second==0x20&&lbaToMsf(10383).sector==0x33,"BCD of 10383 (02:20:33)");
    rejects([]{lbaToMsf(449850);},"beyond 99:59:74");
    rejects([]{msfToLba({0x00,0x1a,0x00});},"invalid BCD");
    rejects([]{msfToLba({0x00,0x60,0x00});},"out of range");
    rejects([]{msfToLba({0x00,0x00,0x75});},"out of range");
    rejects([]{msfToLba({0x00,0x01,0x74});},"lead-in");
    const auto dir=std::filesystem::temp_directory_path()/("pm-cd-backing-"+std::to_string(reinterpret_cast<std::uintptr_t>(&checks)));
    std::filesystem::create_directories(dir);
    struct Cleanup{std::filesystem::path p;~Cleanup(){std::error_code e;std::filesystem::remove_all(p,e);}} cleanup{dir};
    // Raw Mode 2 Form 1 image, read on demand.
    std::vector<std::uint8_t> raw;for(std::uint32_t lba=0;lba<4;++lba){auto s=rawSector(lba);raw.insert(raw.end(),s.begin(),s.end());}
    write(dir/"raw.bin",raw);
    DiscImage image(dir/"raw.bin",ImageLayout::Raw2352Mode2Form1);
    require(image.sectors()==4,"Raw sector count");
    for(std::uint32_t lba=0;lba<4;++lba)require(samePattern(image.read(lba),lba),"Raw user data at +24");
    rejects([&]{image.read(4);},"beyond image");
    // No preload/cache: a sector rewritten after opening is observed on the next read.
    {auto s=rawSector(2);s[24]^=0xff;std::fstream f(dir/"raw.bin",std::ios::binary|std::ios::in|std::ios::out);
        f.seekp(2*2352);f.write(reinterpret_cast<const char*>(s.data()),2352);}
    require(image.read(2)[0]==static_cast<std::uint8_t>(pattern(2,0)^0xff),"Reads must hit the file on demand");
    for(auto [offset,value,text]:{std::tuple{std::size_t(1),std::uint8_t(0),"sync"},std::tuple{std::size_t(12),std::uint8_t(0x09),"address mismatch"},
                                  std::tuple{std::size_t(15),std::uint8_t(1),"not Mode 2"},std::tuple{std::size_t(18),std::uint8_t(0x28),"Form 2"}}){
        auto bad=raw;bad[2352+offset]=value;write(dir/"bad.bin",bad);
        DiscImage b(dir/"bad.bin",ImageLayout::Raw2352Mode2Form1);require(samePattern(b.read(0),0),"Neighbour sector still valid");
        rejects([&]{b.read(1);},text);
    }
    write(dir/"short.bin",std::vector<std::uint8_t>(raw.begin(),raw.end()-1));
    rejects([&]{DiscImage(dir/"short.bin",ImageLayout::Raw2352Mode2Form1);},"whole number of sectors");
    rejects([&]{DiscImage(dir/"missing.bin",ImageLayout::Cooked2048);},"cannot open");
    // Cooked 2048-byte image.
    std::vector<std::uint8_t> cooked;for(std::uint32_t lba=0;lba<3;++lba)for(std::size_t n=0;n<2048;++n)cooked.push_back(pattern(lba,n));
    write(dir/"cooked.iso",cooked);
    DiscImage iso(dir/"cooked.iso",ImageLayout::Cooked2048);
    require(iso.sectors()==3&&samePattern(iso.read(1),1)&&samePattern(iso.read(2),2),"Cooked image");
    // One file mapped at its LBA; last sector zero padded.
    std::vector<std::uint8_t> file(2048*2+100);for(std::size_t n=0;n<file.size();++n)file[n]=static_cast<std::uint8_t>(n%251);
    write(dir/"container.bin",file);
    FileAtLba mapped(dir/"container.bin",10383);
    require(mapped.firstLba()==10383&&mapped.endLba()==10386,"Mapped extent");
    const auto last=mapped.read(10385);
    bool padded=true;for(std::size_t n=0;n<2048;++n)padded=padded&&last[n]==(n<100?static_cast<std::uint8_t>((4096+n)%251):0);
    require(padded,"Partial final sector zero padded");
    require(mapped.read(10383)[5]==5&&mapped.read(10384)[0]==static_cast<std::uint8_t>(2048%251),"Mapped sector contents");
    rejects([&]{mapped.read(10382);},"outside mapped file");
    rejects([&]{mapped.read(10386);},"outside mapped file");
    write(dir/"empty.bin",{});
    rejects([&]{FileAtLba(dir/"empty.bin",0);},"empty mapped file");
    rejects([&]{FileAtLba(dir/"container.bin",449849);},"beyond 99:59:74");
    std::cout<<"CD backing: "<<checks<<" checks passed (MSF/BCD, raw Mode 2 Form 1, cooked, mapped file, on-demand reads; synthetic only)\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
