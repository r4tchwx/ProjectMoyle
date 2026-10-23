#include "../tools/recomp/overlay_unit.hpp"
#include "overlay_unit_fixture.hpp"
#include <fstream>
#include <iostream>
namespace ov=moyle::detail::recomp::overlay;
static unsigned checks=0;
void require(bool v,const char* why){++checks;if(!v)throw std::runtime_error(why);}
template<class F> void rejects(F f,const char* text){try{f();}catch(const std::exception& e){require(std::string(e.what()).find(text)!=std::string::npos,e.what());return;}throw std::runtime_error("Expected rejection");}
recomp_tool::Program synthetic(const std::vector<std::uint8_t>& image){
    const auto hash=ov::fingerprint(ov::palTitle,image);auto identity=ov::palTitle;identity.maskedSha1=hash.c_str();
    return recomp_tool::overlay_unit::build(image,identity);
}
// LANGUAGE layout: same synthetic program with the +4 table shift (palLanguage geometry, synthetic digest).
recomp_tool::Program syntheticLanguage(const std::vector<std::uint8_t>& image,std::uint32_t shift=ov::palLanguageTableShift){
    const auto hash=ov::fingerprint(ov::palLanguage,image);auto identity=ov::palLanguage;identity.maskedSha1=hash.c_str();
    return recomp_tool::overlay_unit::build(image,identity,shift,"Synthetic LANGUAGE unit");
}
void languageLayout(const recomp_tool::Program& title,std::string& output){
    const auto image=overlay_fixture::languageImage();
    require(image.size()==ov::palLanguage.size&&ov::palLanguage.size==ov::palTitle.size+ov::palLanguageTableShift,"LANGUAGE geometry is TITLE plus one pad word");
    const auto p=syntheticLanguage(image);
    const auto text=recomp_tool::generate(p,"executeSyntheticLanguage",true);
    require(text==recomp_tool::generate(syntheticLanguage(image),"executeSyntheticLanguage",true),"Nondeterministic LANGUAGE unit");
    require(p.regions.size()==5&&p.instructions.size()==title.instructions.size(),"LANGUAGE: same entries and live code");
    bool same=true;for(const auto& [pc,i]:title.instructions)same=same&&p.instructions.count(pc)&&p.instructions.at(pc).bits==i.bits;
    require(same,"LANGUAGE: identical synthetic code words");
    for(unsigned n=0;n<ov::tables.size();++n){
        const auto t=ov::tables[n];
        require(text.find("const StaticTable overlayTable"+std::to_string(n)+"{"+recomp_tool::hex(t.base+4)+"U,")!=std::string::npos,"LANGUAGE table base is +4");
        require(text.find("const StaticTable overlayTable"+std::to_string(n)+"{"+recomp_tool::hex(t.base)+"U,")==std::string::npos,"LANGUAGE table base is not the TITLE base");
        require(text.find("overlayTable"+std::to_string(n)+","+std::to_string(n)+"U,pc,a+0x00000000U,4U)")!=std::string::npos,"LANGUAGE checked load carries the layout");
        require(p.instructions.at(t.site).callKind==recomp_tool::CallKind::StaticTableTailJump,"LANGUAGE table transfer kind");
    }
    for(auto pc:{0x80012b54U,0x80012b58U,0x800144b4U})require(!p.instructions.count(pc),"LANGUAGE pad/table/data not emitted");
    require(text.find("\"Synthetic LANGUAGE unit\",0x80010200U,0x42b8U,")!=std::string::npos,"LANGUAGE identity literal");
    // Geometry: only TITLE/shift 0 and LANGUAGE/shift 4.
    rejects([&]{syntheticLanguage(image,0);},"Incompatible overlay unit geometry");
    rejects([&]{syntheticLanguage(image,8);},"Incompatible overlay unit geometry");
    rejects([&]{const auto title=overlay_fixture::image();const auto hash=ov::fingerprint(ov::palTitle,title);auto id=ov::palTitle;id.maskedSha1=hash.c_str();
        recomp_tool::overlay_unit::build(title,id,ov::palLanguageTableShift);},"Incompatible overlay unit geometry");
    rejects([&]{recomp_tool::overlay_unit::build(image);},"unknown size");             // TITLE descriptor never accepts 0x42B8 bytes
    rejects([&]{recomp_tool::overlay_unit::build(image,ov::palLanguage,ov::palLanguageTableShift);},"SHA-1"); // production LANGUAGE digest
    // A table entry read at the TITLE position would be the pad word: generation must use the shifted base.
    auto bad=image;overlay_fixture::put(bad,ov::tables[0].base+4,0x80012b54U);
    rejects([&]{syntheticLanguage(bad);},"outside live code");
    output+=text;
}
int main(int argc,char** argv){try{
    auto image=overlay_fixture::image();const auto p=synthetic(image);
    auto output=recomp_tool::generate(p,"executeSyntheticTitle",true);
    require(output==recomp_tool::generate(synthetic(image),"executeSyntheticTitle",true),"Nondeterministic unit");
    require(p.regions.size()==5,"Public entries");
    for(auto pc:{0x80010200U,0x80010930U,0x80010ba0U,0x80012aa4U,0x80012aacU,0x80012b54U,0x800144b0U})
        require(!p.instructions.count(pc),"Data/dead code emitted");
    for(auto t:ov::tables)require(p.instructions.at(t.site).callKind==recomp_tool::CallKind::StaticTableTailJump,"Table transfer kind");
    for(auto target:{0x80012b54U,0x80010930U,0x80012004U+4,0x80012001U}){
        auto bad=image;overlay_fixture::put(bad,ov::tables[0].base,target);
        rejects([&]{synthetic(bad);},target&3?"aligned":"outside live code");
    }
    auto bad=image;overlay_fixture::put(bad,ov::tables[0].load,0);
    rejects([&]{synthetic(bad);},"verified retired table LW");
    // B/D shape: LW in a branch slot whose two paths join before the JR.
    const auto jtB=ov::tables[1];
    bad=image;overlay_fixture::put(bad,jtB.load+8,overlay_fixture::imm(9,8,8,4));
    rejects([&]{synthetic(bad);},"JR source redefined");
    bad=image;overlay_fixture::put(bad,jtB.load+4,overlay_fixture::imm(15,0,8,0x8001));
    rejects([&]{synthetic(bad);},"JR source redefined"); // the not-taken path is verified too
    bad=image;overlay_fixture::put(bad,jtB.load+8,(3U<<26)|((0x80012000U>>2)&0x3ffffff));
    rejects([&]{synthetic(bad);},"call or indirect transfer");
    bad=image;overlay_fixture::put(bad,0x80012020,(2U<<26)|(((jtB.load+12)>>2)&0x3ffffff));overlay_fixture::put(bad,0x80012024,0);
    rejects([&]{synthetic(bad);},"enters dispatch region");
    bad=image;overlay_fixture::put(bad,0x80012020,(2U<<26)|((0x80012b54U>>2)&0x3ffffff));overlay_fixture::put(bad,0x80012024,0);
    rejects([&]{synthetic(bad);},"outside live code");
    bad=image;overlay_fixture::put(bad,0x80012020,(2U<<26)|((0x80010930U>>2)&0x3ffffff));overlay_fixture::put(bad,0x80012024,0);
    rejects([&]{synthetic(bad);},"dead range");
    // RingSpaceWait body is emitted; only [poll point, poll end) traps. BREAK is diagnostic.
    for(auto pc=ov::ringSpaceWait;pc<ov::ringSpacePollEnd+8;pc+=4){
        const bool spin=pc>=ov::ringSpacePollPoint&&pc<ov::ringSpacePollEnd;
        require((p.instructions.at(pc).code.find("poll point 0x80012a04")!=std::string::npos)==spin,"RingSpaceWait trap extent");
    }
    require(p.instructions.at(ov::breakTrap).code.find("overlay::breakError")!=std::string::npos,"BREAK diagnostic emission");
    // T4: setter emitted as ordinary code, sites as RAM-read branches; no T4 trap remains.
    for(auto pc=ov::cullSetter;pc<ov::cullSetter+32;pc+=4)require(p.instructions.at(pc).code.find("throw")==std::string::npos,"Setter must execute");
    for(auto site:ov::palTitle.patchSites){const auto& i=p.instructions.at(site);
        require(i.control&&i.direct&&i.target==site+16&&i.code.find("overlay::patchedBranch(c,pc,a)")!=std::string::npos,"Patched branch emission");}
    require(output.find("requires T4")==std::string::npos&&output.find("patch semantics")==std::string::npos,"Residual T4 trap");
    require(output.find("canonicalCodeAddress(entry)==overlay::cullSetter")!=std::string::npos,"Setter entry validation phase");
    for(unsigned n=0;n<ov::tables.size();++n)
        require(output.find("overlayTable"+std::to_string(n)+","+std::to_string(n)+"U,pc,")!=std::string::npos,"Table id in checked load");
    rejects([&]{recomp_tool::overlay_unit::build(image);},"SHA-1"); // production never accepts synthetic identity
    languageLayout(p,output); // the output file carries executeSyntheticTitle and executeSyntheticLanguage
    if(argc!=2)throw std::runtime_error("Usage: OverlayUnitGeneratorTest output.cpp");
    std::ofstream file(argv[1]);file<<output;if(!file)throw std::runtime_error("Cannot write generated test");
    std::cout<<"Overlay unit generator: "<<checks<<" checks passed; deterministic synthetic output\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
