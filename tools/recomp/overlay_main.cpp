#include "overlay_unit.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
int main(int argc,char** argv){try{
    if(argc!=3)throw std::runtime_error("Usage: OverlayUnitGenerator EXTERNAL_TYPE2_IMAGE OUTPUT_CPP (PAL TITLE or LANGUAGE)");
    for(const auto& path:{std::string(argv[2]),std::string(argv[2])+".disasm.txt"})
        if(std::filesystem::weakly_canonical(argv[1])==std::filesystem::weakly_canonical(path)||
           (std::filesystem::exists(path)&&std::filesystem::equivalent(argv[1],path)))
            throw std::runtime_error("Input and output must differ");
    std::ifstream input(argv[1],std::ios::binary|std::ios::ate);
    namespace ov=moyle::detail::recomp::overlay;
    if(!input||(input.tellg()!=ov::palTitle.size&&input.tellg()!=ov::palLanguage.size))
        throw std::runtime_error("Cannot read type-2 image or unknown size (expected PAL TITLE 0x42B4 or LANGUAGE 0x42B8)");
    input.seekg(0);std::vector<std::uint8_t> image((std::istreambuf_iterator<char>(input)),{});
    const auto& identity=ov::recognize(0x80010200,image,ov::LoadPhase::InitialImage);
    const bool language=&identity==&ov::palLanguage;
    const auto program=recomp_tool::overlay_unit::build(image,identity,language?ov::palLanguageTableShift:0,
                                                        language?"PAL LANGUAGE unit":"PAL TITLE unit");
    const auto save=[](const std::string& path,const std::string& text){std::ofstream f(path,std::ios::binary);f<<text;if(!f)throw std::runtime_error("Cannot write output");};
    save(argv[2],recomp_tool::generate(program,language?"executePalLanguage":"executePalTitle",true));
    save(std::string(argv[2])+".disasm.txt",recomp_tool::disassembly(program));
    std::cout<<(language?"LANGUAGE":"TITLE")<<" unit: "<<program.instructions.size()<<" live words, 5 public entries, 4 tables"
             <<(language?" (+4 layout)":"")<<"; cull patches live; T5 GTE subset enabled\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
