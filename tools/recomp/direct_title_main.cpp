// Opt-in Direct TITLE unit generator (Phase 3). Discovery + Phase 2C closure + the Phase 3 opt-ins, then C++ emission of
// every resolved extent behind the matching runtime guards (tools/recomp/closure_emit.hpp). The EXE is read-only external
// input; the generated C++ is proprietary-derived and must only be written under build/ (never committed).
#include "closure_emit.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

namespace {
std::uint32_t number(const char* value) {
    const std::string s=value;std::size_t used=0;
    if(s.empty()||s[0]=='-')throw std::runtime_error("Invalid number");
    auto n=std::stoull(s,&used,0);
    if(used!=s.size()||n>0xffffffffULL)throw std::runtime_error("Invalid 32-bit number");
    return static_cast<std::uint32_t>(n);
}
void save(const std::string& path,const std::string& content){std::ofstream out(path,std::ios::binary);out<<content;if(!out)throw std::runtime_error("Output write failed");}
}
int main(int argc,char** argv){
    try{
        if(argc<4)throw std::runtime_error("Usage: DirectTitleGenerator EXE OUTPUT_PREFIX --seed ENTRY CONFIDENCE MAX_WORDS ... --text BEGIN END "
                                           "[--derived-words N] [--function NAME] [--noreturn ENTRY]... [--callback-set SITE T1,T2,... EVIDENCE]... [--callback-empty SITE CELL EVIDENCE]... [--table-host SITE BASE COUNT EVIDENCE]... [--dead-gap ENTRY BEGIN END]... [--external-entry ENTRY EVIDENCE]... [--shared-delay-slots] [--probe] [--boot-bios] [--boot-isa] [--boot-gte] [--boot-card] [--no-trap-break] [--no-bios-hle] [--no-callbacks]");
        std::vector<recomp_tool::Seed> seeds;recomp_tool::closure::TextRange text;std::uint32_t derivedWords=1024;
        recomp_tool::closure::Extras extras;extras.trapBreak=extras.biosHle=extras.callbacks=true;
        std::string name="executeDirectTitle";bool probe=false;
        for(int i=3;i<argc;){const std::string option=argv[i++];
            if(option=="--text"&&i+1<argc){text.begin=number(argv[i]);text.end=number(argv[i+1]);i+=2;}
            else if(option=="--derived-words"&&i<argc){derivedWords=number(argv[i]);i+=1;}
            else if(option=="--seed"&&i+2<argc){seeds.push_back({number(argv[i]),argv[i+1],number(argv[i+2])});i+=3;}
            else if(option=="--function"&&i<argc){name=argv[i];i+=1;}
            else if(option=="--probe")probe=true;
            else if(option=="--callback-set"&&i+2<argc){
                recomp_tool::closure::PinnedSet set;const auto site=number(argv[i]);std::string list=argv[i+1];set.evidence=argv[i+2];
                for(std::size_t at=0;at<list.size();){const auto comma=list.find(',',at);const auto end=comma==std::string::npos?list.size():comma;
                    set.targets.push_back(number(list.substr(at,end-at).c_str()));at=end+1;}
                if(!extras.pinnedSets.emplace(site,set).second)throw std::runtime_error("Duplicate --callback-set site");
                i+=3;}
            else if(option=="--callback-empty"&&i+2<argc){
                recomp_tool::closure::PinnedSet set;const auto site=number(argv[i]);set.targets.push_back(number(argv[i+1]));set.evidence=argv[i+2];
                if(!extras.pinnedEmpty.emplace(site,set).second)throw std::runtime_error("Duplicate --callback-empty site");
                i+=3;}
            else if(option=="--table-host"&&i+3<argc){
                const auto site=number(argv[i]);const auto base=number(argv[i+1]);const auto count=number(argv[i+2]);
                if(!extras.hostTableEvidence.emplace(site,argv[i+3]).second)throw std::runtime_error("Duplicate --table-host site");
                extras.hostTables.push_back({site,base,count});i+=4;}
            else if(option=="--dead-gap"&&i+2<argc){
                extras.deadGaps[number(argv[i])].push_back({number(argv[i+1]),number(argv[i+2])});i+=3;}
            else if(option=="--external-entry"&&i+1<argc){
                if(!extras.externalEntries.emplace(number(argv[i]),argv[i+1]).second)throw std::runtime_error("Duplicate --external-entry");
                i+=2;}
            else if(option=="--noreturn"&&i<argc){extras.noReturn.insert(number(argv[i]));i+=1;}
            else if(option=="--no-trap-break")extras.trapBreak=false;
            else if(option=="--boot-bios")extras.bootBios=true;
            else if(option=="--boot-isa")extras.bootIsa=true;
            else if(option=="--boot-gte")extras.bootGte=true;
            else if(option=="--halt-loops")extras.haltLoops=true;
            else if(option=="--shared-delay-slots")extras.sharedDelaySlots=true;
            else if(option=="--boot-card")extras.bootCard=true;
            else if(option=="--no-bios-hle")extras.biosHle=false;
            else if(option=="--no-callbacks")extras.callbacks=false;
            else throw std::runtime_error("Invalid generator arguments");
        }
        if(extras.bootCard&&!extras.bootBios)throw std::runtime_error("--boot-card requires --boot-bios");
        if(text.begin==0&&text.end==0)throw std::runtime_error("--text BEGIN END is required");
        for(const auto& suffix:{".cpp",".json",".discovery.json",".map"}){const auto output=std::string(argv[2])+suffix;
            if(std::filesystem::weakly_canonical(argv[1])==std::filesystem::weakly_canonical(output)||
                (std::filesystem::exists(output)&&std::filesystem::equivalent(argv[1],output)))throw std::runtime_error("Input/output alias");
        }
        std::ifstream input(argv[1],std::ios::binary);if(!input)throw std::runtime_error("Cannot read external EXE");
        const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
        const auto closed=recomp_tool::closure::closureDiscover(bytes,seeds,{},text,derivedWords,extras);
        const auto unit=recomp_tool::closure_emit::buildUnit(bytes,closed,"verified external PS-X EXE closure extents (Direct TITLE)",probe);
        const auto source=recomp_tool::generate(unit.program,name,true);
        save(std::string(argv[2])+".cpp",source);
        save(std::string(argv[2])+".json",recomp_tool::closure_emit::reportJson(unit.report,closed.discovery));
        save(std::string(argv[2])+".map",recomp_tool::closure_emit::functionMap(unit.report,closed.discovery));
        save(std::string(argv[2])+".discovery.json",recomp_tool::discoveryJson(closed.discovery));
        const auto& r=unit.report;
        std::cout<<"Direct TITLE unit: "<<r.functions<<" generated functions, "<<r.instructions<<" instructions, "<<r.stubs<<" boundary stubs\n"
                 <<"Closure call sites: "<<(r.libgpuSlots+r.cellGuarded+r.emptyRegistries+r.setGuarded+r.ringRegistries)<<" (libgpu slots "<<r.libgpuSlots
                 <<", cell "<<r.cellGuarded<<", empty registry "<<r.emptyRegistries<<", set "<<r.setGuarded<<", ring registry "<<r.ringRegistries<<")\n"
                 <<"Table-switch sites: "<<r.tableSwitches<<"; BIOS thunks: "<<r.biosThunks<<"; BREAK traps: "<<r.breakTraps<<"; return guards: "<<r.returnSites<<"\n";
        if(r.sharedSlots)std::cout<<"Shared delay slots (direct-branch target and slot): "<<r.sharedSlots<<"\n";
        if(r.externalCalls)std::cout<<"External-entry call sites (registry dispatch): "<<r.externalCalls<<"\n";
        for(const auto& e:r.notGenerated)std::cout<<"Not generated: "<<recomp_tool::hex(e.first)<<": "<<e.second<<"\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
