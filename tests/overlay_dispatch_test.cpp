// Overlay selector + LANGUAGE layout runtime tests (synthetic images only; no proprietary input).
// The executors come from the synthetic generator output (executeSyntheticTitle / executeSyntheticLanguage); the EXE side
// is emulated exactly as the generated JAL dispatch does it: RA = continuation, then dispatchDynamic after the slot.
#include "overlay_unit_fixture.hpp"
#include "../src/overlay_dispatch.hpp"
#include <iostream>
using namespace moyle::detail::recomp;
namespace moyle::detail::recomp {
void executeSyntheticTitle(Context&,std::uint32_t,std::uint64_t);
void executeSyntheticLanguage(Context&,std::uint32_t,std::uint64_t);
}
namespace {
unsigned checks=0;
void require(bool v,const char* why){++checks;if(!v)throw std::runtime_error(why);}
template<class F> void rejects(F f,const char* text){try{f();}catch(const std::exception& e){require(std::string(e.what()).find(text)!=std::string::npos,e.what());return;}throw std::runtime_error(std::string("Expected rejection: ")+text);}
std::string titleHash,languageHash;
overlay::Metadata titleId=overlay::palTitle,languageId=overlay::palLanguage;
void selector(Context& c,std::uint32_t entry,std::uint64_t budget){
    overlay::selectAndExecute(c,entry,budget,{{&titleId,executeSyntheticTitle},{&languageId,executeSyntheticLanguage}});
}
void languageOnly(Context& c,std::uint32_t entry,std::uint64_t budget){
    overlay::selectAndExecute(c,entry,budget,{{&languageId,executeSyntheticLanguage}});
}
constexpr std::uint32_t site=0x80030000U,continuation=site+8U;
// EXE-side call as emitted for an --external-entry JAL: lookup at the JAL, RA = JAL + 8, dispatch after the slot.
void call(Context& c,const DynamicRegistry& registry,std::uint32_t entry,std::uint64_t budget=500){
    c.registry=&registry;const auto target=lookupDynamic(c,site,entry);
    c.r[31]=continuation;dispatchDynamic(c,target,site,continuation,budget);
}
DynamicRegistry registryWith(RecompFunction f){DynamicRegistry r;for(auto e:overlay::entries)r.add(e,f);return r;}
}
int main(){try{
    titleHash=overlay::fingerprint(overlay::palTitle,overlay_fixture::image());titleId.maskedSha1=titleHash.c_str();
    languageHash=overlay::fingerprint(overlay::palLanguage,overlay_fixture::languageImage());languageId.maskedSha1=languageHash.c_str();
    // Production descriptors: LANGUAGE is TITLE geometry plus one pad word, same sites/word0/patch states.
    require(overlay::palLanguage.base==overlay::palTitle.base&&overlay::palLanguage.size==0x42b8U&&overlay::palTitle.size==0x42b4U,"LANGUAGE extent");
    require(overlay::palLanguage.patchSites==overlay::palTitle.patchSites&&overlay::palLanguage.runtimeWord0==0x8006b340U&&
            overlay::palLanguage.initialPatchHigh==0x1840&&overlay::palLanguage.alternatePatchHigh==0x1c40,"LANGUAGE sites/word0/states");
    require(std::string(overlay::palLanguage.maskedSha1)=="d5ccba9cc741fc82e3e87360de8aad18d391be87","LANGUAGE digest");
    const std::uint32_t languageBases[4]={0x80012b58U,0x80012ba8U,0x80012bc8U,0x80012c18U};
    for(unsigned n=0;n<4;++n)require(overlay::tables[n].base+overlay::palLanguageTableShift==languageBases[n],"LANGUAGE table bases are the +4 layout");
    require(overlay::publicEntry(0x8001020cU)&&!overlay::publicEntry(0x80010208U)&&overlay::entries.size()==5,"five public entries");
    rejects([&]{overlay::recognize(overlay::palTitle.base,std::vector<std::uint8_t>(0x42bcU),overlay::LoadPhase::InitialImage);},"unknown size");
    rejects([&]{overlay::fingerprint(overlay::palLanguage,overlay_fixture::image());},"unknown size");
    rejects([&]{overlay::recognize(overlay::palTitle.base,overlay_fixture::languageImage(),overlay::LoadPhase::InitialImage);},"unknown masked SHA-1 for PAL LANGUAGE");
    const auto both=registryWith(selector);const auto languageRegistry=registryWith(languageOnly);
    // 1. Every LANGUAGE table dispatches at its +4 base through the selector, returns to the EXE continuation, and a load
    //    in the overlay's jr-ra slot stays pending for the caller.
    for(auto t:overlay::tables){
        Context c;overlay_fixture::install(c,true);c.r[4]=overlay_fixture::dispatch(t);
        c.r[5]=t.base+overlay::palLanguageTableShift+4*t.minIndex;c.r[6]=0x80150000;c.r[9]=7;c.ram.write(c.r[6],0xabcdef01,4);
        call(c,both,0x80010204);
        require(c.pc==continuation&&c.r[31]==continuation,"LANGUAGE: returns to the EXE continuation");
        require(c.r[20]==1&&c.r[21]==1&&c.r[22]==1,"LANGUAGE: overlay delay slots exactly once");
        require(c.r[9]==7&&c.loadRegister==9&&c.loadValue==0xabcdef01,"LANGUAGE: pending load survives the return");
        require(c.dynamicCalls==1&&c.dynamicTrace.size()==1&&c.dynamicTrace[0].site==site&&c.dynamicTrace[0].target==0x80010204U&&
                c.dynamicTrace[0].returnAddress==continuation,"LANGUAGE: one registry dispatch");
        require(c.tableTrace.size()==1&&c.tableTrace[0].index==t.minIndex,"LANGUAGE: table index at the shifted base");
    }
    // 2. The TITLE base inside a LANGUAGE image is out of bounds (it is the previous table's tail / the pad word).
    for(auto t:overlay::tables){
        Context c;overlay_fixture::install(c,true);c.r[4]=overlay_fixture::dispatch(t);c.r[5]=t.base+4*t.minIndex;
        rejects([&]{call(c,both,0x80010204);},"index out of bounds");
    }
    // 3. Selection by live identity: a TITLE image runs the TITLE executor through the same registry.
    {   Context c;overlay_fixture::install(c);c.r[4]=0x80012060;call(c,both,0x80010258);
        require(c.pc==continuation&&c.r[15]==0x8001206c&&c.r[27]==1&&c.r[25]==1,"TITLE image selects the TITLE executor");
        const auto& b=overlay::selectBackend(c,0x80010258,{{&titleId,executeSyntheticTitle},{&languageId,executeSyntheticLanguage}});
        require(b.execute==executeSyntheticTitle,"TITLE backend selected");
        Context l;overlay_fixture::install(l,true);
        require(overlay::selectBackend(l,0x80010258,{{&titleId,executeSyntheticTitle},{&languageId,executeSyntheticLanguage}}).execute==executeSyntheticLanguage,"LANGUAGE backend selected");
        rejects([&]{call(c,languageRegistry,0x80010258);},"matches no compiled descriptor"); }
    // 4. Unknown overlay: any non-masked byte change (here one table word) is fatal before any guest instruction runs.
    {   Context c;overlay_fixture::install(c,true);c.ram.write(0x80012b58U,0x80012004U,4);const auto steps=c.steps;c.r[4]=0x80012060;
        rejects([&]{call(c,both,0x80010204);},"matches no compiled descriptor");require(c.steps==steps,"unknown overlay: nothing executed"); }
    // 5. Runtime word0 and patch-state rules are the executor's, after selection.
    {   Context c;overlay_fixture::install(c,true);c.ram.write(0x80010200U,0,4);c.r[4]=0x80012060;
        rejects([&]{call(c,both,0x80010204);},"runtime word0"); }
    const auto& sites=overlay::palLanguage.patchSites;
    {   Context c;overlay_fixture::install(c,true);c.ram.write(sites[0]+2,0x1c40,2);c.r[4]=0x80012060;
        rejects([&]{call(c,both,0x80010204);},"mixed runtime patch state"); }
    {   Context c;overlay_fixture::install(c,true);c.ram.write(sites[0]+2,0x1c40,2);c.r[4]=0x1840; // setter entry tolerates the mix
        call(c,both,overlay::cullSetter);
        bool uniform=true;for(auto s:sites)uniform=uniform&&c.ram.read(s+2,2)==0x1840;
        require(uniform&&c.pc==continuation,"setter entry: transition state accepted, uniform afterwards, returns to the EXE"); }
    {   Context c;overlay_fixture::install(c,true);c.ram.write(sites[3]+2,0x1234,2);c.r[4]=0x1840;
        rejects([&]{call(c,both,overlay::cullSetter);},"runtime patch high half"); }
    // 6. Entry rules: only the five public entries (any RAM alias); a pending redirect is refused before selection.
    {   Context c;overlay_fixture::install(c,true);c.r[4]=0x80012060;
        rejects([&]{selector(c,0x80010208U,500);},"not one of the five public overlay entries");
        rejects([&]{call(c,both,0x80010210U);},"unregistered recomp target");
        c.redirectPending=true;rejects([&]{selector(c,0x80010204U,500);},"probe redirect is pending");c.redirectPending=false;
        call(c,both,0xa0010204U);require(c.pc==continuation&&c.r[15]==0x8001206c,"KSEG1 alias of a public entry"); }
    // 7. Ambiguous descriptor sets are refused.
    {   Context c;overlay_fixture::install(c,true);
        rejects([&]{overlay::selectBackend(c,0x80010204,{{&languageId,executeSyntheticLanguage},{&languageId,executeSyntheticLanguage}});},"more than one"); }
    std::cout<<"Overlay dispatch: "<<checks<<" checks passed (selector, LANGUAGE +4 layout, EXE continuation, synthetic only)\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
