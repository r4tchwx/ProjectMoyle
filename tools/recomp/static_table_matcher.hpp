#pragma once
#include "static_tables.hpp"
#include "discovery.hpp"
#include <optional>

namespace recomp_tool::table_v2 {
enum class Bound { None, GuestBound, HostTrap };
inline const char* boundName(Bound b){return b==Bound::GuestBound?"GuestBound":b==Bound::HostTrap?"HostTrap":"None";}
struct Domain {std::uint32_t begin,end;}; // Reviewed function ownership, exclusive end.
struct HostPolicy {std::uint32_t site,base,count;};
struct Descriptor {
    std::uint32_t site=0,begin=0,load=0,base=0,count=0,indexPc=0,indexRegister=0;
    std::uint32_t branch=0,defaultTarget=0,indexAddress=0;
    Domain function{};Bound bound=Bound::None;bool call=false;
    std::vector<std::uint32_t> targets;
};
struct Outcome {std::optional<Descriptor> descriptor;std::string reason;};
struct Constant {
    enum Kind {Unknown,Literal,MemoryWord} kind=Unknown;std::uint32_t value=0;
    bool operator==(const Constant& b)const{return kind==b.kind&&value==b.value;}
};
struct State {std::array<Constant,32> r{},pending{};std::array<bool,32> delayed{};};
inline std::uint32_t immediate(std::uint32_t w){return (w&0x8000)?w|0xffff0000U:w&65535;}
inline void retire(State& s){for(unsigned n=1;n<32;++n)if(s.delayed[n])s.r[n]=s.pending[n];s.pending={};s.delayed={};}
inline void step(State& s,std::uint32_t w){
    const auto op=w>>26,rs=(w>>21)&31,rt=(w>>16)&31,rd=(w>>11)&31,fn=w&63,sh=(w>>6)&31;
    const auto a=s.r[rs],b=s.r[rt];retire(s);Constant v;unsigned dest=0;
    if(op==15){dest=rt;v={Constant::Literal,(w&65535)<<16};}
    else if(op==9||op==8||op==13){dest=rt;if(a.kind==Constant::Literal)v={Constant::Literal,op==13?a.value|(w&65535):a.value+immediate(w)};}
    else if(op>=32&&op<=38){if(op==35&&a.kind==Constant::Literal)v={Constant::MemoryWord,a.value+immediate(w)};s.pending[rt]=v;s.delayed[rt]=true;}
    else if(op==0){
        if(fn==8||fn==9){if(fn==9)dest=rd;}
        else if(fn==24||fn==25||fn==26||fn==27||fn==17||fn==19){} // HI/LO writes only.
        else {dest=rd;
            if(fn==0&&b.kind==Constant::Literal)v={Constant::Literal,b.value<<sh};
            else if((fn==32||fn==33||fn==37)&&b.kind==Constant::Literal&&b.value==0)v=a;
            else if((fn==32||fn==33||fn==37)&&a.kind==Constant::Literal&&a.value==0)v=b;
            else if((fn==32||fn==33)&&a.kind==Constant::Literal&&b.kind==Constant::Literal)v={Constant::Literal,a.value+b.value};
        }
    }else if(op>=40&&op<=63){} // Stores cannot establish register constants.
    else if(op==1||(op>=4&&op<=7)||op==2){}
    else if(op==3)dest=31;
    else if(op>=16&&op<=19){if(rs<=2)dest=rt;}
    else dest=rt;
    if(dest)s.r[dest]=v;s.r[0]={Constant::Literal,0};s.delayed[0]=false;
}
using Edges=std::map<std::uint32_t,std::set<std::uint32_t>>;
using States=std::map<std::uint32_t,State>;
// Join by value, not by definition address. Calls use the ordinary MIPS ABI:
// caller-saved registers and pending loads are invalidated, s0-s7/gp/sp/fp kept.
inline States reaching(const std::vector<std::uint8_t>& bytes,Domain domain,const Edges& indirect={}){
    States states;std::deque<std::uint32_t> queue;
    auto valid=[&](std::uint32_t pc){return pc>=domain.begin&&pc<domain.end&&!(pc&3);};
    auto merge=[&](std::uint32_t pc,State s){
        if(!valid(pc))return;s.r[0]={Constant::Literal,0};
        auto [it,fresh]=states.emplace(pc,s);bool changed=fresh;
        if(!fresh)for(unsigned n=1;n<32;++n){auto& old=it->second;
            auto join=[&](Constant& x,Constant y){if(!(x==y)&&x.kind!=Constant::Unknown){x={};changed=true;}};
            join(old.r[n],s.r[n]);
            if(old.delayed[n]!=s.delayed[n]){if(!old.delayed[n]||old.pending[n].kind!=Constant::Unknown)changed=true;old.delayed[n]=true;old.pending[n]={};}
            else join(old.pending[n],s.pending[n]);
        }
        if(changed)queue.push_back(pc);
    };
    merge(domain.begin,{});
    while(!queue.empty()){
        auto pc=queue.front();queue.pop_front();auto s=states.at(pc);const auto w=imageWord(bytes,pc),op=w>>26,fn=w&63;
        if(!controlWord(w)){step(s,w);merge(pc+4,s);continue;}
        if(!valid(pc+4))continue;
        const auto slot=imageWord(bytes,pc+4);if(controlWord(slot))continue;
        const bool call=op==3||(op==0&&fn==9);
        retire(s);if(call)s.r[31]={Constant::Literal,pc+8};
        // Slot state is informational: do not queue it as an independent block.
        step(s,slot);
        if(call){for(unsigned n=1;n<32;++n)if(n<16||n==24||n==25||n==26||n==27||n==31)s.r[n]={};s.pending={};s.delayed={};merge(pc+8,s);}
        else if(op==0){auto it=indirect.find(pc);if(it!=indirect.end())for(auto target:it->second)merge(target,s);}
        else if(op==2)merge(((pc+4)&0xf0000000U)|((w&0x3ffffffU)<<2),s);
        else {merge(pc+4+immediate(w)*4U,s);merge(pc+8,s);}
    }
    return states;
}
inline std::set<std::uint32_t> delaySlots(const std::vector<std::uint8_t>& bytes,Domain text){
    std::set<std::uint32_t> slots;
    for(auto pc=text.begin;pc<text.end;pc+=4)if(controlWord(imageWord(bytes,pc)))slots.insert(pc+4);
    return slots;
}
inline void validateTargets(const std::vector<std::uint8_t>& bytes,Descriptor& d,Domain text,
                            const std::set<std::uint32_t>& slots,const std::set<std::uint32_t>& entries){
    if(!d.count||d.count>65536||std::uint64_t(d.base)+4ULL*d.count>0x80200000ULL)throw std::runtime_error("invalid table extent");
    d.targets.clear();
    for(unsigned n=0;n<d.count;++n){auto raw=imageWord(bytes,d.base+4*n),pc=canonicalCodeAddress(raw);
        if(pc<text.begin||pc>=text.end)throw std::runtime_error("target outside text");
        if(slots.count(pc))throw std::runtime_error("target in delay slot");
        if(d.call){if(!entries.count(pc))throw std::runtime_error("target is not a certified function entry");}
        else if(pc<d.function.begin||pc>=d.function.end)throw std::runtime_error("switch target outside owning function");
        imageWord(bytes,pc);d.targets.push_back(raw);
    }
}
inline Outcome match(const std::vector<std::uint8_t>& bytes,Domain domain,std::uint32_t site,
                     const States& constants,Domain text,const std::set<std::uint32_t>& slots,
                     const std::set<std::uint32_t>& entries,const std::optional<HostPolicy>& host={}){
    try{
        if(site<domain.begin||site+4>=domain.end||slots.count(site))return {{},"site outside function or in delay slot"};
        const auto transfer=imageWord(bytes,site);const bool call=(transfer&0xfc1fffffU)==0x0000f809U;
        if(!call&&((transfer&0xfc1fffffU)!=8||((transfer>>21)&31)==31))return {{},"not a table transfer candidate"};
        std::uint32_t start=0;
        // Only a nearby dominating unsigned bound, or explicit HostTrap policy.
        for(auto pc=site;pc>=domain.begin+4&&site-pc<64;){pc-=4;auto w=imageWord(bytes,pc);
            if((w>>26)==11){start=pc;break;}
            if(host&&(w&0xffe007ffU)==0x00000080U){start=pc;break;}
        }
        if(!start)return {{},"no recognized bound; no HostTrap policy"};
        // No alternate direct edge may bypass the bound/index capture. Treat
        // even unreachable syntactic edges conservatively rather than guessing.
        for(auto pc=domain.begin;pc<domain.end;pc+=4){auto w=imageWord(bytes,pc),op=w>>26;std::uint32_t target=0;
            if(op==2||op==3)target=((pc+4)&0xf0000000U)|((w&0x3ffffffU)<<2);
            else if(op==1||(op>=4&&op<=7))target=pc+4+immediate(w)*4U;
            if(target>start&&target<=site+4)return {{},"control edge bypasses bound/index provenance"};
        }
        auto incoming=constants.find(start);if(incoming==constants.end())return {{},"bound/index not reachable from function entry"};
        Descriptor d;d.site=site;d.begin=start;d.function=domain;d.call=call;d.indexPc=start;
        d.bound=host?Bound::HostTrap:Bound::GuestBound;d.count=host?host->count:(imageWord(bytes,start)&65535);
        d.indexRegister=host?((imageWord(bytes,start)>>16)&31):((imageWord(bytes,start)>>21)&31);
        if(!d.count)return {{},"zero bound"};
        const auto source=incoming->second.r[d.indexRegister];if(source.kind==Constant::MemoryWord)d.indexAddress=source.value;
        enum Kind {Unknown,Literal,Index,Address,Target,Predicate};
        struct Value {Kind kind=Unknown;std::uint32_t value=0,scale=0;};
        std::array<Value,32> regs{};for(unsigned n=0;n<32;++n)if(incoming->second.r[n].kind==Constant::Literal)regs[n]={Literal,incoming->second.r[n].value,0};
        regs[d.indexRegister]={Index,0,1};regs[0]={Literal,0,0};
        std::array<Value,32> delayed{};auto pending=incoming->second.delayed;
        for(unsigned n=1;n<32;++n)if(incoming->second.pending[n].kind==Constant::Literal)delayed[n]={Literal,incoming->second.pending[n].value,0};
        bool sawBound=false;
        for(auto pc=start;pc<=site;pc+=4){
            auto w=imageWord(bytes,pc),op=w>>26,rs=(w>>21)&31,rt=(w>>16)&31,rd=(w>>11)&31,fn=w&63,sh=(w>>6)&31;
            auto a=regs[rs],b=regs[rt];for(unsigned n=1;n<32;++n)if(pending[n])regs[n]=delayed[n];pending={};delayed={};
            if(pc==site){if(a.kind!=Target)return {{},"target provenance lost or ambiguous base"};d.base=canonicalCodeAddress(a.value);break;}
            if(op==11&&pc==start&&!host){if(a.kind!=Index)return {{},"bound has no index"};regs[rt]={Predicate,d.count,0};}
            else if(op==4&&rt==0&&a.kind==Predicate&&!sawBound){
                d.branch=pc;d.defaultTarget=pc+4+immediate(w)*4U;
                if(d.defaultTarget<=site+4&&d.defaultTarget>=start)return {{},"default enters table chain"};
                if(d.defaultTarget<domain.begin||d.defaultTarget>=domain.end||slots.count(d.defaultTarget))return {{},"default outside function or in slot"};
                sawBound=true; // Condition is captured now, before the following slot.
            }else if(controlWord(w))return {{},"unrecognized branch in table chain"};
            else if(op==15)regs[rt]={Literal,(w&65535)<<16,0};
            else if(op==9){if(a.kind==Literal)regs[rt]={Literal,a.value+immediate(w),0};else regs[rt]={};}
            else if(op==0&&fn==0){
                if(sh==2&&a.kind==Literal&&a.value==0&&b.kind==Index)regs[rd]={Address,0,4};
                else if(w==0){}else regs[rd]={};
            }else if(op==0&&(fn==32||fn==33)){
                if(a.kind==Literal&&b.kind==Address)regs[rd]={Address,a.value+b.value,b.scale};
                else if(b.kind==Literal&&a.kind==Address)regs[rd]={Address,b.value+a.value,a.scale};
                else if(a.kind==Literal&&b.kind==Literal)regs[rd]={Literal,a.value+b.value,0};
                else regs[rd]={};
            }else if(op==35&&a.kind==Address&&a.scale==4){pending[rt]=true;delayed[rt]={Target,a.value+immediate(w),0};d.load=pc;}
            else if(op>=40&&op<=43){}else {if(op==0)regs[rd]={};else regs[rt]={};}
            regs[0]={Literal,0,0};
        }
        if(!d.load||(!host&&!sawBound))return {{},"GuestBound required but pattern absent"};
        if(host&&(host->site!=site||canonicalCodeAddress(host->base)!=d.base))return {{},"HostTrap table mismatch"};
        if(controlWord(imageWord(bytes,site+4)))return {{},"control in transfer delay slot"};
        validateTargets(bytes,d,text,slots,entries);return {d,{}};
    }catch(const std::exception& e){return {{},e.what()};}
}
struct Census {std::map<std::uint32_t,Descriptor> resolved;std::map<std::uint32_t,std::string> unresolved;};
inline Census discoverTables(const std::vector<std::uint8_t>& bytes,const std::vector<Domain>& functions,
                            Domain text,const std::set<std::uint32_t>& entries,const std::vector<HostPolicy>& policies={}){
    const auto validDomain=[&](Domain d){return d.begin<d.end&&!(d.begin&3)&&!(d.end&3)&&d.begin>=text.begin&&d.end<=text.end;};
    if(!validDomain(text))throw std::runtime_error("Invalid text domain");
    imageWord(bytes,text.begin);imageWord(bytes,text.end-4);
    for(auto d:functions)if(!validDomain(d))throw std::runtime_error("Invalid function domain");
    Census result;const auto slots=delaySlots(bytes,text);
    for(auto domain:functions){
        Edges edges;std::map<std::uint32_t,Descriptor> resolved;
        for(unsigned pass=0;pass<64;++pass){
            auto constants=reaching(bytes,domain,edges);bool changed=false;resolved.clear();
            for(auto pc=domain.begin;pc<domain.end;pc+=4){auto w=imageWord(bytes,pc);
                if((w>>26)!=0||((w&63)!=8&&(w&63)!=9)||((w>>21)&31)==31)continue;
                std::optional<HostPolicy> host;for(auto policy:policies)if(policy.site==pc)host=policy;
                auto r=match(bytes,domain,pc,constants,text,slots,entries,host);
                if(r.descriptor){resolved.emplace(pc,*r.descriptor);if(!r.descriptor->call)for(auto t:r.descriptor->targets)changed|=edges[pc].insert(canonicalCodeAddress(t)).second;}
                else result.unresolved[pc]=r.reason;
            }
            if(!changed)break;
            if(pass==63)throw std::runtime_error("Table CFG did not converge");
        }
        for(auto pair:resolved){bool bypass=false;
            for(const auto& edge:edges)for(auto target:edge.second)if(target>pair.second.begin&&target<=pair.second.site+4)bypass=true;
            if(bypass)result.unresolved[pair.first]="table edge bypasses bound/index provenance";
            else{result.resolved.emplace(pair);result.unresolved.erase(pair.first);}
        }
    }
    return result;
}
inline std::string json(const Census& c){
    std::ostringstream o;o<<"{\"schema\":2,\"sites\":[";bool comma=false;
    for(const auto& [pc,d]:c.resolved){if(comma)o<<',';comma=true;
        o<<"{\"site\":\""<<hex(pc)<<"\",\"kind\":\""<<(d.call?"static_table_call":"static_table_switch")<<"\",\"bound\":\""<<boundName(d.bound)
         <<"\",\"host_range_check\":true,\"base\":\""<<hex(d.base)<<"\",\"count\":"<<d.count<<",\"function_begin\":\""<<hex(d.function.begin)
         <<"\",\"function_end\":\""<<hex(d.function.end)<<"\",\"index_pc\":\""<<hex(d.indexPc)<<"\",\"index_register\":"<<d.indexRegister
         <<",\"index_address\":\""<<hex(d.indexAddress)<<"\",\"branch\":\""<<hex(d.branch)<<"\",\"default\":\""<<hex(d.defaultTarget)<<"\",\"targets\":[";
        for(std::size_t n=0;n<d.targets.size();++n){if(n)o<<',';o<<'"'<<hex(d.targets[n])<<'"';}o<<"]}";
    }
    o<<"],\"unresolved\":[";comma=false;for(const auto& [pc,why]:c.unresolved){if(comma)o<<',';comma=true;o<<"{\"site\":\""<<hex(pc)<<"\",\"bound\":\"None\",\"reason\":\""<<why<<"\"}";}o<<"]}\n";return o.str();
}
inline std::string markdown(const Census& c){std::ostringstream o;o<<"# Static table matcher v2\n\nDiscovery only; no switch gameplay integration.\n\n| Site | Kind | Bound | Table | Count | Default |\n| --- | --- | --- | --- | ---: | --- |\n";
    for(const auto& [pc,d]:c.resolved)o<<"| "<<hex(pc)<<" | "<<(d.call?"call":"switch")<<" | "<<boundName(d.bound)<<" | "<<hex(d.base)<<" | "<<d.count<<" | "<<hex(d.defaultTarget)<<" |\n";
    o<<"\n## Unresolved\n\n";for(const auto& [pc,why]:c.unresolved)o<<"- "<<hex(pc)<<": "<<why<<"\n";return o.str();}
}
