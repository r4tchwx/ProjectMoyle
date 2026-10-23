#pragma once
#include "generator.hpp"
#include "../../src/static_table.hpp"
#include <array>
#include <deque>

namespace recomp_tool {
using moyle::detail::recomp::canonicalCodeAddress;
using moyle::detail::recomp::TableKind;
struct TableSpec {
    std::uint32_t begin,indexLoad,load,site,base,count;
    unsigned indexBase,indexOffset,indexWidth;
    TableKind kind;
    // Optional incoming base register. Its value is always checked at runtime.
    unsigned baseRegister=0;
    std::uint64_t fingerprint=0;
};
struct TableResolution {
    TableSpec spec;
    std::vector<std::uint32_t> targets;
    std::uint64_t fingerprint=14695981039346656037ULL;
    std::map<std::uint32_t,Instruction> slice;
};
inline const char* tableKind(TableKind k){return k==TableKind::Call?"static_table_call":"static_table_tailjump";}
inline std::uint32_t imageWord(const std::vector<std::uint8_t>& bytes,std::uint32_t address) {
    if(bytes.size()<0x800||std::string(bytes.begin(),bytes.begin()+8)!="PS-X EXE")throw std::runtime_error("Invalid table EXE");
    const auto base=canonicalCodeAddress(word(bytes,24)),size=word(bytes,28),pc=canonicalCodeAddress(address);
    if(!size||(size&3)||std::uint64_t(base)+size>0x80200000ULL||size>bytes.size()-0x800||pc<base||std::uint64_t(pc-base)+4>size)throw std::runtime_error("Table/code outside executable");
    return word(bytes,0x800+pc-base);
}
inline TableResolution resolveTable(const std::vector<std::uint8_t>& bytes,TableSpec s) {
    if(!s.count||s.count>65536||s.begin>s.indexLoad||s.indexLoad>=s.load||s.load>=s.site||
       s.site-s.begin>256||s.indexBase>=32||s.baseRegister>=32||
       (s.indexWidth!=1&&s.indexWidth!=2))throw std::runtime_error("Invalid table descriptor");
    s.base=canonicalCodeAddress(s.base);
    if(std::uint64_t(s.base)+4ULL*s.count>0x80200000ULL)throw std::runtime_error("Table range overflow");
    TableResolution r;r.spec=s;
    for(std::uint32_t n=0;n<s.count;++n){
        const auto value=imageWord(bytes,s.base+4*n);
        if(canonicalCodeAddress(value)==0x80000000U)throw std::runtime_error("Null table target");
        imageWord(bytes,value); // Reject null, unaligned, unmapped, outside-image targets.
        r.targets.push_back(value);
        for(unsigned b=0;b<4;++b){r.fingerprint^=(value>>(8*b))&255;r.fingerprint*=1099511628211ULL;}
    }
    if(s.fingerprint&&s.fingerprint!=r.fingerprint)throw std::runtime_error("Table fingerprint mismatch");
    enum Kind { Unknown,Input,Constant,Index,Scaled,Slot,Target };
    struct Value {Kind kind=Unknown;std::uint32_t value=0;};
    std::array<Value,32> regs{};for(unsigned n=1;n<32;++n)regs[n]={Input,n};regs[0]={Constant,0};
    if(s.baseRegister)regs[s.baseRegister]={Constant,s.base};
    unsigned pending=0;Value pendingValue;
    for(auto pc=s.begin;pc<=s.site;pc+=4){
        const auto w=imageWord(bytes,pc),op=w>>26,rs=(w>>21)&31,rt=(w>>16)&31,rd=(w>>11)&31,fn=w&63,sh=(w>>6)&31;
        const auto a=regs[rs],b=regs[rt];if(pending)regs[pending]=pendingValue;pending=0;
        if(pc==s.site){
            const auto mask=s.kind==TableKind::Call?0x0000f809U:0x00000008U;
            if((w&0xfc1fffffU)!=mask||a.kind!=Target)throw std::runtime_error("Unverified table transfer chain");
            Instruction i{pc,w,rs,rt,tableKind(s.kind),""};i.control=true;
            i.callKind=s.kind==TableKind::Call?CallKind::StaticTableCall:CallKind::StaticTableTailJump;
            r.slice.emplace(pc,i);continue;
        }
        auto i=decode(pc,w);if(i.control)throw std::runtime_error("Control flow in table provenance slice");
        r.slice.emplace(pc,i);
        if(pc==s.indexLoad){
            if(op!=(s.indexWidth==1?36U:37U)||a.kind!=Input||a.value!=s.indexBase||(w&65535)!=s.indexOffset||!rt)
                throw std::runtime_error("Index source mismatch");
            pending=rt;pendingValue={Index,0};
        }else if(pc==s.load){
            if(op!=35||a.kind!=Slot||(w&65535)||!rt)throw std::runtime_error("Table LW provenance mismatch");
            pending=rt;pendingValue={Target,0};
        }else if(w==0){}else if(op==15){regs[rt]={Constant,(w&65535)<<16};}
        else if(op==9&&a.kind==Constant){regs[rt]={Constant,a.value+((w&0x8000)?(w|0xffff0000U):(w&65535))};}
        else if(op==0&&fn==0&&sh==2&&b.kind==Index){regs[rd]={Scaled,0};}
        else if(op==0&&(fn==0x20||fn==0x21||fn==0x25)&&b.kind==Constant&&b.value==0){regs[rd]=a;}
        else if(op==0&&(fn==0x20||fn==0x21)&&
                ((a.kind==Scaled&&b.kind==Constant&&canonicalCodeAddress(b.value)==s.base)||
                 (b.kind==Scaled&&a.kind==Constant&&canonicalCodeAddress(a.value)==s.base))){regs[rd]={Slot,0};}
        else throw std::runtime_error("Unsupported table provenance instruction at "+hex(pc));
        regs[0]={Constant,0};
    }
    auto delay=decode(s.site+4,imageWord(bytes,s.site+4));
    if(delay.control)throw std::runtime_error("Control in table delay slot");
    r.slice.emplace(s.site+4,delay);
    return r;
}
// Bounded CFG emission; unknown operations/uncertified calls remain explicit
// traps. A table-derived entry is not a proof of a complete function extent.
struct TableProgram {Program program;std::map<std::uint32_t,std::string> unresolved;std::set<std::uint32_t> handlerEntries;};
inline TableProgram tableProgram(const std::vector<std::uint8_t>& bytes,
                                const std::vector<TableResolution>& tables,
                                const std::vector<std::uint32_t>& extraEntries={},
                                std::uint32_t fragmentExit=0,unsigned budget=512) {
    TableProgram result;auto& p=result.program;p.fragmentExit=fragmentExit;
    if(tables.empty()||!budget)throw std::runtime_error("Empty table analysis");
    if(fragmentExit&&std::none_of(tables.begin(),tables.end(),[&](const TableResolution& t){
        return t.spec.kind==TableKind::Call&&t.spec.site+8==fragmentExit;
    }))throw std::runtime_error("Fragment exit is not a table call continuation");
    std::set<std::uint32_t> entries(extraEntries.begin(),extraEntries.end()),slots;
    for(const auto& t:tables){
        entries.insert(t.spec.begin);
        for(auto target:t.targets)result.handlerEntries.insert(canonicalCodeAddress(target));
    }
    entries.insert(result.handlerEntries.begin(),result.handlerEntries.end());
    for(const auto& t:tables){
        const auto& s=t.spec;const auto id=std::to_string(s.site);
        const auto name="table"+id,ticket="ticket"+id;
        p.tablePrelude+="const StaticTable "+name+"{"+hex(s.base)+"U,{";
        for(auto target:t.targets)p.tablePrelude+=hex(target)+"U,";
        p.tablePrelude+="}}; TableTicket "+ticket+";\n";
        for(auto pair:t.slice){
            auto& i=pair.second;
            if(i.pc==s.indexLoad)i.code+=" tableIndex("+ticket+","+name+","+hex(s.site)+"U,c.loadValue);";
            if(i.pc==s.load)i.code="c.loadValue = tableLoad(c,"+ticket+","+name+","+hex(s.site)+"U,a); c.loadRegister = "+std::to_string((i.bits>>16)&31)+";";
            if(i.pc==s.site)i.code="following = tableTransfer(c,"+ticket+",pc,a,TableKind::"+(s.kind==TableKind::Call?"Call":"TailJump")+");";
            if(!p.instructions.emplace(pair.first,i).second)throw std::runtime_error("Overlapping table slices");
        }
        slots.insert(s.site+4);p.regions.push_back({s.begin,1});
        if(s.kind==TableKind::Call&&s.site+8!=fragmentExit)entries.insert(s.site+8);
    }
    auto trap=[&](std::uint32_t pc,const std::string& reason){
        result.unresolved.emplace(pc,reason);
        p.instructions.emplace(pc,Instruction{pc,0,0,0,"unresolved", "throw std::runtime_error(\"Unresolved static-table CFG at "+hex(pc)+": "+reason+"\");"});
    };
    for(auto root:entries){
        p.regions.push_back({root,1});std::deque<std::uint32_t> queue{root};unsigned used=0;
        while(!queue.empty()){
            auto pc=queue.front();queue.pop_front();if(p.instructions.count(pc))continue;
            if(++used>budget){trap(pc,"analysis budget");continue;}
            Instruction i;
            // Keep the reviewed v1 execution subset stable. Expanding real handler
            // extents is a separate integration task, not implied by new opcodes.
            try{i=decode(pc,imageWord(bytes,pc),false);}catch(const std::exception&){trap(pc,"unsupported instruction or image boundary");continue;}
            p.instructions.emplace(pc,i);
            if(!i.control){queue.push_back(pc+4);continue;}
            const auto slot=pc+4;slots.insert(slot);
            try{auto d=decode(slot,imageWord(bytes,slot),false);if(d.control||(!i.direct&&d.load))throw std::runtime_error("slot");p.instructions.emplace(slot,d);}
            catch(const std::exception&){trap(slot,"unsupported delay slot");}
            if(!i.direct)continue;
            const auto op=i.bits>>26;
            if(op==3){
                if(entries.count(i.target))queue.push_back(i.target);
                else trap(i.target,"callee not certified in this translation unit");
                queue.push_back(pc+8);
            }else {queue.push_back(i.target);if(op!=2)queue.push_back(pc+8);}
        }
    }
    for(auto root:entries)if(slots.count(root))throw std::runtime_error("Table target in delay slot");
    for(const auto& pair:p.instructions)if(pair.second.direct&&slots.count(pair.second.target))throw std::runtime_error("Direct target in delay slot");
    for(const auto& t:tables){
        const auto interior=[&](std::uint32_t pc){return pc>t.spec.begin&&pc<=t.spec.site+4;};
        for(auto root:entries)if(interior(root))throw std::runtime_error("Entry bypasses table provenance");
        for(const auto& pair:p.instructions)if(pair.second.direct&&interior(pair.second.target))throw std::runtime_error("Branch bypasses table provenance");
    }
    if(fragmentExit&&p.instructions.count(fragmentExit))throw std::runtime_error("Fragment exit overlaps emitted code");
    std::sort(p.regions.begin(),p.regions.end(),[](Region a,Region b){return a.entry<b.entry;});
    p.regions.erase(std::unique(p.regions.begin(),p.regions.end(),[](Region a,Region b){return a.entry==b.entry;}),p.regions.end());
    return result;
}
inline std::string tableJson(const std::vector<TableResolution>& tables,const TableProgram& program) {
    std::ostringstream o;o<<"{\n\"schema\":1,\"unique_handler_entries\":"<<program.handlerEntries.size()<<",\"sites\":[\n";
    bool comma=false;
    for(const auto& t:tables){if(comma)o<<",\n";comma=true;
        o<<"{\"site\":\""<<hex(t.spec.site)<<"\",\"kind\":\""<<tableKind(t.spec.kind)<<"\",\"base\":\""<<hex(t.spec.base)
         <<"\",\"count\":"<<t.targets.size()<<",\"index_load\":\""<<hex(t.spec.indexLoad)<<"\",\"index_base_register\":"<<t.spec.indexBase
         <<",\"index_offset\":"<<t.spec.indexOffset<<",\"index_width\":"<<t.spec.indexWidth<<",\"runtime_validation\":true,\"targets\":[";
        for(std::size_t n=0;n<t.targets.size();++n){if(n)o<<',';o<<'"'<<hex(t.targets[n])<<'"';}o<<"]}";
    }
    o<<"\n],\"unresolved_execution_boundaries\":[";comma=false;
    for(const auto& e:program.unresolved){if(comma)o<<',';comma=true;o<<"{\"pc\":\""<<hex(e.first)<<"\",\"reason\":\""<<e.second<<"\"}";}
    o<<"]\n}\n";return o.str();
}
inline std::string tableReport(const std::vector<TableResolution>& tables,const TableProgram& program) {
    std::ostringstream o;o<<"# Static table discovery\n\n";
    std::size_t edges=0;for(const auto& t:tables)edges+=t.targets.size();
    o<<"Sites: "<<tables.size()<<"; slot edges: "<<edges<<"; unique handler entries: "<<program.handlerEntries.size()<<"; unresolved CFG locations: "<<program.unresolved.size()<<".\n\n";
    for(const auto& t:tables){o<<"## "<<hex(t.spec.site)<<" "<<tableKind(t.spec.kind)<<"\n\nBase: "<<hex(t.spec.base)<<"; count: "<<t.targets.size()<<"; fingerprint FNV1a64: "<<std::hex<<t.fingerprint<<std::dec<<".\n\n";
        for(std::size_t n=0;n<t.targets.size();++n)o<<"- "<<n<<": "<<hex(t.targets[n])<<"\n";
    }
    o<<"\n## Unresolved execution boundaries\n\n";for(const auto& e:program.unresolved)o<<"- "<<hex(e.first)<<": "<<e.second<<"\n";
    return o.str();
}
}
