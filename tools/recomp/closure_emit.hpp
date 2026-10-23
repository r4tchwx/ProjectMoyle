#pragma once
// Phase 3: turns a closure discovery result (Phase 2C proofs + the explicit Phase 3 opt-ins) into one generated
// "Direct TITLE" execution unit. Nothing here proves anything: every transfer the unit may make was classified by
// closure.hpp, and each is emitted behind the matching runtime guard:
//   * resolved-indirect-cell-guarded -> moyle::detail::validateCellTarget (src/indirect_cells.hpp)
//   * set-guarded / registry          -> moyle::detail::validateTargetSet  (same header, same membership rule)
//   * libgpu allowlisted slots        -> moyle::detail::validateGuardedTarget (src/guarded_indirect.hpp)
//   * bounded JR tables               -> tableLoadSlot / tableTransfer      (src/static_table.hpp)
//   * BIOS thunks                     -> dispatchBios after the delay slot  (src/bios_boundary.hpp policy)
//   * divide-by-zero BREAK            -> dispatchBreak (fatal)
//   * jr $ra                          -> return-site guard (src/closure_guard.hpp)
//   * JAL to a pinned external entry  -> DynamicRegistry lookup at the JAL, dispatchDynamic after the slot (--external-entry)
// Any other register jump/call inside a generated function is a generation error, not an unrestricted dispatch.
// Resolved functions are generated; a callee that discovery could not resolve becomes a terminal boundary stub so every
// direct call target exists and the failure is a diagnostic at runtime.
#include "closure.hpp"

namespace recomp_tool::closure_emit {
using u32=std::uint32_t;
struct Report {
    std::size_t functions=0,instructions=0,stubs=0;
    std::size_t directCalls=0,libgpuSlots=0,cellGuarded=0,emptyRegistries=0,setGuarded=0,ringRegistries=0,tableSwitches=0,
                biosThunks=0,breakTraps=0,returnSites=0,jumps=0,externalCalls=0,sharedSlots=0;
    std::map<u32,std::string> notGenerated; // unresolved discovered entry -> why it has no generated body
    std::vector<u32> entries;               // generated function registry (entry points), ascending
    std::vector<u32> stubEntries;           // boundary stubs, ascending
};
struct Unit {Program program;Report report;};
inline std::string idOf(u32 pc){return hex(pc).substr(2);}
inline Unit buildUnit(const std::vector<std::uint8_t>& bytes,const closure::Result& result,
                      const std::string& description="Direct TITLE closure unit",bool probe=false) {
    const Image image(bytes);
    const auto& d=result.discovery;
    if(!d.closure||!d.extendedIsa)throw std::runtime_error("Closure unit requires a closure discovery result");
    Unit unit;auto& rep=unit.report;
    std::vector<Region> regions;std::map<u32,Instruction> overrides;GuardedCalls guarded;
    std::string prelude,tables;
    std::set<u32> generated,stubs,externalSites,sharedSlots;
    const auto base=[&](u32 pc){return decode(pc,image.at(pc),true,result.discovery.bootGte,true,result.discovery.bootIsa);};
    for(const auto& pair:d.functions) {
        const auto& f=pair.second;
        if(!f.resolved){
            std::string why;
            for(const auto& i:f.unresolved)why+=(why.empty()?"":", ")+hex(i.site)+" "+i.reason;
            rep.notGenerated.emplace(pair.first,why.empty()?"unresolved":why);continue;
        }
        if(f.end<=pair.first||((f.end-pair.first)&3))throw std::runtime_error("Invalid extent for "+hex(pair.first));
        if(f.gaps.empty())regions.push_back({pair.first,static_cast<u32>((f.end-pair.first)/4)});
        else { // verified dead runs split the extent into contiguous regions; the dead words are not emitted at all
            u32 start=pair.first;
            for(const auto& g:f.gaps){if(g.first>start)regions.push_back({start,static_cast<u32>((g.first-start)/4)});start=g.second;}
            if(f.end>start)regions.push_back({start,static_cast<u32>((f.end-start)/4)});
        }
        generated.insert(pair.first);
    }
    // Per-function proofs -> instruction overrides.
    for(u32 entry:generated) {
        const auto& f=d.functions.at(entry);
        for(const auto& g:f.guarded){guarded.emplace(g.first,g.second);++rep.libgpuSlots;}
        rep.directCalls+=f.calls.size();
        for(const auto& e:f.cellCalls) {
            const auto& s=e.second;auto i=base(e.first);
            if(!i.control||i.callKind!=CallKind::IndirectCall||i.rs!=s.rs)throw std::runtime_error("Cell proof does not match the JALR at "+hex(e.first));
            const auto id="cellSite"+idOf(e.first);
            prelude+="static const moyle::detail::CellSite "+id+"{"+hex(e.first)+"U,"+hex(s.cell)+"U,"+hex(s.offset)+"U,"+(s.field?"true":"false")+",{";
            for(auto t:s.targets)prelude+=hex(t)+"U,";
            prelude+="}};\n";
            i.text+=s.empty?" [registry-empty-guarded]":" [cell-guarded]";i.callKind=CallKind::CellGuarded;
            i.code="following = moyle::detail::validateCellTarget(c.ram, "+id+", a); c.r[31] = pc + 8U; ++c.calls;";
            overrides.emplace(e.first,i);
            if(s.empty)++rep.emptyRegistries;else ++rep.cellGuarded;
        }
        for(const auto& e:f.setCalls) {
            const auto& s=e.second;auto i=base(e.first);
            if(!i.control||i.callKind!=CallKind::IndirectCall||i.rs!=s.rs)throw std::runtime_error("Set proof does not match the JALR at "+hex(e.first));
            const auto id="setSite"+idOf(e.first);
            prelude+="static const moyle::detail::SetSite "+id+"{"+hex(e.first)+"U,{";
            for(auto t:s.targets)prelude+=hex(t)+"U,";
            prelude+="}};\n";
            i.text+=" [set-guarded "+s.kind+"]";i.callKind=CallKind::SetGuarded;
            i.code="following = moyle::detail::validateTargetSet("+id+", a); c.r[31] = pc + 8U; ++c.calls;";
            overrides.emplace(e.first,i);
            if(s.kind=="ring-registry")++rep.ringRegistries;else ++rep.setGuarded;
        }
        for(const auto& e:f.switchSites) {
            const auto& s=e.second;auto jr=base(e.first);
            if(!jr.control||jr.direct||(jr.bits&0xfc1fffffU)!=0x00000008U||jr.rs!=s.rs)throw std::runtime_error("Table proof does not match the JR at "+hex(e.first));
            if(!s.load||s.load>=e.first||(image.at(s.load)>>26)!=35U||((image.at(s.load)>>16)&31U)!=s.rs)
                throw std::runtime_error("Table proof has no matching LW for the JR at "+hex(e.first));
            const auto id=idOf(e.first);
            tables+="const StaticTable table"+id+"{"+hex(s.table)+"U,{";
            for(u32 n=0;n<s.count;++n)tables+=hex(image.at(s.table+4U*n))+"U,";
            tables+="}}; TableTicket ticket"+id+";\n";
            auto lw=base(s.load);
            if(!lw.load||lw.control)throw std::runtime_error("Table LW decode mismatch at "+hex(s.load));
            const auto imm=(lw.bits&0x8000U)?(lw.bits|0xffff0000U):(lw.bits&0xffffU);
            lw.text+=" [table-slot "+hex(e.first)+"]";
            lw.code="c.loadValue = tableLoadSlot(c, ticket"+id+", table"+id+", "+hex(e.first)+"U, a + "+hex(imm)+"U); c.loadRegister = "+std::to_string((lw.bits>>16)&31U)+";";
            overrides.emplace(s.load,lw);
            jr.text+=" [table-switch]";jr.callKind=CallKind::TableSwitch;
            jr.code="following = tableTransfer(c, ticket"+id+", pc, a, TableKind::TailJump);";
            overrides.emplace(e.first,jr);++rep.tableSwitches;
        }
        for(const auto& e:f.biosHle) {
            auto jr=base(e.first);
            if(!jr.control||jr.direct||(jr.bits&0xfc1fffffU)!=0x00000008U)throw std::runtime_error("BIOS site is not a JR at "+hex(e.first));
            jr.text+=" [bios "+hex(e.second.table)+":"+hex(static_cast<u32>(e.second.function))+"]";jr.callKind=CallKind::BiosVector;
            jr.code="biosArmed = true; biosSite = pc; biosTable = a; biosExpectTable = "+hex(e.second.table)+"U; biosExpectFunction = "+
                    hex(static_cast<u32>(e.second.function))+"U; following = pc + 8U;";
            overrides.emplace(e.first,jr);++rep.biosThunks;
        }
        for(const auto& e:f.breakTraps) {
            Instruction b{e.first,image.at(e.first),0,0,((e.second>>16)&0x3ffU)==7U?"break 0x7 [divide-by-zero trap]":"break "+hex((e.second>>6)&0xfffffU)+" [fatal trap]",""};
            b.terminal=true;b.code="dispatchBreak(c, pc, "+hex(e.second)+"U);";
            overrides.emplace(e.first,b);++rep.breakTraps;
        }
        // --external-entry: the JAL keeps its delay slot and RA = pc + 8; the target is looked up in the DynamicRegistry at
        // the JAL (unregistered = fatal before RA/slot) and dispatched after the slot on the shared Context. The callee must
        // return to the continuation (dispatchDynamic checks it). Never emitted unless the option produced external calls.
        sharedSlots.insert(f.sharedSlots.begin(),f.sharedSlots.end());rep.sharedSlots+=f.sharedSlots.size();
        for(const auto& e:f.externalCalls) {
            auto jal=base(e.site);
            if(!jal.control||!jal.direct||(jal.bits>>26)!=3U||jal.target!=e.target)throw std::runtime_error("External-entry call does not match the JAL at "+hex(e.site));
            jal.direct=false;jal.callKind=CallKind::DynamicRuntime;jal.text+=" [external-entry registry dispatch]";
            jal.code="pending = lookupDynamic(c, pc, codeAlias("+hex(e.target)+"U, pc)); pendingSite = pc; continuation = pc + 8U; "
                     "c.r[31] = continuation; following = continuation; waiting = true; ++c.calls;";
            overrides.emplace(e.site,jal);externalSites.insert(e.site);++rep.externalCalls;
        }
        for(auto pc:f.returns) {
            auto jr=base(pc);
            if(jr.bits!=0x03e00008U)throw std::runtime_error("Return site is not jr ra at "+hex(pc));
            jr.text+=" [return-guard]";jr.callKind=CallKind::ReturnGuarded;
            jr.code="if (a != stop) returnSiteOk(pc, a); following = a;";
            overrides.emplace(pc,jr);++rep.returnSites;
        }
    }
    // Every static transfer target must be a function entry of the unit; an unresolved callee becomes a boundary stub.
    const auto requireEntry=[&](u32 target,const std::string& from){
        if(generated.count(target)||stubs.count(target))return;
        const auto found=d.functions.find(target);
        if(found==d.functions.end())throw std::runtime_error(from+" targets "+hex(target)+", which is not a discovered function entry");
        stubs.insert(target);
    };
    for(u32 entry:generated) {
        const auto& f=d.functions.at(entry);
        for(const auto& e:f.calls)requireEntry(e.target,"call at "+hex(e.site));
        for(const auto& e:f.tailJumps)requireEntry(e.target,"tail jump at "+hex(e.site));
        for(const auto& g:f.guarded)requireEntry(g.second.expectedTarget,"guarded slot at "+hex(g.first));
        for(const auto& c:f.cellCalls)for(auto t:c.second.targets)requireEntry(t,"cell call at "+hex(c.first));
        for(const auto& c:f.setCalls)for(auto t:c.second.targets)requireEntry(t,"set call at "+hex(c.first));
    }
    for(u32 entry:stubs) {
        regions.push_back({entry,1});
        Instruction s{entry,image.at(entry),0,0,"boundary stub (function not generated)",""};
        s.terminal=true;
        const auto why=d.functions.at(entry).unresolved.empty()?std::string("unresolved"):d.functions.at(entry).unresolved.begin()->reason;
        s.code="throw std::runtime_error(\"Direct TITLE boundary: function "+hex(entry)+" is not generated ("+why+")\");";
        overrides.emplace(entry,s);
    }
    std::sort(regions.begin(),regions.end(),[](Region a,Region b){return a.entry<b.entry;});
    unit.program=analyze(bytes,regions,guarded,{},0,true,overrides,d.bootIsa,d.bootGte,sharedSlots);
    auto& p=unit.program;
    p.dynamic=externalSites; // enables the existing after-slot dispatch locals; empty for every legacy unit
    // Strict: no generic register transfer other than the ones above may remain.
    for(const auto& pair:p.instructions) {
        const auto& i=pair.second;
        if(!i.control||i.direct)continue;
        const bool known=i.callKind==CallKind::CellGuarded||i.callKind==CallKind::SetGuarded||i.callKind==CallKind::TableSwitch||
                         i.callKind==CallKind::BiosVector||i.callKind==CallKind::ReturnGuarded||i.callKind==CallKind::Guarded||
                         (i.callKind==CallKind::DynamicRuntime&&externalSites.count(i.pc));
        if(!known)throw std::runtime_error("Unproven register transfer at "+hex(i.pc)+" ("+i.text+"): generation refused");
    }
    // Targets must exist as instructions at function entries.
    for(u32 entry:generated) {
        const auto& f=d.functions.at(entry);
        for(const auto& c:f.cellCalls)for(auto t:c.second.targets)if(!p.instructions.count(t))throw std::runtime_error("Cell target "+hex(t)+" has no generated code");
        for(const auto& c:f.setCalls)for(auto t:c.second.targets)if(!p.instructions.count(t))throw std::runtime_error("Set target "+hex(t)+" has no generated code");
    }
    // Return-site guard: every call continuation in the unit.
    std::set<u32> continuations;
    for(const auto& pair:p.instructions) {
        const auto k=pair.second.callKind;
        if(k==CallKind::Direct||k==CallKind::Guarded||k==CallKind::CellGuarded||k==CallKind::SetGuarded)
            continuations.insert(canonicalCodeAddress(pair.second.pc+8));
    }
    std::string guardCode="const auto returnSiteOk = [](std::uint32_t site, std::uint32_t target) {\nswitch (closureReturnCanonical(site, target)) {\n";
    for(auto c:continuations)guardCode+="case "+hex(c)+"U:\n";
    guardCode+=continuations.empty()?"default: break; }\n":"return;\ndefault: break; }\n";
    guardCode+="closureReturnRejected(site, target);\n};\n";
    p.tablePrelude=tables.empty()?std::string():tables;
    p.closurePrelude=prelude+guardCode;
    p.closure=true;p.sourceDescription=description;
    p.extraIncludes="#include \"indirect_cells.hpp\"\n#include \"closure_guard.hpp\"\n";
    if(rep.biosThunks){
        p.loopLocals="bool biosArmed = false; std::uint32_t biosSite = 0, biosTable = 0, biosExpectTable = 0, biosExpectFunction = 0;\n";
        p.iterationLocals="const bool biosNow = biosArmed;\n";
        p.postSlot="if (biosNow) {\nbiosArmed = false;\n"
            "if (biosTable != biosExpectTable || c.r[9] != biosExpectFunction) throw std::runtime_error(\"BIOS thunk register mismatch\");\n"
            "dispatchBios(c, biosSite, biosTable, c.r[9]);\n"
            "const std::uint32_t back = c.r[31];\nif (back != stop) returnSiteOk(biosSite, back);\n"
            "pc = back; next = pc + 4U; c.pc = pc;\n}\n";
    }
    // Phase 4 (opt-in): per-instruction probe call, so a host harness can checkpoint function entries and stop deterministically.
    if(probe){
        // With external calls, a probe redirect may never coexist with a pending after-slot dispatch (fail closed).
        p.iterationLocals+=externalSites.empty()
            ?"if (c.probe) { c.probe(c, pc); if (c.redirectPending) { c.redirectPending = false; pc = c.redirectPc; next = pc + 4U; c.pc = pc; continue; } }\n"
            :"if (c.probe) { c.probe(c, pc); if (c.redirectPending) { if (dispatchAfterSlot) throw std::runtime_error(\"Probe redirect in the delay slot of an external-entry call\"); "
             "c.redirectPending = false; pc = c.redirectPc; next = pc + 4U; c.pc = pc; continue; } }\n";
        if(rep.biosThunks)p.postSlot="if (biosNow) {\nbiosArmed = false;\n"
            "if (biosTable != biosExpectTable || c.r[9] != biosExpectFunction) throw std::runtime_error(\"BIOS thunk register mismatch\");\n"
            "dispatchBios(c, biosSite, biosTable, c.r[9]);\n"
            "if (c.redirectPending) { c.redirectPending = false; pc = c.redirectPc; next = pc + 4U; c.pc = pc; } else {\n"
            "const std::uint32_t back = c.r[31];\nif (back != stop) returnSiteOk(biosSite, back);\n"
            "pc = back; next = pc + 4U; c.pc = pc;\n}\n}\n";
    }
    // Report.
    rep.functions=generated.size();rep.stubs=stubs.size();
    for(const auto& pair:p.instructions)if(!pair.second.terminal||pair.second.text.compare(0,13,"boundary stub")!=0)++rep.instructions;
    rep.entries.assign(generated.begin(),generated.end());rep.stubEntries.assign(stubs.begin(),stubs.end());
    for(u32 entry:generated)rep.jumps+=d.functions.at(entry).jumps.size()+d.functions.at(entry).tailJumps.size();
    return unit;
}
// Deterministic "entry end kind" listing (kind G = generated function, S = boundary stub) for host harness diagnostics.
inline std::string functionMap(const Report& r,const Discovery& d) {
    std::map<u32,std::pair<u32,char>> all;
    for(auto e:r.entries)all[e]={static_cast<u32>(d.functions.at(e).end),'G'};
    for(auto e:r.stubEntries)all[e]={e+4U,'S'};
    std::ostringstream o;
    for(const auto& p:all)o<<hex(p.first)<<" "<<hex(p.second.first)<<" "<<p.second.second<<"\n";
    return o.str();
}
inline std::string reportJson(const Report& r,const Discovery& d) {
    std::ostringstream o;
    o<<"{\n  \"schema\": 1,\n  \"discovered_functions\": "<<d.functions.size()<<",\n  \"generated_functions\": "<<r.functions
     <<",\n  \"generated_instructions\": "<<r.instructions<<",\n  \"boundary_stubs\": "<<r.stubs
     <<",\n  \"direct_call_sites\": "<<r.directCalls<<",\n  \"internal_jump_sites\": "<<r.jumps
     <<",\n  \"closure_call_sites\": {\"libgpu_guarded_slots\": "<<r.libgpuSlots<<", \"cell_guarded\": "<<r.cellGuarded
     <<", \"registry_empty_guarded\": "<<r.emptyRegistries<<", \"set_guarded\": "<<r.setGuarded<<", \"ring_registry_guarded\": "<<r.ringRegistries
     <<", \"total\": "<<(r.libgpuSlots+r.cellGuarded+r.emptyRegistries+r.setGuarded+r.ringRegistries)<<"}"
     <<",\n  \"table_switch_sites\": "<<r.tableSwitches<<",\n  \"bios_thunks\": "<<r.biosThunks<<",\n  \"break_traps\": "<<r.breakTraps
     <<",\n  \"return_guard_sites\": "<<r.returnSites<<(r.externalCalls?",\n  \"external_call_sites\": "+std::to_string(r.externalCalls):std::string())
     <<(r.sharedSlots?",\n  \"shared_delay_slots\": "+std::to_string(r.sharedSlots):std::string())
     <<",\n  \"not_generated\": [";
    bool comma=false;
    for(const auto& e:r.notGenerated){if(comma)o<<",";comma=true;o<<"{\"entry\":\""<<hex(e.first)<<"\",\"reason\":\""<<e.second<<"\"}";}
    o<<"],\n  \"stub_entries\": [";comma=false;
    for(auto s:r.stubEntries){if(comma)o<<",";comma=true;o<<"\""<<hex(s)<<"\"";}
    o<<"],\n  \"function_registry\": [";comma=false;
    for(auto e:r.entries){if(comma)o<<",";comma=true;o<<"\""<<hex(e)<<"\"";}
    o<<"]\n}\n";
    return o.str();
}
}
