#pragma once
#include "recomp_dispatch.hpp"

namespace moyle::detail::recomp {
enum class TableKind { TailJump, Call };
struct StaticTable {
    std::uint32_t base;
    std::vector<std::uint32_t> targets;
};
// Per-executor ticket: only a checked index followed by its checked LW may
// authorize a table transfer. It does not assert that guest RAM is immutable.
struct TableTicket { bool indexed=false,loaded=false; std::uint32_t index=0,target=0; };
inline std::runtime_error tableError(std::uint32_t site,const char* reason) {
    std::ostringstream o;o<<"static table at 0x"<<std::hex<<site<<": "<<reason;
    return std::runtime_error(o.str());
}
inline void tableIndex(TableTicket& ticket,const StaticTable& table,std::uint32_t site,std::uint32_t index) {
    ticket={};
    if(index>=table.targets.size())throw tableError(site,"index out of range");
    ticket.indexed=true;ticket.index=index;
}
inline std::uint32_t tableLoad(Context& c,TableTicket& ticket,const StaticTable& table,
                               std::uint32_t site,std::uint32_t address) {
    if(!ticket.indexed)throw tableError(site,"missing checked index");
    const auto expected=std::uint64_t(canonicalCodeAddress(table.base))+4ULL*ticket.index;
    if(expected>0xffffffffULL||canonicalCodeAddress(address)!=expected)
        throw tableError(site,"table base/slot mismatch");
    const auto actual=c.ram.read(address,4);
    if(canonicalCodeAddress(actual)!=canonicalCodeAddress(table.targets.at(ticket.index)))
        throw tableError(site,"guest slot changed from executable target");
    ticket.loaded=true;ticket.target=actual;
    return actual;
}
// Closure (Phase 2C bounded-table) variant: the guest already bounds the index with SLTIU/BEQ, so the LW's effective
// address is what identifies the slot. The host re-derives the index from that address (range, alignment, table base),
// then applies the same checked load as the v1 tickets (the live word must still equal the executable's table word).
inline std::uint32_t tableLoadSlot(Context& c,TableTicket& ticket,const StaticTable& table,
                                   std::uint32_t site,std::uint32_t address) {
    ticket={};
    std::uint32_t slot=0,base=0;
    try{slot=canonicalCodeAddress(address);base=canonicalCodeAddress(table.base);}
    catch(const std::out_of_range&){throw tableError(site,"table slot is unaligned or unmapped");}
    if(slot<base||(slot-base)%4U)throw tableError(site,"table slot below the table or misaligned");
    tableIndex(ticket,table,site,(slot-base)/4U);
    return tableLoad(c,ticket,table,site,address);
}
inline std::uint32_t tableTransfer(Context& c,TableTicket& ticket,std::uint32_t site,
                                  std::uint32_t actual,TableKind kind) {
    if(!ticket.loaded||actual!=ticket.target)throw tableError(site,"target without matching checked table load");
    const auto index=ticket.index;
    ticket={};
    // The generated loop executes the slot before following this guest address.
    if(kind==TableKind::Call){c.r[31]=site+8U;++c.calls;}
    c.tableTrace.push_back({site,actual,c.r[31],kind==TableKind::Call,index});
    return actual;
}
}
