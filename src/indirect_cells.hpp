#pragma once
// Runtime half of Phase 2C `resolved-indirect-cell-guarded`: a JALR through a fixed guest cell (or one field of a
// fixed object) whose static writers are all code constants (tools/recomp/closure.hpp proves the set from the
// executable). The proof is static evidence only, never "the cell is immutable", so the call must still be checked:
//   * the captured target (the register BEFORE any pending load retires, as in guarded_indirect.hpp) must equal the
//     live RAM cell/field exactly, aliases included;
//   * it must be a member of the proven set (compared on the canonical RAM address, so KSEG0/KSEG1/physical spellings
//     of a proven entry are accepted and everything else is not);
//   * null, unaligned, unmapped, unknown or interior addresses are fatal. No target is ever substituted.
// The check reads RAM without logging effects. Single-threaded guest only.
//
// Phase 3 adds validateTargetSet: the SAME canonicalisation and membership rule, without the live-cell comparison, for
// callbacks that are not read from one fixed cell (a callback argument, an entry of a callback ring). It shares
// cell_detail::requireMember with validateCellTarget; there is deliberately no second membership implementation.
#include "recomp_dispatch.hpp"
#include <sstream>
#include <vector>

namespace moyle::detail {
struct CellSite {
    std::uint32_t site=0;                 // JALR PC (diagnostics)
    std::uint32_t cell=0;                 // pointer cell; for a field site, the cell holding the object pointer
    std::uint32_t offset=0;               // field offset inside M[cell]; 0 for a plain cell
    bool field=false;
    std::vector<std::uint32_t> targets;   // proven function entries (any alias spelling)
};
namespace cell_detail {
inline std::uint32_t peek(const Ps1Memory& ram,std::uint32_t address) {
    const auto at=Ps1Memory::offset(address,4); // RAM-only, aligned; throws std::out_of_range otherwise
    return std::uint32_t(ram.bytes[at])|std::uint32_t(ram.bytes[at+1])<<8|std::uint32_t(ram.bytes[at+2])<<16|std::uint32_t(ram.bytes[at+3])<<24;
}
// `canonical` is already the canonical RAM spelling of the captured target (null/unaligned handled by the caller).
template<class Reject>
inline void requireMember(const std::vector<std::uint32_t>& targets,std::uint32_t canonical,const Reject& reject) {
    for(const auto target:targets){
        std::uint32_t proven=0;
        try{proven=recomp::canonicalCodeAddress(target);}catch(const std::out_of_range&){continue;}
        if(proven==canonical)return;
    }
    reject("target is not a member of the proven set");
}
[[noreturn]] inline void reject(const CellSite& s,std::uint32_t captured,const char* why) {
    std::ostringstream message;
    message<<"resolved-indirect-cell-guarded validation failed at 0x"<<std::hex<<s.site<<" (cell=0x"<<s.cell;
    if(s.field)message<<"+0x"<<s.offset;
    message<<", captured=0x"<<captured<<"): "<<why<<"; dynamic dispatch is not enabled for this edge";
    throw std::runtime_error(message.str());
}
}
// Called at the JALR, BEFORE its delay slot. Returns `captured` (the original virtual spelling is kept so RA/PC alias
// semantics survive) or throws std::runtime_error without touching guest state.
inline std::uint32_t validateCellTarget(const Ps1Memory& ram,const CellSite& s,std::uint32_t captured) {
    if(s.targets.empty())cell_detail::reject(s,captured,"empty proven target set");
    std::uint32_t live=0;
    try{
        std::uint32_t slot=s.cell;
        if(s.field){
            const auto object=cell_detail::peek(ram,s.cell);
            if(!object)cell_detail::reject(s,captured,"object pointer cell is null");
            slot=object+s.offset;
        }
        live=cell_detail::peek(ram,slot);
    }catch(const std::out_of_range&){cell_detail::reject(s,captured,"pointer cell or object is unaligned or unmapped");}
    if(captured!=live)cell_detail::reject(s,captured,"captured target differs from the live RAM cell");
    std::uint32_t canonical=0;
    try{canonical=recomp::canonicalCodeAddress(captured);}
    catch(const std::out_of_range&){cell_detail::reject(s,captured,"unaligned or unmapped code address");}
    if(canonical==0x80000000U)cell_detail::reject(s,captured,"null function pointer");
    cell_detail::requireMember(s.targets,canonical,[&](const char* why){cell_detail::reject(s,captured,why);});
    return captured;
}
struct SetSite {
    std::uint32_t site=0;                 // JALR PC (diagnostics)
    std::vector<std::uint32_t> targets;   // proven function entries (any alias spelling)
};
// Called at the JALR, BEFORE its delay slot. Membership only: null, unaligned, unmapped and unknown targets are fatal.
inline std::uint32_t validateTargetSet(const SetSite& s,std::uint32_t captured) {
    const auto reject=[&](const char* why){
        std::ostringstream message;
        message<<"resolved-indirect-set-guarded validation failed at 0x"<<std::hex<<s.site<<" (captured=0x"<<captured
               <<"): "<<why<<"; dynamic dispatch is not enabled for this edge";
        throw std::runtime_error(message.str());
    };
    if(s.targets.empty())reject("empty proven target set");
    std::uint32_t canonical=0;
    try{canonical=recomp::canonicalCodeAddress(captured);}
    catch(const std::out_of_range&){reject("unaligned or unmapped code address");}
    if(canonical==0x80000000U)reject("null function pointer");
    cell_detail::requireMember(s.targets,canonical,reject);
    return captured;
}
}
