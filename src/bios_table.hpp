#pragma once
// The kernel function-table entries the host runtime implements and discovery therefore treats as resolved boundaries
// (tools/recomp/discovery.hpp `biosHleSupported`). One list, two consumers. `phase3Table` is the Phase 3 set implemented by
// src/bios_boundary.hpp; `bootTable` is the Phase 4 extension implemented by src/bios_boot.hpp (opt-in `--boot-bios`).
// The names are external psx-spx / PsyQ knowledge and are NOT evidence; the argument/return/effect semantics live in the
// two policy headers and are justified there from the PAL call sites.
#include <cstdint>

namespace moyle::detail::recomp::bios {
struct TableEntry {std::uint32_t table,function;const char* name;};
inline constexpr TableEntry phase3Table[]={
    {0xb0U,0x35U,"write"},{0xb0U,0x5bU,"ChangeClearPad"},{0xc0U,0x0aU,"ChangeClearRCnt"},
};
inline constexpr TableEntry bootTable[]={
    {0xa0U,0x39U,"InitHeap"},{0xa0U,0x44U,"FlushCache"},{0xa0U,0x49U,"GPU_cw"},{0xa0U,0x72U,"CdRemove"},
    {0xb0U,0x07U,"DeliverEvent"},{0xb0U,0x08U,"OpenEvent"},{0xb0U,0x0aU,"WaitEvent"},{0xb0U,0x0bU,"TestEvent"},
    {0xb0U,0x0cU,"EnableEvent"},{0xb0U,0x17U,"ReturnFromException"},{0xb0U,0x19U,"SetCustomExitFromException"},
};
// Phase 5 (opt-in `--boot-card`): the one libcard kernel call the PAL's pad/card init reaches next. State-only, see src/bios_boot.hpp.
inline constexpr TableEntry cardTable[]={
    {0xb0U,0x4aU,"InitCARD"},
};
inline const TableEntry* findEntry(std::uint32_t table,std::uint32_t function) {
    for(const auto& e:phase3Table)if(e.table==table&&e.function==function)return &e;
    return nullptr;
}
inline const TableEntry* findBootEntry(std::uint32_t table,std::uint32_t function,bool card=false) {
    if(const auto* e=findEntry(table,function))return e;
    for(const auto& e:bootTable)if(e.table==table&&e.function==function)return &e;
    if(card)for(const auto& e:cardTable)if(e.table==table&&e.function==function)return &e;
    return nullptr;
}
}
