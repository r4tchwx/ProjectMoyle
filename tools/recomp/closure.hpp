#pragma once
// Phase 2C closure of indirect control flow (explicit opt-in; the default discovery is untouched).
//
// Everything here is derived from the executable itself. Nothing is guessed and no site is accepted merely
// because it is a JALR/JR:
//   * bounded static JR tables are verified by the v2 matcher (index bound + table words in the owning function);
//   * a JALR through a fixed guest cell M[A], or through one field of a fixed object M[M[P]+off], is closed only when
//     every STATIC writer of that location stores a code constant, and nothing in the text materializes the cell's
//     address as data. The resulting target set is a *guarded* static set: the runtime must still compare the captured
//     target with the live RAM cell and require membership (src/indirect_cells.hpp). Absence of an observed writer is
//     not proof of immutability, overlays and unmodelled indirect stores are outside this proof.
//   * everything else (callback arguments, indexed array fields, pointers loaded through computed pointers) is
//     classified and left unresolved.
#include "static_table_matcher.hpp"
#include <functional>
#include <optional>

namespace recomp_tool::closure {
using u32=std::uint32_t;
using u64=std::uint64_t;
struct TextRange {u32 begin=0,end=0;}; // [begin,end) executable words; the data after it is only used for jump/pointer leaders
// Documented analysis windows (named so the tests and the report can state them).
inline constexpr u32 kAliasWindow=0x40;   // a materialized address up to this far below a cell may be the base of an enclosing object
inline constexpr u32 kIndexWindow=0x100;  // an indexed store based up to this far below a cell may reach it
inline constexpr u32 kSummaryWords=1024;  // analysis bound for function return-value summaries
inline constexpr unsigned kMaxRounds=16;

// ---- abstract values ---------------------------------------------------------------------------------------------
struct V {
    enum K : std::uint8_t {Unknown,Const,Param,Cell,Field,Idx,IdxLoad,Opaque} k=Unknown;
    u32 a=0,b=0;
    bool mat=false; // Const produced by an addiu/ori/addu from a non-zero constant: an address materialization
    bool same(const V& o) const {return k==o.k&&a==o.a&&b==o.b;}
};
inline V mk(V::K k,u32 a=0,u32 b=0,bool mat=false){V v;v.k=k;v.a=a;v.b=b;v.mat=mat;return v;}
inline V joinV(const V& x,const V& y){if(x.same(y)){V r=x;r.mat=x.mat||y.mat;return r;}return {};}
struct State {std::array<V,32> r{},pending{};std::array<bool,32> has{};};
inline void retire(State& s){for(unsigned n=1;n<32;++n)if(s.has[n])s.r[n]=s.pending[n];s.pending={};s.has={};}
struct Obs {
    std::function<void(u32 pc,unsigned op,const V& base,std::int32_t imm,const V& value)> store;
    std::function<void(const V& value,u32 pc)> use;
};
inline void step(State& s,u32 pc,u32 w,const Obs* obs) {
    const u32 op=w>>26,rs=(w>>21)&31,rt=(w>>16)&31,rd=(w>>11)&31,fn=w&63,sh=(w>>6)&31,u=w&0xffff;
    const std::int32_t simm=static_cast<std::int16_t>(u);
    const V a=s.r[rs],b=s.r[rt];
    const auto use=[&](const V& v){if(obs&&obs->use)obs->use(v,pc);};
    if(op==0&&fn==12){for(unsigned n=1;n<32;++n)s.r[n]={};s.pending={};s.has={};return;} // SYSCALL: handler may rewrite anything
    retire(s);
    V result;unsigned dest=0;bool load=false;
    if(op==15){dest=rt;result=mk(V::Const,u<<16);}
    else if(op==9||op==8){dest=rt;
        if(a.k==V::Const)result=mk(V::Const,a.a+static_cast<u32>(simm),0,a.a!=0);
        else if(a.k==V::Idx)result=mk(V::Idx,a.a+static_cast<u32>(simm));
        else use(a);}
    else if(op==13){dest=rt;
        if(a.k==V::Const)result=mk(V::Const,a.a|u,0,a.a!=0);else use(a);}
    else if(op==12||op==14||op==10||op==11){dest=rt;use(a);}
    else if(op==35){dest=rt;load=true;
        if(a.k==V::Const)result=mk(V::Cell,a.a+static_cast<u32>(simm));
        else if(a.k==V::Cell)result=mk(V::Field,a.a,static_cast<u32>(simm));
        else if(a.k==V::Idx)result=mk(V::IdxLoad,a.a+static_cast<u32>(simm));
        else result=mk(V::Opaque);}
    else if(op==32||op==33||op==34||op==36||op==37||op==38){dest=rt;load=true;}
    else if(op==43||op==40||op==41||op==42||op==46){use(b);if(obs&&obs->store)obs->store(pc,op,a,simm,b);}
    else if(op==58){if(obs&&obs->store)obs->store(pc,op,a,simm,V{});}
    else if(op==50){}
    else if(op==0){
        switch(fn){
        case 0: dest=rd;if(b.k==V::Const)result=mk(V::Const,b.a<<sh);else use(b);break;
        case 32: case 33: case 37: {
            dest=rd;
            if(b.k==V::Const&&b.a==0&&!b.mat)result=a;
            else if(a.k==V::Const&&a.a==0&&!a.mat)result=b;
            else if(a.k==V::Const&&b.k==V::Const)result=mk(V::Const,fn==37?(a.a|b.a):(a.a+b.a),0,true);
            else if(fn!=37&&a.k==V::Const){use(b);result=mk(V::Idx,a.a);}
            else if(fn!=37&&b.k==V::Const){use(a);result=mk(V::Idx,b.a);}
            else if(fn!=37&&a.k==V::Idx&&b.k==V::Const)result=mk(V::Idx,a.a+b.a);
            else if(fn!=37&&b.k==V::Idx&&a.k==V::Const)result=mk(V::Idx,b.a+a.a);
            else {use(a);use(b);}
            break;}
        case 8: case 9: break; // control: handled by the drivers
        case 24: case 25: case 26: case 27: case 17: case 19: use(a);break;
        default: dest=rd;use(a);use(b);break;
        }
    }
    else if(op==16||op==18){if(rs==0||rs==2)dest=rt;}
    else if(op==17||op==19||op==48||op==49||op==56||op==57){}
    else dest=rt;
    if(dest){if(load){s.pending[dest]=result;s.has[dest]=true;}else s.r[dest]=result;}
    s.r[0]=mk(V::Const,0);s.pending[0]={};s.has[0]=false;
}
inline void afterCall(State& s,const V& v0) {
    for(unsigned n=1;n<32;++n){const bool saved=(n>=16&&n<=23)||n==28||n==29||n==30;if(!saved)s.r[n]={};}
    s.r[2]=v0;s.pending={};s.has={};
}
inline bool joinInto(State& old,const State& s) {
    bool changed=false;
    for(unsigned n=1;n<32;++n){
        const auto j=joinV(old.r[n],s.r[n]);
        if(!(j.same(old.r[n])&&j.mat==old.r[n].mat)){old.r[n]=j;changed=true;}
        if(old.has[n]!=s.has[n]){if(!old.has[n]||old.pending[n].k!=V::Unknown)changed=true;old.has[n]=true;old.pending[n]={};}
        else if(old.has[n]){const auto p=joinV(old.pending[n],s.pending[n]);if(!(p.same(old.pending[n])&&p.mat==old.pending[n].mat)){old.pending[n]=p;changed=true;}}
    }
    return changed;
}
inline u32 jumpTarget(u32 pc,u32 w){return ((pc+4)&0xf0000000U)|((w&0x3ffffffU)<<2);}
inline u32 branchTarget(u32 pc,u32 w){return pc+4+static_cast<u32>(static_cast<std::int32_t>(static_cast<std::int16_t>(w&0xffff)))*4U;}

// ---- per-function dataflow (site provenance and return summaries) -------------------------------------------------
// One call/jump transfer with the argument registers a0..a3 as they are on entry to the callee (after the delay slot).
struct CallRec {u32 kind=0;u32 target=0;V value;std::array<V,4> args{};}; // kind: 3 = JAL, 2 = J, 9 = JALR (value = rs)
struct FuncFlow {
    std::map<u32,V> sites;   // generic JR/JALR PC -> abstract value of rs at the transfer (before its slot)
    std::map<u32,V> returns; // JR ra PC -> abstract v0 after the slot
    std::map<u32,CallRec> calls; // JAL / J / JALR PC -> arguments handed to the callee (Phase 3 parameter propagation)
    bool complete=true;      // false when the walk left the bound, met a control slot or an unsupported link form
};
class Analyzer {
public:
    Analyzer(const Image& image,TextRange text,std::set<u32> starts):image_(image),text_(text),starts_(std::move(starts)) {
        for(u32 pc=text_.begin;pc<text_.end;pc+=4){const auto w=image_.at(pc);if((w>>26)==3)starts_.insert(jumpTarget(pc,w));}
    }
    u32 ceilingFor(u32 entry,u64 words) const {
        u64 c=std::min<u64>(std::min<u64>(text_.end,std::uint64_t(entry)+4*words),std::uint64_t(image_.base)+image_.size);
        const auto next=starts_.upper_bound(entry);
        if(next!=starts_.end())c=std::min<u64>(c,*next);
        return static_cast<u32>(c);
    }
    // v0 is a single constant on every return of a completely analysed callee, else nullopt.
    std::optional<u32> returnConst(u32 entry) {
        const auto found=memo_.find(entry);if(found!=memo_.end())return found->second;
        if(!inProgress_.insert(entry).second||!image_.contains(entry)||entry<text_.begin||entry>=text_.end)return std::nullopt;
        std::optional<u32> result;
        const auto flow=analyze(entry,ceilingFor(entry,kSummaryWords));
        if(flow.complete&&!flow.returns.empty()){
            bool ok=true;u32 value=0;bool first=true;
            for(const auto& r:flow.returns){
                if(r.second.k!=V::Const){ok=false;break;}
                if(first){value=r.second.a;first=false;}else if(value!=r.second.a){ok=false;break;}
            }
            if(ok)result=value;
        }
        inProgress_.erase(entry);memo_[entry]=result;return result;
    }
    FuncFlow analyze(u32 entry,u32 ceiling,const Obs* obs=nullptr) {
        FuncFlow out;std::map<u32,State> states;std::deque<u32> queue;
        const auto valid=[&](std::uint64_t pc){return !(pc&3)&&pc>=entry&&pc+4<=ceiling&&image_.contains(pc);};
        const auto merge=[&](u32 pc,const State& s){
            if(!valid(pc)){out.complete=false;return;}
            auto fresh=states.emplace(pc,s);bool changed=fresh.second;
            if(!fresh.second)changed=joinInto(fresh.first->second,s);
            if(changed)queue.push_back(pc);
        };
        State init;init.r[0]=mk(V::Const,0);
        for(unsigned r=4;r<=7;++r)init.r[r]=mk(V::Param,r);
        merge(entry,init);
        while(!queue.empty()){
            const auto pc=queue.front();queue.pop_front();auto s=states.at(pc);const auto w=image_.at(pc);
            if(!controlWord(w)){step(s,pc,w,obs);merge(pc+4,s);continue;}
            if(!valid(std::uint64_t(pc)+4)){out.complete=false;continue;}
            const auto slot=image_.at(pc+4);
            if(controlWord(slot)){out.complete=false;continue;}
            const u32 op=w>>26,rs=(w>>21)&31,rt=(w>>16)&31,rd=(w>>11)&31,fn=w&63;
            const V target=s.r[rs];
            retire(s);step(s,pc+4,slot,obs);
            const bool jr=op==0&&fn==8,jalr=op==0&&fn==9;
            if(jr||jalr)out.sites[pc]=target;
            if(op==3||op==2||jalr){
                CallRec rec;rec.kind=jalr?9:op;rec.target=jalr?0:jumpTarget(pc,w);rec.value=target;
                for(unsigned r=0;r<4;++r)rec.args[r]=s.has[4+r]?V{}:s.r[4+r]; // a load pending into an argument is not yet visible
                out.calls[pc]=rec;
            }
            if(op==3){auto t=s;afterCall(t,mk(V::Unknown));const auto rc=returnConst(jumpTarget(pc,w));if(rc)t.r[2]=mk(V::Const,*rc);merge(pc+8,t);}
            else if(jalr){auto t=s;afterCall(t,mk(V::Unknown));if(rd!=0)merge(pc+8,t);}
            else if(jr){if(rs==31){V v0=s.r[2];if(s.has[2])v0={};out.returns[pc]=v0;}}
            else if(op==2)merge(jumpTarget(pc,w),s);
            else if(op==1&&rt>=16)out.complete=false;
            else {merge(branchTarget(pc,w),s);merge(pc+8,s);}
        }
        return out;
    }
private:
    const Image& image_;TextRange text_;std::set<u32> starts_;
    std::map<u32,std::optional<u32>> memo_;std::set<u32> inProgress_;
};

// ---- whole-text writer index -------------------------------------------------------------------------------------
struct StoreRec {u32 pc=0;unsigned op=0;V value;};
struct IdxRec {u32 addr=0,pc=0;unsigned op=0;V value;}; // store through computed (array + index) address; addr = constant part + imm
struct Escape {u32 value=0,pc=0;};
struct WriterIndex {
    std::multimap<u32,StoreRec> constStores;                 // effective address -> store
    std::multimap<std::pair<u32,u32>,StoreRec> fieldStores;  // (cell, offset): store through a pointer loaded from cell
    std::vector<std::pair<u32,u32>> idxStores;               // (array base + imm, pc)
    std::vector<IdxRec> idxRecs;                             // same stores with their op and value (Phase 3 registries)
    std::vector<Escape> escapes;                             // materialized constants used other than as a load/store base
    std::vector<Escape> cellEscapes;                         // pointers loaded from a fixed cell used other than as a base
    std::uint64_t unknownBaseStores=0;
    std::set<u32> delaySlots;
};
inline std::pair<u32,u32> storeRange(unsigned op,u32 ea) {
    switch(op){
    case 40: return {ea,ea};
    case 41: return {ea,ea+1};
    case 42: return {ea&~3U,ea};
    case 46: return {ea,ea|3U};
    default: return {ea,ea+3};
    }
}
// li t2,{0xa0,0xb0,0xc0}; jr t2; li t1,N: the kernel function-table thunk the PAL libraries use.
inline bool isBiosThunk(const Image& image,u32 entry) {
    if(!image.contains(entry)||!image.contains(entry+8))return false;
    const auto w0=image.at(entry),w1=image.at(entry+4),w2=image.at(entry+8);
    const auto table=w0&0xffU;
    return (w0&0xffffff00U)==0x240a0000U&&(table==0xa0||table==0xb0||table==0xc0)&&w1==0x01400008U&&(w2&0xffff0000U)==0x24090000U;
}
inline WriterIndex buildIndex(const Image& image,TextRange text,Analyzer& analyzer) {
    WriterIndex idx;std::set<u32> leaders{text.begin};
    for(u32 pc=text.begin;pc<text.end;pc+=4){
        const auto w=image.at(pc);const auto op=w>>26;
        if(!controlWord(w))continue;
        idx.delaySlots.insert(pc+4);
        if(op==2||op==3)leaders.insert(jumpTarget(pc,w));
        else if(op==1||(op>=4&&op<=7))leaders.insert(branchTarget(pc,w));
    }
    // Any data word that looks like a code address may be a jump-table slot or function pointer: start a block there.
    for(std::uint64_t pc=text.end;pc+4<=std::uint64_t(image.base)+image.size;pc+=4){
        const auto v=image.at(static_cast<u32>(pc));
        if(!(v&3)&&v>=text.begin&&v<text.end)leaders.insert(v);
    }
    Obs obs;
    obs.store=[&](u32 pc,unsigned op,const V& base,std::int32_t imm,const V& value){
        const u32 off=static_cast<u32>(imm);
        if(base.k==V::Const)idx.constStores.emplace(base.a+off,StoreRec{pc,op,value});
        else if(base.k==V::Cell)idx.fieldStores.emplace(std::make_pair(base.a,off),StoreRec{pc,op,value});
        else if(base.k==V::Idx){idx.idxStores.emplace_back(base.a+off,pc);idx.idxRecs.push_back({base.a+off,pc,op,value});}
        else ++idx.unknownBaseStores;
    };
    obs.use=[&](const V& v,u32 pc){
        if(v.k==V::Const&&v.mat)idx.escapes.push_back({v.a,pc});
        else if(v.k==V::Cell)idx.cellEscapes.push_back({v.a,pc});
    };
    State s;s.r[0]=mk(V::Const,0);
    for(u32 pc=text.begin;pc<text.end;){
        if(leaders.count(pc)){ // live materialized values entering an unanalysed block are escapes
            for(unsigned n=1;n<32;++n)obs.use(s.r[n],pc);
            s=State{};s.r[0]=mk(V::Const,0);
        }
        const auto w=image.at(pc);
        if(!controlWord(w)){step(s,pc,w,&obs);pc+=4;continue;}
        if(pc+8>text.end){pc+=4;continue;}
        const auto slot=image.at(pc+4);
        const u32 op=w>>26,rs=(w>>21)&31,rd=(w>>11)&31,fn=w&63;
        retire(s);
        if(!controlWord(slot))step(s,pc+4,slot,&obs);
        if(op==3||(op==0&&fn==9)){
            // Arguments handed to an unknown callee escape; a BIOS thunk is a runtime boundary we implement ourselves.
            if(!(op==3&&isBiosThunk(image,jumpTarget(pc,w))))for(unsigned n=4;n<=7;++n)obs.use(s.r[n],pc);
            const auto rc=op==3?analyzer.returnConst(jumpTarget(pc,w)):std::optional<u32>{};
            afterCall(s,rc?mk(V::Const,*rc):mk(V::Unknown));
            if(op==0&&rd==0){s=State{};s.r[0]=mk(V::Const,0);}
        } else if(op==2||(op==0&&fn==8)){
            // A return hands back v0/v1 only (everything else is dead by the ABI); any other transfer may carry any register.
            if(op==0&&rs==31){for(unsigned n=2;n<=3;++n)obs.use(s.r[n],pc);}
            else for(unsigned n=1;n<32;++n)if(!(op==0&&n==31))obs.use(s.r[n],pc);
            s=State{};s.r[0]=mk(V::Const,0);
        }
        pc+=8; // the slot was consumed with its control instruction
    }
    return idx;
}

// ---- proofs --------------------------------------------------------------------------------------------------------
struct Proof {std::optional<CellProof> proof;std::string reason;};
class Prover {
public:
    Prover(const Image& image,TextRange text,const WriterIndex& idx):image_(image),text_(text),idx_(idx) {}
    Proof cell(u32 a) const {
        CellProof p;p.cell=a;
        std::string why;
        if(!writers(a,p.writers,why))return {{},why};
        if(const auto e=escapeNear(a,a))return {{},"address near cell materialized as data at "+hex(*e)};
        if(const auto e=indexedNear(a))return {{},"indexed store based below the cell at "+hex(*e)+" may reach it"};
        if(!image_.contains(a))return {{},"cell outside the executable payload: initial value unknown"};
        p.initial=image_.at(a);
        return finish(p);
    }
    // Phase 3: a fixed cell that no static writer ever stores to and whose initial value is null. The proven target set
    // is EMPTY, so the runtime guard (src/indirect_cells.hpp) rejects every non-null callback. Unlike cell() this does
    // not refuse because the cell address leaks to callees; each leak is listed as an assumption instead. The guard is
    // what keeps this sound: a callee that did store a code pointer would turn into a fatal diagnostic, never a call.
    Proof cellEmpty(u32 a) const {
        CellProof p;p.cell=a;p.empty=true;std::string why;
        if(!writers(a,p.writers,why))return {{},why};
        if(!p.writers.empty())return {{},"cell has constant writers"};
        if(const auto e=indexedNear(a))return {{},"indexed store based below the cell at "+hex(*e)+" may reach it"};
        if(!image_.contains(a))return {{},"cell outside the executable payload: initial value unknown"};
        p.initial=image_.at(a);
        if(p.initial)return {{},"cell is initially non-null"};
        const u32 from=a>kAliasWindow?a-kAliasWindow:0;
        for(const auto& e:idx_.escapes)if(e.value>=from&&e.value<=a+3)
            p.assumptions.push_back("address near the cell escapes to a callee at "+hex(e.pc)+" (value "+hex(e.value)+")");
        std::sort(p.assumptions.begin(),p.assumptions.end());
        p.assumptions.erase(std::unique(p.assumptions.begin(),p.assumptions.end()),p.assumptions.end());
        return {p,{}};
    }
    // `leaks` (Phase 3, optional): when non-null the three "address leaks to a callee as data" refusals are recorded there
    // instead of failing. Writers that are not code constants, a missing/unaligned object and indexed stores still fail.
    Proof field(u32 cell,u32 off,std::vector<std::string>* leaks=nullptr) const {
        CellProof p;p.cell=cell;p.offset=off;p.field=true;
        std::vector<std::pair<u32,u32>> own;std::string why;
        if(!writers(cell,own,why))return {{},"object pointer cell: "+why};
        if(!own.empty())return {{},"object pointer cell has constant writers; the object is not unique"};
        if(!image_.contains(cell))return {{},"object pointer cell outside the executable payload"};
        const u32 object=image_.at(cell);
        if(!object||(object&3)||!image_.contains(object))return {{},"object pointer cell does not hold an aligned in-payload object"};
        for(const auto& e:idx_.cellEscapes)if(e.value==cell){
            if(!leaks)return {{},"pointer loaded from the cell is used as data at "+hex(e.pc)};
            leaks->push_back("the object pointer loaded from "+hex(cell)+" is used as data at "+hex(e.pc));
        }
        if(const auto e=escapeNear(cell,cell)){
            if(!leaks)return {{},"address near the pointer cell materialized as data at "+hex(*e)};
            leaks->push_back("an address near the pointer cell "+hex(cell)+" is materialized as data at "+hex(*e));
        }
        const u32 slot=object+off;
        // Stores through the cell's pointer at exactly this offset.
        for(const auto& s:idx_.fieldStores){
            if(s.first.first!=cell)continue;
            const auto range=storeRange(s.second.op,s.first.second);
            if(range.second<off||range.first>off+3)continue;
            if(s.second.op==43&&s.first.second==off&&s.second.value.k==V::Const)p.writers.emplace_back(s.second.pc,s.second.value.a);
            else return {{},"partial or non-constant store through the object pointer at "+hex(s.second.pc)};
        }
        // Direct constant-address stores to the same slot.
        if(!writers(slot,p.writers,why))return {{},why};
        if(const auto e=escapeNear(object,slot)){
            if(!leaks)return {{},"object address materialized as data at "+hex(*e)};
            leaks->push_back("the object address "+hex(object)+" is materialized as data at "+hex(*e));
        }
        if(const auto e=indexedNear(slot))return {{},"indexed store based below the slot at "+hex(*e)+" may reach it"};
        if(!image_.contains(slot))return {{},"slot outside the executable payload: initial value unknown"};
        p.initial=image_.at(slot);
        return finish(p);
    }
    bool validTarget(u32 t) const {
        return t&&!(t&3)&&t>=text_.begin&&t<text_.end&&!idx_.delaySlots.count(t);
    }
private:
    bool writers(u32 a,std::vector<std::pair<u32,u32>>& out,std::string& why) const {
        for(u32 key=a>=3?a-3:0;key<=a+3;++key){
            const auto range=idx_.constStores.equal_range(key);
            for(auto it=range.first;it!=range.second;++it){
                const auto r=storeRange(it->second.op,it->first);
                if(r.second<a||r.first>a+3)continue;
                if(it->second.op==43&&it->first==a&&it->second.value.k==V::Const)out.emplace_back(it->second.pc,it->second.value.a);
                else {why="partial or non-constant writer at "+hex(it->second.pc);return false;}
            }
        }
        return true;
    }
    std::optional<u32> escapeNear(u32 lo,u32 hi) const {
        const u32 from=lo>kAliasWindow?lo-kAliasWindow:0;
        for(const auto& e:idx_.escapes)if(e.value>=from&&e.value<=hi+3)return e.pc;
        return std::nullopt;
    }
    std::optional<u32> indexedNear(u32 a) const {
        for(const auto& s:idx_.idxStores)if(s.first<=a&&a<s.first+kIndexWindow)return s.second;
        return std::nullopt;
    }
    Proof finish(CellProof p) const {
        std::set<u32> targets;
        for(const auto& w:p.writers)targets.insert(w.second);
        if(p.initial)targets.insert(p.initial);
        for(auto t:targets)if(!validTarget(t))return {{},"candidate "+hex(t)+" is not an aligned non-delay-slot code address inside the text"};
        if(targets.empty())return {{},"no non-null target: never written and initially null"};
        p.targets.assign(targets.begin(),targets.end());
        std::sort(p.writers.begin(),p.writers.end());
        return {p,{}};
    }
    const Image& image_;TextRange text_;const WriterIndex& idx_;
};

// ---- site classification and the closure driver ---------------------------------------------------------------------
inline std::string describe(const V& v) {
    switch(v.k){
    case V::Const: return "constant "+hex(v.a);
    case V::Param: return "register r"+std::to_string(v.a)+" on function entry";
    case V::Cell: return "M["+hex(v.a)+"]";
    case V::Field: return "M[M["+hex(v.a)+"]+"+hex(v.b)+"]";
    case V::Idx: return "computed address "+hex(v.a)+" + index";
    case V::IdxLoad: return "M["+hex(v.a)+" + index]";
    case V::Opaque: return "load through a computed pointer";
    default: return "no provenance";
    }
}
inline const char* kindOf(const V& v) {
    switch(v.k){
    case V::Const: return "constant";
    case V::Param: return "argument-callback";
    case V::Cell: return "fixed-cell";
    case V::Field: return "object-field";
    case V::Idx: return "computed-address";
    case V::IdxLoad: return "indexed-array-field";
    case V::Opaque: return "computed-pointer-load";
    default: return "unknown";
    }
}
inline u32 functionCeiling(const Image& image,const Seed& seed,const std::map<u32,Function>& functions,u32 derivedWords) {
    (void)derivedWords;
    std::uint64_t ceiling=std::min<std::uint64_t>(std::uint64_t(image.base)+image.size,std::uint64_t(seed.entry)+4ULL*seed.words);
    const auto next=functions.upper_bound(seed.entry);
    if(next!=functions.end())ceiling=std::min<std::uint64_t>(ceiling,next->first);
    return static_cast<u32>(ceiling);
}
// Phase 3 opt-ins. Everything defaults to off, which reproduces the Phase 2C closure exactly.
//  trapBreak: exact divide-by-zero BREAK idiom is a terminal fatal trap (DiscoveryOptions::trapBreak)
//  biosHle:   implemented BIOS thunks are resolved boundaries (DiscoveryOptions::biosHle)
//  callbacks: parameter-set / ring-registry / empty-cell proofs for the callback sites Phase 2C left open
// Phase 4: a callback target set pinned by the boot manifest for one unresolved `jalr` site (when the dataflow engine cannot model the
// loop that indexes the callback table). It is NOT an automatic proof: the generated code guards it with the same membership check as
// every other set (validateTargetSet), so a target outside the pinned set is a fatal diagnostic, and the evidence string is carried
// into the discovery/report output.
struct PinnedSet {std::vector<u32> targets;std::string evidence;};
struct Extras {std::vector<table_v2::HostPolicy> hostTables;std::map<u32,std::string> hostTableEvidence; // --table-host SITE BASE COUNT EVIDENCE
    bool trapBreak=false,biosHle=false,callbacks=false,bootBios=false,bootIsa=false,bootCard=false,bootGte=false,haltLoops=false;std::set<u32> noReturn;std::map<u32,PinnedSet> pinnedSets;
    std::map<u32,std::vector<std::pair<u32,u32>>> deadGaps; // --dead-gap ENTRY BEGIN END
    // --callback-empty SITE CELL EVIDENCE: the site's fixed cell is pinned as a proven-EMPTY set (targets[0] is the cell).
    // Guarded at run time exactly like a derived empty cell (validateCellTarget): any non-null or null value is fatal.
    std::map<u32,PinnedSet> pinnedEmpty;
    // --external-entry ENTRY EVIDENCE: JAL targets outside the payload that are public entries of another generated unit
    // (the PAL type-2 overlay at 0x80010200), dispatched through the DynamicRegistry at run time.
    std::map<u32,std::string> externalEntries;
    bool sharedDelaySlots=false; // --shared-delay-slots (DiscoveryOptions::sharedDelaySlots)
};
struct Result {Discovery discovery;ClosureProofs proofs;};
// Runs extended discovery to a fixed point with proofs derived from the executable. Legacy output is unaffected: this
// is a separate entry point, and discover() without `closure` never looks at proofs.
inline Result closureDiscover(const std::vector<std::uint8_t>& bytes,const std::vector<Seed>& seeds,const std::vector<Region>& scans,
                              TextRange text,u32 derivedWords=1024,Extras extras={}) {
    const Image image(bytes);
    if(text.begin>=text.end||(text.begin&3)||(text.end&3)||!image.contains(text.begin)||!image.contains(text.end-4))
        throw std::runtime_error("Invalid closure text range");
    for(const auto& e:extras.externalEntries){
        if((e.first&3)||e.first<0x80000000U||e.first>=0x80200000U)throw std::runtime_error("External entry "+hex(e.first)+" is not an aligned KSEG0 RAM address");
        if(image.contains(e.first))throw std::runtime_error("External entry "+hex(e.first)+" lies inside the executable payload");
        if(e.second.empty())throw std::runtime_error("External entry "+hex(e.first)+" has no evidence");
    }
    Result result;
    std::set<u32> startSeed;for(const auto& s:seeds)startSeed.insert(s.entry);
    Analyzer analyzer(image,text,startSeed);
    const auto index=buildIndex(image,text,analyzer);
    const Prover prover(image,text,index);
    std::map<u32,std::string> failed; // last failure reason per unresolved site
    unsigned round=0;
    std::map<u32,FuncFlow> flowCache; // per round: dataflow of every discovered function (Phase 3 propagation)
    for(;round<kMaxRounds;) {
        ++round;
        DiscoveryOptions options;options.extendedIsa=true;options.closure=true;options.derivedWords=derivedWords;options.proofs=&result.proofs;
        options.trapBreak=extras.trapBreak;options.biosHle=extras.biosHle;options.bootBios=extras.bootBios;options.bootIsa=extras.bootIsa;options.bootCard=extras.bootCard;options.bootGte=extras.bootGte;options.haltLoops=extras.haltLoops;options.deadGaps=&extras.deadGaps;options.noReturn=&extras.noReturn;
        if(!extras.externalEntries.empty())options.externalEntries=&extras.externalEntries;
        options.sharedDelaySlots=extras.sharedDelaySlots;
        result.discovery=discover(bytes,seeds,scans,options);
        auto& d=result.discovery;bool grew=false;
        flowCache.clear();
        const auto flowOf=[&](u32 entry)->const FuncFlow&{
            auto found=flowCache.find(entry);
            if(found==flowCache.end())found=flowCache.emplace(entry,analyzer.analyze(entry,functionCeiling(image,d.functions.at(entry).seed,d.functions,derivedWords))).first;
            return found->second;
        };
        const auto ownerOf=[&](u32 pc)->std::optional<u32>{for(const auto& p:d.functions)if(p.second.body.count(pc))return p.first;return std::nullopt;};
        // Values a callee's argument register can hold, over every in-unit caller (direct/tail calls and calls through
        // proven guarded sets). A caller whose value is not itself provable makes the whole parameter unprovable.
        std::vector<std::string> acc; // escape assumptions used by the proof currently being built
        std::map<u32,std::map<u32,V>> storeCache; // owner entry -> store pc -> value at the analysis fixed point
        const auto storeValue=[&](u32 owner,u32 pc)->std::optional<V>{
            auto found=storeCache.find(owner);
            if(found==storeCache.end()){
                std::map<u32,V> values;Obs obs;
                obs.store=[&](u32 spc,unsigned,const V&,std::int32_t,const V& value){values[spc]=value;}; // last visit = joined state
                analyzer.analyze(owner,functionCeiling(image,d.functions.at(owner).seed,d.functions,derivedWords),&obs);
                found=storeCache.emplace(owner,std::move(values)).first;
            }
            const auto at=found->second.find(pc);
            if(at==found->second.end())return std::nullopt;
            return at->second;
        };
        std::function<bool(u32,unsigned,std::set<std::pair<u32,unsigned>>&,std::set<u32>&,std::vector<std::string>&,std::string&)> paramValues;
        paramValues=[&](u32 callee,unsigned reg,std::set<std::pair<u32,unsigned>>& visiting,std::set<u32>& out,
                        std::vector<std::string>& sources,std::string& why)->bool{
            if(!visiting.insert({callee,reg}).second)return true; // cycle: contributes no new value
            bool any=false;
            for(const auto& gp:d.functions){
                const u32 g=gp.first;const auto& gf=gp.second;
                for(const auto& cr:flowOf(g).calls){
                    const u32 site=cr.first;const auto& rec=cr.second;bool calls=false;
                    if(rec.kind==3||rec.kind==2)calls=rec.target==callee&&!(rec.kind==2&&g==callee);
                    else{
                        const auto gi=gf.guarded.find(site);
                        if(gi!=gf.guarded.end()&&gi->second.expectedTarget==callee)calls=true;
                        const auto ci=gf.cellCalls.find(site);
                        if(ci!=gf.cellCalls.end()&&std::find(ci->second.targets.begin(),ci->second.targets.end(),callee)!=ci->second.targets.end())calls=true;
                        const auto si=gf.setCalls.find(site);
                        if(si!=gf.setCalls.end()&&std::find(si->second.targets.begin(),si->second.targets.end(),callee)!=si->second.targets.end())calls=true;
                    }
                    if(!calls)continue;
                    any=true;const V& v=rec.args[reg-4];
                    const auto note=[&](const std::string& what){sources.push_back(hex(site)+": "+what);};
                    if(v.k==V::Const){out.insert(v.a);note("constant "+hex(v.a));}
                    else if(v.k==V::Cell||v.k==V::Field){
                        auto pr=v.k==V::Cell?prover.cell(v.a):prover.field(v.a,v.b);
                        if(!pr.proof&&v.k==V::Field){
                            // The object pointer leaks to another routine as data: keep the (still exact) slot value set, but
                            // say so. The consumer's membership guard is what makes this fail closed.
                            std::vector<std::string> leaks;const auto relaxed=prover.field(v.a,v.b,&leaks);
                            if(relaxed.proof){pr=relaxed;for(auto& l:leaks)acc.push_back(l);}
                        }
                        if(!pr.proof){why="caller "+hex(site)+" passes "+describe(v)+": "+pr.reason;return false;}
                        for(auto t:pr.proof->targets)out.insert(t);
                        note(describe(v));
                    }
                    else if(v.k==V::Param&&v.a>=4&&v.a<=7){
                        if(!paramValues(g,v.a,visiting,out,sources,why))return false;
                        note("argument r"+std::to_string(v.a)+" of "+hex(g));
                    }
                    else{why="caller "+hex(site)+" passes "+describe(v);return false;}
                }
            }
            if(!any){why="no in-unit caller of "+hex(callee);return false;}
            return true;
        };
        const auto finishSet=[&](u32 site,u32 owner,const char* kind,std::set<u32> values,std::vector<std::string> sources,
                                 std::vector<std::string> assumptions,std::string& why)->bool{
            for(auto t:values)if(!prover.validTarget(t)){why="candidate "+hex(t)+" is not an aligned non-delay-slot code address inside the text";return false;}
            if(values.empty()){why="empty candidate set";return false;}
            SetProof sp;sp.site=site;sp.rs=(image.at(site)>>21)&31;sp.function=owner;sp.kind=kind;
            sp.targets.assign(values.begin(),values.end());
            std::sort(sources.begin(),sources.end());sources.erase(std::unique(sources.begin(),sources.end()),sources.end());
            for(std::size_t n=0;n<sources.size();++n)sp.origin+=(n?"; ":"")+sources[n];
            sp.assumptions=std::move(assumptions);
            result.proofs.sets.emplace(site,sp);return true;
        };
        std::set<u32> entries;for(const auto& p:d.functions)entries.insert(p.first);
        for(const auto& pair:d.functions) {
            const auto& f=pair.second;
            const auto ceiling=functionCeiling(image,f.seed,d.functions,derivedWords);
            // Bounded static tables for unresolved JR sites (matcher: bound + table words inside the owning function).
            std::set<u32> jr;for(const auto& e:f.indirectJumps)if(((image.at(e.site))&63)==8&&e.rs!=31&&!result.proofs.switches.count(e.site))jr.insert(e.site);
            if(!jr.empty()&&f.seed.entry>=text.begin&&ceiling<=text.end){
                try{
                    const auto census=table_v2::discoverTables(bytes,{table_v2::Domain{f.seed.entry,ceiling}},table_v2::Domain{text.begin,text.end},{},extras.hostTables);
                    for(auto site:jr){
                        const auto found=census.resolved.find(site);
                        if(found!=census.resolved.end()&&!found->second.call&&(found->second.bound==table_v2::Bound::GuestBound||
                                                                (found->second.bound==table_v2::Bound::HostTrap&&extras.hostTableEvidence.count(site)))){
                            const auto& t=found->second;SwitchProof sp;sp.site=site;sp.rs=(image.at(site)>>21)&31;sp.table=t.base;sp.count=t.count;sp.defaultTarget=t.defaultTarget;sp.load=t.load;if(t.bound==table_v2::Bound::HostTrap)sp.evidence=extras.hostTableEvidence.at(site);
                            std::set<u32> targets;for(auto raw:t.targets)targets.insert(canonicalCodeAddress(raw));
                            sp.targets.assign(targets.begin(),targets.end());
                            result.proofs.switches.emplace(site,sp);grew=true;
                        } else {const auto why=census.unresolved.find(site);failed[site]=why!=census.unresolved.end()?why->second:"not recognized as a bounded table";}
                    }
                }catch(const std::exception& e){for(auto site:jr)failed[site]=std::string("table matcher: ")+e.what();}
            }
            // Fixed-cell / object-field calls.
            std::set<u32> calls;for(const auto& e:f.indirectCalls)if(e.rd==31&&!result.proofs.cells.count(e.site))calls.insert(e.site);
            if(calls.empty())continue;
            const auto flow=analyzer.analyze(f.seed.entry,ceiling);
            for(auto site:calls) {
                const auto pinned=extras.pinnedSets.find(site);
                if(pinned!=extras.pinnedSets.end()&&!result.proofs.sets.count(site)) {
                    std::set<u32> values(pinned->second.targets.begin(),pinned->second.targets.end());std::string why;
                    if(finishSet(site,pair.first,"manifest-set",values,{"manifest-pinned: "+pinned->second.evidence},
                                 {"pinned by the boot manifest, not derived; membership guard at run time"},why)){
                        result.proofs.sets.at(site).assumed=true;grew=true;continue;
                    }
                    failed[site]="pinned set rejected: "+why;continue;
                }
                const auto found=flow.sites.find(site);
                if(found==flow.sites.end()){failed[site]="provenance walk did not reach the site";continue;}
                const auto& v=found->second;Proof pr;
                const auto pinnedEmpty=extras.pinnedEmpty.find(site);
                if(pinnedEmpty!=extras.pinnedEmpty.end()) {
                    const u32 cell=pinnedEmpty->second.targets.at(0);
                    if(v.k!=V::Cell||v.a!=cell){failed[site]="pinned-empty cell "+hex(cell)+" is not the cell the call loads from ("+describe(v)+")";continue;}
                    if(!image.contains(cell)||image.at(cell)!=0){failed[site]="pinned-empty cell "+hex(cell)+" is outside the payload or initially non-null";continue;}
                    CellProof cp;cp.site=site;cp.rs=(image.at(site)>>21)&31;cp.cell=cell;cp.empty=true;cp.initial=0;
                    cp.assumptions.push_back("pinned by the boot manifest, not derived: "+pinnedEmpty->second.evidence);
                    result.proofs.cells.emplace(site,cp);grew=true;continue;
                }
                if(v.k==V::Cell){pr=prover.cell(v.a);
                    // Phase 3: a cell nothing ever writes is a proven EMPTY set (any non-null callback is fatal).
                    if(!pr.proof&&extras.callbacks){auto empty=prover.cellEmpty(v.a);if(empty.proof)pr=empty;}}
                else if(v.k==V::Field){pr=prover.field(v.a,v.b);
                    // Phase 4 (callbacks opt-in): the object pointer is also used as data. The exact slot value set is kept and each
                    // leak is recorded as an assumption; the runtime cell guard (live slot == captured target, member of the set)
                    // is what makes a callee that overwrote the slot fail closed.
                    if(!pr.proof&&extras.callbacks){
                        std::vector<std::string> leaks;auto relaxed=prover.field(v.a,v.b,&leaks);
                        if(relaxed.proof){pr=relaxed;for(auto& l:leaks)pr.proof->assumptions.push_back(l);
                            std::sort(pr.proof->assumptions.begin(),pr.proof->assumptions.end());
                            pr.proof->assumptions.erase(std::unique(pr.proof->assumptions.begin(),pr.proof->assumptions.end()),pr.proof->assumptions.end());}
                    }
                }
                else if(extras.callbacks&&v.k==V::Param&&v.a>=4&&v.a<=7){
                    std::set<std::pair<u32,unsigned>> visiting;std::set<u32> values;std::vector<std::string> sources;std::string why;
                    acc.clear();
                    if(paramValues(pair.first,v.a,visiting,values,sources,why)){
                        std::vector<std::string> notes{"every caller of "+hex(pair.first)+" known to the unit passes a provable value; entry from outside the unit is checked by the runtime guard"};
                        std::sort(acc.begin(),acc.end());acc.erase(std::unique(acc.begin(),acc.end()),acc.end());
                        for(auto& a:acc)notes.push_back(a);
                        if(finishSet(site,pair.first,"param",values,sources,notes,why)){result.proofs.sets.at(site).assumed=!acc.empty();grew=true;continue;}
                    }
                    failed[site]="parameter set not provable: "+why;continue;
                }
                else if(extras.callbacks&&v.k==V::IdxLoad){
                    std::set<u32> values;std::vector<std::string> sources;std::string why;bool ok=true;bool any=false;
                    std::set<std::pair<u32,unsigned>> visiting;
                    acc.clear();
                    for(const auto& r:index.idxRecs){
                        if(r.addr!=v.a)continue;any=true;
                        if(r.op!=43){why="non-word store into the indexed field at "+hex(r.pc);ok=false;break;}
                        // The text-wide index is block-local; the stored value needs the owning function's dataflow.
                        const auto owner=ownerOf(r.pc);
                        if(!owner){why="writer "+hex(r.pc)+" is not inside a discovered function";ok=false;break;}
                        const auto stored=storeValue(*owner,r.pc);
                        if(!stored){why="no function-level dataflow for the writer at "+hex(r.pc);ok=false;break;}
                        if(stored->k==V::Const){values.insert(stored->a);sources.push_back(hex(r.pc)+": constant "+hex(stored->a));}
                        else if(stored->k==V::Param&&stored->a>=4&&stored->a<=7){
                            if(!paramValues(*owner,stored->a,visiting,values,sources,why)){ok=false;break;}
                            sources.push_back(hex(r.pc)+": argument r"+std::to_string(stored->a)+" of "+hex(*owner));
                        }else{why="writer "+hex(r.pc)+" stores "+describe(*stored);ok=false;break;}
                    }
                    if(ok&&!any){why="no static writer of the indexed field";ok=false;}
                    std::sort(acc.begin(),acc.end());acc.erase(std::unique(acc.begin(),acc.end()),acc.end());
                    std::vector<std::string> notes{"the indexed field is written only by the listed store(s); stores through pointers the analysis cannot model (e.g. a variable-length argument copy) are not proven alias-free, so a foreign value is fatal at runtime instead of being called"};
                    for(auto& a:acc)notes.push_back(a);
                    if(ok&&finishSet(site,pair.first,"ring-registry",values,sources,notes,why)){result.proofs.sets.at(site).assumed=true;grew=true;continue;}
                    failed[site]="indexed registry not provable: "+why;continue;
                }
                else {
                    failed[site]=v.k==V::Param?"callback supplied by the caller (argument register r"+std::to_string(v.a)+"); no fixed writer set"
                                              :"no static proof mechanism for "+std::string(kindOf(v))+" provenance";
                    continue;
                }
                if(!pr.proof){failed[site]=pr.reason;continue;}
                pr.proof->site=site;pr.proof->rs=(image.at(site)>>21)&31;
                result.proofs.cells.emplace(site,*pr.proof);grew=true;
            }
        }
        if(!grew)break;
        if(round==kMaxRounds)throw std::runtime_error("Closure did not converge");
    }
    auto& d=result.discovery;d.closureRounds=round;d.callbacks=extras.callbacks;
    // Deterministic per-site report for every indirect transfer the final discovery knows about.
    for(const auto& pair:d.functions) {
        const auto& f=pair.second;
        const auto ceiling=functionCeiling(image,f.seed,d.functions,derivedWords);
        const auto flow=analyzer.analyze(f.seed.entry,ceiling);
        const auto base=[&](u32 site,bool jump){IndirectSiteReport r;r.site=site;r.function=pair.first;r.jump=jump;
            const auto w=image.at(site);r.rs=(w>>21)&31;r.rd=(w>>11)&31;return r;};
        const auto value=[&](u32 site){const auto it=flow.sites.find(site);return it==flow.sites.end()?V{}:it->second;};
        for(const auto& e:f.cellCalls){auto r=base(e.first,false);const auto& s=e.second;
            r.kind=s.field?"object-field":"fixed-cell";r.status=s.empty?"registry-empty-guarded":"closed-cell-guarded";
            r.detail=s.field?"M[M["+hex(s.cell)+"]+"+hex(s.offset)+"]":"M["+hex(s.cell)+"]";
            r.targets=s.targets;
            if(s.empty){const bool pin=!s.assumptions.empty()&&s.assumptions.front().rfind("pinned by the boot manifest",0)==0;
                r.reason=pin?"pinned empty cell (not derived): every callback is fatal at runtime":"no static writer and null initial value: every non-null callback is fatal at runtime";
                for(const auto& a:s.assumptions)r.reason+="; assumption: "+a;}
            d.indirectReport.push_back(r);}
        for(const auto& e:f.setCalls){auto r=base(e.first,false);const auto& s=e.second;
            r.kind=s.kind=="param"?"argument-callback":"indexed-array-field";
            r.status=s.kind=="param"?(s.assumed?"registry-param-guarded":"closed-param-set-guarded"):"registry-ring-guarded";
            r.detail=s.origin;r.targets=s.targets;
            for(const auto& a:s.assumptions)r.reason+=(r.reason.empty()?"":"; ")+std::string("assumption: ")+a;
            d.indirectReport.push_back(r);}
        for(const auto& e:f.switchSites){auto r=base(e.first,true);const auto& s=e.second;
            r.kind="static-table";r.status=s.evidence.empty()?"closed-static-table":"host-trap-table-pinned";
            r.detail="table "+hex(s.table)+" x"+std::to_string(s.count)+", default "+hex(s.defaultTarget);
            if(!s.evidence.empty())r.reason="pinned by the boot manifest, not derived (the index has no guest bound; the runtime table guard is fatal outside the pinned count): "+s.evidence;
            r.targets=s.targets;d.indirectReport.push_back(r);}
        for(const auto& e:f.guarded){auto r=base(e.first,false);const auto& s=e.second;
            r.kind="libgpu-slot";r.status="closed-guarded-slot";r.detail="M[M["+hex(s.baseGlobal)+"]+"+hex(s.offset)+"] (Phase A allowlist)";
            r.targets={s.expectedTarget};d.indirectReport.push_back(r);}
        for(const auto& e:f.biosCalls){auto r=base(e.site,!e.call);r.kind="bios-vector";r.status=f.biosHle.count(e.site)?"bios-hle-boundary":"bios-boundary";
            const auto* name=biosName(e.table,e.function,extras.bootBios,extras.bootCard);
            r.detail=std::string(e.table==0xa0?"A0":e.table==0xb0?"B0":"C0")+":"+(e.function>=0?hex(static_cast<u32>(e.function)):std::string("unknown"))+
                (name?std::string(" ")+name+" (external reference, not verified in repo)":std::string(" (unnamed)"));
            r.reason=f.biosHle.count(e.site)?(extras.bootBios&&!moyle::detail::recomp::bios::findEntry(e.table,e.function)?"boot HLE in src/bios_boot.hpp; returns to the caller":"minimal HLE in src/bios_boundary.hpp; returns to the caller"):"no BIOS HLE: boundary preserved";d.indirectReport.push_back(r);}
        const auto unresolved=[&](const std::set<RegisterSite>& sites,bool jump){
            for(const auto& e:sites){auto r=base(e.site,jump);const auto v=value(e.site);
                r.kind=kindOf(v);r.status="unresolved";r.detail=describe(v);
                const auto why=failed.find(e.site);
                r.reason=why!=failed.end()?why->second:"no static proof mechanism for this provenance";
                d.indirectReport.push_back(r);}
        };
        unresolved(f.indirectCalls,false);unresolved(f.indirectJumps,true);
    }
    std::sort(d.indirectReport.begin(),d.indirectReport.end());
    return result;
}
}
