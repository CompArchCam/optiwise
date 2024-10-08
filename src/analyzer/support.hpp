#ifndef SUPPORT_H
#define SUPPORT_H

#include <iomanip>
#include <cstring>
#include <vector>
#include <map>
#include <list>
#include <set>
#include <utility>
#include <algorithm>
#include <memory>

#define INST_LEN 4

using namespace std;

class parse_error;

struct app_module {
    set<string> paths;
    map<uint64_t, pair<uint64_t, uint64_t>> file_offset_to_vaddr;
    bool have_disassemble = false;
    bool have_count = false;
    bool have_sample = false;
    std::unique_ptr<parse_error> disassemble_error = nullptr;
    uint64_t samples = 0;
    uint64_t counts = 0;

    app_module(string path) {
        paths.insert(path);
    }
    const string &path() const { return *paths.begin(); }
};

typedef vector<app_module>::size_type app_module_id;
typedef pair<app_module_id, uint64_t> address;

enum class module_add_or_find_role {
    none,
    disassemble,
    count,
    sample,
};
app_module_id module_add_or_find(
        const string &path, module_add_or_find_role role);
app_module &module_lookup(app_module_id id);

struct loop;

struct back_edge {
    address head;
    address tail;
};

struct function { // non-inlined function
    address entry;
    string name;
    set<const function *> callers;
    set<const function *> callees;
    set<address> callsites;
    shared_ptr<function> immediate_parent; // most nested function in which all calls to this function are nested
    address immediate_return; // most nested return address to which this function must always eventually return
    const loop *immediate_loop; // most nested loop in which all calls to this function occur.
    size_t length; // in bytes, 0 if unknown
    // these stats are for samples not otherwise associated with a particular
    // call site (e.g. due to a tail call)
    uint64_t callee_samples;        // perf samples
    uint64_t callee_cycles;         // perf cpu cycles
    uint64_t callee_instcount;      // count of instructions executed in functions called from this one
    uint64_t self_instcount;        // count of instructions executed in this function
};

struct source_line {
    shared_ptr<string> filename;
    int line;
};

struct loop {
    back_edge addr;             // head and tail address
    uint64_t samples;           // how many perf samples this loop has
    uint64_t cpu_cycles;        // perf cpu cycles
    uint64_t inst_retired;      // inst retired in the loop
    uint64_t count;             // how many times the loop is executed
    uint64_t size;              // static loop size (inst)
    uint64_t total_iteration;   // sum of all back edge counts
    set<address> loop_body;     // blocks included by this loop
    set<address> exclusive_body;// blocks included ONLY by this loop
    shared_ptr<function> func;  // non-inlined function that contains the loop
    shared_ptr<string> loop_func;   // function that contains this loop (inlined).
    shared_ptr<source_line> source; // source code location
    int source_line_count;          // number of source code lines
    set<const loop *> nested_loops; // within the same function only
    set<address> back_edges;    // address of tall possible tails
    const loop* parent_loop;    // within same function only
    uint64_t self_samples;      // how many perf samples this loop has not nested in other loops
    uint64_t self_cpu_cycles;   // perf cpu cycles not nested in other loops
    uint64_t self_inst_retired; // inst retired in the loop not nested in other loops
    uint64_t self_size;         // static loop size (inst) not nested in other loops
};

struct cfg_node {           // each node is a DynamoRio Block with no overlap
    uint64_t call_return_addr;      // return address of any call originating from this block.
    uint64_t count;                 // execution count of each instruction in the block
    uint64_t samples;               // perf samples
    uint64_t cpu_cycles;            // perf cpu cycles
    uint64_t inst_retired;          // inst retired in the loop
    uint64_t callee_instcount;      // count of instructions executed in functions called from this block
    set<uint64_t> inst_addrs;       // address of each instruction in this block.
    bool is_call;                   // last instruction is a call
    bool is_tail_call;              // last instruction is a tail call
    bool is_ret;                    // last instruction is a ret
    bool is_function_entry;         // this is the start of a function
    shared_ptr<function> func;      // function that contains this block
    const loop *parent_loop;        // most nested loop in which all calls to this function occur.
    address immediate_dominator;    // idom in a CFG where each 'is_return' is unlinked, but each is_call is linked to the next block
    string callee;                  // callee function name(s) if is_call, otherwise nullptr
    shared_ptr<string> last_inlined_func_name;
    map<address, uint64_t> child;   // child of this node: <start address of a child block, count of entering this block>
    map<string, map<string, set<int>>> source_line_map;    // inlined_func map of filename map of set of source lines.

    uint64_t last_inst_addr() const { return inst_addrs.crbegin() != inst_addrs.crend() ? *inst_addrs.crbegin() : 0; }
    unsigned int block_size() const { return inst_addrs.size(); }
};

struct trace_pair {
    address addr;
};

struct Perf_result {
    uint32_t cpu_cycles;
    address addr;
    vector<trace_pair> stack_trace;
};

struct sample_point {
    uint64_t cpu_cycles;    // for all instructions but not a specific one
    uint64_t samples;
};

struct objdump_line {
    string disassembly;
    shared_ptr<function> func;
    shared_ptr<string> inlined_func_name;
    shared_ptr<source_line> source;
};

struct processed_perf_result {
    uint64_t cpu_cycles;    // for all instructions but not a specific one
    uint64_t samples;
    uint64_t execution_count;
    app_module_id mod;
    const objdump_line *line;
    string block_num;
    shared_ptr<function> func() const { return line ? line->func : nullptr; }
    string func_name() const { return line && line->func ? line->func->name : "NA"; }
    string inlined_func_name() const {
        return line && line->inlined_func_name ? *line->inlined_func_name : func_name();
    }
    string disassembly() const { return line ? line->disassembly : "NA"; }
    shared_ptr<source_line> source() const { return line ? line->source : nullptr; }
};

typedef map<address, processed_perf_result> inst_table;
typedef map<address, objdump_line> objdump_table;
typedef map<string, map<int, pair<string, bool>>> source_table;
typedef map<address, shared_ptr<function>> func_table;
typedef map<address, sample_point> func_sample;
typedef map<address, cfg_node> dycfg;

/* for parse_error */
#include "io.hpp"

#endif
