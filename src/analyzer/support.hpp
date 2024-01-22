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

struct app_module {
    string path;
    map<uint64_t, pair<uint64_t, uint64_t>> file_offset_to_vaddr;
};

typedef vector<app_module>::size_type app_module_id;
typedef pair<app_module_id, uint64_t> address;

app_module_id module_add_or_find(const string &path);
app_module &module_lookup(app_module_id id);

struct back_edge {
    address head;
    address tail;
};

struct function {
    string name;
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
    function *func;             // non-inlined function that contains the loop
    shared_ptr<string> loop_func;   // function that contains this loop (inlined).
    shared_ptr<source_line> source; // source code location
    int source_line_count;          // number of source code lines
    set<const loop *> nested_loops; // within the same function only
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
    bool is_ret;                    // last instruction is a ret
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
    function *func;
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
    function *func() const { return line ? line->func : nullptr; }
    string func_name() const { return line && line->func ? line->func->name : "NA"; }
    string inlined_func_name() const {
        return line && line->inlined_func_name ? *line->inlined_func_name : "NA";
    }
    string disassembly() const { return line ? line->disassembly : "NA"; }
    shared_ptr<source_line> source() const { return line ? line->source : nullptr; }
};

typedef map<address, processed_perf_result> inst_table;
typedef map<address, objdump_line> objdump_table;
typedef map<string, map<int, pair<string, bool>>> source_table;
typedef map<address, sample_point> func_sample;
typedef map<address, cfg_node> dycfg;

#endif
