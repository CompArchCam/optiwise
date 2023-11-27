#include "dr_api.h"
#include "drutil.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <errno.h>
#include <fcntl.h>
#include <map>
#include <memory>
#include <set>
#include <stack>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace std;

#if !defined(__x86_64__) && !defined(__aarch64__)
#error Architecture not recognised.
#endif

#define PRINTF_STDERR(format, ...) dr_fprintf(STDERR, format, ##__VA_ARGS__)
#define PRINT_STDERR(msg) PRINTF_STDERR("%s", msg)
#define PRINTF_STDOUT(format, ...)  dr_printf(format, ##__VA_ARGS__)
#define PRINT_STDOUT(msg) PRINTF_STDOUT("%s", msg)

/* ---Macros below should be disabled to maxmize the dyclient efficiency--- */
/* Enable this to check the CFG generated */
// #define CHECK

/* Disavle this to use inlined instructions for stack profiling
   and app_pc to address pair conversion inflight */
// #define ADDR_CONV
/* ------------------------------------------------------------------------ */

/* ---Macros below should be enabled to generate correct profiling output--- */
#define CBR /* Enable inlined instructions for condition branches */
#define UBR /* Enable inlined instructions for uncondition branches */
#define SYS /* Enable inlined instructions for system calls */
#define MBR /* Enable clean calls for indirect branches */
#define JUMP_MBR /* Enable selectively jump mbr clean calls (result is still correct) */
#define LOCAL /* Enable inlined instructions vertex profiling */
#define GLOBAL /* Enable inlined instructions for incrmenting counter for stack profiling */
#define SP /* Enable stack profiling */
#define SP_CALL /* Enable stack profiling on call side */
#define SP_RET /* Enable stack profiling on return side */
/* ------------------------------------------------------------------------- */

#define INST_LEN 4 /* instruction length for AArch64 in byte */
size_t stack_size = 2048; /* max size of simulated stack for stack profiling */

struct app_module;
typedef vector<app_module>::size_type module_id;
typedef pair<module_id,uint64_t> address;

typedef struct app_module {
    uint64_t addr;
    uint64_t end_addr;
    uint64_t base;
    module_id index;
    string path;
} app_module;

typedef struct cfg_node {           // each node is a DynamoRio Block with no overlap
    uint64_t count;                 // execution count
    address star_addr;              // start addr of this block
    uint64_t end_addr;              // end addr of this block
    const char *inst_name;          // name of last inst
    uint64_t fall_count;            // counter for fall-through addr of cbr
    uint64_t first_targ;            // counter of the first target if the block ends with mbr
    #ifdef __x86_64__
    int* inst_length;               // pointer to an array containing all inst length
    #endif
    uint32_t block_size;            // size of the node block
    map<address, uint64_t> child;   // child of this node, <start address of successor, count of this block>
} cfg_node;

#ifdef ADDR_CONV
typedef struct stack_entry {
    address call_addr;   // addr of the func call inst
    address return_addr; // addr of the inst next to func call
    uint64_t counter;    // num of inst executed in the callee func
} stack_entry;
#else
typedef struct stack_entry {
    app_pc call_addr;   // addr of the func call inst
    app_pc return_addr; // addr of the inst next to func call
    uint64_t counter;   // num of inst executed in the callee func
    uint64_t* pointer;  // point to stack_counter_map_pc[call_addr]
} stack_entry;
#endif

typedef map<address, cfg_node> dycfg;

static vector<app_module> modules;
static vector<module_id> loaded_modules;
void *modules_lock;
void *as_built_lock;

static dycfg cfg_block;
/* A class representing a dynamically sized vector that gives each element a
 * fixed address.  This is needed so that instrumented instructions can contain
 * pointers to the elements and these will never be invalidated (unlike the
 * inbuilt vector class. */
template<class T, uint64_t allocation_size=512> class FixedAddressVector {
private:
    vector<unique_ptr<T[]>> allocations;
    uint64_t block_count;
public:
    T &operator[](uint64_t index) {
        return allocations[index / allocation_size][index % allocation_size];
    }
    uint64_t size() const { return block_count; }
    uint64_t allocate() {
        dr_mutex_lock(as_built_lock);
        if (block_count % allocation_size == 0) {
            allocations.emplace_back(new T[allocation_size]);
            DR_ASSERT_MSG(allocations.end()[-1], "Error: failed to allocate memory for array");
        }
        block_count++;
        dr_mutex_unlock(as_built_lock);
        return block_count-1;
    }
};

static FixedAddressVector<cfg_node> cfg_table;
static map<app_pc, uint64_t> mbr_first_targ; // address of the first target of each mbr

/* TODO these variables will need to be in thread local storage in
   multi-threaded code. */
static bool missed_mbr = false; // did an mbr fail to resolve target
static bool module_unload_flag;
static uint64_t prev_block; // index of previous block for mbr with missed targ
#ifdef __x86_64__
static map<app_pc, uint64_t> blocknum_table; // x86 only, used to find block_num for mbr
static map<pair<address, app_pc>, address> missed_mbr_table; // x86 only, <addr_of_missed_mbr,missed_targ>, true_targ>>
static app_pc missed_targ; // x86 only, address of the missed targ in previous block
static uint64_t mbr_target_addr; // target_opnd is mem
#endif

static address prev_block_cl; // address of previous block in clean call

static uint64_t inst_counter; // global counter for number of inst executed in stack profiling
static stack_entry* call_stack;
static int64_t stack_index;
static map<address, uint64_t> stack_counter_map; // number of instructions associated with each func call instruction
#ifndef ADDR_CONV // no address conversion in stack profiling clean call
static map<app_pc, uint64_t> stack_counter_map_pc; // number of instructions associated with each func call instruction
#endif

void *count_lock;

// Output file names as supplied on command line.
static const char *path_cfg;

static void event_exit(void);
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating);
static void clean_call(uint block_size, app_pc start_pc, app_pc end_pc, int opcode);
static void event_module_load(void *drcontext, const module_data_t *info, bool loaded);
static void event_module_unload(void *drcontext, const module_data_t *info);
static void mbr_clean_call(void *drcontext, uint64_t src, app_pc targ);
static void at_mbr(uint64_t src, app_pc branch_addr, app_pc targ);
static address app_pc_to_address(app_pc arg, bool allow_miss=false);

#ifdef __x86_64__
static void at_call(app_pc call_addr, int len);
static void at_return(app_pc inst_addr, app_pc targ_addr);
static void at_mbr_x86(app_pc instr_addr, app_pc target_addr);
#elif defined(__aarch64__)
static void at_call(app_pc call_addr);
static void at_return(app_pc targ_addr);
#endif

#ifndef ADDR_CONV
void stackoverflow_exit();
#ifdef __x86_64__
static void inlined_at_call_x86(void *drcontext, instrlist_t *bb, instr_t *where, app_pc call_addr, int len);
static void inlined_at_return_x86(void *drcontext, instrlist_t *bb, instr_t *where);
#elif defined(__aarch64__)
static void inlined_at_call_aarch64(void *drcontext, instrlist_t *bb, instr_t *where, app_pc call_addr, int len);
static void inlined_at_return_aarch64(void *drcontext, instrlist_t *bb, instr_t *where);
#endif
#endif

#if CHECK
static uint64_t num_mbr = 0;
#endif

/* TODO:
 * error check for inlined stack profiling
**/

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    if (argc != 5) {
        PRINT_STDERR(
            "Usage: drrun -c /path/to/libcount.so count.txt STACKSIZE STDOUT STDERR -- COMMAND [ARGS]...\n"
            "Measures execution count and control flow graph of all instructions run by\n"
            "COMMAND with arguments ARGS.\n"
            "\n"
            "  count.txt  where to put the execution count output. Best to use an\n"
            "             absolute path.\n"
            "  STACKSIZE  1-65535 max number of in-flight calls recorded by stack profiling\n"
            "  STDOUT     where to redirect COMMAND's stdout; '-' for no redirect\n"
            "  STDERR     where to redirect COMMAND's stderr; '-' for no redirect\n"
        );
        dr_abort_with_code(1);
    }

    path_cfg = argv[1];
    const char *str_stacksize = argv[2];
    const char *path_stdout = argv[3];
    const char *path_stderr = argv[4];

    stack_size = size_t(atol(str_stacksize));
    if (stack_size < 1 || stack_size > INT16_MAX)  {
        PRINTF_STDERR("Error: invalid --stack-size\n");
        dr_abort_with_code(1);
    }

    if (strcmp(path_stdout, "-")) {
        STDOUT = dr_dup_file_handle(STDOUT);
        int fd;
        if ((fd = open(path_stdout, O_WRONLY | O_TRUNC | O_CREAT, 0664)) == -1 ||
            dup2(fd, 1) != 1 ||
            close(fd) == -1) {
            PRINTF_STDERR("Error: failed to redirect stdout fd=%d errno=%d\n", fd, errno);
            dr_abort_with_code(1);
        }
    }
    if (strcmp(path_stderr, "-")) {
        STDERR = dr_dup_file_handle(STDERR);
        int fd;
        if ((fd = open(path_stderr, O_WRONLY | O_TRUNC | O_CREAT, 0664)) == -1 ||
            dup2(fd, 2) != 2 ||
            close(fd) == -1) {
            PRINTF_STDERR("Error: failed to redirect stderr fd=%d errno=%d\n", fd, errno);
            dr_abort_with_code(1);
        }
    }

#ifdef CHECK
    /* print the architecture */
    #ifdef __x86_64__
    PRINT_STDOUT("x86_64\n");
    #elif defined(__aarch64__)
    PRINT_STDOUT("aarch64\n");
    #endif
#endif

    /* init global variable */
    inst_counter = 0;
    prev_block = ~0;
    prev_block_cl = address(0, 0);
    module_unload_flag = false;
    modules.emplace_back(app_module{
        .addr = 0,
        .end_addr = 0,
        .base = 0,
        .index = (module_id)modules.size(),
        .path = "[no module]",
    });
    loaded_modules.push_back(modules.size()-1);
    call_stack = new stack_entry[stack_size];
    stack_index = -1;

    /* Check the path is writeable */
    file_t cfg_file = dr_open_file(path_cfg, DR_FILE_WRITE_APPEND);
    if (cfg_file == INVALID_FILE) {
        PRINTF_STDERR("Error: couldn't open file %s\n", path_cfg);
        dr_abort_with_code(1);
    }
    dr_close_file(cfg_file);

    /* register events */
    dr_register_exit_event(event_exit);
    dr_register_bb_event(event_basic_block);
    dr_register_module_load_event(event_module_load);
    dr_register_module_unload_event(event_module_unload);

    /* initialize lock */
    modules_lock = dr_mutex_create();
    as_built_lock = dr_mutex_create();
    count_lock = dr_mutex_create();
}

static void event_exit(void) {
    ssize_t len;

    /* output summary */
    #ifdef CHECK
    PRINTF_STDOUT("Number of static blocks: %ld\n"
                  "Num of total dynamic block: %ld",
                  cfg_table.size(), cfg_block.size()-1);
    #endif
    /* fetch from pre-allocated cfg array */
    dycfg cfg_map;
    set<address> child_set; // for check entry of the cfg
    PRINT_STDOUT("process cfg\n");
    for (uint64_t i = 0; i < cfg_table.size(); ++i) {
        /* handle cbr counter */
        if (cfg_table[i].fall_count > 0) {
            DR_ASSERT(cfg_table[i].child.size() > 0);
            auto tmp = cfg_table[i].child.begin();
            uint64_t targ_count = cfg_table[i].count - cfg_table[i].fall_count;
            if (targ_count > 0)
                tmp->second =  targ_count; // update target count
            else
                cfg_table[i].child.erase(tmp);
            uint64_t block_bytes = 0;
            #ifdef __x86_64__
            for (int j = 0; j < cfg_table[i].block_size; j++) {
                block_bytes += cfg_table[i].inst_length[j];
            }
            #elif defined(__aarch64__)
            block_bytes = cfg_table[i].block_size * INST_LEN;
            #endif
            const address next(cfg_table[i].star_addr.first, cfg_table[i].star_addr.second + block_bytes);
            cfg_table[i].child[next] = cfg_table[i].fall_count; // insert fall-through count
        }
        if (cfg_table[i].child.size() == 1 && cfg_table[i].child.begin()->second == 0) {
            cfg_table[i].child.begin()->second = cfg_table[i].count; // update target count if fall-through count == 0
            if (cfg_table[i].child.begin()->second == 0) { // if count == 0
                cfg_table[i].child.erase(cfg_table[i].child.begin());
            }
        }

        /* correct count of the first target of mbr */
        if (cfg_table[i].first_targ > 0) {
            address tmp = app_pc_to_address((app_pc) mbr_first_targ[(app_pc) (cfg_table[i].end_addr + modules[cfg_table[i].star_addr.first].addr)]);
            cfg_table[i].child[tmp] += cfg_table[i].first_targ;
        }

        /* move cfg into map */
        cfg_node tmp_node = cfg_table[i];
        if (cfg_map.count(cfg_table[i].star_addr) == 0) {
            cfg_map[cfg_table[i].star_addr] = tmp_node;
        } else {
            DR_ASSERT(cfg_map[cfg_table[i].star_addr].end_addr == tmp_node.end_addr);
            cfg_map[cfg_table[i].star_addr].count += tmp_node.count;
            cfg_map[cfg_table[i].star_addr].first_targ += tmp_node.first_targ;
            if (!tmp_node.child.empty()) {
                for (auto j: tmp_node.child) {
                    if (j.second != 0) { // avoid insert empty counter from duplicated element in cfg_table
                        if (cfg_map[cfg_table[i].star_addr].child.count(j.first) == 0)
                            cfg_map[cfg_table[i].star_addr].child[j.first] = j.second;
                        else
                            cfg_map[cfg_table[i].star_addr].child[j.first] += j.second;
                    }
                }
            }
        }

        /* setup the child set */
        for (auto child_itr: cfg_table[i].child) {
            child_set.insert(child_itr.first);
        }
    } // end fetch from pre-allocated array

    /* hanle entry and exit of cfg */
    if (child_set.count(cfg_table[0].star_addr) == 0) {
        cfg_map[address(0, 0)].child[cfg_table[0].star_addr] = cfg_table[0].count; // insert null element for entry
    }
    if (cfg_map.count(cfg_table[cfg_table.size()-1].child.begin()->first) == 0 &&
        cfg_map[cfg_table[cfg_table.size()-1].star_addr].child.size() == 1
       )
    {
        cfg_map[cfg_table[cfg_table.size()-1].star_addr].child.clear(); // delete child of exit block
    }

    /* clean up the stack (i.e., assume that those functions return at program exit) */
    while (stack_index >= 0) { // use array
        #ifdef ADDR_CONV
        stack_counter_map[call_stack[stack_index].call_addr] += inst_counter;
        #else // no address conversion in sp clean call
        stack_counter_map_pc[call_stack[stack_index].call_addr] += inst_counter;
        #endif
        inst_counter += call_stack[stack_index].counter;
        stack_index--;
    }

    #ifndef ADDR_CONV
    if (!module_unload_flag){
        for (auto itr: stack_counter_map_pc) {
            stack_counter_map[app_pc_to_address(itr.first)] = stack_counter_map_pc[itr.first];
        }
    }
    #endif

    /* merge overlap blocks */
    PRINT_STDOUT("Info: merge blocks\n");
    const char overlap_end[] = "[[fallthrough]]"; // used as the last instruction name to indicate a overlap break
    set<module_id> executed_modules;
    for (auto itr = cfg_map.begin(); itr != prev(cfg_map.end()); ++itr) {
        const auto &address = itr->first;
        auto &block = itr->second;
        if (address.first != 0 || address.second != 0)
            executed_modules.insert(address.first);
        auto next = std::next(itr);
        if (block.end_addr == next->second.end_addr) { // blocks overlap
            next->second.count += block.count; // update execution count
            next->second.first_targ += block.first_targ; // update execution count
            block.first_targ = 0;
            for (auto itr_child : block.child) { // merge child blocks
                if (next->second.child.count(itr_child.first) > 0) { // if the child of current block exists in the child of next block
                    next->second.child[itr_child.first] += itr_child.second;
                } else {
                    next->second.child[itr_child.first] = itr_child.second;
                }
            }
            block.child.clear();
            block.child[next->first] = block.count; // update child blcok of new splitted block
            block.block_size -= next->second.block_size; // update block size
            block.inst_name = overlap_end;
            unsigned next_bytes;
            #ifdef __x86_64__
            next_bytes = 0;
            for (int i = 0; i < next->second.block_size; ++i) {
                next_bytes += next->second.inst_length[i];
            }
            #elif defined(__aarch64__)
            next_bytes = next->second.block_size * INST_LEN;
            #endif
            block.end_addr -= next_bytes;
        }
    } // end merge

    /* output cfg with stack profiling count */
    PRINT_STDOUT("Info: output cfg\n");
    file_t cfg_file = dr_open_file(path_cfg, DR_FILE_WRITE_OVERWRITE);
    if (cfg_file == INVALID_FILE) {

    }
    DR_ASSERT(cfg_file != INVALID_FILE);
    len = dr_fprintf(cfg_file, "%s\n",
"# optiwise count control flow graph 0.1\n"
"#\n"
"# File Format\n"
"# > Architecture <name>\n"
"# Specifies the processor architecture e.g. x86_64.\n"
"#\n"
"# > Module <index> <path>\n"
"# Introduces a module (executable or library).\n"
"#\n"
"# > Entry <module>:<offset> <edge count>\n"
"# Specifies the entry point. Can appear multiple times (if multiple programs are\n"
"# combined), <edge count> specifies how many times this entry occurred.\n"
"#\n"
"# > <module>:<offset> <execution count> <callee execution count> <last inst name>\n"
"# > 	+<offset> <len>\n"
"# > 	...\n"
"# > 	+<offset> <len>\n"
"# > 	<target module>:<target offset> <edge count>\n"
"# > 	...\n"
"# > 	<target module>:<target offset> <edge count>\n"
"# Introduces a basic block; a sequence of instructions with the same execution\n"
"# count containing at most one control transfer instruction at the end. The\n"
"# block begins at address <module>:<offset> e.g. 0:4ac means it is in module 0\n"
"# and the preferred address of this block is 4ac.  The <execution count> is the\n"
"# number of times (in decimal) this block has executed, and the<callee execution\n"
"# count> is the total number of instructions (in decimal) executed during calls\n"
"# that originate from the last instruction of this block (avoiding double\n"
"# counting in the event of recursion). <last inst name> is the 'name' of the\n"
"# last instruction in this block, used to identify how the block ends (e.g.\n"
"# call, return, conditional branch).\n"
"#\n"
"# +<offset> <len> says there is an instruction of <len> bytes that starts at the\n"
"# specified offset (in hexadecimal) into this block.\n"
"#\n"
"# <target module>:<target offset> says that after executing this\n"
"# block, the next block to execute was at the specified module and offset, and\n"
"# <edge count> says how many times this was the case. The sum of all edge counts\n"
"# for a block should equal the execution count of the block except for the\n"
"# block at program exit.\n"
    );
    DR_ASSERT(len > 0);
    #ifdef __x86_64__
    cfg_map.begin()->second.inst_length = (int*) calloc(1, sizeof(int));
    cfg_map.begin()->second.block_size = 1;
    #endif
    dr_fprintf(cfg_file, "Architecture %s\n",
#ifdef __x86_64__
            "x86_64"
#elif defined(__aarch64__)
            "aarch64"
#else
#error Unknown architecture
#endif
    );
    for (auto m: executed_modules) {
        len = dr_fprintf(cfg_file, "Module %zu %s\n",
                         modules.at(m).index, modules.at(m).path.c_str());
        DR_ASSERT(len > 0);
    }
    for (auto i: cfg_map) {
        const address &block_addr = i.first;
        const cfg_node &block = i.second;
        if (block_addr.first == 0 && block_addr.second == 0) {
            for (auto j: block.child) {
                const address &child_addr = j.first;
                len = dr_fprintf(cfg_file, "Entry %zu:%" PRIx64 " %" PRIu64 "\n",
                                 child_addr.first, child_addr.second, j.second);
                DR_ASSERT(len > 0);
            }
            continue;
        }
        const module_id mod = block_addr.first;
        const uint64_t block_offset = block_addr.second;
        const address block_end_addr(mod, block.end_addr);
        uint64_t callee_count = 0;
        if (stack_counter_map.count(block_end_addr) > 0) {
            // if it is a func call inst with additional count in its callee
            callee_count = stack_counter_map[block_end_addr];
        }
        len = dr_fprintf(cfg_file, "%zu:%" PRIx64 " %" PRIu64 " %" PRIu64 " %s\n",
                         modules[mod].index, block_offset, block.count,
                         callee_count, block.inst_name);
        DR_ASSERT(len > 0);

        uint64_t offset = 0;
        for (int i = 0; i < block.block_size; ++i) {
            int inst_len;
#ifdef __x86_64__
            inst_len = block.inst_length[i];
#elif defined(__aarch64__)
            inst_len = INST_LEN;
#endif
            len = dr_fprintf(cfg_file, "\t+%" PRIx64 " %d\n", offset, inst_len);
            offset += inst_len;
            DR_ASSERT(len > 0);
        }
        for (auto j: block.child){
            const address &child_addr = j.first;
            len = dr_fprintf(cfg_file, "\t%zu:%" PRIx64 " %" PRIu64 "\n",
                             child_addr.first, child_addr.second, j.second);
            DR_ASSERT(len > 0);
        }
    } // end output cfg
    dr_close_file(cfg_file);

    #ifdef CHECK
    PRINT_STDOUT("check result\n");
    /* merge cfg_block */
    for (auto itr = cfg_block.begin(); itr != prev(cfg_block.end()); ++itr) {
        auto next = std::next(itr);
        if (itr->second.end_addr == next->second.end_addr) { // blocks overlap
            next->second.count += itr->second.count; // update execution count
            for (auto itr_child : itr->second.child) { // merge child blocks
                if (next->second.child.count(itr_child.first) > 0) { // if the child of current block exists in the child of next block
                    next->second.child[itr_child.first] += itr_child.second;
                } else {
                    next->second.child[itr_child.first] = itr_child.second;
                }
            }
            itr->second.child.clear();
            itr->second.child[next->first] = itr->second.count; // update child blcok of new splitted block
            itr->second.block_size -= next->second.block_size; // update block size
            #ifdef __x86_64__
            int offset = 0;
            for (int i = 0; i < itr->second.block_size - 1; ++i) {
                offset += itr->second.inst_length[i];
            }
            itr->second.end_addr = itr->first.second + offset;
            #elif defined(__aarch64__)
            itr->second.end_addr = itr->first.second + (itr->second.block_size-1)*INST_LEN; // update end address
            #endif
        }
    } // end merge
    #ifdef __x86_64__
    cfg_block.begin()->second.block_size = 1;
    #endif
    /* check result */
    bool flag = false;
    for (auto itr: cfg_block) {
        if (cfg_map.count(itr.first) == 0 ||
            cfg_map[itr.first].count != itr.second.count ||
            cfg_map[itr.first].end_addr != itr.second.end_addr ||
            cfg_map[itr.first].block_size != itr.second.block_size ||
            cfg_map[itr.first].child.size() != itr.second.child.size()
           )
        {
            PRINTF_STDOUT("block: %lx %lx %ld %ld %s %s\n",
                          itr.first.second, itr.second.end_addr,
                          itr.second.count, cfg_map[itr.first].count,
                          itr.second.inst_name, modules[itr.first.first].path.c_str());
            flag = true;
        }
        for (auto itr_child: itr.second.child) {
            if (
                (cfg_map[itr.first].child.count(itr_child.first) == 0) ||
                (cfg_map[itr.first].child[itr_child.first] != itr_child.second)
               )
            {
                PRINTF_STDOUT("child of block: %lx, %lx, %ld, %ld, %s, %s\n",
                              itr.second.end_addr, itr_child.first.second,
                              itr_child.second, cfg_map[itr.first].child[itr_child.first],
                              itr.second.inst_name, modules[itr_child.first.first].path.c_str());
                flag = true;
            }
        }
    } // end check

    if (flag) {
        PRINT_STDERR("Error: not match!\n");
    } else {
        PRINT_STDOUT("Result match!\n");
    }
    #endif

    /* free mutex */
    dr_mutex_destroy(modules_lock);
    dr_mutex_destroy(as_built_lock);
    dr_mutex_destroy(count_lock);

    delete[] call_stack;

#if CHECK
    PRINTF_STDOUT("number of static mbr: %ld, number of block: %ld, ratio: %f\n",
                num_mbr, cfg_table.size(), (float) num_mbr/cfg_table.size());
#endif
}

static void clean_call(uint block_size, app_pc start_pc, app_pc end_pc, int opcode)
{
    dr_mutex_lock(count_lock);

    uint64_t addr = (uint64_t) start_pc;
    uint64_t end_addr = (uint64_t) end_pc;
    const address key(app_pc_to_address(start_pc));

    if (cfg_block.count(key) == 0)
        cfg_block[key].count = 1;
    else
        cfg_block[key].count += 1;

    if (cfg_block[prev_block_cl].child.count(key) == 0)
        cfg_block[prev_block_cl].child[key] = 1;
    else
        cfg_block[prev_block_cl].child[key] += 1;

    prev_block_cl = key;
    dr_mutex_unlock(count_lock);
}

#ifdef __aarch64__
/* move a 64-bit imm integer into register */
static void opnd_create_reg64(uint64_t imm, void *drcontext, instrlist_t *bb, instr_t *where, opnd_t reg) {
    uint16_t array[4];
    for (int i = 0; i < 4; ++i) {
        array[i] = 0x000000000000ffff & (imm>>(16*i));
        if (i == 0) {
            instrlist_meta_preinsert(bb,
                                     where,
                                     INSTR_CREATE_movz(drcontext,
                                                       reg,
                                                       OPND_CREATE_INT(array[i]),
                                                       OPND_CREATE_INT(i*16)));
        } else {
            instrlist_meta_preinsert(bb,
                                     where,
                                     INSTR_CREATE_movk(drcontext,
                                                       reg,
                                                       OPND_CREATE_INT(array[i]),
                                                       OPND_CREATE_INT(i*16)));
        }
    }
}
#endif

static void mbr_clean_call(void *drcontext, uint64_t src, app_pc targ) {
    uint64_t targ_u = (uint64_t) dr_read_saved_reg(drcontext, SPILL_SLOT_4);
    const address targ_addr(app_pc_to_address((app_pc)targ_u, true));
    if (targ_addr.first == 0) {
        missed_mbr = true;
        prev_block = src;
        return;
    }
    if (cfg_table[src].child.count(targ_addr) == 0)
        cfg_table[src].child[targ_addr] = 1;
    else
        cfg_table[src].child[targ_addr] += 1;
}

static void at_mbr(uint64_t src, app_pc branch_addr, app_pc targ) {
#ifdef JUMP_MBR
    if (mbr_first_targ[branch_addr] == 0) {
        mbr_first_targ[branch_addr] = (uint64_t) targ;
    }
#endif
    const address targ_addr(app_pc_to_address(targ, true));
    if (targ_addr.first == 0) {
        missed_mbr = true;
        prev_block = src;
        return;
    }
    if (cfg_table[src].child.count(targ_addr) == 0)
        cfg_table[src].child[targ_addr] = 1;
    else
        cfg_table[src].child[targ_addr] += 1;
}

#ifdef __x86_64__
static void at_mbr_x86(app_pc instr_addr, app_pc target_addr) {
    uint64_t src = blocknum_table[instr_addr];
#ifdef JUMP_MBR
    if (mbr_first_targ[instr_addr] == 0) {
        mbr_first_targ[instr_addr] = (uint64_t) target_addr;
    }
#endif
    const address targ_addr(app_pc_to_address(target_addr, true));
    /* missed_mbr */
    if (targ_addr.first == 0) {
        missed_mbr = true;
        prev_block = src;
        const address mbr_addr(app_pc_to_address(instr_addr, true));
        auto tmp_pair = make_pair(mbr_addr, target_addr);
        if (missed_mbr_table.count(tmp_pair) == 0) {
            missed_mbr_table[tmp_pair] = address(0, 0);
            missed_targ = target_addr;
        } else {
            cfg_table[src].child[missed_mbr_table[tmp_pair]] += 1;
            missed_mbr = false;
        }
        return;
    }

    if (cfg_table[src].child.count(targ_addr) == 0)
        cfg_table[src].child[targ_addr] = 1;
    else
        cfg_table[src].child[targ_addr] += 1;
}
#endif

static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
    // uint64_t block_num = !for_trace ? cfg_table.allocate() : cfg_table.size()-1;
    uint64_t block_num = cfg_table.allocate();
    uint num_instructions = 0;
    instr_t *instr;
    instr_t *first_inst = instrlist_first_app(bb);
    instr_t *last_inst = instrlist_last_app(bb);

    /* count the number of instructions in this block */
    for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next_app(instr)) {
        num_instructions++;
    }

    #ifdef __x86_64__
    /* count the number of instructions and inst length in this block */
    cfg_table[block_num].inst_length = (int*) malloc(num_instructions*sizeof(int));
    int i = 0;
    for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next_app(instr)) {
        cfg_table[block_num].inst_length[i] = decode_sizeof(drcontext, instr_get_app_pc(instr), NULL, NULL);
        ++i;
    }
    #endif

    /* get PC and opcode of the first/last inst */
    app_pc addr_f = instr_get_app_pc(first_inst);
    app_pc addr_l = instr_get_app_pc(last_inst);
    int opcode = instr_get_opcode(last_inst); // opcode of last inst in the block

    const address key(app_pc_to_address(addr_f));
    const app_module &mod = modules[key.first];

    if (missed_mbr) {
        /* Last block was an mbr to an unloaded module. The dynamic linker will
         * now have resolved this and this block is the real target. */
        #ifdef __x86_64__
        missed_mbr_table[make_pair(cfg_table[prev_block].star_addr, missed_targ)] = key;
        #endif
        if (cfg_table[prev_block].child.count(key) == 0)
            cfg_table[prev_block].child[key] = 1;
        else
            cfg_table[prev_block].child[key] += 1;

        missed_mbr = false;
    }
    #ifdef CHECK
    if (cfg_block.count(key) == 0) { // inst not exist
        cfg_node tmp = {.count = 0,
                        .star_addr = key,
                        .end_addr = (uint64_t) addr_l - mod.addr,
                        .inst_name = decode_opcode_name(opcode),
                        #ifdef __x86_64__
                        .inst_length = cfg_table[block_num].inst_length,
                        #endif
                        .block_size = num_instructions
                       };
        cfg_block[key] = tmp;
    } else {
        if (for_trace &&
            (cfg_block[key].end_addr != (uint64_t) addr_l - mod.addr ||
             cfg_block[key].block_size != num_instructions))
        {
            PRINTF_STDOUT("statr %ld %lx %ld %lx\n", cfg_block[key].star_addr.first,cfg_block[key].star_addr.second, key.first, key.second);
            PRINTF_STDOUT("end %lx %lx\n", cfg_block[key].end_addr, (uint64_t) addr_l - mod.addr);
            PRINTF_STDOUT("size %ld %d\n", cfg_block[key].block_size, num_instructions);
            PRINTF_STDOUT("name %s %s\n", cfg_block[key].inst_name, decode_opcode_name(opcode));
        }
    }
    #endif

    cfg_table[block_num].star_addr = key;
    cfg_table[block_num].end_addr = (uint64_t) addr_l - mod.addr;
    cfg_table[block_num].inst_name = decode_opcode_name(opcode);
    cfg_table[block_num].block_size = num_instructions;
    cfg_table[block_num].count = 0;
    cfg_table[block_num].fall_count = 0;
    cfg_table[block_num].first_targ = 0;

    /* save arithmetic flags and registers */
    #ifdef __x86_64__
    dr_save_arith_flags(drcontext, bb, first_inst, SPILL_SLOT_1);
    #elif defined(__aarch64__)
    dr_save_reg(drcontext, bb, first_inst, DR_REG_X1, SPILL_SLOT_2);
    dr_save_reg(drcontext, bb, first_inst, DR_REG_X2, SPILL_SLOT_3);
    dr_save_reg(drcontext, bb, first_inst, DR_REG_X0, SPILL_SLOT_1);
    dr_save_arith_flags_to_reg(drcontext, bb, first_inst, DR_REG_X0);
    opnd_t reg_val = opnd_create_reg(DR_REG_X1);
    opnd_t reg_addr = opnd_create_reg(DR_REG_X2);
    #endif
    opnd_t mem;

    bool cbr = instr_is_cbr(last_inst);
    bool ubr = instr_is_ubr(last_inst);
    bool mbr = instr_is_mbr(last_inst);
    bool dir_call = instr_is_call_direct(last_inst);
    if (cbr) { // dir con, increment child counter of fall-through inst
#ifdef CBR // instrumentaion
        app_pc targ = instr_get_branch_target_pc(last_inst);
        DR_ASSERT(targ);
        cfg_table[block_num].child[app_pc_to_address(targ)] = 0;
        #ifdef __x86_64__
        /* create label before last_inst */
        instr_t* app_cbr_label = INSTR_CREATE_label(drcontext);
        /* create & insert conditional jump same with last_inst except the targ addr */
        instr_t *my_cbr = instr_clone(drcontext, last_inst);
        instr_set_target(my_cbr, opnd_create_instr(app_cbr_label));
        instrlist_meta_preinsert(bb, last_inst, my_cbr);
        /* save arithmetic flags and registers */
        dr_save_arith_flags(drcontext, bb, last_inst, SPILL_SLOT_2);
        /* increment fall counter */
        mem = OPND_CREATE_ABSMEM((::byte*) &cfg_table[block_num].fall_count, OPSZ_8);
        instrlist_meta_preinsert(bb, last_inst, INSTR_CREATE_add(drcontext, mem, OPND_CREATE_INT8(1)));
        /* restore arithmetic flags and registers */
        dr_restore_arith_flags(drcontext, bb, last_inst, SPILL_SLOT_2);
        /* insert app_cbr_label before the application cbr */
        instrlist_meta_preinsert(bb, last_inst, app_cbr_label);
        #elif defined(__aarch64__)
        /* save arithmetic flags and registers */
        dr_save_reg(drcontext, bb, NULL, DR_REG_X1, SPILL_SLOT_2);
        dr_save_reg(drcontext, bb, NULL, DR_REG_X2, SPILL_SLOT_3);
        dr_save_reg(drcontext, bb, NULL, DR_REG_X0, SPILL_SLOT_1);
        dr_save_arith_flags_to_reg(drcontext, bb, NULL, DR_REG_X0);
        /* increment fall counter */
        opnd_create_reg64((uint64_t) &cfg_table[block_num].fall_count, drcontext, bb, NULL, reg_addr);
        mem = OPND_CREATE_MEM64(DR_REG_X2, 0); // set addr opnd for counter
        instrlist_meta_preinsert(bb, NULL, INSTR_CREATE_ldr(drcontext, reg_val, mem)); // load [reg_addr] to reg_val
        instrlist_meta_preinsert(bb, NULL, INSTR_CREATE_add(drcontext, reg_val, reg_val, OPND_CREATE_INT(1))); // increment reg_val
        instrlist_meta_preinsert(bb, NULL, INSTR_CREATE_str(drcontext, mem, reg_val)); // store reg_val into [reg_addr]
        /* restore arithmetic flags and registers */
        dr_restore_arith_flags_from_reg(drcontext, bb, NULL, DR_REG_X0);
        dr_restore_reg(drcontext, bb, NULL, DR_REG_X0, SPILL_SLOT_1);
        dr_restore_reg(drcontext, bb, NULL, DR_REG_X1, SPILL_SLOT_2);
        dr_restore_reg(drcontext, bb, NULL, DR_REG_X2, SPILL_SLOT_3);
        #endif
#endif // if 0, instrumentaion
    } else if (ubr || dir_call) { // dir uncon, just increment child counter of branch target
#ifdef UBR // instrumentaion
        address targ(app_pc_to_address(instr_get_branch_target_pc(last_inst)));
        cfg_table[block_num].child[targ] = 0;
        /* increment child counter */
        #ifdef __x86_64__
        mem = OPND_CREATE_ABSMEM((::byte*) &cfg_table[block_num].child[targ], OPSZ_8);
        instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_add(drcontext, mem, OPND_CREATE_INT8(1)));
        #elif defined(__aarch64__)
        opnd_create_reg64((uint64_t) &cfg_table[block_num].child[targ], drcontext, bb, first_inst, reg_addr);
        mem = OPND_CREATE_MEM64(DR_REG_X2, 0); // set addr opnd for counter
        instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_ldr(drcontext, reg_val, mem)); // load [reg_addr] into reg_val
        instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_add(drcontext, reg_val, reg_val, OPND_CREATE_INT(1))); // increment reg_val
        instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_str(drcontext, mem, reg_val)); // store reg_val into [reg_addr]
        #endif
#endif // if 0, instrumentaion
    } else { // mbr (handled later by clean call), or sys (incrment the child counter of next inst)
#ifdef SYS // instrumentaion
        app_pc next = (app_pc) decode_next_pc(drcontext, (::byte *)addr_l);
        if (next && !mbr) { // sys
            const address key(app_pc_to_address(next));
            cfg_table[block_num].child[key] = 0;
            /* increment child counter */
            #ifdef __x86_64__
            mem = OPND_CREATE_ABSMEM((::byte*) &cfg_table[block_num].child[key], OPSZ_8);
            instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_add(drcontext, mem, OPND_CREATE_INT8(1)));
            #elif defined(__aarch64__)
            opnd_create_reg64((uint64_t) &cfg_table[block_num].child[key], drcontext, bb, first_inst, reg_addr);
            mem = OPND_CREATE_MEM64(DR_REG_X2, 0); // set addr opnd for counter
            instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_ldr(drcontext, reg_val, mem)); // load [reg_addr] into reg_val
            instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_add(drcontext, reg_val, reg_val, OPND_CREATE_INT(1))); // increment reg_val
            instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_str(drcontext, mem, reg_val)); // store reg_val into [reg_addr]
            #endif
        }
#endif // if 0, instrumentaion
    }

#ifdef LOCAL // instrumentaion
    /* increment the local counter of block */
    #ifdef __x86_64__
    mem = OPND_CREATE_ABSMEM((::byte*) &cfg_table[block_num].count, OPSZ_8);
    // instrlist_meta_preinsert(bb, first_inst, LOCK(INSTR_CREATE_inc(drcontext, mem)));
    instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_add(drcontext, mem, OPND_CREATE_INT8(1)));
    #elif defined(__aarch64__)
    opnd_create_reg64((uint64_t) &cfg_table[block_num].count, drcontext, bb, first_inst, reg_addr); // move the addr of counter to reg_addr
    mem = OPND_CREATE_MEM64(DR_REG_X2, 0); // set addr opnd for counter
    instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_ldr(drcontext, reg_val, mem)); // load [reg_addr] into reg_val
    instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_add(drcontext, reg_val, reg_val, OPND_CREATE_INT(1))); // increment reg_val
    instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_str(drcontext, mem, reg_val)); // store reg_val into [reg_addr]
    #endif
#endif // if 0, instrumentaion

#ifdef GLOBAL // instrumentaion
    /* increment the global counter for stack profiling */
    #ifdef __x86_64__
    mem = OPND_CREATE_ABSMEM((::byte*) &inst_counter, OPSZ_8);
    instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_add(drcontext, mem, OPND_CREATE_INT32(num_instructions)));
    #elif defined(__aarch64__)
    opnd_create_reg64((uint64_t) &inst_counter, drcontext, bb, first_inst, reg_addr); // move the addr of counter to reg_addr
    mem = OPND_CREATE_MEM64(DR_REG_X2, 0); // set addr opnd for counter
    instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_ldr(drcontext, reg_val, mem)); // load [reg_addr] into reg_val
    instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_add(drcontext, reg_val, reg_val, OPND_CREATE_INT(num_instructions))); // increment reg_val
    instrlist_meta_preinsert(bb, first_inst, INSTR_CREATE_str(drcontext, mem, reg_val)); // store reg_val into [reg_addr]
    #endif
#endif // if 0, instrumentaion

    /* restore arithmetic flags and registers */
    #ifdef __x86_64__
    dr_restore_arith_flags(drcontext, bb, first_inst, SPILL_SLOT_1); // x86
    #elif defined(__aarch64__)
    dr_restore_arith_flags_from_reg(drcontext, bb, first_inst, DR_REG_X0);
    dr_restore_reg(drcontext, bb, first_inst, DR_REG_X0, SPILL_SLOT_1);
    dr_restore_reg(drcontext, bb, first_inst, DR_REG_X1, SPILL_SLOT_2);
    dr_restore_reg(drcontext, bb, first_inst, DR_REG_X2, SPILL_SLOT_3);
    #endif

#ifdef MBR // mbr clean call
    /* insert clean call for indirect branches */
    if (mbr) {
#if CHECK
        num_mbr++;
#endif
        DR_ASSERT(instr_is_cti(last_inst));
        opnd_t target_opnd = instr_get_target(last_inst);
        #ifdef __x86_64__
        DR_ASSERT(opnd_is_reg(target_opnd) || opnd_is_memory_reference(target_opnd));
#ifdef JUMP_MBR
        if (mbr_first_targ.count(addr_l) == 0)
            mbr_first_targ[addr_l] = 0;
        /* create label */
        instr_t* first_targ_label = INSTR_CREATE_label(drcontext);
        instr_t* last_inst_label = INSTR_CREATE_label(drcontext);
        /* move mbr targ addr to targ_reg */
        opnd_t tls_opnd = dr_reg_spill_slot_opnd(drcontext, SPILL_SLOT_3);
        instr_t *newinst;
        reg_id_t reg_target;
        reg_id_t reg_first_addr;
        for (reg_target = DR_REG_RAX+1; reg_target <= DR_REG_R15; reg_target++) {
            if (!instr_uses_reg(last_inst, reg_target))
                break; // find a reg not used by the mbr
        }
        newinst = INSTR_CREATE_mov_st(drcontext, tls_opnd, opnd_create_reg(reg_target));
        instrlist_meta_preinsert(bb, last_inst, newinst); // store the original reg into SPILL_SLOT_3
        for (reg_first_addr = DR_REG_RAX+1; reg_first_addr <= DR_REG_R15; reg_first_addr++) {
            if ((reg_first_addr != reg_target) && (!instr_uses_reg(last_inst, reg_first_addr)))
                break; // find a another reg not used by the mbr
        }
        dr_save_reg(drcontext, bb, last_inst, reg_first_addr, SPILL_SLOT_2); // save reg_first_addr
        if (instr_is_return(last_inst)) {
            /* the retaddr operand is always the final source for all OP_ret* instrs */
            opnd_t retaddr = instr_get_src(last_inst, instr_num_srcs(last_inst) - 1);
            opnd_size_t sz = opnd_get_size(retaddr);
            /* Even for far ret and iret, retaddr is at TOS
            * but operand size needs to be set to stack size
            * since iret pops more than return address.
            */
            opnd_set_size(&retaddr, OPSZ_STACK);
            newinst = instr_create_1dst_1src(drcontext, sz == OPSZ_2 ? OP_movzx : OP_mov_ld,
                                             opnd_create_reg(reg_target), retaddr);
            instrlist_meta_preinsert(bb, last_inst, newinst); // move the targ addr into reg_target
        } else {
            /* call* or jmp* */
            opnd_t src = instr_get_src(last_inst, 0);
            opnd_size_t sz = opnd_get_size(src);
            /* if a far cti, we can't fit it into a register: asserted above.
            * in release build we'll get just the address here.
            */
            if (instr_is_far_cti(last_inst)) {
                if (sz == OPSZ_10) {
                    sz = OPSZ_8;
                } else if (sz == OPSZ_6) {
                    sz = OPSZ_4;
                # ifdef X64
                    reg_target = reg_64_to_32(reg_target);
                # endif
                } else /* target has OPSZ_4 */ {
                    sz = OPSZ_2;
                }
                opnd_set_size(&src, sz);
            }
            newinst = instr_create_1dst_1src(drcontext, sz == OPSZ_2 ? OP_movzx : OP_mov_ld,
                                             opnd_create_reg(reg_target), src);
            if (opnd_is_far_base_disp(src))
                DR_ASSERT(drutil_insert_get_mem_addr(drcontext, bb, last_inst, src, reg_target, reg_first_addr));
            else
                instrlist_meta_preinsert(bb, last_inst, newinst);
        }
        /* move mbr_first_targ[addr_f] into reg_first_addr */
        instrlist_meta_preinsert(bb, last_inst,
                                 INSTR_CREATE_mov_ld(drcontext,
                                                     opnd_create_reg(reg_first_addr),
                                                     OPND_CREATE_ABSMEM((::byte*) &mbr_first_targ[addr_l], OPSZ_8)));
        /* create cmp */
        dr_save_arith_flags(drcontext, bb, last_inst, SPILL_SLOT_1);
        instrlist_meta_preinsert(bb, last_inst,
                                 INSTR_CREATE_cmp(drcontext,
                                                  opnd_create_reg(reg_target),
                                                  opnd_create_reg(reg_first_addr)));
        /* restore reg_target and reg_first_addr */
        instrlist_meta_preinsert(bb, last_inst, INSTR_CREATE_xchg(drcontext, tls_opnd, opnd_create_reg(reg_target)));
        dr_restore_reg(drcontext, bb, last_inst, reg_first_addr, SPILL_SLOT_2);
        /* create je */
        instr_t *my_je = instr_create(drcontext);
        instr_set_opcode(my_je, OP_je);
        instr_set_num_opnds(drcontext, my_je, 0, 1);
        instr_set_src(my_je, 0, opnd_create_instr(first_targ_label));
        instrlist_meta_preinsert(bb, last_inst, my_je);
        dr_restore_arith_flags(drcontext, bb, last_inst, SPILL_SLOT_1); // restore if my_je fall-through to clean call
#endif // jump mbr
        /* insert clean call for other targets */
        if (blocknum_table.count(addr_l) == 0) {
            blocknum_table[addr_l] = block_num;
        }
        dr_insert_mbr_instrumentation(drcontext, bb, last_inst, (app_pc) at_mbr_x86, SPILL_SLOT_2);
#ifdef JUMP_MBR
        /* create jmp */
        instr_t *my_jmp = instr_create(drcontext);
        instr_set_opcode(my_jmp, OP_jmp);
        instr_set_num_opnds(drcontext, my_jmp, 0, 1);
        instr_set_src(my_jmp, 0, opnd_create_instr(last_inst_label));
        instrlist_meta_preinsert(bb, last_inst, my_jmp); // jump to end the block last inst
        /* insert first_targ_label */
        instrlist_meta_preinsert(bb, last_inst, first_targ_label);
        /* increment the first target counter (targ of my_je) */
        mem = OPND_CREATE_ABSMEM((::byte*) &cfg_table[block_num].first_targ, OPSZ_8); // first targ
        instrlist_meta_preinsert(bb, last_inst, INSTR_CREATE_add(drcontext, mem, OPND_CREATE_INT8(1)));
        dr_restore_arith_flags(drcontext, bb, last_inst, SPILL_SLOT_1); // restore if my_je is taken
        /* insert last_inst_label */
        instrlist_meta_preinsert(bb, last_inst, last_inst_label);
#endif // jump mbr
        #elif defined(__aarch64__)
        DR_ASSERT(opnd_is_reg(target_opnd));
#ifdef JUMP_MBR
        if (mbr_first_targ.count(addr_l) == 0)
            mbr_first_targ[addr_l] = 0;
        /* create label */
        instr_t* first_targ_label = INSTR_CREATE_label(drcontext);
        instr_t* last_inst_label = INSTR_CREATE_label(drcontext);
        /* move mbr_first_targ[addr_f] into reg_first_addr */
        reg_id_t reg_first_addr, reg_tmp;
        for (reg_first_addr = DR_REG_X0+1; reg_first_addr <= DR_REG_X30; reg_first_addr++) {
            if (!instr_uses_reg(last_inst, reg_first_addr))
                break; // find a another reg not used by the mbr
        }
        for (reg_tmp = DR_REG_X0+1; reg_tmp <= DR_REG_X30; reg_tmp++) {
            if ((reg_tmp != reg_first_addr) && (!instr_uses_reg(last_inst, reg_tmp)))
                break; // find a another reg not used by the mbr
        }
        dr_save_reg(drcontext, bb, last_inst, reg_first_addr, SPILL_SLOT_2); // save reg_first_addr
        dr_save_reg(drcontext, bb, last_inst, reg_tmp, SPILL_SLOT_3); // save reg_tmp
        opnd_create_reg64((uint64_t) &mbr_first_targ[addr_l], drcontext, bb, last_inst, opnd_create_reg(reg_tmp));
        instrlist_meta_preinsert(bb, last_inst, INSTR_CREATE_ldr(drcontext,
                                                                 opnd_create_reg(reg_first_addr),
                                                                 OPND_CREATE_MEM64(reg_tmp, 0)));
        /* create cmp */
        dr_save_reg(drcontext, bb, last_inst, DR_REG_X0, SPILL_SLOT_1);
        dr_save_arith_flags_to_reg(drcontext, bb, last_inst, DR_REG_X0);
        instrlist_meta_preinsert(bb, last_inst,
                                 INSTR_CREATE_cmp(drcontext,
                                                  target_opnd,
                                                  opnd_create_reg(reg_first_addr)));
        /* create je */
        instr_t *my_je = INSTR_CREATE_bcond(drcontext, opnd_create_instr(first_targ_label));
        INSTR_PRED(my_je, DR_PRED_EQ);
        instrlist_meta_preinsert(bb, last_inst, my_je);
        /*-----test-------*/
        dr_save_reg(drcontext, bb, last_inst, opnd_get_reg(target_opnd), SPILL_SLOT_4);
        /*-----test-------*/
        /* restore if my_je fall-through to clean call */
        dr_restore_arith_flags_from_reg(drcontext, bb, last_inst, DR_REG_X0);
        dr_restore_reg(drcontext, bb, last_inst, DR_REG_X0, SPILL_SLOT_1);
        dr_restore_reg(drcontext, bb, last_inst, reg_first_addr, SPILL_SLOT_2);
        dr_restore_reg(drcontext, bb, last_inst, reg_tmp, SPILL_SLOT_3);
#endif
        dr_insert_clean_call(drcontext, bb, last_inst, (void *) at_mbr, false, 3,
                             OPND_CREATE_INT(block_num),
                             OPND_CREATE_INT(addr_l),
                             target_opnd);
#ifdef JUMP_MBR
        /* create jmp */
        instr_t *my_jmp = instr_create(drcontext);
        instr_set_opcode(my_jmp, OP_b);
        instr_set_num_opnds(drcontext, my_jmp, 0, 1);
        instr_set_src(my_jmp, 0, opnd_create_instr(last_inst_label));
        instrlist_meta_preinsert(bb, last_inst, my_jmp); // jump to end the block last inst
        /* insert first_targ_label */
        instrlist_meta_preinsert(bb, last_inst, first_targ_label);
        /* increment the first target counter (targ of my_je) */
        opnd_create_reg64((uint64_t) &cfg_table[block_num].first_targ, drcontext, bb, last_inst, opnd_create_reg(reg_first_addr));
        mem = OPND_CREATE_MEM64(reg_first_addr, 0); // set addr opnd for counter
        instrlist_meta_preinsert(bb, last_inst, INSTR_CREATE_ldr(drcontext, opnd_create_reg(reg_tmp), mem));
        instrlist_meta_preinsert(bb, last_inst, INSTR_CREATE_add(drcontext,
                                                                 opnd_create_reg(reg_tmp),
                                                                 opnd_create_reg(reg_tmp),
                                                                 OPND_CREATE_INT(1)));
        instrlist_meta_preinsert(bb, last_inst, INSTR_CREATE_str(drcontext, mem, opnd_create_reg(reg_tmp)));
        /* restore if my_je is taken */
        dr_restore_arith_flags_from_reg(drcontext, bb, last_inst, DR_REG_X0);
        dr_restore_reg(drcontext, bb, last_inst, DR_REG_X0, SPILL_SLOT_1);
        dr_restore_reg(drcontext, bb, last_inst, reg_first_addr, SPILL_SLOT_2);
        dr_restore_reg(drcontext, bb, last_inst, reg_tmp, SPILL_SLOT_3);
        /* insert last_inst_label */
        instrlist_meta_preinsert(bb, last_inst, last_inst_label);
#endif
        #endif
    }
#endif // if 0, mbr clean call

#ifdef SP
    /* insert clean call for stack profiling */
    if (instr_is_call(last_inst)) {
        if (stack_counter_map.count(app_pc_to_address(addr_l)) == 0)
            stack_counter_map[app_pc_to_address(addr_l)] = 0;
        #ifdef __x86_64__
        #ifdef ADDR_CONV
        dr_insert_clean_call(drcontext, bb, last_inst, (void *) at_call, false, 2, OPND_CREATE_INT64(addr_l),
                             OPND_CREATE_INT32(decode_sizeof(drcontext, addr_l, NULL, NULL)));
        #else
        if (stack_counter_map_pc.count(addr_l) == 0)
            stack_counter_map_pc[addr_l] = 0;
        inlined_at_call_x86(drcontext, bb, last_inst, addr_l, decode_sizeof(drcontext, addr_l, NULL, NULL));
        #endif
        #elif defined(__aarch64__)
        #ifdef ADDR_CONV
        dr_insert_clean_call(drcontext, bb, last_inst, (void *) at_call, false, 1, OPND_CREATE_INT(addr_l));
        #else
        if (stack_counter_map_pc.count(addr_l) == 0)
            stack_counter_map_pc[addr_l] = 0;
        inlined_at_call_aarch64(drcontext, bb, last_inst, addr_l, INST_LEN);
        #endif
        #endif
    } else if (instr_is_return(last_inst)) {
        #ifdef __x86_64__
        #ifdef ADDR_CONV
        dr_insert_mbr_instrumentation(drcontext, bb, last_inst, (void *) at_return, SPILL_SLOT_1);
        #else
        inlined_at_return_x86(drcontext, bb, last_inst);
        #endif // ADDR_CONV
        #elif defined(__aarch64__)
        #ifdef ADDR_CONV
        opnd_t targ = instr_get_target(last_inst);
        dr_insert_clean_call(drcontext, bb, last_inst, (void *) at_return, false, 1, targ);
        #else
        inlined_at_return_aarch64(drcontext, bb, last_inst);
        #endif // ADDR_CONV
        #endif // __x86_64__
    }
#endif // sp

    #ifdef CHECK
    /* insert clean call */
    #ifdef __x86_64__
    dr_insert_clean_call(drcontext, bb, first_inst, (void *) clean_call, false, 4,
                        OPND_CREATE_INT32(num_instructions), OPND_CREATE_INT64(addr_f),
                        OPND_CREATE_INT64(addr_l), OPND_CREATE_INT32(opcode));
    #elif defined(__aarch64__)
    dr_insert_clean_call(drcontext, bb, first_inst, (void *) clean_call, false, 4,
                        OPND_CREATE_INT(num_instructions), OPND_CREATE_INT(addr_f),
                        OPND_CREATE_INT(addr_l), OPND_CREATE_INT(opcode));
    #endif // __x86_64__
    #endif // CHECK

    return DR_EMIT_DEFAULT;
}

static void event_module_load(void *drcontext, const module_data_t *info, bool loaded) {
    dr_mutex_lock(modules_lock);
    modules.emplace_back(app_module{
        .addr = (uint64_t)info->start,
        .end_addr = (uint64_t)info->end,
        .base = (uint64_t)info->preferred_base,
        .index = (module_id)modules.size(),
        .path = string(info->full_path),
    });
    loaded_modules.push_back(modules.size()-1);
    dr_mutex_unlock(modules_lock);
}

static void event_module_unload(void *drcontext, const module_data_t *info) {
    dr_mutex_lock(modules_lock);
    #ifndef ADDR_CONV
    module_unload_flag = true;
    for (auto itr: stack_counter_map_pc) {
        stack_counter_map[app_pc_to_address(itr.first)] = itr.second;
    }
    #endif
    for (auto itr = loaded_modules.begin(); itr != loaded_modules.end(); itr++) {
        const app_module *m = &modules[*itr];
        if (m->addr == (uint64_t)info->start) {
            loaded_modules.erase(itr);
            dr_mutex_unlock(modules_lock);
            return;
        }
    }

    dr_mutex_unlock(modules_lock);
    PRINT_STDERR("Warning: non-existent module unloaded?\n");
}

static address app_pc_to_address(app_pc arg, bool allow_miss) {
    uint64_t addr = (uint64_t)arg;
    const app_module *mod = nullptr;
    for (auto i: loaded_modules) {
        const app_module *m = &modules[i];
        if (m->addr <= addr && m->end_addr > addr) {
            mod = m;
            break;
        }
    }
    if (!mod) {
        if (!allow_miss)
            PRINTF_STDERR("Error: no known module loaded @ %p\n", arg);
        mod = &modules[0];
    }
    return address(mod->index, addr - mod->addr + mod->base);
}

#ifdef ADDR_CONV
#ifdef __x86_64__
static void at_call(app_pc call_addr, int len) {
    DR_ASSERT(stack_index < (stack_size-1));
    stack_index++;
    #ifdef SP_CALL
    call_stack[stack_index] = { .call_addr = app_pc_to_address(call_addr),
                                .return_addr = app_pc_to_address(call_addr+len),
                                .counter = inst_counter
                              };
    inst_counter = 0;
    #endif
}
    #elif defined(__aarch64__)
static void at_call(app_pc call_addr) {
    DR_ASSERT(stack_index < (stack_size-1));
    stack_index++;
    call_stack[stack_index] = {.call_addr = app_pc_to_address(call_addr),
                               .return_addr = app_pc_to_address(call_addr+INST_LEN),
                               .counter = inst_counter
                              };

    inst_counter = 0;
}
#endif

#ifdef __x86_64__
static void at_return(app_pc inst_addr, app_pc targ_addr) {
    // DR_ASSERT(stack_index >= 0);
    stack_entry last_caller = call_stack[stack_index];
    stack_index--;
    #ifdef SP_RET
    if (app_pc_to_address(targ_addr) != last_caller.return_addr) // check if the retrun addr is correct
        PRINTF_STDERR("Error: mismatched stack info: %ld %lx, %ld %lx\n",
                  last_caller.call_addr.first, last_caller.call_addr.second,
                  app_pc_to_address(targ_addr).first, app_pc_to_address(targ_addr).second);
    bool found = false;
    for (int64_t i = 0; i <= stack_index; ++i) {
        if (call_stack[i].return_addr == last_caller.return_addr) { found = true; break; }
    }
    if (!found) {
        stack_counter_map[last_caller.call_addr] += inst_counter; // no duplicated element (i.e., no recursion)
    }
    inst_counter += last_caller.counter;
    #endif
}
#elif defined(__aarch64__)
static void at_return(app_pc targ_addr) {
    stack_entry last_caller = call_stack[stack_index];
    stack_index--;
    if (app_pc_to_address(targ_addr) != last_caller.return_addr) // check if the retrun addr is correct
        PRINTF_STDERR("Error: mismatched stack info: %ld %lx, %ld %lx\n",
                  last_caller.call_addr.first, last_caller.call_addr.second,
                  app_pc_to_address(targ_addr).first, app_pc_to_address(targ_addr).second);
    bool found = false;
    for (int16_t i = 0; i <= stack_index; ++i) {
        if (call_stack[i].return_addr == last_caller.return_addr) { found = true; break; }
    }
    if (!found)
        stack_counter_map[last_caller.call_addr] += inst_counter; // no duplicated element (i.e., no recursion)
    inst_counter += last_caller.counter;
}
#endif

#else // do not do address conversion in sp clean call
#ifdef __x86_64__
static void at_call(app_pc call_addr, int len) {
    DR_ASSERT(stack_index < (stack_size-1));
    stack_index++;
    call_stack[stack_index] = { .call_addr = call_addr,
                                .return_addr = call_addr+len,
                                .counter = inst_counter,
                                .pointer = &stack_counter_map_pc[call_addr]
                              };
    inst_counter = 0;
}
#elif defined(__aarch64__)
static void at_call(app_pc call_addr) {
    DR_ASSERT(stack_index < (stack_size-1));
    stack_index++;
    call_stack[stack_index] = {.call_addr = call_addr,
                               .return_addr = call_addr+INST_LEN,
                               .counter = inst_counter
                              };

    inst_counter = 0;
}
#endif

#ifdef __x86_64__
static void at_return(app_pc inst_addr, app_pc targ_addr) {
    DR_ASSERT(stack_index >= 0);
    stack_entry last_caller = call_stack[stack_index];
    stack_index--;
    if (targ_addr != last_caller.return_addr) // check if the retrun addr is correct
        PRINTF_STDERR("Error: mismatched stack info: %lx, %lx\n", last_caller.call_addr,targ_addr);
    bool found = false;
    for (int64_t i = 0; i <= stack_index; ++i) {
        if (call_stack[i].return_addr == last_caller.return_addr) { found = true; break; }
    }
    if (!found) {
        stack_counter_map_pc[last_caller.call_addr] += inst_counter; // no duplicated element (i.e., no recursion)
    }
    inst_counter += last_caller.counter;
}
#elif defined(__aarch64__)
static void at_return(app_pc targ_addr) {
    stack_entry last_caller = call_stack[stack_index];
    stack_index--;
    if (targ_addr != last_caller.return_addr) // check if the retrun addr is correct
        PRINTF_STDERR("Error: mismatched stack info: %lx, %lx\n",
                  last_caller.call_addr, targ_addr);
    bool found = false;
    for (int16_t i = 0; i <= stack_index; ++i) {
        if (call_stack[i].return_addr == last_caller.return_addr) { found = true; break; }
    }
    if (!found)
        stack_counter_map_pc[last_caller.call_addr] += inst_counter; // no duplicated element (i.e., no recursion)
    inst_counter += last_caller.counter;
}
#endif
#endif // ADDR_CONV

#ifndef ADDR_CONV
void stackoverflow_exit() {
    PRINT_STDERR("Error: overflow occurs when doing stack profiling! Please use a larger value for --stack-size.\n");
    dr_abort();
}

#ifdef __x86_64__
// insert instructions before where to achieve the functionality of at_call()
static void inlined_at_call_x86(void *drcontext, instrlist_t *bb, instr_t *where, app_pc call_addr, int len) {
    opnd_t index = OPND_CREATE_ABSMEM((::byte*) &stack_index, OPSZ_8);
    opnd_t stack_base = OPND_CREATE_INT64((uint64_t) call_stack);
    opnd_t counter = OPND_CREATE_ABSMEM((::byte*) &inst_counter, OPSZ_8);

    reg_id_t reg_index = DR_REG_R14;
    reg_id_t reg_stack_base = DR_REG_R15;
    /* save arithmetic flag and registers */
    dr_save_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    dr_save_reg(drcontext, bb, where, reg_index, SPILL_SLOT_2);
    dr_save_reg(drcontext, bb, where, reg_stack_base, SPILL_SLOT_3);
    /* load stack_index into reg_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                 opnd_create_reg(reg_index),
                                                 index));
    /* check if stack_index is overflow */
    /* compare reg_index with stack_size-1 */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_cmp(drcontext,
                                              opnd_create_reg(reg_index),
                                              OPND_CREATE_INT32(stack_size-1)));
    /* jump to my_label if stack_index < stack_size-1 */
    instr_t* my_label = INSTR_CREATE_label(drcontext);
    instr_t *my_jl = instr_create(drcontext);
    instr_set_opcode(my_jl, OP_jl);
    instr_set_num_opnds(drcontext, my_jl, 0, 1);
    instr_set_src(my_jl, 0, opnd_create_instr(my_label));
    instrlist_meta_preinsert(bb, where, my_jl);
    /* insert clean call for exit */
    dr_insert_clean_call(drcontext, bb, where, (void*) stackoverflow_exit, false, 0);
    /* my_label */
    instrlist_meta_preinsert(bb, where, my_label);

    /* increment stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_index),
                                              OPND_CREATE_INT8(1)));
    /* store stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_st(drcontext,
                                                 index,
                                                 opnd_create_reg(reg_index)));
    /* reg_index <<= 5 (i.e., reg_index *= 32) */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_shl(drcontext,
                                              opnd_create_reg(reg_index),
                                              opnd_create_immed_int(5, OPSZ_1)));
    /* move call_stack base address into reg_stack_base */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_imm(drcontext,
                                                  opnd_create_reg(reg_stack_base),
                                                  stack_base));
    /* reg_stack_base = address of the element we want to access (reg_index is free after this instrumentaion) */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_index)));
    /* update call_stack[stack_index] */
    opnd_t call_addr_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 1, 0, OPSZ_8);
    opnd_t return_addr_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 1, 8, OPSZ_8);
    opnd_t counter_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 1, 16, OPSZ_8);
    opnd_t pointer_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 1, 24, OPSZ_8);
    /* update call_addr, reg_index is free */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_imm(drcontext,
                                                  opnd_create_reg(reg_index),
                                                  OPND_CREATE_INT64((uint64_t) call_addr)));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_st(drcontext,
                                                 call_addr_mem,
                                                 opnd_create_reg(reg_index)));
    /* update retrun_addr */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_imm(drcontext,
                                                  opnd_create_reg(reg_index),
                                                  OPND_CREATE_INT64(((uint64_t) call_addr) + len)));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_st(drcontext,
                                                 return_addr_mem,
                                                 opnd_create_reg(reg_index)));
    /* update counter */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                  opnd_create_reg(reg_index),
                                                  counter));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_st(drcontext,
                                                 counter_mem,
                                                 opnd_create_reg(reg_index)));
    /* set pointer = &stack_counter_map_pc[call_addr] */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_imm(drcontext,
                                                  opnd_create_reg(reg_index),
                                                  OPND_CREATE_INT64((uint64_t) &stack_counter_map_pc[call_addr])));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_st(drcontext,
                                                 pointer_mem,
                                                 opnd_create_reg(reg_index)));
    /* clear inst_counter */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_st(drcontext,
                                                 counter,
                                                 OPND_CREATE_INT32(0)));
    /* restore arithmetic flag and registers */
    dr_restore_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    dr_restore_reg(drcontext, bb, where, reg_index, SPILL_SLOT_2);
    dr_restore_reg(drcontext, bb, where, reg_stack_base, SPILL_SLOT_3);
}

// insert instructions before where to achieve the functionality of at_return()
static void inlined_at_return_x86(void *drcontext, instrlist_t *bb, instr_t *where) {
    opnd_t index = OPND_CREATE_ABSMEM((::byte*) &stack_index, OPSZ_8);
    opnd_t stack_base = OPND_CREATE_INT64((uint64_t) call_stack);
    opnd_t counter = OPND_CREATE_ABSMEM((::byte*) &inst_counter, OPSZ_8);

    // reg_id_t reg_0 = DR_REG_R9;
    reg_id_t reg_1 = DR_REG_R10;
    reg_id_t reg_2 = DR_REG_R11;
    reg_id_t reg_3 = DR_REG_R12;
    reg_id_t reg_4 = DR_REG_R13;
    reg_id_t reg_index = DR_REG_R14;
    reg_id_t reg_stack_base = DR_REG_R15;

    // opnd_t call_addr_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 0, 0, OPSZ_8);
    opnd_t return_addr_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 0, 8, OPSZ_8);
    opnd_t counter_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 0, 16, OPSZ_8);
    opnd_t pointer_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 0, 24, OPSZ_8);
    /* create labels */
    instr_t* loop_label = INSTR_CREATE_label(drcontext);
    instr_t* loop_end_label = INSTR_CREATE_label(drcontext);
    instr_t* end_label = INSTR_CREATE_label(drcontext);
    /* save arithmetic flag and registers */
    dr_save_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    dr_save_reg(drcontext, bb, where, reg_1, SPILL_SLOT_2);
    dr_save_reg(drcontext, bb, where, reg_2, SPILL_SLOT_3);
    dr_save_reg(drcontext, bb, where, reg_3, SPILL_SLOT_4);
    dr_save_reg(drcontext, bb, where, reg_4, SPILL_SLOT_5);
    dr_save_reg(drcontext, bb, where, reg_index, SPILL_SLOT_6);
    dr_save_reg(drcontext, bb, where, reg_stack_base, SPILL_SLOT_7);

    /*---access call_stack[stack_index]---*/
    /* load stack_index into reg_index  */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                 opnd_create_reg(reg_index),
                                                 index));
    /* reg_index <<= 5 (i.e., reg_index *= 32) */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_shl(drcontext,
                                              opnd_create_reg(reg_index),
                                              opnd_create_immed_int(5, OPSZ_1)));
    /* move call_stack base address into reg_stack_base */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_imm(drcontext,
                                                  opnd_create_reg(reg_stack_base),
                                                  stack_base));
    /* reg_stack_base = address of the element we want to access (reg_index is free after this instrumentaion) */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_index)));
    /* reg1, 2, 3 <- call_stack[stack_index].pointer, return_addr, counter */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                 opnd_create_reg(reg_1),
                                                 pointer_mem));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                 opnd_create_reg(reg_2),
                                                 return_addr_mem));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                 opnd_create_reg(reg_3),
                                                 counter_mem));
    /*---decrement stack_index---*/
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_sub(drcontext,
                                              index,
                                              OPND_CREATE_INT8(1)));
    /*--- i = 0, reg_index = i ---*/
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_imm(drcontext,
                                                  opnd_create_reg(reg_index),
                                                  OPND_CREATE_INT64(0)));
    /*--- loop ---*/
    instrlist_meta_preinsert(bb, where, loop_label);
    /*--- exit loop if i > stack_index ---*/
    /* reg_4 = stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                 opnd_create_reg(reg_4),
                                                 index));
    /* cmp i, stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_cmp(drcontext,
                                              opnd_create_reg(reg_index), // i
                                              opnd_create_reg(reg_4))); // stack_index
    /* jump to loop_end_label if i > stack_index */
    instr_t *my_jge = instr_create(drcontext);
    instr_set_opcode(my_jge, OP_jg);
    instr_set_num_opnds(drcontext, my_jge, 0, 1);
    instr_set_src(my_jge, 0, opnd_create_instr(loop_end_label));
    instrlist_meta_preinsert(bb, where, my_jge);
    /*---access call_stack[i].return_addr---*/
    instrlist_meta_preinsert(bb, where,
                             XINST_CREATE_move(drcontext,
                                                 opnd_create_reg(reg_4),
                                                 opnd_create_reg(reg_index)));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_shl(drcontext,
                                              opnd_create_reg(reg_4),
                                              opnd_create_immed_int(5, OPSZ_1)));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_imm(drcontext,
                                                  opnd_create_reg(reg_stack_base),
                                                  stack_base));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_4)));
    /* reg4 = call_stack[i].return_addr */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                 opnd_create_reg(reg_4),
                                                 opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 0, 8, OPSZ_8)));
    // instrlist_meta_preinsert(bb, where,
    //                          INSTR_CREATE_mov_imm(drcontext,
    //                                               opnd_create_reg(reg_2),
    //                                               OPND_CREATE_INT64(0)));
    /*--- jump to end_label if call_stack[i].return_addr == last_caller.return_addr ---*/
    /* create cmp */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_cmp(drcontext,
                                              opnd_create_reg(reg_2),
                                              opnd_create_reg(reg_4)));
    /* create je */
    instr_t *my_je = instr_create(drcontext);
    instr_set_opcode(my_je, OP_je);
    instr_set_num_opnds(drcontext, my_je, 0, 1);
    instr_set_src(my_je, 0, opnd_create_instr(end_label));
    instrlist_meta_preinsert(bb, where, my_je);
    /* i++ */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_index),
                                              OPND_CREATE_INT8(1)));
    /*--- jump back to loop head ---*/
    instr_t *my_jmp = instr_create(drcontext);
    instr_set_opcode(my_jmp, OP_jmp);
    instr_set_num_opnds(drcontext, my_jmp, 0, 1);
    instr_set_src(my_jmp, 0, opnd_create_instr(loop_label));
    instrlist_meta_preinsert(bb, where, my_jmp);
    /*--- loop_end_label ---*/
    instrlist_meta_preinsert(bb, where, loop_end_label);
    /*--- loop end ---*/
    /*--- update map[last_caller.call_addr(reg_1)] ---*/
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext,
                                                 opnd_create_reg(reg_4),
                                                 counter));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              OPND_CREATE_MEM64(reg_1, 0),
                                              opnd_create_reg(reg_4)));
    /*--- end_label ---*/
    instrlist_meta_preinsert(bb, where, end_label);
    /*--- inst_counter += last_caller.counter ---*/
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              counter,
                                              opnd_create_reg(reg_3)));
    /* restore arithmetic flag and registers */
    dr_restore_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    dr_restore_reg(drcontext, bb, where, reg_1, SPILL_SLOT_2);
    dr_restore_reg(drcontext, bb, where, reg_2, SPILL_SLOT_3);
    dr_restore_reg(drcontext, bb, where, reg_3, SPILL_SLOT_4);
    dr_restore_reg(drcontext, bb, where, reg_4, SPILL_SLOT_5);
    dr_restore_reg(drcontext, bb, where, reg_index, SPILL_SLOT_6);
    dr_restore_reg(drcontext, bb, where, reg_stack_base, SPILL_SLOT_7);
}

#elif defined(__aarch64__)
// insert instructions before where to achieve the functionality of at_call()
static void inlined_at_call_aarch64(void *drcontext, instrlist_t *bb, instr_t *where, app_pc call_addr, int len) {
    reg_id_t reg_index = DR_REG_X10;
    reg_id_t reg_stack_base = DR_REG_X11;
    reg_id_t reg_tmp = DR_REG_X12;

    /* save arithmetic flag and registers */
    dr_save_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    dr_save_reg(drcontext, bb, where, reg_index, SPILL_SLOT_2);
    dr_save_reg(drcontext, bb, where, reg_stack_base, SPILL_SLOT_3);
    dr_save_reg(drcontext, bb, where, reg_tmp, SPILL_SLOT_4);

    /* move &stack_index into reg_stack_base */
    opnd_create_reg64((uint64_t) &stack_index, drcontext, bb, where, opnd_create_reg(reg_tmp));
    opnd_t index = OPND_CREATE_MEM64(reg_tmp, 0);

    /* load stack_index into reg_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_index),
                                              index));
    /* check if stack_index is overflow */
    /* compare reg_index with stack_size-1 */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_cmp(drcontext,
                                              opnd_create_reg(reg_index),
                                              OPND_CREATE_INT16(stack_size-1)));
    /* jump to my_label if stack_index < stack_size-1 */
    instr_t* my_label = INSTR_CREATE_label(drcontext);
    instr_t *my_jl = INSTR_CREATE_bcond(drcontext, opnd_create_instr(my_label));
    INSTR_PRED(my_jl, DR_PRED_LT);
    instrlist_meta_preinsert(bb, where, my_jl);
    /* insert clean call for exit */
    dr_insert_clean_call(drcontext, bb, where, (void*) stackoverflow_exit, false, 0);
    /* my_label */
    instrlist_meta_preinsert(bb, where, my_label);

    /* increment stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_index),
                                              opnd_create_reg(reg_index),
                                              OPND_CREATE_INT(1)));
    /* store stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              index,
                                              opnd_create_reg(reg_index)));
    /* reg_index <<= 5 (i.e., reg_index *= 32) */
    instrlist_meta_preinsert(bb, where, INSTR_CREATE_movz(drcontext,
                                                          opnd_create_reg(reg_tmp),
                                                          OPND_CREATE_INT(5),
                                                          OPND_CREATE_INT(0)));
    instrlist_meta_preinsert(bb, where, instr_create_1dst_2src(drcontext, OP_lslv,
                                                               opnd_create_reg(reg_index),
                                                               opnd_create_reg(reg_index),
                                                               opnd_create_reg(reg_tmp)));
    /* move call_stack base address into reg_stack_base */
    opnd_create_reg64((uint64_t) call_stack, drcontext, bb, where, opnd_create_reg(reg_stack_base));
    /* reg_stack_base = address of the element we want to access (reg_index is free after this instrumentaion) */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_index)));
    /* update call_stack[stack_index] */
    opnd_t call_addr_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 1, 0, OPSZ_8);
    opnd_t return_addr_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 1, 8, OPSZ_8);
    opnd_t counter_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 1, 16, OPSZ_8);
    opnd_t pointer_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 1, 24, OPSZ_8);
    /* update call_addr, reg_index is free */
    opnd_create_reg64((uint64_t) call_addr, drcontext, bb, where, opnd_create_reg(reg_index));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              call_addr_mem,
                                              opnd_create_reg(reg_index)));
    /* update retrun_addr */
    opnd_create_reg64(((uint64_t) call_addr) + len, drcontext, bb, where, opnd_create_reg(reg_index));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              return_addr_mem,
                                              opnd_create_reg(reg_index)));
    /* update counter */
    /* move &inst_counter into reg_tmp */
    opnd_create_reg64((uint64_t) &inst_counter, drcontext, bb, where, opnd_create_reg(reg_tmp));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_index),
                                              OPND_CREATE_MEM64(reg_tmp, 0)));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              counter_mem,
                                              opnd_create_reg(reg_index)));
    /* clear inst_counter */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              OPND_CREATE_MEM64(reg_tmp, 0),
                                              OPND_CREATE_ZR(opnd_create_reg(reg_tmp))));
    /* set pointer = &stack_counter_map_pc[call_addr] */
    opnd_create_reg64((uint64_t) &stack_counter_map_pc[call_addr], drcontext, bb, where, opnd_create_reg(reg_index));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              pointer_mem,
                                              opnd_create_reg(reg_index)));
    /* restore arithmetic flag and registers */
    dr_restore_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    dr_restore_reg(drcontext, bb, where, reg_index, SPILL_SLOT_2);
    dr_restore_reg(drcontext, bb, where, reg_stack_base, SPILL_SLOT_3);
    dr_restore_reg(drcontext, bb, where, reg_tmp, SPILL_SLOT_4);
}

// insert instructions before where to achieve the functionality of at_return()
static void inlined_at_return_aarch64(void *drcontext, instrlist_t *bb, instr_t *where) {
    reg_id_t reg_1 = DR_REG_X10;
    reg_id_t reg_2 = DR_REG_X11;
    reg_id_t reg_3 = DR_REG_X12;
    reg_id_t reg_4 = DR_REG_X13;
    reg_id_t reg_index = DR_REG_X14;
    reg_id_t reg_index_addr = DR_REG_X15;
    reg_id_t reg_stack_base = DR_REG_X16;

    opnd_t return_addr_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 0, 8, OPSZ_8);
    opnd_t counter_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 0, 16, OPSZ_8);
    opnd_t pointer_mem = opnd_create_base_disp(reg_stack_base, DR_REG_NULL, 0, 24, OPSZ_8);
    /* create labels */
    instr_t* loop_label = INSTR_CREATE_label(drcontext);
    instr_t* loop_end_label = INSTR_CREATE_label(drcontext);
    instr_t* end_label = INSTR_CREATE_label(drcontext);
    /* save arithmetic flag and registers */
    dr_save_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    dr_save_reg(drcontext, bb, where, reg_1, SPILL_SLOT_2);
    dr_save_reg(drcontext, bb, where, reg_2, SPILL_SLOT_3);
    dr_save_reg(drcontext, bb, where, reg_3, SPILL_SLOT_4);
    dr_save_reg(drcontext, bb, where, reg_4, SPILL_SLOT_5);
    dr_save_reg(drcontext, bb, where, reg_index, SPILL_SLOT_6);
    dr_save_reg(drcontext, bb, where, reg_index_addr, SPILL_SLOT_7);
    dr_save_reg(drcontext, bb, where, reg_stack_base, SPILL_SLOT_8);

    /*---access call_stack[stack_index]---*/
    /* move &stack_index into reg_stack_base */
    opnd_create_reg64((uint64_t) &stack_index, drcontext, bb, where, opnd_create_reg(reg_index_addr));
    opnd_t index = OPND_CREATE_MEM64(reg_index_addr, 0);
    /* load stack_index into reg_index  */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_index),
                                              index));
    /* reg_index <<= 5 (i.e., reg_index *= 32) */
    instrlist_meta_preinsert(bb, where, INSTR_CREATE_movz(drcontext,
                                                          opnd_create_reg(reg_1),
                                                          OPND_CREATE_INT(5),
                                                          OPND_CREATE_INT(0)));
    instrlist_meta_preinsert(bb, where, instr_create_1dst_2src(drcontext, OP_lslv,
                                                               opnd_create_reg(reg_index),
                                                               opnd_create_reg(reg_index),
                                                               opnd_create_reg(reg_1)));
    // instrlist_meta_preinsert(bb, where,
    //                          INSTR_CREATE_shl(drcontext,
    //                                           opnd_create_reg(reg_index),
    //                                           opnd_create_immed_int(5, OPSZ_1)));
    /* move call_stack base address into reg_stack_base */
    opnd_create_reg64((uint64_t) call_stack, drcontext, bb, where, opnd_create_reg(reg_stack_base));
    // instrlist_meta_preinsert(bb, where,
    //                          INSTR_CREATE_mov_imm(drcontext,
    //                                               opnd_create_reg(reg_stack_base),
    //                                               stack_base));
    /* reg_stack_base = address of the element we want to access */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_index)));
    /*---decrement stack_index (reg_index is free) ---*/
    /* reg_index >>= 5 (i.e., shift back to original value) */
    instrlist_meta_preinsert(bb, where, INSTR_CREATE_movz(drcontext,
                                                          opnd_create_reg(reg_3),
                                                          OPND_CREATE_INT(5),
                                                          OPND_CREATE_INT(0)));
    instrlist_meta_preinsert(bb, where, instr_create_1dst_2src(drcontext, OP_lsrv,
                                                               opnd_create_reg(reg_index),
                                                               opnd_create_reg(reg_index),
                                                               opnd_create_reg(reg_3)));
    /* decrement */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_sub(drcontext,
                                              opnd_create_reg(reg_index),
                                              opnd_create_reg(reg_index),
                                              OPND_CREATE_INT(1)));
    /* store reg_index back to stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              index,
                                              opnd_create_reg(reg_index)));
    // instrlist_meta_preinsert(bb, where,
    //                          INSTR_CREATE_sub(drcontext,
    //                                           index,
    //                                           OPND_CREATE_INT8(1)));
    /* reg1, 2, 3 <- call_stack[stack_index].pointer, return_addr, counter */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_1),
                                              pointer_mem));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_2),
                                              return_addr_mem));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_3),
                                              counter_mem));
    /*--- i = 0, reg_index = i ---*/
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_movz(drcontext,
                                               opnd_create_reg(reg_index),
                                               OPND_CREATE_INT(0),
                                               OPND_CREATE_INT(0)));
    /*--- loop ---*/
    instrlist_meta_preinsert(bb, where, loop_label);
    /*--- exit loop if i > stack_index ---*/
    /* reg_4 = stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                                 opnd_create_reg(reg_4),
                                                 index));
    /* cmp i, stack_index */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_cmp(drcontext,
                                              opnd_create_reg(reg_index), // i
                                              opnd_create_reg(reg_4))); // stack_index
    /* jump to loop_end_label if i > stack_index */
    instr_t *my_jge = INSTR_CREATE_bcond(drcontext, opnd_create_instr(loop_end_label));
    INSTR_PRED(my_jge, DR_PRED_GT);
    instrlist_meta_preinsert(bb, where, my_jge);
    /*---access call_stack[i].return_addr---*/
    instrlist_meta_preinsert(bb, where,
                             XINST_CREATE_move(drcontext,
                                                 opnd_create_reg(reg_4),
                                                 opnd_create_reg(reg_index)));
    /* reg_4 <<= 5 (i.e., reg_4 *= 32) */
    instrlist_meta_preinsert(bb, where, instr_create_1dst_3src(drcontext, OP_ubfm,
                                                               opnd_create_reg(reg_4),
                                                               opnd_create_reg(reg_4),
                                                               OPND_CREATE_INT(59), // (-shf) % 64
                                                               OPND_CREATE_INT(58))); // 63 - shf
    /* reg_stack_base = stack_base + 32*stack_index */
    opnd_create_reg64((uint64_t) call_stack, drcontext, bb, where, opnd_create_reg(reg_stack_base));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_stack_base),
                                              opnd_create_reg(reg_4)));
    /* reg4 = call_stack[i].return_addr */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_4),
                                              return_addr_mem));
    /*--- jump to end_label if call_stack[i].return_addr == last_caller.return_addr ---*/
    /* create cmp */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_cmp(drcontext,
                                              opnd_create_reg(reg_2),
                                              opnd_create_reg(reg_4)));
    /* create je */
    instr_t *my_je = INSTR_CREATE_bcond(drcontext, opnd_create_instr(end_label));
    INSTR_PRED(my_je, DR_PRED_EQ);
    instrlist_meta_preinsert(bb, where, my_je);
    /* i++ */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_index),
                                              opnd_create_reg(reg_index),
                                              OPND_CREATE_INT(1)));
    /*--- jump back to loop head ---*/
    instr_t *my_jmp = instr_create(drcontext);
    instr_set_opcode(my_jmp, OP_b);
    instr_set_num_opnds(drcontext, my_jmp, 0, 1);
    instr_set_src(my_jmp, 0, opnd_create_instr(loop_label));
    instrlist_meta_preinsert(bb, where, my_jmp);
    /*--- loop_end_label ---*/
    instrlist_meta_preinsert(bb, where, loop_end_label);
    /*--- loop end ---*/
    /*--- update map[last_caller.call_addr] (reg_1) ---*/
    // load inst_counter into reg_4
    opnd_create_reg64((uint64_t) &inst_counter, drcontext, bb, where, opnd_create_reg(reg_2));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_4),
                                              OPND_CREATE_MEM64(reg_2, 0)));
    /* load map[last_caller.call_addr] into reg_2 */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_2),
                                              OPND_CREATE_MEM64(reg_1, 0)));
    /* update */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_2),
                                              opnd_create_reg(reg_2),
                                              opnd_create_reg(reg_4)));
    /* store back */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              OPND_CREATE_MEM64(reg_1, 0),
                                              opnd_create_reg(reg_2)));
    /*--- end_label ---*/
    instrlist_meta_preinsert(bb, where, end_label);
    /*--- inst_counter (reg_4) += last_caller.counter (reg_3) ---*/
    opnd_create_reg64((uint64_t) &inst_counter, drcontext, bb, where, opnd_create_reg(reg_2));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_ldr(drcontext,
                                              opnd_create_reg(reg_4),
                                              OPND_CREATE_MEM64(reg_2, 0)));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_add(drcontext,
                                              opnd_create_reg(reg_4),
                                              opnd_create_reg(reg_4),
                                              opnd_create_reg(reg_3)));
    /* store inst_counter back */
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext,
                                              OPND_CREATE_MEM64(reg_2, 0),
                                              opnd_create_reg(reg_4)));
    /* restore arithmetic flag and registers */
    dr_restore_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
    dr_restore_reg(drcontext, bb, where, reg_1, SPILL_SLOT_2);
    dr_restore_reg(drcontext, bb, where, reg_2, SPILL_SLOT_3);
    dr_restore_reg(drcontext, bb, where, reg_3, SPILL_SLOT_4);
    dr_restore_reg(drcontext, bb, where, reg_4, SPILL_SLOT_5);
    dr_restore_reg(drcontext, bb, where, reg_index, SPILL_SLOT_6);
    dr_restore_reg(drcontext, bb, where, reg_index_addr, SPILL_SLOT_7);
    dr_restore_reg(drcontext, bb, where, reg_stack_base, SPILL_SLOT_8);
}
#endif
#endif
