#include <cassert>
#include <cstdlib>

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <sstream>

#include "io.hpp"
#include "support.hpp"
#include "loop_fetcher.hpp"

void detect_functions_and_calls(dycfg &cfg, objdump_table &objdump_result);
void generate_loop_statistics(inst_table &profiling_result, dycfg &cfg, list<loop> &all_loops,
                             func_sample &func_sample_table, source_table& objdump_source);
void guess_loop_source_lines(
        loop &loop, const function *loop_func,
        const map<string, map<string, set<int>>> &source_line_map,
        const source_table &objdump_source
);
inline bool is_subloop(loop l1, loop l2);
inline void merge_loops(vector<loop> &merged_list, dycfg &cfg, list<loop> &all_loops);
void check_inner_loops(vector<loop> &inner_list, dycfg &cfg, list<loop> &all_loops);
void eliminate_multi_backedge(list<loop> &all_loops, dycfg &cfg, inst_table& profiling_result);
void update_loop_statistics(list<loop> &all_loops, dycfg &cfg);
int inner_main(int argc, char **argv);

int main(int argc, char **argv) {
    try {
        return inner_main(argc, argv);
    } catch (const exception &e) {
        cerr << "Error: Uncaught exception:\n";
        cerr << e.what() << endl;
        return 1;
    }
}

static inline ostream &operator<<(ostream &os, const address &addr) {
    const ios_base::fmtflags flags(os.flags());
    app_module_id mid(addr.first);
    uint64_t offset(addr.second);
    os << dec << mid << ':' << hex << offset;
    os.flags(flags);
    return os;
}

int inner_main(int argc, char **argv) {
    if (argc < 7) {
        cerr <<  "Error: please enter the correct input parameters!\n"
                "input parameters are:\n"
                "1) path to perf output (output of perf script),\n"
                "2) path to assembly code file (output of objdump),\n"
                "3) path to cfg file (output of DynamoRio client)\n"
                "4) path to inst csv file (output of this tool)\n"
                "5) path to loop csv file (output of this tool)\n"
                "6) path to loop body file (output of this tool)\n"
              << endl;
        return 1;
    }


    /* read the instruction name from objdump output */
    objdump_table objdump_result;
    cout << "Info: Reading disassebly from " << argv[2] << "..." << endl;
    read_disassembly(argv[2], objdump_result);

    source_table objdump_source;
    cout << "Info: Reading source code..." << endl;
    read_source_table(objdump_result, objdump_source);

    /* read cfg and generate loop inforamtion */
    dycfg cfg;
    address entry_node;
    cout << "Info: Reading execution counts " << argv[3] << "..." << endl;
    read_cfg(argv[3], cfg, entry_node);

    /* Spot missing functions */
    cout << "Info: Detecting functions..." << endl;
    detect_functions_and_calls(cfg, objdump_result);

    /* read data from txt */
    inst_table profiling_result;
    func_sample func_sample_table;
    cout << "Info: Reading perf result from " << argv[1] << endl;
    read_perf_result(argv[1], objdump_result, profiling_result, func_sample_table);

    /* read instruction execution count from DynamoRio output */
    cout << "Info: Writing per instruction statistics..." << endl;
    write_exe_count(argv[4], cfg, profiling_result, objdump_result);

    list<loop> all_loops;
    cout << "Info: Finding loops..." << endl;
    extract_loops(cfg, entry_node, all_loops);

    cout << "Info: Aggregating loop statistics..." << endl;
    generate_loop_statistics(profiling_result, cfg, all_loops,
            func_sample_table, objdump_source);

    cout << "Info: Writing per loop statistics..." << endl;
    write_loop(argv[5], argv[6], all_loops, cfg, profiling_result);
    cout << "Info: All tasks complete." << endl;

    return 0;
} // end main()

void detect_functions_and_calls(dycfg &cfg, objdump_table &objdump_result) {
    // algorithm:
    // 1) look for calls, any call target is a function
    // 2) given the list of functions, any jump that crosses a function is a call
    // 3) goto 1 if any new functions were discovered
    bool discovery = true;
    map<address, function *> functions;
    function *current_func = nullptr;
    for (const auto &itr: objdump_result) {
        const auto &node = itr.second;
        if (current_func != node.func) {
            functions[itr.first] = node.func;
        }
        current_func = node.func;
    }
    while (discovery) {
        discovery = false;
        for (auto &itr: cfg) {
            const auto &addr = itr.first;
            auto &node = itr.second;
            // detect calls
            if (!node.is_call && !node.is_ret) {
                for (const auto child: node.child) {
                    const auto &child_address = child.first;
                    // module crosses are always calls
                    if (child_address.first != addr.first) {
                        node.is_call = true;
                        break;
                    }
                    bool before = child_address.second < addr.second;
                    const auto bound =
                        before ?
                        functions.upper_bound(child_address) :
                        functions.upper_bound(addr);
                    if (bound == functions.end()) continue;
                    if (bound->first.first != addr.first) continue;
                    if (before ?
                            bound->first.second < addr.second :
                            bound->first.second < child_address.second
                    ) {
                        node.is_call = true;
                        break;
                    }
                }
            }

            if (node.is_call) {
                for (const auto child: node.child) {
                    const address &child_address = child.first;
                    if (functions.count(child_address) == 0) {
                        functions[child_address] = nullptr;
                        discovery = true;
                    }
                }
            }
        }
    }

    current_func = nullptr;
    shared_ptr<string> inlined_func_name;
    shared_ptr<string> new_inlined_func_name;
    for (auto &itr: objdump_result) {
        const auto &addr = itr.first;
        auto &node = itr.second;
        const auto &f = functions.find(addr);
        if (f != functions.end() && f->second == nullptr) {
            current_func = new function();
            ostringstream os;

            os << 'f' << hex << addr.second;
            current_func->name = os.str();
            new_inlined_func_name = make_shared<string>(current_func->name);
        } else if (f != functions.end())
            current_func = f->second;
        if (current_func && node.func != current_func) {
            node.func = current_func;
            if (node.inlined_func_name == inlined_func_name)
                node.inlined_func_name = new_inlined_func_name;
        } else
            inlined_func_name = node.inlined_func_name;
    }
}

/* complete loop info */
void generate_loop_statistics(inst_table &profiling_result, dycfg &cfg, list<loop> &all_loops,
                             func_sample &func_sample_table, source_table& objdump_source)
{
    cout << "generate loop statistics..." << endl;
    /* accumulate block statistics into cfg */
    for (auto &itr: cfg) {
        auto &block = itr.second;
        uint64_t samples = 0;
        uint64_t cpu_cycles = 0;
        uint64_t inst_retired = 0;

        // for each inst in the block
        uint32_t remaining = block.block_size();
        for (auto inst_addr : block.inst_addrs) {
            remaining--;
            address addr(itr.first.first, inst_addr);
            if (profiling_result.count(addr) < 0) {
                throw runtime_error("missing instruction in DynamoRio inst output!");
            }
            const auto &prof = profiling_result.at(addr);
            samples += prof.samples;
            cpu_cycles += prof.cpu_cycles;
            inst_retired += prof.execution_count;
            // check if there are extra samples of the inst caused by func call
            if (func_sample_table.count(addr) > 0) {
                const auto &func_sample = func_sample_table.at(addr);
                samples += func_sample.samples;
                cpu_cycles += func_sample.cpu_cycles;
            }
            if (remaining == 0 && prof.line) {
                block.last_inlined_func_name = prof.line->inlined_func_name;
            }
            if (prof.line && prof.line->inlined_func_name && prof.line->source) {
                auto &source = prof.line->source;
                auto &inlined_func_name = *prof.line->inlined_func_name;
                auto &file_map = block.source_line_map[inlined_func_name];
                auto &line_set = file_map[*source->filename];
                line_set.insert(source->line);
            }
        }
        // check if there are extra execount of the inst caused by func call
        if (block.is_call) {
            inst_retired += block.callee_instcount;
            for (auto itr_child: block.child) {
                const address &target = itr_child.first;
                stringstream tmp;
                tmp << dec << target.first;
                tmp << ' ' << hex << target.second;
                tmp << ",";
                block.callee += tmp.str();
            }
        }

        block.samples = samples;
        block.cpu_cycles = cpu_cycles;
        block.inst_retired = inst_retired;
    } // for each cfg node

    /* handle loops with multiple backedges */
    eliminate_multi_backedge(all_loops, cfg, profiling_result);

    /* for each loop */
    for (auto &itr: all_loops) {
        const auto &prof_head = profiling_result.at(itr.addr.head);
        const auto &prof_tail = profiling_result.at(itr.addr.tail);
        function *loop_func = itr.func = prof_head.func();
        function *tail_func = prof_tail.func();
        /* Assume the loop is in the function that the last instruction of the
         * tail block reports itself in. */
        itr.loop_func = cfg.at(itr.addr.tail).last_inlined_func_name;
        if (!itr.loop_func)
            itr.loop_func = cfg.at(itr.addr.head).last_inlined_func_name;
        if (!itr.loop_func)
            if (tail_func) itr.loop_func = make_shared<string>(tail_func->name);
        if (!itr.loop_func)
            if (loop_func) itr.loop_func = make_shared<string>(loop_func->name);
        if (!itr.loop_func)
            itr.loop_func = make_shared<string>("NA");
        // skip cross-function loop
        if (loop_func != tail_func) {
            cerr << "Warning: cross function loop detected? " << itr.addr.head << "<-" <<
                itr.addr.tail << endl;
            itr.count = 0;
            itr.size = 0;
            itr.cpu_cycles = 0;
            itr.inst_retired = 0;
            itr.samples = 0;
            itr.loop_body.clear();
            continue;
        }
        map<string, map<string, set<int>>> source_line_map; // inlined_func map of filename map of set of source lines.

        /* get loop statistics */
        itr.count = cfg[itr.addr.head].count; // loop count = header block
        uint64_t size = 0;
        uint64_t samples = 0;
        uint64_t cpu_cycles = 0;
        uint64_t inst_retired = 0;
        for (auto &body: itr.loop_body) {
            const auto &node = cfg.at(body);
            size += node.block_size();
            if (profiling_result.count(body) == 0) continue;
            if (profiling_result.at(body).func() == loop_func) {
                samples += node.samples;
                cpu_cycles += node.cpu_cycles;
                inst_retired += node.inst_retired;
                for (auto &func: node.source_line_map) {
                    for (auto &file: func.second) {
                        for (int line: file.second) {
                            source_line_map[func.first][file.first].insert(line);
                        }
                    }
                }
            }
        }
        itr.size = size; // dynamic size for loops with func call
        itr.samples = samples;
        itr.cpu_cycles = cpu_cycles;
        itr.inst_retired = inst_retired;
        if (itr.total_iteration == 0)
            if (cfg.count(itr.addr.tail) > 0 && cfg.at(itr.addr.tail).child.count(itr.addr.head) > 0)
                itr.total_iteration = cfg.at(itr.addr.tail).child.at(itr.addr.head);
        guess_loop_source_lines(itr, loop_func, source_line_map, objdump_source);
    } // end all loops

    update_loop_statistics(all_loops, cfg); // correct data for loops with multi backedges

    // detect nesting
    for (auto &loop: all_loops) {
        set<address> in_nested;
        for (const auto &inner: all_loops) {
            if (&inner == &loop) continue;
            if (loop.loop_body.count(inner.addr.head) == 0) continue;
            if (loop.loop_body.count(inner.addr.tail) == 0) continue;
            loop.nested_loops.insert(&inner);
            for (const auto &addr: inner.loop_body) {
                in_nested.insert(addr);
            }
        }

        loop.self_samples = loop.samples;
        loop.self_cpu_cycles = loop.cpu_cycles;
        loop.self_inst_retired = loop.inst_retired;
        loop.self_size = loop.size;
        for (const auto &addr: loop.loop_body) {
            if (in_nested.count(addr) == 0) continue;
            const auto &node = cfg.at(addr);
            loop.self_size -= node.block_size();
            if (profiling_result.count(addr) == 0) continue;
            if (profiling_result.at(addr).func() != loop.func) continue;
            loop.self_samples -= node.samples;
            loop.self_cpu_cycles -= node.cpu_cycles;
            loop.self_inst_retired -= node.inst_retired;
        }
    }
}

void guess_loop_source_lines(
        loop &loop, const function *loop_func,
        // inlined_func map of filename map of set of source lines.
        const map<string, map<string, set<int>>> &source_line_map,
        const source_table &objdump_source
) {
    if (source_line_map.size() == 0) return;
    const string &inlined_func = *loop.loop_func;
    // only consider lines that we believe are associated with the function
    // containing the loop.
    auto &func = source_line_map.at(
        source_line_map.count(inlined_func) > 0  ? inlined_func :
        loop_func && source_line_map.count(loop_func->name) > 0 ? loop_func->name :
        source_line_map.begin()->first
    );
    // find the first loop in those lines. If we don't find one, just return the
    // full range.
    bool have_loop = false;
    for (auto &file: func) {
        const string &filename = file.first;
        const set<int> &lines = file.second;
        // we don't expect this outer 'file' loop to go round more than once;
        // that would imply a loop in a function was split across multiple
        // files.  It's possible in C using the preprocessor, but not likely.
        loop.source.reset();
        for (int line: lines) {
            auto sourceline = objdump_source.at(filename).at(line);
            bool is_loop = sourceline.second;
            if (!loop.source || (!have_loop && is_loop)) {
                loop.source_line_count = 0;
                loop.source.reset(new source_line{
                    .filename = make_shared<string>(filename), .line = line
                });
                have_loop = is_loop;
            }
            loop.source_line_count++;
        }
        if (have_loop) break;
    }
}

/* check if l1 is a subset of l2 (l2 should be larger than l1 in terms of block num) */
inline bool is_subloop(loop l1, loop l2) {
    bool sub_flag = true;
    for (auto each_block: l1.loop_body) {
        if (l2.loop_body.count(each_block) == 0) { // block does not exist
            sub_flag = false;
            break;
        }
    }
    return sub_flag;
}

/* merge all loops in merged_list into a single loop
   and then push the merged loop into all_loops */
inline void merge_loops(vector<loop> &merged_list, dycfg &cfg, list<loop> &all_loops) {
    loop merged_loop;
    merged_loop.addr.head = merged_list.front().addr.head;
    merged_loop.addr.tail = merged_list.front().addr.tail;
    uint64_t sum_of_backedge = 0;
    for (auto i: merged_list) {
        sum_of_backedge += cfg[i.addr.tail].child[i.addr.head];
        merged_loop.addr.tail = i.addr.tail.second>merged_loop.addr.tail.second ? i.addr.tail : merged_loop.addr.tail;
        for (auto body: i.loop_body) {
            merged_loop.loop_body.insert(body);
        }
    }
    merged_loop.total_iteration = sum_of_backedge;
    all_loops.push_back(merged_loop);
}

/* recursively walk through the inner loops until all loops are merged or judged as
   a inner loop */
void check_inner_loops(vector<loop> &inner_list, dycfg &cfg, list<loop> &all_loops) {
    vector<loop> merged_list;
    vector<loop> new_inner_list;
    if (inner_list.empty())
        cerr << "Error: empty input in check_inner_loops!" << endl;
    // sort the list by size
    sort(inner_list.begin(), inner_list.end(),
         [](loop a, loop b) {return a.loop_body.size() < b.loop_body.size();}
        );
    for (size_t i = 0; i < inner_list.size(); ++i) {
        bool inner_flag = false;
        for (size_t j = i + 1; j < inner_list.size(); ++j) {
            if (inner_list[i].loop_body.size() != inner_list[j].loop_body.size()
                && is_subloop(inner_list[i], inner_list[j])) {
                inner_flag = true;
                break;
            }
        }
        if (inner_flag) { // inner loop
            new_inner_list.push_back(inner_list[i]);
        } else { // not inner loop
            merged_list.push_back(inner_list[i]);
        }
    }
    if (!merged_list.empty())
        merge_loops(merged_list, cfg, all_loops);
    if (!new_inner_list.empty())
        check_inner_loops(new_inner_list, cfg, all_loops);
}

/* eliminate multiple backedges in loops */
void eliminate_multi_backedge(list<loop> &all_loops, dycfg &cfg, inst_table& profiling_result) {
    map<address, vector<loop>> same_head_loops;
    // find all loops with the same head (i.e., loops with multi backedges)
    for (auto i: all_loops) {
        // skip cross-function loop
        if (profiling_result.at(i.addr.head).func() != profiling_result.at(i.addr.tail).func()) {
            cerr << "Warning: cross function loop detected? " << i.addr.head << "<-" <<
                i.addr.tail << endl;
            continue;
        }
        same_head_loops[i.addr.head].emplace_back(i);
    }
    all_loops.clear();

    // merge or separate loops based on our heuristic
    for (auto loops: same_head_loops) {
        if (loops.second.size() > 1) { // loops with multi backedges
            // sort loops with the same head by size (num of block)
            map<size_t, vector<loop>> size_sorted_loops;
            for (auto i: loops.second) {
                size_sorted_loops[i.loop_body.size()].emplace_back(i);
            }
            // find the superset of each loop
            vector<loop> merged_loops;
            vector<loop> inner_loops;
            for (auto this_size = size_sorted_loops.begin(); this_size != size_sorted_loops.end(); ++this_size) {
                for (auto this_loop: this_size->second) {
                    uint64_t superset_back_edge = 0;
                    for (auto next_size = next(this_size); next_size != size_sorted_loops.end(); ++next_size) {
                        for (auto next_loop: next_size->second) {
                            if (is_subloop(this_loop, next_loop)) {
                                superset_back_edge += cfg[next_loop.addr.tail].child[next_loop.addr.head];
                            } // end each block in this_loop
                        } // end next_loop
                    } // end next_size
                    if (superset_back_edge == 0) { // this_loop has no superset
                        merged_loops.emplace_back(this_loop); // merged with other loops
                    } else if (cfg[this_loop.addr.tail].child[this_loop.addr.head] >= 3*superset_back_edge) {
                        inner_loops.emplace_back(this_loop); // this is a inner loop
                    } else { // has superset but no enough backedge count
                        merged_loops.emplace_back(this_loop); // merged with other loops
                    }
                } // end this_size
            } // end all back edges
            if (!merged_loops.empty())
                merge_loops(merged_loops, cfg, all_loops); // merge and then push to all_loops
            if (!inner_loops.empty())
                check_inner_loops(inner_loops, cfg, all_loops); // handle inner loops
        } else { // only one loop with this header
            loops.second.front().total_iteration = 0;
            all_loops.emplace_back(loops.second.front());
        }
    } // end all loops
}

// correct loop iteration and invocation number for nsested loops with the same header
void update_loop_statistics(list<loop> &all_loops, dycfg &cfg) {
    map<address, vector<loop>> same_head_loops;
    // find all loops with the same head (i.e., loops with multi backedges)
    for (auto i: all_loops) {
        same_head_loops[i.addr.head].emplace_back(i);
    }
    all_loops.clear();

    // merge or separate loops based on our heuristic
    for (auto &loops: same_head_loops) {
        if (loops.second.size() > 1) { // loops with multi backedges
            // sort loops with the same head by size (num of block)
            sort(loops.second.begin(), loops.second.end(),
                 [](loop a, loop b)
                  {
                    return a.loop_body.size() < b.loop_body.size();
                  });
            uint64_t accum_backedge_count = cfg[loops.second[0].addr.tail].child[loops.second[0].addr.head];
            all_loops.emplace_back(loops.second[0]);
            for (size_t i = 1; i < loops.second.size(); ++i) {
                if (loops.second[i].loop_body.size() <= loops.second[i-1].loop_body.size()) {
                    if (loops.second[i].size > 0) {
                        cerr << "Error: unmerged loops with the same header! " << hex
                             << loops.second[i].addr.head.second
                             << dec << ' ' << loops.second[i].loop_body.size()
                             << ' ' << loops.second[i].size << endl;
                    }
                    continue;
                }
                loops.second[i].count = cfg[loops.second[i].addr.head].count - accum_backedge_count;
                all_loops.emplace_back(loops.second[i]);
                accum_backedge_count += cfg[loops.second[i].addr.tail].child[loops.second[i].addr.head];
            }
        } else { // only one loop with this header
            all_loops.emplace_back(loops.second.front());
        }
    } // end all loops
}
