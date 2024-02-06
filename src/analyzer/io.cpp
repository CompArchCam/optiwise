/* Input and output routines. */

#include "io.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>

#include "support.hpp"

using namespace std;

static vector<app_module> modules;
static uint64_t total_cycles = 0;

parse_error::parse_error(const std::string &msg, const std::string &file, unsigned line)
        : std::runtime_error(msg), file(file), line(line) {
    ostringstream os;

    os << file << ':' << line << ' ' << runtime_error::what();
    whats = move(os.str());
}

const char* parse_error::what() const noexcept {
    return whats.c_str();
}

static inline istream &operator>>(istream &is, address &addr) {
    const ios_base::fmtflags flags(is.flags());
    app_module_id mid;
    char sep;
    uint64_t offset;
    is >> dec >> mid >> sep >> hex >> offset;
    addr = address(mid, offset);
    is.flags(flags);
    if (sep != ':') is.setstate(ios::failbit);
    return is;
}

static inline ostream &operator<<(ostream &os, const address &addr) {
    const ios_base::fmtflags flags(os.flags());
    os << dec << addr.first << ':' << hex << addr.second;
    os.flags(flags);
    return os;
}

app_module_id module_add_or_find(const string &path) {
    app_module_id id = 0;
    for (auto &m: modules) {
        if (m.path == path) return id;
        id++;
    }
    modules.emplace_back(app_module{
        .path = path,
    });
    return id;
}

app_module &module_lookup(app_module_id id) {
    static app_module undefined{
        .path = "NA",
    };
    if (id == app_module_id(-1)) {
        return undefined;
    }
    return modules.at(id);
}

struct loaded_module {
    uint64_t addr;
    uint64_t length;
    uint64_t offset;
    app_module_id id;
};

trace_pair parseTracePair(istream &ss, const vector<loaded_module> &loaded_modules) {
    uint64_t addr;
    static bool perf_uses_vaddrs = true;
    static bool perf_uses_vaddrs_checked = false;
    static uint64_t perf_samples_vaddr = 0;
    static uint64_t perf_samples_offset = 0;
    string module;

    ss >> hex >> addr;
    getline(ss, module);
    const auto paren_l = module.find('(');
    const auto paren_r = module.rfind(')');
    app_module_id mod(-1);
    if (paren_l != string::npos && paren_r != string::npos && paren_l < paren_r) {
        module = module.substr(paren_l+1, paren_r - paren_l - 1);
        if (module != "[unknown]") {
            mod = module_add_or_find(module);
            const loaded_module *load_vaddr = nullptr;
            const loaded_module *load_offset = nullptr;
            for (const auto &m: loaded_modules) {
                if (m.id != mod) continue;
                if (m.addr <= addr && addr - m.addr < m.length) {
                    load_vaddr = &m;
                }
                if (m.offset <= addr && addr - m.offset < m.length) {
                    load_offset = &m;
                }
            }
            // Heuristically guess whether perf is using virtual addresses or
            // offsets for addresses. It can use either depending on version (it
            // flip-flopped in practice)
            if (load_vaddr && !load_offset) {
                perf_samples_vaddr++;
                if (!perf_uses_vaddrs_checked) {
                    perf_uses_vaddrs = true;
                    perf_uses_vaddrs_checked = true;
                    cout << "Info: Assuming perf uses vaddrs." << endl;
                } else if (!perf_uses_vaddrs) {
                    cerr << "Warning: conflicting perf format." << endl;
                }
            }
            if (!load_vaddr && load_offset) {
                perf_samples_offset++;
                if (!perf_uses_vaddrs_checked) {
                    perf_uses_vaddrs = false;
                    perf_uses_vaddrs_checked = true;
                    cout << "Info: Assuming perf uses offsets." << endl;
                } else if (perf_uses_vaddrs) {
                    cerr << "Warning: conflicting perf format." << endl;
                }
            }
            if (load_vaddr && perf_uses_vaddrs) {
                addr -= load_vaddr->addr;
                addr += load_vaddr->offset;
            }
            if (load_offset && !perf_uses_vaddrs) {
                // nothing to do.
            }
        }
    }
    return trace_pair{
        .addr = address(mod, addr),
    };
}

/* read one event from the perf file */
void inputEvent(const string &filename, ifstream &fp, vector<Perf_result> &perf, int &lineno, int &no_stack_trace) {
    string line;
    string timestamp, counter;
    static string last_timestamp("");
    static bool last_no_stack = false;
    static vector<loaded_module> loaded_modules;
    uint64_t sample_address;
    bool have_sample_address = false;
    bool bad_sample_address = false;
    istringstream ss;
    do {
        if (!fp) return;
        lineno++;
        getline(fp, line);
        ss = istringstream(line);

        // allow any empty lines.
        if (line.size() < 2)
           return;

        if (!(ss >> timestamp)) {
            throw parse_error("Error: incorrect format in sample!", filename, lineno);
        }

        if (line.find("PERF_RECORD_SAMPLE") != string::npos) {
            // extract the PEBS sample address
            have_sample_address = true;
            const auto index = line.find(": 0x");
            if (index != string::npos) {
                ss.seekg(index + 4);
                ss >> hex >> sample_address;
                have_sample_address = bool(ss);
            }
        }
    } while (timestamp.size() == 0 || timestamp.at(timestamp.size()-1) != ':' || timestamp.find('.') == string::npos);

    char tempc;
    ss >> tempc;
    ss.unget();
    if (tempc == 'P') { // PERF_RECORD_MMAP2 event
        // Line looks like e.g.
        // 25443039.405394: PERF_RECORD_MMAP2 790929/790929: [0xaaaabb3c0000(0x18000) @ 0 fd:00 709 2942758367]: r-xp /usr/bin/echo
        string temp;
        ss >> temp;
        if (!ss || temp != "PERF_RECORD_MMAP2") {
            throw parse_error("Error: incorrect format in sample!", filename, lineno);
        }
        ss >> temp; // e.g. 790929/790929:
        char tempc;
        ss >> tempc;
        if (!ss || tempc != '[') {
            throw parse_error("Error: incorrect format in sample!", filename, lineno);
        }
        uint64_t address, length, offset;
        ss >> showbase >> hex >> address >> tempc >> showbase >> hex >> length;
        if (!ss || tempc != '(') {
            throw parse_error("Error: incorrect format in sample!", filename, lineno);
        }
        ss >> tempc;
        if (tempc != ')') {
            throw parse_error("Error: incorrect format in sample!", filename, lineno);
        }
        ss >> tempc >> showbase >> hex >> offset;
        if (tempc != '@') {
            throw parse_error("Error: incorrect format in sample!", filename, lineno);
        }
        ss.ignore(numeric_limits<streamsize>::max(), ':');
        while (ss >> tempc && tempc != ':') ; // skip to :
        ss >> temp;
        if (!ss) {
            throw parse_error("Error: incorrect format in sample!", filename, lineno);
        }
        // Check this is a code mapping.
        if (temp.size() < 3)
            throw parse_error("Error: incorrect format in sample!", filename, lineno);
        if (temp[2] != 'x') return;
        string path;
        ss.get();
        getline(ss, path);
        const uint64_t mmap_offset = offset;
        const app_module_id id(module_add_or_find(path));
        const app_module &mod = module_lookup(id);
        // find a program header line that this mapping covers entirely.
        auto offs = mod.file_offset_to_vaddr.upper_bound(mmap_offset);
        if (offs != mod.file_offset_to_vaddr.begin()) offs--;
        bool range_found = false;
        static bool ambiguous_mmap_warning = false;
        for (; offs != mod.file_offset_to_vaddr.end(); offs++) {
            uint64_t file_offset = offs->first;
            uint64_t vaddr = offs->second.first;
            uint64_t filesz = offs->second.second;
            if (filesz == 0) continue;
            if (file_offset < mmap_offset || file_offset + filesz > mmap_offset + length) continue;
            if (!range_found) {
                offset = vaddr + (mmap_offset - file_offset);
                range_found = true;
            } else {
                // multiple valid mappings found. Do they agree?
                if (offset == vaddr + (mmap_offset - file_offset)) continue;
                if (ambiguous_mmap_warning) continue;
                cerr <<
"Warning: ambiguous mmap in sampling run. This may mean samples get the incorrect\n"
"         address, resulting in incorrect analysis."
                    << endl;
                ambiguous_mmap_warning = true;
            }
        }
        loaded_modules.emplace_back(loaded_module{
            .addr = address,
            .length = length,
            .offset = offset,
            .id = id,
        });
        return;
    }
    uint32_t value;
    if (!(ss >> value >> counter)) {
        throw parse_error("Error: incorrect format in sample!", filename, lineno);
    }

    bool have_stack = timestamp == last_timestamp;
    Perf_result *p(nullptr);

    if (have_stack && !last_no_stack) p = &*(perf.end() - 1);
    if (have_sample_address) {
        app_module_id id(-1);
        for (const auto &m: loaded_modules) {
            if (m.addr <= sample_address && sample_address - m.addr < m.length) {
                id = m.id;
                sample_address -= m.addr;
                sample_address += m.offset;
            }
        }
        bad_sample_address = id == 0 || id == app_module_id(-1);
        perf.emplace_back(Perf_result{
            .addr = make_pair(id, sample_address),
        });
    }
    // first line of first stack trace; add this event to the list
    while (1) {
        int nextChar = fp.peek();

        if (nextChar != '\t' && nextChar != ' ' && nextChar != '\r' && nextChar != '\n') break;
        // this line is func call trace in stack

        lineno++;
        getline(fp, line); // read the sample

        // only actually parse the stack trace once
        if (have_stack) continue;
        // allow blank lines
        if (line.size() < 2) continue;

        istringstream sss(line);

        trace_pair tp;
        try {
            tp = parseTracePair(sss, loaded_modules);
            if (!sss) {
                throw parse_error("Error: incorrect format in trace!", filename, lineno);
            }
        } catch (std::invalid_argument &e) {
            throw parse_error("Error: incorrect format in trace!", filename, lineno);
        }
        if (!p) {
            if (!have_sample_address) {
                perf.emplace_back(Perf_result{
                    .addr = tp.addr,
                });
            }
            // first line of first stack trace; add this event to the list
            last_timestamp = timestamp;
            p = &*(perf.end() - 1);
            if (bad_sample_address && tp.addr.first > 0 && tp.addr.first != app_module_id(-1)) {
                p->addr = tp.addr;
            }
        } else {
            p->stack_trace.emplace_back(tp);
        }
    }

    if (!p) {
        no_stack_trace++;
        last_no_stack = true;
        return;
    }
    last_no_stack = false;

    if (counter.substr(0,3+1+6+1) == "cpu-cycles:") {
        p->cpu_cycles = value;
        total_cycles += value;
    }
}

void read_perf_result(
        const char* perf_result_path,
        objdump_table& objdump_result,
        inst_table& profiling_result,
        func_sample &func_sample_table
) {
    string filename(perf_result_path);
    ifstream myfileptr(filename);
    if (!myfileptr.is_open()) {
        throw runtime_error("can not open perf result file!");
    }

    int i = 0;
    vector<Perf_result> perf;
    int no_stack_trace = 0;
    while (myfileptr) {
        inputEvent(filename, myfileptr, perf, i, no_stack_trace);
    }
    myfileptr.close();
    if (no_stack_trace) {
        cerr << "Warning: skipped " << no_stack_trace << " events with no stack trace in perf result." << endl;
    }

    /* accumulate perf data */
    processed_perf_result tmp_pair = {.cpu_cycles = 0,
                                      .samples = 0, .execution_count = 0
                                     };
    for (const auto &event : perf) {
        const address &key = event.addr;
        // push value to map and accumulate
        if (profiling_result.count(key) == 0) {
            auto fline = objdump_result.find(key);
            objdump_line *line = fline != objdump_result.end() ? &fline->second : nullptr;
            profiling_result[key] = processed_perf_result {
                .cpu_cycles = 0,
                .samples = 0,
                .line = line,
            };
        }
        processed_perf_result &result = profiling_result.at(key);
        result.cpu_cycles += event.cpu_cycles;
        result.samples += 1;

        // push value to the extra map for func call
        set<function *> unique_queue;
        if (result.line && result.line->func)
            unique_queue.insert(result.line->func.get());
        for (auto j: event.stack_trace) {
            auto fline = objdump_result.find(j.addr);
            objdump_line *line = fline != objdump_result.end() ? &fline->second : nullptr;
            /* if sample func name is different with the recursive func name */
            if (!line || !line->func) {

            } else if (unique_queue.count(line->func.get()) == 0) {
                unique_queue.insert(line->func.get());
            } else {
                continue;
            }

            if (func_sample_table.count(j.addr) == 0) {
                func_sample_table[j.addr] = {
                    .cpu_cycles = 0,
                    .samples = 0,
                };
            }
            auto &sample = func_sample_table.at(j.addr);
            sample.cpu_cycles += event.cpu_cycles;
            sample.samples += 1;
        }

        for (auto func : set<function *>(unique_queue)) {
            address current = func->immediate_return;
            size_t i = 0;
            while (current.first != 0) {
                i++;
                if (i == objdump_result.size()) throw runtime_error("Infinite loop detected");
                auto n = objdump_result.find(current);
                if (n == objdump_result.end()) break;
                auto &node = n->second;
                if (!node.func) break;
                if (unique_queue.count(node.func.get()) == 0) {
                    unique_queue.insert(node.func.get());

                    if (func_sample_table.count(current) == 0) {
                        func_sample_table[current] = {
                            .cpu_cycles = 0,
                            .samples = 0,
                        };
                    }
                    auto &sample = func_sample_table.at(current);
                    sample.cpu_cycles += event.cpu_cycles;
                    sample.samples += 1;
                }
                current = node.func->immediate_return;
            }
        }
    } // end for
}

static void parse_program_header_line(
        const string &filename,
        unsigned lineno,
        const string &asm_line,
        app_module_id current_module,
        bool &last_load,
        uint64_t &off,
        uint64_t &vaddr
) {
    // asm_line looks like e.g.
    //     LOAD off    0x00000000006c9d80 vaddr 0x00000000008d9d80 paddr 0x00000000008d9d80 align 2**16
    //          filesz 0x0000000001456ac0 memsz 0x0000000001456ac0 flags r-x
    istringstream sss(asm_line);

    if (last_load) {
        last_load = false;

        string fileszs, memszs, flagss, flags;
        uint64_t filesz, memsz;

        sss >> fileszs >> hex >> showbase >> filesz
            >> memszs >> hex >> showbase >> memsz
            >> flagss >> flags;

        if (!sss || fileszs != "filesz" || memszs != "memsz" || flagss !=
                "flags") throw parse_error("bad program header line", filename, lineno);
        if (flags.size() < 3)
            throw parse_error("bad program header line", filename, lineno);
        if (flags[2] != 'x') return;

        modules[current_module].file_offset_to_vaddr[off] = make_pair(vaddr, filesz);
    } else {
        string type;
        sss >> type;

        if (!sss || type != "LOAD") return;

        string offs, vaddrs;

        sss >> offs >> hex >> showbase >> off
            >> vaddrs >> hex >> showbase >> vaddr;

        if (!sss || offs != "off" || vaddrs != "vaddr") throw parse_error("bad program header line", filename, lineno);

        last_load = true;
    }
}

static void parse_symbol_line(
        const string &filename,
        unsigned lineno,
        const string &asm_line,
        app_module_id current_module,
        map<string, map<uint64_t, pair<shared_ptr<function>, uint64_t>>> &symbol_table,
        bool dynamic
) {
    // asm_line looks like e.g.
    // if (!dynamic)
    // 0000000000099270 l     F .text	00000000000001d2 malloc_check
    // if (dynamic)
    // 0000000000000690  w   DF .text	0000000000000348  LINUX_2.6   gettimeofday

    const size_t tab_pos = asm_line.find('\t');
    if (tab_pos == string::npos) return;
    const size_t first_space = asm_line.find(' ');
    const size_t last_space = asm_line.rfind(' ', tab_pos);
    if (first_space == string::npos) return;
    if (last_space == string::npos) return;
    if (first_space == last_space) return;
    const size_t F_pos = asm_line.find('F', first_space);
    // Check if it's a function
    if (F_pos == string::npos || F_pos > last_space) return;
    istringstream sss(asm_line);
    uint64_t addr;
    sss >> hex >> addr;
    if (!sss) return;
    const string section =
        asm_line.substr(last_space + 1, tab_pos - last_space - 1);
    // Check if it's defined
    if (section == "*UND*") return;
    sss.seekg(tab_pos+1);
    uint64_t size;
    sss >> hex >> size;
    if (!sss) return;
    if (dynamic) {
        string version;
        sss >> version;
    }
    // skip to the first char of the name.
    char first;
    sss >> first;
    shared_ptr<function> f(new function{});
    f->entry = address(current_module, addr);
    f->name = asm_line.substr(size_t(sss.tellg())-1);
    /* strip non-name prefixes that sometimes are present */
    const size_t name_space = f->name.find(' ');
    if (name_space != string::npos) {
        if (f->name.substr(0, 8) == ".hidden ") {
            f->name = f->name.substr(8);
        } else if (f->name.substr(0, 10) == ".internal ") {
            f->name = f->name.substr(10);
        } else if (f->name.substr(0, 11) == ".protected ") {
            f->name = f->name.substr(11);
        } else if (f->name.substr(0, 2) == "0x" && name_space > 2) {
            bool not_hex = false;
            for (size_t i = 2; i < name_space; i++) {
                if (isxdigit(f->name.at(i))) continue;
                not_hex = true;
                break;
            }
            if (!not_hex) f->name = f->name.substr(name_space + 1);
        }
    }
    // prefer functions with size if possible
    if (symbol_table[section].count(addr) > 0 && size == 0) return;
    symbol_table[section][addr] = make_pair(f, size);
}

static void parse_disassembly_line(
        const string &filename,
        unsigned lineno,
        const string &asm_line,
        objdump_table& objdump_result,
        app_module_id current_module,
        const map<uint64_t, pair<shared_ptr<function>, uint64_t>> &symtab,
        shared_ptr<string> &inlined_func_name,
        shared_ptr<source_line> &source
) {
    if (asm_line[0] == ' ') {
        uint64_t addr;
        size_t pos;
        string disassembly;
        // this line represents an inst e.g.
        // '1084:	push   %r12'
        if ((pos = asm_line.find(":")) != string::npos){
            addr = stoll(asm_line.substr(0, pos), nullptr, 16);
            disassembly = asm_line.substr(pos+2);
        } else {
            throw parse_error("wrong format in asm txt file: no ':'!", filename, lineno);
        }

        auto symbol = symtab.upper_bound(addr);
        if (symbol != symtab.begin()) symbol--;
        shared_ptr<function> func = nullptr;
        if (symbol != symtab.end()) {
            if (symbol->second.second == 0 || addr - symbol->first < symbol->second.second) {
                func = symbol->second.first;
            } else if (symbol->second.second != 0 &&  addr - symbol->first == symbol->second.second) {
                inlined_func_name = nullptr;
                source.reset();
            }
            if (symbol->first == addr) {
                inlined_func_name = func ? make_shared<string>(func->name) : nullptr;
                source.reset();
            }
        }


        /* load inst and func name into map and add the unsampled inst */
        address key(current_module, addr);
        if (objdump_result.count(key) > 0) { // inst exsit
            throw parse_error("error: duplicated instruction in objdump?", filename, lineno);
        }
        objdump_result[key] = objdump_line{
            .disassembly = disassembly,
            .func = func,
            .inlined_func_name = nullptr,
            .source = source,
        };
    } else if (asm_line.size() > 3 && asm_line.substr(asm_line.size() - 3, 3) == "():") {
        // this line is an inlined func name e.g.
        // '_ZN11xercesc_2_516ValueHashTableOfItE10initializeEj():'
        // Note that the (): suffix is present even for mangled names.
        inlined_func_name.reset(new string(asm_line.substr(0, asm_line.size() - 3)));
        source.reset();
    } else if (isxdigit(asm_line[0])) {
        // this line is a func name e.g.
        // '0000000000001080 <main>:'
        // nothing to do
    } else {
        // this is a source line number. e.g.
        // '/usr/include/stdlib.h:363 (discriminator 1)'
        // '/usr/include/c++/10/bits/stl_tree.h:210'
        size_t colon = asm_line.rfind(':');
        if (colon >= asm_line.size() - 1) return;
        if (!isdigit(asm_line[colon+1])) return;
        string file = asm_line.substr(0, colon);
        int line = stoi(asm_line.substr(colon+1));
        source.reset(new source_line{
            .filename = shared_ptr<string>(new string(file)),
            .line = line,
        });
    }
}

void read_disassembly(string filename, objdump_table& objdump_result){
    ifstream asm_code(filename);
    if (!asm_code.is_open()) {
        throw runtime_error("can not open asm code file");
    }
    /* get inst name and address */
    string asm_line;
    shared_ptr<string> inlined_func_name = nullptr;
    shared_ptr<source_line> source(nullptr);
    map<string, map<uint64_t, pair<shared_ptr<function>, uint64_t>>> symbol_table;
    const map<uint64_t, pair<shared_ptr<function>, uint64_t>> empty_symtab;
    const map<uint64_t, pair<shared_ptr<function>, uint64_t>> *current_symtab;
    current_symtab = &empty_symtab;
    bool ph_last_load = false;
    uint64_t ph_off = 0;
    uint64_t ph_vaddr = 0;
    app_module_id current_module(-1);
    enum class parser_state {
        none,
        in_file,
        in_symbol_table,
        in_symbol_table_dynamic,
        in_program_header,
        in_disassembly,
    } state = parser_state::none;
    unsigned int lineno = 0;
    while (getline(asm_code, asm_line)){
        lineno++;
        if (asm_line.size() == 0) {
            if (state != parser_state::in_disassembly && state != parser_state::none)
                state = parser_state::in_file;
            continue;
        }
        if (asm_line.substr(0, 5) == "FILE ") {
            // a module e.g.
            // 'FILE /usr/lib/x86_64-linux-gnu/ld-2.31.so'
            current_module = module_add_or_find(asm_line.substr(5));
            symbol_table.clear();
            current_symtab = &empty_symtab;
            state = parser_state::in_file;
            continue;
        } else if (asm_line.substr(0, 15) == "Program Header:") {
            state = parser_state::in_program_header;
            continue;
        } else if (asm_line.substr(0, 23) == "Disassembly of section ") {
            state = parser_state::in_disassembly;
            const auto section = asm_line.substr(23, asm_line.size() - 24);
            const auto table = symbol_table.find(section);
            current_symtab = table != symbol_table.end() ?
                &table->second : &empty_symtab;
            inlined_func_name = nullptr;
            source.reset();
            continue;
        } else if (asm_line.substr(0, 13) == "SYMBOL TABLE:") {
            state = parser_state::in_symbol_table;
            continue;
        } else if (asm_line.substr(0, 21) == "DYNAMIC SYMBOL TABLE:") {
            state = parser_state::in_symbol_table_dynamic;
            continue;
        }

        switch (state) {
        case parser_state::none: break;
        case parser_state::in_file: break;
        case parser_state::in_program_header:
            parse_program_header_line(
                    filename, lineno, asm_line, current_module,
                    ph_last_load, ph_off, ph_vaddr
            );
            break;
        case parser_state::in_disassembly:
            parse_disassembly_line(
                    filename, lineno, asm_line, objdump_result, current_module,
                    *current_symtab, inlined_func_name, source
            );
            break;
        case parser_state::in_symbol_table:
        case parser_state::in_symbol_table_dynamic:
            parse_symbol_line(
                    filename, lineno, asm_line, current_module, symbol_table,
                    state == parser_state::in_symbol_table_dynamic
            );
            break;
        }
    } // end while
    asm_code.close();
}

bool has_keyword(const string &cpp_source_line, const string &keyword) {
    size_t pos = cpp_source_line.find(keyword);
    if (pos == string::npos) return false;
    if (pos > 0 && isalnum(cpp_source_line.at(pos))) return false;
    if (pos < cpp_source_line.length() - keyword.length() &&
            isalnum(cpp_source_line.at(pos + keyword.length()))) return false;
    return true;
}

bool is_loop(const string &cpp_source_line) {
    return has_keyword(cpp_source_line, "for") ||
        has_keyword(cpp_source_line, "while") ||
        has_keyword(cpp_source_line, "do") ||
        /* try to catch macros */
        has_keyword(cpp_source_line, "FOR") ||
        has_keyword(cpp_source_line, "WHILE") ||
        0;
}

void read_source_table(const objdump_table &objdump_result, source_table& objdump_source) {
    map<string, set<int>> source_lines;
    map<string, set<app_module_id>> file_referenced_by;
    map<app_module_id, bool> any_source;
    map<app_module_id, string> missing_source;

    for (auto &line: objdump_result) {
        auto &source = line.second.source;
        app_module_id module = line.first.first;
        if (!source) continue;
        source_lines[*source->filename].insert(source->line);
        file_referenced_by[*source->filename].insert(module);
    }

    for (auto &file: source_lines) {
        const string &filename = file.first;
        auto &lines = file.second;
        ifstream f(filename);
        if (!f.is_open()) {
            for (auto module: file_referenced_by[filename]) {
                missing_source[module] = filename;
            }
            for (int lineno: lines) {
                objdump_source[filename][lineno] = make_pair("NA", true);
            }
            continue;
        }
        for (auto module: file_referenced_by[filename]) {
            any_source[module] = true;
        }
        int i = 0;
        for (int lineno: lines) {
            for (; i + 1 < lineno; i++)
                f.ignore(numeric_limits<streamsize>::max(), '\n');
            string line;
            getline(f, line);
            i++;
            objdump_source[filename][lineno] = make_pair(line, is_loop(line));
        }
    }

    for (auto &missing: missing_source) {
        app_module_id module = missing.first;
        const string &filename = missing.second;
        if (any_source[module])
            cerr << "Warning: some source files not available e.g. '" << filename << "'" << endl;
        else
            cerr << "Warning: source files not available for '" << module_lookup(module).path << "'" << endl;
    }
}


void read_cfg(
        const string &filename,
        dycfg& cfg,
        address& entry) {
    fstream cfg_input(filename);
    if (!cfg_input.is_open()) {
        throw runtime_error("failed to read from the cfg file");
    }

    string line;
    enum class arch {
        none,
        x86_64,
        aarch64,
    } arch = arch::none;
    cfg_node *current_node;
    map<app_module_id, app_module_id> module_map;
    bool entry_found(false);
    unsigned int last_instruction_end = 0;
    unsigned int lineno = 0;
    address start_addr;
    while (getline(cfg_input, line)) {
        lineno++;
        if (line[0] == '#') continue;
        if (line.size() == 0) continue;
        stringstream line_stream(line);
        if (line.substr(0, 12) == "Architecture") {
            string temp, architecture;
            line_stream >> temp >> architecture;
            if (architecture == "x86_64")
                arch = arch::x86_64;
            else if (architecture == "aarch64")
                arch = arch::aarch64;
            else {
                throw parse_error("Unrecognised architecture", filename, lineno);
            }
            if (!line_stream)
                throw parse_error("Incorrect format in Architecture", filename, lineno);
        } else if (line.substr(0, 6) == "Module") { // this is a module start
            string temp, path;
            app_module_id index;
            line_stream >> temp >> dec >> index;
            if (!line_stream)
                throw parse_error("Incorrect format in Module", filename, lineno);
            line_stream.get();
            getline(line_stream, path);
            module_map[index] = module_add_or_find(path);
        } else if (line.substr(0, 5) == "Entry") {
            string temp, path;
            address addr;
            uint64_t count;
            line_stream >> temp >> entry >> count;
            if (!line_stream)
                throw parse_error("Incorrect format in Entry", filename, lineno);
            if ((entry_found && count != 0) || count != 1)
                throw parse_error("multiple entry points in CFG", filename, lineno);
            entry_found = true;
        } else if (line[0] != '\t') { // this is a cfg node
            cfg_node tmp{};
            string end_inst;
            line_stream >> start_addr
                        >> dec >> tmp.count >> tmp.callee_instcount >> end_inst;
            if (!line_stream) {
                throw parse_error("incorrect format in cfg file", filename, lineno);
            }
            tmp.is_ret = end_inst == "ret";
            switch (arch) {
            case arch::none:
                throw parse_error("incorrect format in cfg file", filename, lineno);
            case arch::x86_64: tmp.is_call = end_inst == "call"; break;
            case arch::aarch64: tmp.is_call = end_inst == "bl" || end_inst == "blr"; break;
            }
            last_instruction_end = 0;
            if (start_addr.first != app_module_id(-1)) {
                cfg[start_addr] = tmp;
                current_node = &cfg.at(start_addr);
            }
        } else if (line[1] == '+') { // this is an instruction offset and length
            unsigned int instruction_start;
            int instruction_len;
            char plus;
            line_stream >> plus >> hex >> instruction_start >> dec >> instruction_len;
            if (!current_node || plus != '+') {
                throw parse_error("incorrect format in cfg file", filename, lineno);
            }
            unsigned int instruction_end = instruction_start + instruction_len;
            current_node->inst_addrs.insert(start_addr.second + last_instruction_end);
            current_node->call_return_addr = start_addr.second + instruction_end;
            last_instruction_end = instruction_end;
        } else { // this is a successor of the node
            address child_addr;
            uint64_t count;
            line_stream >> child_addr >> dec >> count;
            if (!current_node || !line_stream) {
                throw parse_error("incorrect format in cfg file", filename, lineno);
            }
            current_node->child[child_addr] = count;
        }
    }

    // convert from cfg file module numbering to this session's numbering
    dycfg old_cfg;
    old_cfg.swap(cfg);
    for (auto &node: old_cfg) {
        address key(module_map[node.first.first], node.first.second);
        cfg[key] = node.second;
        cfg_node &newnode = cfg.at(key);
        map<address, uint64_t> old_child;
        old_child.swap(newnode.child);
        for (auto &child: old_child) {
            address ckey(module_map[child.first.first], child.first.second);
            newnode.child[ckey] = child.second;
        }
    }

    // sanity check: connectivity test.
    bool fail = false;
    for (auto &node: cfg) {
        for (auto &child: node.second.child) {
            if (!cfg.count(child.first)) {
                cerr << "Error: bad child " << child.first << " of " << node.first << endl;
                fail = true;
            }
        }
    }
    if (fail) throw runtime_error("bad child");

    // find entry node of cfg
    if (entry_found) {
        entry.first = module_map.at(entry.first);
        cfg.at(entry).is_function_entry = true;
    } else {
        throw parse_error("failed to find the entry of cfg", filename, lineno);
    }
}

void write_exe_count(
        const string &inst_csv_path,
        const dycfg &cfg,
        inst_table& profiling_result,
        const objdump_table& objdump_result) {

    for (const auto &i: cfg) {
        const auto &addr = i.first;
        const auto &block = i.second;
        for (auto inst_addr: block.inst_addrs) {
            address key(addr.first, inst_addr);
            // load execution count into map
            if (profiling_result.count(key) > 0) { // inst exsit
                profiling_result.at(key).execution_count = block.count;
            } else { // does not exist
                const objdump_line *line = nullptr;
                if (objdump_result.count(key) > 0) {
                    line = &objdump_result.at(key);
                }
                profiling_result[key] = processed_perf_result{
                    .cpu_cycles = 0,
                    .samples = 0,
                    .execution_count = block.count,
                    .mod = key.first,
                    .line = line,
                };
            }
        }
    }

    /* output to instruction csv file */
    ofstream myfile;
    myfile.open (inst_csv_path);
    if (!myfile.is_open()) {
        throw runtime_error("faild to open inst csv file");
    }

    myfile << "path,inst_addr_hex,samples,execution_count,"
           << "cpu_cycle,CPI,disassembly,func_name,inlined_func,line\n";
    inst_table::iterator itr;
    for (itr = profiling_result.begin(); itr != profiling_result.end(); ++itr) {
        const address &address = itr->first;
        const app_module &mod = module_lookup(address.first);
        float cpi = itr->second.execution_count == 0 ? 0.0 :
            ((float)itr->second.cpu_cycles/itr->second.execution_count);
        myfile << '"' << mod.path << "\","
               << hex << "0x" << address.second << ","
               << dec << itr->second.samples << "," << itr->second.execution_count << ','
               << itr->second.cpu_cycles << ','
               << fixed << showpoint << setprecision(2) << cpi
               << ",\"" << itr->second.disassembly() << "\""
               << ",\"" << itr->second.func_name() << "\""
               << ",\"" << itr->second.inlined_func_name() << "\"";
        if (itr->second.source()) {
            myfile
                << ",\""
                << *itr->second.source()->filename << ':'
                << itr->second.source()->line
                << "\"\n";
        } else
            myfile << ",\"?:?\"\n";
    }
    myfile.close();
}

void write_loop(string loops_csv_path, string loop_body_path, list<loop> &all_loops, dycfg &cfg, inst_table& profiling_result) {
    /* write loop info to csv */
    ofstream myfile, bodyfile;
    myfile.open(loops_csv_path);
    if (!myfile.is_open()) {
        throw runtime_error("failed to open loops csv file!");
    }
    bodyfile.open(loop_body_path);
    if (!bodyfile.is_open()) {
        throw runtime_error("failed to open loops body file!");
    }

    myfile << "file,head_addr,tail_addr,size,self_size,iters,invocs,iter_per_invoc,samples,cycles,insts,cyc_per_iter,inst_per_iter,cover,IPC,self_cyc_per_iter,self_inst_per_iter,self_cover,self_IPC,loop_func,source\n";
    app_module_id current_module(-1);
    for (auto itr : all_loops) {
        const app_module &mod = module_lookup(itr.addr.head.first);
        auto invocations = itr.count - itr.total_iteration;
        float iter_per_invoc = invocations <= 0 ? 0.0 : ((float)itr.count / invocations);
        float cyc_per_iter = itr.count == 0 ? 0.0 : ((float)itr.cpu_cycles / itr.count);
        float inst_per_iter = itr.count == 0 ? 0.0 : ((float)itr.inst_retired / itr.count);
        float cover = total_cycles == 0 ? 0.0 : ((float)itr.cpu_cycles / total_cycles);
        float ipc = itr.cpu_cycles == 0 ? 0.0 : ((float)itr.inst_retired/itr.cpu_cycles);
        float self_cover = total_cycles == 0 ? 0.0 : ((float)itr.self_cpu_cycles / total_cycles);
        float self_ipc = itr.self_cpu_cycles == 0 ? 0.0 : ((float)itr.self_inst_retired/itr.self_cpu_cycles);
        float self_cyc_per_iter = itr.count == 0 ? 0.0 : ((float)itr.self_cpu_cycles / itr.count);
        float self_inst_per_iter = itr.count == 0 ? 0.0 : ((float)itr.self_inst_retired / itr.count);
        myfile << '"' << mod.path << "\",0x"
               << hex << itr.addr.head.second << ",0x"
               << itr.addr.tail.second << ','
               << dec << itr.size << ',' << itr.self_size << ',' << itr.count << ',' << invocations << ','
               << fixed << showpoint << setprecision(1) << iter_per_invoc << ','
               << itr.samples << ',' << itr.cpu_cycles << ',' << itr.inst_retired << ','
               << fixed << showpoint << setprecision(1) << cyc_per_iter << ','
               << fixed << showpoint << setprecision(1) << inst_per_iter << ','
               << fixed << showpoint << setprecision(3) << cover << ','
               << fixed << showpoint << setprecision(2) << ipc << ','
               << fixed << showpoint << setprecision(1) << self_cyc_per_iter << ','
               << fixed << showpoint << setprecision(1) << self_inst_per_iter << ','
               << fixed << showpoint << setprecision(3) << self_cover << ','
               << fixed << showpoint << setprecision(2) << self_ipc << ",\""
               << *itr.loop_func << "\",\"";
        if (itr.source) {
            auto &source = *itr.source;
            myfile
                << *source.filename << ':'
                << dec << source.line;
            if (itr.source_line_count > 1)
                myfile << '-' << dec << (source.line + itr.source_line_count-1);
            myfile << "\"\n";
        } else
            myfile << "?:?\"\n";

        while (current_module != itr.addr.head.first) {
            current_module++;
            const app_module &cmod = module_lookup(current_module);
            bodyfile << "Module " << dec << current_module << ' ' << cmod.path << '\n';
        }
        bodyfile << hex << itr.addr.head.second << ", "
                 << itr.addr.tail.second << ", "
                 << dec << itr.loop_body.size() << '\n';
        bodyfile << '\t';
        string func_in_loop;
        for (auto body: itr.loop_body) {
            bodyfile << dec << body.first << ' ' << hex << body.second << ',';
            if (!cfg[body].callee.empty()) {
                func_in_loop += cfg[body].callee;
            }
        }
        bodyfile << "\n\t" << func_in_loop;
        bodyfile << "\n\n";
    }
    while (current_module + 1 != modules.size()) {
        current_module++;
        const app_module &cmod = module_lookup(current_module);
        bodyfile << "Module " << dec << current_module << ' ' << cmod.path << '\n';
    }
    myfile.close();
    bodyfile.close();
}
