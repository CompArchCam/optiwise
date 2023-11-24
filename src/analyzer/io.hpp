#ifndef IO_HPP_
#define IO_HPP_

#include <stdexcept>

#include "support.hpp"

class parse_error : public std::runtime_error {
private:
    const std::string &file;
    unsigned line;
    std::string whats;
public:
    parse_error(const std::string &msg, const std::string &file, unsigned line);
    const char* what() const noexcept override;
};

void read_perf_result(
        const char* perf_result_path,
        objdump_table& objdump_result,
        inst_table& profiling_result,
        func_sample &func_sample_table);
void read_disassembly(string asm_file_path, objdump_table& objdump_result);
void read_source_table(const objdump_table &objdump_result, source_table& objdump_source);
void read_cfg(
        const string &path,
        dycfg& cfg,
        address& entry);
void write_exe_count(
        const string &inst_csv_path,
        const dycfg &cfg,
        inst_table& profiling_result,
        const objdump_table& objdump_result);
void write_loop(string loops_csv_path, string loop_body_path, list<loop> &all_loops, dycfg &cfg, inst_table& profiling_result);

#endif /* ifndef IO_HPP_ */
