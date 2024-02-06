#ifndef LOOP_FETCHER_H
#define LOOP_FETCHER_H

#include "support.hpp"

void extract_loops_and_nesting(dycfg& cfg, const address &entry, list<loop>& all_loops);

#endif
