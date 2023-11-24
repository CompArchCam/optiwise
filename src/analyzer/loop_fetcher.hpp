#ifndef LOOP_FETCHER_H
#define LOOP_FETCHER_H

#include "support.hpp"

int extract_loops(const dycfg& cfg, const address &entry, list<loop>& all_loops);

#endif
