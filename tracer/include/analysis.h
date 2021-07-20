#pragma once

#include "cfg.h"
#include <stdint.h>
#include "trace.h"
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <stdio.h>


uint64_t findDispatch(Trace& trace);
void dumpTraces(const Trace& trace, uint64_t dispatchAddr, std::fstream& traceDumpStream);
void dumpInstrList(const Trace& trace, FILE* codeDumpFile);