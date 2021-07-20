#pragma once

#include "cfg.h"
#include <stdint.h>
#include "trace.h"
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <stdio.h>


void findFetchDispatch(Trace& trace);
void dumpFetchDispatch(const Trace& trace, std::fstream& stream);
void dumpTraces(const Trace& trace, std::fstream& stream);
void dumpInstrList(const Trace& trace, FILE* codeDumpFile);