#include "analysis.h"
#include "errors.h"
#include "mem.h"

std::map<uint64_t, uint32_t> getOutEdges(const Trace& trace)
{
    std::map<uint64_t, uint32_t> outEdges;
    for (const BasicBlock* bb : trace.cfg->getBasicBlocks()) {
        for (size_t i = 0; i < bb->instrs.size() - 1; i++) {
            outEdges[bb->instrs[i]->addr] = 1;
        }
        outEdges[bb->instrs.back()->addr] = bb->nextBBs.size();
    }
    return outEdges;
}

std::set<uint64_t> getSmallReadInstrs(const Trace& trace, uint32_t maxReadSize)
{
    std::set<uint64_t> smallReadInstrs;
    for (const auto& te : trace.completeTrace) {
        for (const auto& read : te.reads) {
            if (read.size <= maxReadSize) {
                smallReadInstrs.insert(te.instr->addr);
                break;
            }
        }
    }
    return smallReadInstrs;
}

uint64_t findFetchDispatch(Trace& trace)
{
    uint32_t dispatchMinExecCount = 1000;
    uint32_t dispatchMinOutEdges = 5;
    uint32_t dispatchMaxReadSize = 2;
    // get basic metrics
    auto outEdges = getOutEdges(trace);
    auto smallReadInstrs = getSmallReadInstrs(trace, dispatchMaxReadSize);
    // trim down the cfg
    trace.cfg->filterBBs(dispatchMinExecCount, dispatchMinExecCount / 2);
    trace.cfg->checkIntegrity();
    trace.cfg->mergeBlocks();
    trace.cfg->checkIntegrity();
    // find the dispatch
    std::set<uint64_t> potentialDispatch;
    for (const BasicBlock* bb : trace.cfg->getBasicBlocks()) {
        // does the block read a small memory region ?
        bool read = false;
        for (Instruction* instr : bb->instrs) {
            if (smallReadInstrs.find(instr->addr) != smallReadInstrs.end()) {
                read = true;
                break;
            }
        }
        if (!read) {
            continue;
        }
        for (const Instruction* instr : bb->instrs) {
            if (outEdges[instr->addr] >= dispatchMinOutEdges &&
                instr->execCount >= dispatchMinExecCount) 
            {
                // we found the dispatch !
                potentialDispatch.insert(instr->addr);                
            }
        }
    }
    if (potentialDispatch.size() != 1) {
        panic("didn't find the dispatch");
    }
    uint64_t dispatch = *(potentialDispatch.begin());
    printf("[+] Found dispatch at 0x%lx\n", dispatch);
    return dispatch;
}

void saveTrace(const std::vector<TraceElement>& trace, std::fstream& traceDumpStream)
{
    if (trace.size() == 0) {
        return;
    }
    traceDumpStream << "[";
    for (size_t i = 0; i < trace.size(); i++) {
        if (i > 0) {
            traceDumpStream << ", ";
        }
        trace[i].toJson(traceDumpStream);
    }
    traceDumpStream << "]\n";
}

void dumpTraces(const Trace& trace, uint64_t dispatchAddr, std::fstream& traceDumpStream)
{
    printf("[+] Trace info\n");
    std::vector<TraceElement> currTrace;
    bool foundDispatch = false;
    printf("\ttotal size: %lu\n", trace.completeTrace.size());
    for (const TraceElement& te : trace.completeTrace) {
        if (te.instr->addr == dispatchAddr) {
            if (foundDispatch) {
                // save the current trace
                saveTrace(currTrace, traceDumpStream);
            } 
            else {
                // don't save the header
                foundDispatch = true;
                printf("\theader size: %lu\n", currTrace.size());
            }
            // start a new trace
            currTrace.clear();
        }
        currTrace.push_back(te);
    }
    // don't save the footer
    printf("\tfooter size: %lu\n", currTrace.size());
}


void dumpInstrList(const Trace& trace, FILE* codeDumpFile)
{
    fprintf(codeDumpFile, "{\n");
    for (auto it = trace.instrList.begin(); it != trace.instrList.end(); it++) {
        Instruction* instr = it->second;
        if (isInPythonRegion(instr->addr)) {
            std::stringstream opcodeStr;
            opcodeStr << std::hex << "[ ";
            for (size_t i = 0; i < instr->opcodesCount; i++) {
                if (i > 0) {
                    opcodeStr << ", ";
                }
                opcodeStr << "\"" << (uint32_t)(instr->opcodes[i]) << "\"";
            }
            opcodeStr << " ]";
            fprintf(codeDumpFile, "\"%lx\": { \"exec_count\": %u, \"opcodes\": %s},\n", 
                instr->addr, instr->execCount, opcodeStr.str().c_str());
        }
    }
    // remove the trailing comma
    fseek(codeDumpFile, -2, SEEK_CUR);
    fprintf(codeDumpFile, "}\n");
}

