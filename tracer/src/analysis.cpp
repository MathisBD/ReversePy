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

void findFetchDispatch(Trace& trace)
{
    uint32_t dispatchMinExecCount = 2000;
    uint32_t dispatchMinOutEdges = 10;
    uint32_t dispatchMaxReadSize = 2;
    // get basic metrics
    auto outEdges = getOutEdges(trace);
    auto smallReadInstrs = getSmallReadInstrs(trace, dispatchMaxReadSize);
    // trim down the cfg : I expect all the fetches and the dispatch to be 
    // in the same block after this.
    trace.cfg->filterBBs(dispatchMinExecCount, dispatchMinExecCount / 2);
    trace.cfg->checkIntegrity();
    trace.cfg->mergeBlocks();
    trace.cfg->checkIntegrity();
    // find the block
    std::vector<uint64_t> potentialDispatch;
    std::vector<std::vector<uint64_t>> potentialFetches;
    for (const BasicBlock* bb : trace.cfg->getBasicBlocks()) {
        // does the block read a small memory region ?
        std::vector<uint64_t> reads;
        for (Instruction* instr : bb->instrs) {
            if (smallReadInstrs.find(instr->addr) != smallReadInstrs.end()) {
                reads.push_back(instr->addr);
            }
        }
        if (reads.empty()) {
            continue;
        }
        //printf("block at 0x%lx\n", bb->firstAddr());
        for (const Instruction* instr : bb->instrs) {
            //printf("0x%lx\tout=%u\texec=%u\n", instr->addr, 
            //    outEdges[instr->addr], instr->execCount);
            if (outEdges[instr->addr] >= dispatchMinOutEdges &&
                instr->execCount >= dispatchMinExecCount) 
            {
                // we found the dispatch ! (and the fetches)  
                //printf("Found dispatch at 0x%lx\n", instr->addr);          
                potentialDispatch.push_back(instr->addr);
                potentialFetches.push_back(reads);                
            }
        }
    }
    if (potentialDispatch.size() != 1) {
        panic("didn't find the dispatch/fetch");
    }
    trace.dispatch = potentialDispatch[0];
    trace.fetches = potentialFetches[0];
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
        bool allRegs = (i == 0);
        trace[i].toJson(traceDumpStream, allRegs);
    }
    traceDumpStream << "]\n";
}

void dumpFetchDispatch(const Trace& trace, std::fstream& stream)
{
    stream << "{ \"dispatch\": \"" << trace.dispatch << "\", "
        << "\"fetches\": [ ";
    for (size_t i = 0; i < trace.fetches.size(); i++) {
        if (i > 0) {
            stream << ", ";
        }
        stream << "\"" << trace.fetches[i] << "\"";
    }
    stream << " ] }\n";
}

// the trace dump file contains :
// a first line { "fetches": [0x.., 0x.., etc.], "dispatch": 0x.. }.
// a json trace for a single opcode on each following line.
// each trace is taken from its first fetch (included) to the next fetch after its dispatch (excluded).
void dumpTraces(const Trace& trace, std::fstream& stream)
{
    // skip the header (before the first opcode trace)
    size_t start = 0;
    while (!trace.isFetch(trace.completeTrace[start].instr->addr)) {
        start++;
    }       
    // the current trace
    std::vector<TraceElement> currTrace;
    // did we find the dispatch for the current trace ?
    bool foundDispatch = false;
    for (size_t i = start; i < trace.completeTrace.size(); i++) {
        const auto& te = trace.completeTrace[i];
        if (te.instr->addr == trace.dispatch) {
            foundDispatch = true;
        }
        else if (trace.isFetch(te.instr->addr) && foundDispatch) {
            // save the current trace
            saveTrace(currTrace, stream);
            // start a new trace
            currTrace.clear();
            foundDispatch = false;
        }
        currTrace.push_back(te);
    }
    // don't save the footer
    printf("[+] Trace size\n");
    printf("\ttotal: %lu\n", trace.completeTrace.size());
    printf("\theader: %lu\n", start);
    printf("\tfooter: %lu\n", currTrace.size());
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

