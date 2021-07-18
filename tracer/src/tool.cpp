#include <map>
#include <string>
#include <stdio.h>
#include <sys/syscall.h>
#include <fstream>
#include <sstream>
#include <set>

#include "mem.h"
#include "errors.h"
#include "cfg.h"
#include "pin.H"
#include "trace.h"


KNOB< std::string > outputFolderKnob(KNOB_MODE_WRITEONCE, "pintool", "o", "output", "specify output folder name");
static FILE* codeDumpFile;
static FILE* cfgDotFile;
static FILE* imgFile;
static FILE* bytecodeFile;
static std::fstream traceDumpStream;

// the ids of the regions used by the python interpreter
static std::set<uint32_t> pythonImgIds;

static std::map<uint64_t, Instruction*> instrList;
static std::map<Jump, uint32_t> jumps;
static uint64_t prevAddr = 0;
static std::vector<uint64_t> callAddrStack;

// is the interpreted program (e.g. prog.py) running ? 
static bool progRunning;
static std::string progName; 

// the trace of the current instruction
static TraceElement traceEle;
static std::vector<TraceElement> completeTrace;
// maps opcode -> list of traces.
// Each entry is a pair of indices, [start, end] in the complete trace.
static std::vector<std::pair<uint64_t, uint64_t>> opcodeTraces[256];


bool isInPythonRegion(uint64_t addr)
{
    return pythonImgIds.find(getImgId(addr)) != pythonImgIds.end();
}

// called by PIN, BEFORE the read
void recordMemRead(ADDRINT memAddr, UINT32 memSize)
{
    if (progRunning) {
        uint64_t value;
        memmove(&value, (void*)memAddr, memSize);
        value &= (1 << (8*memSize)) - 1; // zero out the irrelevant part
        traceEle.reads.emplace_back((uint64_t)memAddr, (uint8_t)memSize, value);
    }
}


// called by PIN, before the write (so we don't have access yet to what will be writte)
void recordMemWrite(ADDRINT memAddr, UINT32 memSize)
{
    if (progRunning) {
        traceEle.writes.emplace_back((uint64_t)memAddr, (uint8_t)memSize, 0);
    }
}

static inline void saveOpcodes(uint64_t insAddr, uint32_t insSize)
{
    uint8_t buf[16];
    uint32_t count = PIN_SafeCopy((void*)buf, (void*)insAddr, insSize);
    if (count < insSize) {
        panic("couldn't get opcodes for instr at address 0x%lx\n", insAddr);
    }
    for (uint32_t i = 0; i < count; i++) {
        traceEle.opcodes.push_back(buf[i]);
    }
}

static inline void saveReg(REG reg, const CONTEXT* ctx)
{
    uint64_t value;
    PIN_GetContextRegval(ctx, reg, (uint8_t*)(&value));
    traceEle.regs.push_back(std::make_pair(reg, value));
}

// called by PIN.
// DON'T modify the context.
void dumpTraceElement(Instruction* instr, const CONTEXT* ctx)
{
    if (progRunning) {
        (instr->execCount)++;
        saveOpcodes(instr->addr, instr->size);
        if (instr->xedOpcode == XED_ICLASS_MOVZX) {
            saveReg(REG_RAX, ctx);
            saveReg(REG_RBX, ctx);
            saveReg(REG_RCX, ctx);
            saveReg(REG_RDX, ctx);
            saveReg(REG_RSI, ctx);
            saveReg(REG_RDI, ctx);
            saveReg(REG_RSP, ctx);
            saveReg(REG_RBP, ctx);
            saveReg(REG_R8, ctx);
            saveReg(REG_R9, ctx);
            saveReg(REG_R10, ctx);
            saveReg(REG_R11, ctx);
            saveReg(REG_R12, ctx);
            saveReg(REG_R13, ctx);
            saveReg(REG_R14, ctx);
            saveReg(REG_R15, ctx);
        }
        saveReg(REG_RIP, ctx);
        saveReg(REG_EFLAGS, ctx);
        traceEle.instr = instr;
        completeTrace.push_back(traceEle);

        // reset the traceElement for the next instruction
        traceEle.opcodes.clear();
        traceEle.regs.clear();
        traceEle.reads.clear();
        traceEle.writes.clear();
    }
}

// called each time we execute a non-call and non-ret instruction
// even in a library (before we actually execute it).
void recordJump(ADDRINT addr)
{
    if (progRunning) {
        jumps[Jump(prevAddr, addr)]++;
    }
    prevAddr = addr;
}

// called each time we execute a call instruction
// even in a library (before we actually execute it).
void recordCall(ADDRINT addr)
{
    if (progRunning) {
        jumps[Jump(prevAddr, addr)]++;
    }
    callAddrStack.push_back(addr);
    // I set prevAddr to 0 to cut the link between the caller and the callee
    // so that the VM loop is more visible on the CFG.
    // If you are not interested in seeing the VM loop, consider
    // setting prevAddr to addr.
    //prevAddr = addr;
    prevAddr = 0;
}

// called each time we execute a ret instruction
// even in a library (before we actually execute it).
void recordRet(ADDRINT addr)
{
    if (progRunning) {
        jumps[Jump(prevAddr, addr)]++;
    }
    if (callAddrStack.empty()) {
        panic("empty call stack");
    }
    uint64_t callAddr = callAddrStack.back();
    callAddrStack.pop_back();
    prevAddr = callAddr;
}

void syscallEntry(ADDRINT scNum, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
    ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
    /*if (!progRunning && scNum == SYS_openat && std::string((char*)arg1) == progName) {
        progRunning = true;
        printf("[+] Opened file %s\n", progName.c_str());
    }*/
    if (scNum == SYS_openat && std::string((char*)arg1) == "tototo") {
        progRunning = true;
        printf("[+] Opened tototo\n");
    }
    if (scNum == SYS_openat && std::string((char*)arg1) == "tototo_after") {
        progRunning = false;
        printf("[+] Opened tototo_after\n");
    }
}

// called by PIN each time we encounter an instruction for 
// the first time (and before we execute this instruction).
// WEIRDLY, pin can call this several times for the same instruction,
// and can call it for an instruction that will never be executed.
// WEIRDLIER, I have to call INS_InsertCall() each time this function is 
// executed on a given instruction, not just the first time.
void insCallback(INS ins, void* v)
{
    if (INS_IsNop(ins)) {
        return;
    }
    Instruction* instr;
    auto it = instrList.find(INS_Address(ins));
    if (it == instrList.end()) {
        instr = new Instruction();
        instr->addr = INS_Address(ins);
        instr->size = INS_Size(ins);
        // get the opcodes
        instr->opcodesCount = PIN_SafeCopy((void*)instr->opcodes, (void*)instr->addr, instr->size);
        if (instr->opcodesCount < instr->size) {
            panic("couldn't get opcodes for instr at address 0x%lx\n", instr->addr);
        }
        instr->xedOpcode = INS_Opcode(ins);
        instr->execCount = 0;
        instr->isMemRead = INS_IsMemoryRead(ins);
        instr->disassembly = INS_Disassemble(ins);    
        // save a pointer to the instruction
        instrList[instr->addr] = instr;
    }
    else {
        instr = it->second;
    }
    // I have to call these InsertCall() every time, not only if we just created instr.if (INS_IsSyscall(ins)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)syscallEntry,
        IARG_SYSCALL_NUMBER,
        IARG_SYSARG_VALUE, 0,
        IARG_SYSARG_VALUE, 1,
        IARG_SYSARG_VALUE, 2,
        IARG_SYSARG_VALUE, 3,
        IARG_SYSARG_VALUE, 4,
        IARG_SYSARG_VALUE, 5,
        IARG_END);
    // record jumps
    if (INS_IsProcedureCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordCall,
            IARG_UINT64, instr->addr,
            IARG_END);
    }
    else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordRet,
            IARG_UINT64, instr->addr,
            IARG_END); 
    }
    else {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordJump,
            IARG_UINT64, instr->addr,
            IARG_END); 
    }
    if (isInPythonRegion(instr->addr)) {
        // dump execution trace
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dumpTraceElement,
            IARG_CALL_ORDER, CALL_ORDER_LAST,
            IARG_PTR, instr,
            IARG_CONST_CONTEXT,
            IARG_END);
        // record memory reads and writes
        uint32_t memOpCount = INS_MemoryOperandCount(ins);
        for (uint32_t memOp = 0; memOp < memOpCount; memOp++) {
            // read : before the instruction executes
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                // predicated means the function is not called
                // if the predicate (e.g. for movcc) is false.
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)recordMemRead,
                    IARG_CALL_ORDER, CALL_ORDER_DEFAULT, // before dumpTrace()
                    IARG_MEMORYOP_EA, memOp, 
                    IARG_MEMORYREAD_SIZE,
                    IARG_END);
            }
            // write : also before the instruction executes
            if (INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)recordMemWrite,
                    IARG_CALL_ORDER, CALL_ORDER_DEFAULT, // before dumpTrace()
                    IARG_MEMORYOP_EA, memOp, 
                    IARG_MEMORYWRITE_SIZE,
                    IARG_END);
            }
        }
    }
}

void removeDeadInstrs()
{
    for (auto it = instrList.begin(); it != instrList.end();) {
        if (it->second->execCount == 0) {
            delete it->second;
            instrList.erase(it++);
        }
        else {
            it++;
        }
    }
}

// the fetch is a movzx that reads 2 bytes in memory
// and is executed a lot
bool isFetch(const TraceElement& te)
{
    if (!isInPythonRegion(te.instr->addr)) {
        return false;
    }
    if (te.instr->xedOpcode != XED_ICLASS_MOVZX) {
        return false;
    }
    if (te.instr->execCount < 500) {
        return false;
    }
    for (const MemoryAccess& read : te.reads) {
        if (read.size == 2) {
            return true;
        }
    }
    return false;
}

void saveTrace(const std::vector<TraceElement>& trace)
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

void dumpTraces()
{
    printf("[+] Dumping trace\n");
    std::vector<TraceElement> currTrace;
    bool foundFetch = false;
    printf("\ttotal size: %lu\n", completeTrace.size());
    for (const TraceElement& te : completeTrace) {
        if (isFetch(te)) {
            if (foundFetch) {
                // save the current trace
                saveTrace(currTrace);
            } 
            else {
                // don't save the header
                printf("\theader size: %lu\n", currTrace.size());
            }
            // start a new trace
            currTrace.clear();
            foundFetch = true;
        }
        currTrace.push_back(te);
    }
    // don't save the footer
    printf("\tfooter size: %lu\n", currTrace.size());
}


void dumpInstrList()
{
    fprintf(codeDumpFile, "{\n");
    for (auto it = instrList.begin(); it != instrList.end(); it++) {
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

void checkFetches()
{
    std::set<uint64_t> fetchAddrs;
    for (const TraceElement& te : completeTrace) {
        if (isFetch(te)) {
            fetchAddrs.insert(te.instr->addr);
        }
    }
    printf("[+] Possible fetch addresses :\n");
    for (auto addr : fetchAddrs) {
        printf("\t0x%lx\n", addr);
    }
}

void dumpCFG()
{
    // get the CFG of the python code
    std::vector<Instruction*> cfgInstrs;
    for (auto it = instrList.begin(); it != instrList.end(); it++) {
        Instruction* instr = it->second;
        if (isInPythonRegion(instr->addr)) {
            cfgInstrs.push_back(instr);
        }
    }
    CFG* cfg = new CFG(cfgInstrs, jumps);
    cfg->checkIntegrity(false);
    cfg->mergeBlocks();
    cfg->checkIntegrity(false);
    cfg->filterBBs(900, 400);
    // exec counts now don't mean anything
    cfg->checkIntegrity(false);
    cfg->mergeBlocks();
    cfg->checkIntegrity(false);
    cfg->writeDotGraph(cfgDotFile, 10);

    fprintf(codeDumpFile, "Basic block count : %lu\n", cfg->getBasicBlocks().size());
}

// called by PIN at the end of the program.
// we can't write to stdout here since stdout might
// have been closed (for PROG=ls at least).
void finiCallback(int code, void* v)
{
    removeDeadInstrs();
    //checkFetches();
    //dumpTraces();

    for (auto te : completeTrace) {
        traceDumpStream 
            << te.instr->addr << "\t"
            << te.instr->disassembly << "\n";
    }

    dumpInstrList();
    dumpCFG();
    printf("[+] Done\n");

    // close the log files
    fclose(codeDumpFile);
    fclose(imgFile);
    fclose(cfgDotFile);
    fclose(bytecodeFile);
    traceDumpStream.close();
}

void imgLoadCallback(IMG img, void* v)
{
    fprintf(imgFile, "Loading %s, ID=%u\n", IMG_Name(img).c_str(), IMG_Id(img));
    for (uint32_t i = 0; i < IMG_NumRegions(img); i++) {
        ImgRegion* reg = new ImgRegion();
        reg->startAddr = IMG_RegionLowAddress(img, i);
        reg->endAddr = IMG_RegionHighAddress(img, i);
        reg->imgId = IMG_Id(img);
        addImgRegion(reg);
        fprintf(imgFile, "\tregion 0x%lx -> 0x%lx\n", reg->startAddr, reg->endAddr);
    }
    const char* pythonPrefix = "/home/mathis/src/StageL3/pypy3.7-v7.3.5-linux64/";
    if (IMG_IsMainExecutable(img) ||
        IMG_Name(img).compare(0, strlen(pythonPrefix), pythonPrefix) == 0) {
        pythonImgIds.insert(IMG_Id(img));
    }
}

void imgUnloadCallback(IMG img, void* v)
{
    fprintf(imgFile, "Unloading %s\n", IMG_Name(img).c_str());
}

int main(int argc, char* argv[])
{
    // init PIN
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        printf("PIN INIT ERROR\n");
        return EXIT_FAILURE;
    }
    PIN_SetSyntaxATT();

    // get the name of the python program we are running
    progName = std::string(argv[argc-1]);
    if (progName.size() > 3 && progName.substr(progName.size() - 3, 3) == ".py") {
        printf("[+] Detected you are running the python program %s\n", progName.c_str());
        // wait for the interpreter to open the program before tracing it
        progRunning = false;
    }
    else {
        progRunning = true;
    }
    

    // open the log files
    std::string outputFolder = outputFolderKnob.Value();
    if (outputFolder[outputFolder.size() - 1] != '/') {
        outputFolder.push_back('/');
    }
    codeDumpFile = fopen((outputFolder + "code_dump").c_str(), "w");
    imgFile = fopen((outputFolder + "img_loading").c_str(), "w");
    cfgDotFile = fopen((outputFolder + "cfg.dot").c_str(), "w");
    bytecodeFile = fopen((outputFolder + "bytecode").c_str(), "w");
    traceDumpStream.open((outputFolder + "traceDump").c_str(), std::ios::out);

    // begin the trace JSON dump
    traceDumpStream << std::hex;

    // add PIN callbacks
    INS_AddInstrumentFunction(insCallback, 0);
    //IMG_AddInstrumentFunction(imgMemCallback, 0);
    IMG_AddInstrumentFunction(imgLoadCallback, 0);
    IMG_AddUnloadFunction(imgUnloadCallback, 0);
    PIN_AddFiniFunction(finiCallback, 0);
    
    PIN_StartProgram();
    return -1;
}