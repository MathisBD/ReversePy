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
#include "analysis.h"


KNOB< std::string > outputFolderKnob(KNOB_MODE_WRITEONCE, "pintool", "o", "output", "specify output folder name");
static FILE* codeDumpFile;
static FILE* cfgDotFile;
static FILE* imgFile;
static FILE* bytecodeFile;
static std::fstream fetchDispatchStream;
static std::fstream traceDumpStream;

static uint64_t prevAddr = 0;
static std::vector<std::pair<uint64_t, uint64_t>> callAddrStack;
// if non zero, this is the expected value of the next instruction
// (e.g. after a ret we expect to go to the fallthrough of the 
// corresponding call)
// this is used to detect if the program uses push-ret
// (in this case our method to build the CFG completely fails).
static uint64_t expectedNextAddr = 0;

// is the interpreted program (e.g. prog.py) running ? 
static bool progRunning;
static std::string progName; 

// the trace of the current instruction
static TraceElement traceEle;
// the complete trace of the program so far
static Trace trace;

// called by PIN, BEFORE the read
void recordMemRead(ADDRINT memAddr, UINT32 memSize)
{
    if (progRunning) {
        uint64_t value = 0;
        uint32_t count = PIN_SafeCopy((void*)&value, (void*)memAddr, memSize);
        if (count < memSize) {
            panic("couldn't get memory read at address 0x%lx", memAddr);
        }
        traceEle.reads.emplace_back((uint64_t)memAddr, (uint8_t)memSize, value);
    }
}


// called by PIN, before the write (so we don't have access yet to what will be writte)
void recordMemWrite(ADDRINT memAddr, UINT32 memSize)
{
    if (progRunning) {
        uint64_t value = 0;
        uint32_t count = PIN_SafeCopy((void*)&value, (void*)memAddr, memSize);
        if (count < memSize) {
            panic("couldn't get memory read at address 0x%lx", memAddr);
        }
        traceEle.writes.emplace_back((uint64_t)memAddr, (uint8_t)memSize, value);
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
        saveReg(REG_RIP, ctx);
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
        traceEle.instr = instr;
        trace.addElement(traceEle);

        // reset the traceElement for the next instruction
        traceEle.opcodes.clear();
        traceEle.regs.clear();
        traceEle.reads.clear();
        traceEle.writes.clear();
    }
}

// if we are expecting a next address,
// check we find it.
void checkExpectedAddr(ADDRINT addr)
{
    if (expectedNextAddr != 0 && addr != expectedNextAddr) {
        panic("didn't find expected next addresss");
    }        
    expectedNextAddr = 0;
}

// called each time we execute a non-call and non-ret instruction
// even in a library (before we actually execute it).
void recordJump(ADDRINT addr)
{
    if (progRunning) {
        trace.recordJump(prevAddr, addr);
    }
    prevAddr = addr;
}

// called each time we execute a call instruction
// even in a library (before we actually execute it).
void recordCall(ADDRINT addr, ADDRINT fallthrough)
{
    if (progRunning) {
        trace.recordJump(prevAddr, addr);
    }
    callAddrStack.push_back(std::make_pair(addr, fallthrough));
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
        trace.recordJump(prevAddr, addr);
    }
    if (callAddrStack.empty()) {
        panic("empty call stack");
    }
    uint64_t callAddr = callAddrStack.back().first;
    expectedNextAddr = callAddrStack.back().second;
    callAddrStack.pop_back();
    prevAddr = callAddr;
}

void syscallEntry(ADDRINT scNum, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
    ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
    if (!progRunning && scNum == SYS_openat && std::string((char*)arg1) == progName) {
        progRunning = true;
        printf("[+] Opened file %s\n", progName.c_str());
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
    Instruction* instr = trace.findInstr(INS_Address(ins));
    if (instr == nullptr) {
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
        trace.addInstr(instr);
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
    // check next address
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)checkExpectedAddr,
        IARG_CALL_ORDER, CALL_ORDER_FIRST,  // before we do the jump/call/ret stuff
        IARG_ADDRINT, instr->addr, 
        IARG_END);
    // record jumps
    if (INS_IsProcedureCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordCall,
            IARG_ADDRINT, instr->addr,
            IARG_ADDRINT, INS_NextAddress(ins),
            IARG_END);
    }
    else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordRet,
            IARG_ADDRINT, instr->addr,
            IARG_END); 
    }
    else {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordJump,
            IARG_ADDRINT, instr->addr,
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

// called by PIN at the end of the program.
// we can't write to stdout here since stdout might
// have been closed (for PROG=ls at least).
void finiCallback(int code, void* v)
{
    printf("[+] Finished tracing\n");

    trace.removeDeadInstrs();
    trace.buildCFG();
    
    // find the fetch/dispatch (this modifies the cfg)
    findFetchDispatch(trace);
    printf("[+] Found dispatch at:\n\t0x%lx\n", trace.dispatch);
    printf("[+] Found fetch(es) at:\n");
    for (uint64_t fetch : trace.fetches) {
        printf("\t0x%lx\n", fetch);
    }
    if (trace.isFetch(trace.dispatch)) {
        panic("the dispatch is also a fetch");
    }
    
    dumpInstrList(trace, codeDumpFile);    
    // write the CFG after it is modified by findFetchDispatch()
    trace.cfg->writeDotGraph(cfgDotFile, 100);
    fclose(cfgDotFile);
    dumpFetchDispatch(trace, fetchDispatchStream);
    dumpTraces(trace, traceDumpStream);

    printf("[+] Done\n");

    // close the log files
    fclose(codeDumpFile);
    fclose(imgFile);
    fclose(cfgDotFile);
    fclose(bytecodeFile);
    traceDumpStream.close();
    fetchDispatchStream.close();
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
    const char* pypyPrefix = "/home/mathis/src/StageL3/pypy3.7-v7.3.5-linux64/";
    //const char* cpythonPrefix = "/home/mathis/src/StageL3/cpython3.8.10";
    if (IMG_IsMainExecutable(img) ||
        IMG_Name(img).compare(0, strlen(pypyPrefix), pypyPrefix) == 0 /*||
        IMG_Name(img).compare(0, strlen(cpythonPrefix), cpythonPrefix) == 0*/) {
        markPythonImg(IMG_Id(img));
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
        printf("[+] You are running the python program %s\n", progName.c_str());
        // wait for the interpreter to open the program before tracing it
        progRunning = false;
    }
    else {
        printf("[+] You are not running a python program\n");
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
    fetchDispatchStream.open((outputFolder + "fetch_dispatch").c_str(), std::ios::out);
    
    traceDumpStream << std::hex;
    fetchDispatchStream << std::hex;

    // add PIN callbacks
    INS_AddInstrumentFunction(insCallback, 0);
    //IMG_AddInstrumentFunction(imgMemCallback, 0);
    IMG_AddInstrumentFunction(imgLoadCallback, 0);
    IMG_AddUnloadFunction(imgUnloadCallback, 0);
    PIN_AddFiniFunction(finiCallback, 0);
    
    PIN_StartProgram();
    return -1;
}