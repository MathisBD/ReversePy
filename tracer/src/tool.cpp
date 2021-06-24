#include <map>
#include <string>
#include <stdio.h>
#include <sys/syscall.h>
#include <fstream>

#include "mem.h"
#include "errors.h"
#include "cfg.h"
#include "bytecode.h"
#include "pin.H"
#include "trace.h"


KNOB< std::string > outputFolderKnob(KNOB_MODE_WRITEONCE, "pintool", "o", "output", "specify output folder name");
static FILE* codeDumpFile;
static FILE* cfgDotFile;
static FILE* imgFile;
static FILE* bytecodeFile;
static std::fstream traceDumpStream;

static std::map<uint64_t, Instruction*> instrList;
static std::map<Jump, uint32_t> jumps;
static uint64_t prevAddr = 0;

// is the interpreted program (e.g. prog.py) running ? 
static bool progRunning;
static std::string progName; 

// the trace of the current instruction
static TraceElement traceEle;
// maps opcode -> list of traces.
// Each entry is a pair of indices, [start, end] in the complete trace.
static std::vector<std::pair<uint64_t, uint64_t>> opcodeTraces[256];

bool isPossibleFetch(Instruction* instr) {
    return instr->opcode == XED_ICLASS_MOVZX && instr->isMemRead;
}

// called by PIN
void recordMemRead(ADDRINT memAddr, UINT32 memSize)
{
    if (progRunning) {
        uint64_t value;
        memmove(&value, (void*)memAddr, memSize);
        traceEle.reads[traceEle.readsCount++] = 
            MemoryAccess((uint64_t)memAddr, (uint64_t)memSize, value);
    }
}

// called by PIN
void recordRegRead(REG reg, ADDRINT val)
{
    if (progRunning) {
        traceEle.regs[traceEle.regsCount++] = std::make_pair(reg, val);
    }
}

static inline void saveOpcodes(uint64_t insAddr, uint32_t insSize)
{
    traceEle.opcodesCount = PIN_SafeCopy((void*)traceEle.opcodes, (void*)insAddr, insSize);
    if (traceEle.opcodesCount < insSize) {
        panic("couldn't get opcodes for instr at address 0x%lx\n", insAddr);
    }
}

static inline void saveReg(REG reg, const CONTEXT* ctx)
{
    uint64_t value;
    PIN_GetContextRegval(ctx, reg, (uint8_t*)(&value));
    traceEle.regs[traceEle.regsCount++] = std::make_pair(reg, value);
}

// called by PIN.
// DON'T modify the context.
void dumpTraceElement(Instruction* instr, const CONTEXT* ctx)
{
    if (progRunning) {
        (instr->execCount)++;
        saveOpcodes(instr->addr, instr->size);
        saveReg(REG_RIP, ctx);
        saveReg(REG_EFLAGS, ctx);
        traceEle.toJson(traceDumpStream);
        traceDumpStream << "\n";

        // reset the traceElement for the next instruction
        traceEle.opcodesCount = 0;
        traceEle.regsCount = 0;
        traceEle.readsCount = 0;
    }
}

// called each time we execute a selected instruction
// (before we actually execute it).
void recordJump(ADDRINT addr)
{
    if (progRunning) {
        jumps[Jump(prevAddr, addr)]++;
        prevAddr = addr;
    }
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
    if (INS_IsNop(ins)) {
        return;
    }
    Instruction* instr;
    auto it = instrList.find(INS_Address(ins));
    if (it == instrList.end()) {
        instr = new Instruction();
        instr->addr = INS_Address(ins);
        instr->size = INS_Size(ins);
        instr->opcode = INS_Opcode(ins);
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
    if (getImgId(instr->addr) == mainImgId) {
        // dump execution trace
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dumpTraceElement,
            IARG_CALL_ORDER, CALL_ORDER_LAST,
            IARG_PTR, instr,
            IARG_CONST_CONTEXT,
            IARG_END);
        // record register reads
        uint32_t regCount = INS_MaxNumRRegs(ins);
        for (uint32_t i = 0; i < regCount; i++) {
            REG reg = INS_RegR(ins, i);
            if (REG_valid(reg) && REG_is_gr(REG_FullRegName(reg))) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordRegRead,
                    IARG_CALL_ORDER, CALL_ORDER_DEFAULT, // before dumpTrace()
                    IARG_UINT32, REG_FullRegName(reg),
                    IARG_REG_VALUE, REG_FullRegName(reg),
                    IARG_END);
            }
        }
        // record memory reads
        uint32_t memOpCount = INS_MemoryOperandCount(ins);
        for (uint32_t memOp = 0; memOp < memOpCount; memOp++) {
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
        }
        // record jumps
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordJump,
            IARG_UINT64, instr->addr,
            IARG_END); 
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

void dumpInstrList()
{
    for (auto it = instrList.begin(); it != instrList.end(); it++) {
        Instruction* instr = it->second;
        if (getImgId(instr->addr) == mainImgId) {
            fprintf(codeDumpFile, "0x%lx: [%u] %s\n", 
                instr->addr, instr->execCount, instr->disassembly.c_str());
        }
    }
}


// called by PIN at the end of the program.
// we can't write to stdout here since stdout might
// have been closed (for PROG=ls at least).
void finiCallback(int code, void* v)
{
    removeDeadInstrs();
    dumpInstrList();
    
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
    if (IMG_IsMainExecutable(img)) {
        mainImgId = IMG_Id(img);
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