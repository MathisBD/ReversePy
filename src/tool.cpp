#include <map>
#include <string>
#include <stdio.h>
#include <sys/syscall.h>

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
static FILE* traceDumpFile;

static std::map<uint64_t, Instruction*> instrList;
static std::map<Jump, uint32_t> jumps;
static uint64_t prevAddr = 0;
// is the interpreted program (e.g. prog.py) running ? 
static bool progRunning = false; 

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
        traceEle.reads.emplace_back((uint64_t)memAddr, (uint64_t)memSize, value);
    }
}

// called by PIN
void recordMemWrite()
{
    if (progRunning) {
        // TODO
    }
}

inline void saveReg(const std::string& name, REG reg, const CONTEXT* ctx)
{
    uint64_t value;
    PIN_GetContextRegval(ctx, reg, (uint8_t*)(&value));
    traceEle.regs[name] = value;
}

inline void saveAllRegs(const CONTEXT* ctx)
{
    saveReg("rip", REG_RIP, ctx);
    saveReg("rax", REG_RAX, ctx);
    saveReg("rbx", REG_RBX, ctx);
    saveReg("rcx", REG_RCX, ctx);
    saveReg("rdx", REG_RDX, ctx);
    saveReg("rdi", REG_RDI, ctx);
    saveReg("rsi", REG_RSI, ctx);
    saveReg("rsp", REG_RSP, ctx);
    saveReg("rbp", REG_RBP, ctx);
    saveReg("r8", REG_R8, ctx);
    saveReg("r9", REG_R9, ctx);
    saveReg("r10", REG_R10, ctx);
    saveReg("r11", REG_R11, ctx);
    saveReg("r12", REG_R12, ctx);
    saveReg("r13", REG_R13, ctx);
    saveReg("r14", REG_R14, ctx);
    saveReg("r15", REG_R15, ctx);
    saveReg("eflags", REG_EFLAGS, ctx);
    //saveReg("fs", REG_FS, ctx);
    //saveReg("gs", REG_GS, ctx);
}

inline void saveOpcodes(uint64_t insAddr, uint32_t insSize)
{
    uint8_t opcodes[16];
    uint32_t fetched = PIN_SafeCopy((void*)opcodes, (void*)insAddr, insSize);
    if (fetched < insSize) {
        panic("couldn't get opcodes for instr at address 0x%lx\n", insAddr);
    }
    for (size_t i = 0; i < insSize; i++) {
        traceEle.opcodes.push_back(opcodes[i]);
    }
}

// called by PIN.
// DON'T modify the context.
void dumpTraceElement(const CONTEXT* ctx, Instruction* instr)
{
    if (progRunning) {
        (instr->execCount)++;
        saveAllRegs(ctx);
        saveOpcodes(instr->addr, instr->size);
        fprintf(traceDumpFile, "%s,\n", traceEle.toJson().c_str());

        // reset the traceElement for the next instruction
        traceEle.opcodes.clear();
        traceEle.reads.clear();
        traceEle.writes.clear();
        // no need to clear the regs,
        // we will overwrite them all.
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
    if (scNum == SYS_openat && !strcmp((char*)arg1, "utils/prog.py")) {
        progRunning = true;
        printf("[+] Opened file utils/prog.py\n");
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
            IARG_CONST_CONTEXT,
            IARG_PTR, instr,
            IARG_END);
        // record memory reads
        uint32_t memOpCount = INS_MemoryOperandCount(ins);
        for (uint32_t memOp = 0; memOp < memOpCount; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                // predicated means the function is not called
                // if the predicate (e.g. for movcc) is false.
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)recordMemRead,
                    IARG_CALL_ORDER, CALL_ORDER_DEFAULT, // between resetTrace() and dumpTrace()
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

Instruction* getFetch()
{
    // get the CFG of the main image's code
    std::vector<Instruction*> cfgInstrVect;
    for (auto it = instrList.begin(); it != instrList.end(); it++) {
        if (getImgId(it->first) == mainImgId) {
            cfgInstrVect.push_back(it->second);
        }
    }
    CFG* cfg = new CFG(cfgInstrVect, jumps);
    cfg->checkIntegrity(false);
    cfg->mergeBlocks();
    cfg->checkIntegrity(false);
    // the fetch will be executed a lot
    //cfg->filterBBs(9000, 400);
    //cfg->checkIntegrity(false);
    //cfg->mergeBlocks();
    //cfg->checkIntegrity(false);
    cfg->writeDotGraph(cfgDotFile, 100);

    /*std::vector<Instruction*> fetches;
    for (auto bb : cfg->getBasicBlocks()) {
        for (auto instr : bb->instrs) {
            if (isPossibleFetch(instr)) {
                fetches.push_back(instr);
            }
        }
    }
    printf("[+] Possible fetch instructions :\n");
    for (auto instr : fetches) {
        printf("\t0x%lx: %s\n", instr->addr, instr->disassembly.c_str());
    }
    if (fetches.size() == 1) {
        return fetches[0];
    }
    panic("Didn't find the python bytecode fetch.");*/
    return nullptr;
}

void dumpBytecode()
{
    Instruction* fetch = getFetch();
    
    /*// dump the bytecode
    printf("[+] Dumping bytecode\n");
    std::vector<uint64_t> fetchIndices;
    for (uint64_t i = 0; i < instrTrace.size(); i++) {
        auto trace = instrTrace[i];
        if (trace.instr == fetch) {
            uint8_t opcode = opcodeFromBytecode(trace.readBytecode);
            uint8_t arg = argFromBytecode(trace.readBytecode);
            fprintf(bytecodeFile, "%x %x %s\n", opcode, arg, opcodeName(opcode).c_str());
            fetchIndices.push_back(i);
        }
    }

    // get the opcode traces
    for (uint64_t i = 0; i < fetchIndices.size(); i++) {
        uint64_t start = fetchIndices[i];
        uint64_t end = fetchIndices[i+1] - 1;
        uint8_t opcode = opcodeFromBytecode(instrTrace[start].readBytecode);
        opcodeTraces[opcode].push_back(std::make_pair(start, end));
    }

    // dump the opcode traces
    for (uint32_t opcode = 0; opcode < 256; opcode++) {
        if (opcodeTraces[opcode].size() == 0) {
            continue;
        }
        fprintf(bytecodeFile, "[0x%x] : %lu traces : ", opcode, opcodeTraces[opcode].size());
        for (uint32_t i = 0; i < opcodeTraces[opcode].size() && i < 10; i++) {
            auto trace = opcodeTraces[opcode][i];
            fprintf(bytecodeFile, "(%lu->%lu) ", trace.first, trace.second);
        }
        fprintf(bytecodeFile, "\n");
    }*/
}

// called by PIN at the end of the program.
// we can't write to stdout here since stdout might
// have been closed (for PROG=ls at least).
void finiCallback(int code, void* v)
{
    removeDeadInstrs();
    dumpInstrList();
    dumpBytecode();    

    // finish the trace JSON dump
    // (remove the last comma)
    fseek(traceDumpFile, -2, SEEK_CUR);
    fprintf(traceDumpFile, "\n]");

    // close the log files
    fclose(codeDumpFile);
    fclose(imgFile);
    fclose(cfgDotFile);
    fclose(bytecodeFile);
    fclose(traceDumpFile);
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

    // open the log files
    std::string outputFolder = outputFolderKnob.Value();
    if (outputFolder[outputFolder.size() - 1] != '/') {
        outputFolder.push_back('/');
    }
    codeDumpFile = fopen((outputFolder + "code_dump").c_str(), "w");
    imgFile = fopen((outputFolder + "img_loading").c_str(), "w");
    cfgDotFile = fopen((outputFolder + "cfg.dot").c_str(), "w");
    bytecodeFile = fopen((outputFolder + "bytecode").c_str(), "w");
    traceDumpFile = fopen((outputFolder + "traceDump").c_str(), "w");

    // begin the trace JSON dump
    fprintf(traceDumpFile, "[\n");

    // add PIN callbacks
    INS_AddInstrumentFunction(insCallback, 0);
    //IMG_AddInstrumentFunction(imgMemCallback, 0);
    IMG_AddInstrumentFunction(imgLoadCallback, 0);
    IMG_AddUnloadFunction(imgUnloadCallback, 0);
    PIN_AddFiniFunction(finiCallback, 0);
    
    PIN_StartProgram();
    return -1;
}