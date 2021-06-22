#include <map>
#include <string>
#include <stdio.h>
#include <sys/syscall.h>

#include "errors.h"
#include "cfg.h"
#include "mem.h"
#include "pin.H"

class InstrTrace
{
public:
    uint64_t addr;
    InstrTrace(uint64_t addr_) : addr(addr_) {};
};

KNOB< std::string > outputFolderKnob(KNOB_MODE_WRITEONCE, "pintool", "o", "output", "specify output folder name");
static FILE* codeDumpFile;
static FILE* cfgDotFile;
static FILE* imgFile;
static FILE* memReadFile;
static FILE* traceDumpFile;

static std::map<uint64_t, Instruction*> instrList;
static std::map<Jump, uint32_t> jumps;
static uint64_t prevAddr = 0;
// is the interpreted program (e.g. prog.py) running ? 
static bool progRunning = false; 

static std::vector<InstrTrace> instrTrace;

// called each time we execute any instruction
// (before we actually execute it).
void increaseExecCount(Instruction* instr) 
{
    if (progRunning) {
        (instr->execCount)++;
    }
}

void recordTrace(ADDRINT addr)
{
    if (progRunning) {
        instrTrace.emplace_back((uint64_t)addr);
    }
}

// called each time we execute an instruction
// (before we actually execute it).
void recordJump(ADDRINT addr, BOOL isCall, BOOL isRet)
{
    if (progRunning) {
        jumps[Jump(prevAddr, addr)]++;
        prevAddr = addr;
    }
}

void recordMemRead(Instruction* instr, ADDRINT memAddr, UINT32 memSize)
{
    if (progRunning) {
        increaseReadCount(instr, (uint64_t)memAddr, (uint64_t)memSize);
    }
}

void syscallEntry(ADDRINT scNum, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
    ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
    if (scNum == SYS_openat && !strcmp((char*)arg1, "prog.py")) {
        progRunning = true;
        printf("[+] Opened file prog.py\n");
        //searchForPyOpcodes();
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
    // instrument syscalls
    if (INS_IsSyscall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)syscallEntry,
            IARG_SYSCALL_NUMBER,
            IARG_SYSARG_VALUE, 0,
            IARG_SYSARG_VALUE, 1,
            IARG_SYSARG_VALUE, 2,
            IARG_SYSARG_VALUE, 3,
            IARG_SYSARG_VALUE, 4,
            IARG_SYSARG_VALUE, 5,
            IARG_END);
    }
    Instruction* instr;
    auto it = instrList.find(INS_Address(ins));
    if (it == instrList.end()) {
        instr = new Instruction();
        instr->addr = INS_Address(ins);
        instr->size = INS_Size(ins);
        instr->opcode = INS_Opcode(ins);
        instr->execCount = 0;
        instr->bytecodeReadCount = 0;
        instr->disassembly = INS_Disassemble(ins);    
        // save a pointer to the instruction
        instrList[instr->addr] = instr;
    }
    else {
        instr = it->second;
    }
    // I have to call these InsertCall() every time, not only if we just created instr.
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)increaseExecCount, 
        IARG_PTR, instr, 
        IARG_END);
    // dump execution trace
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordTrace, 
        IARG_ADDRINT, instr->addr,
        IARG_END);
    if (getImgId(instr->addr) == mainImgId) {
        // record jumps
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordJump,
            IARG_UINT64, instr->addr,
            IARG_BOOL, INS_IsCall(ins),
            IARG_BOOL, INS_IsRet(ins),
            IARG_END); 
        // record memory reads
        uint32_t memOpCount = INS_MemoryOperandCount(ins);
        for (uint32_t memOp = 0; memOp < memOpCount; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                // predicated means the function is not called
                // if the predicate (e.g. for movcc) is false.
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)recordMemRead,
                    IARG_PTR, instr,
                    IARG_MEMORYOP_EA, memOp, 
                    IARG_MEMORYREAD_SIZE,
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

void dumpInstrList()
{
    for (auto it = instrList.begin(); it != instrList.end(); it++) {
        Instruction* instr = it->second;
        if (getImgId(instr->addr) == mainImgId) {
            if (instr->bytecodeReadCount > 0) {
                fprintf(codeDumpFile, ">>>%u>>> ", instr->bytecodeReadCount);
            }
            fprintf(codeDumpFile, "0x%lx: [%u] %s\n", 
                instr->addr, instr->execCount, instr->disassembly.c_str());
        }
    }
}

void dumpTrace()
{
    for (auto trace : instrTrace) {
        fprintf(traceDumpFile, "0x%lx\n", trace.addr);
    }
}

bool isPossibleFetch(BasicBlock* bb)
{
    for (auto instr : bb->instrs) {
        if (instr->opcode == XED_ICLASS_MOVZX) {
            return true;
        }
    }
    return false;
}

std::vector<Instruction*> getFetch()
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
    cfg->filterBBs(9000, 400);
    cfg->checkIntegrity(false);
    //cfg->mergeBlocks();
    //cfg->checkIntegrity(false);
    cfg->writeDotGraph(cfgDotFile);

    std::vector<std::vector<Instruction*>> fetchBBs;
    for (auto bb : cfg->getBasicBlocks()) {
        if (isPossibleFetch(bb)) {
            fetchBBs.push_back(bb->instrs);
        }
    }
    printf("[+] Possible fetches :\n");
    for (auto bb : fetchBBs) {
        printf("\t<<\n");
        for (auto instr : bb) {
            printf("\t0x%lx: %s (%u)\n", instr->addr, instr->disassembly.c_str(), instr->opcode);
        }
        printf("\t>>\n");
    }
    if (fetchBBs.size() == 1) {
        return fetchBBs[0];
    }
    panic("Didn't find the python bytecode fetch.");
    return std::vector<Instruction*>();
}

// called by PIN at the end of the program.
// we can't write to stdout here since stdout might
// have been closed.
void finiCallback(int code, void* v)
{
    removeDeadInstrs();
    dumpInstrList();
    dumpMemReads(memReadFile);
    dumpTrace();

    // get the fetch
    auto fetch = getFetch();

    // close the log files
    fclose(codeDumpFile);
    fclose(imgFile);
    fclose(cfgDotFile);
    fclose(memReadFile);
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
    memReadFile = fopen((outputFolder + "mem_reads").c_str(), "w");
    traceDumpFile = fopen((outputFolder + "traceDump").c_str(), "w");

    // add PIN callbacks
    INS_AddInstrumentFunction(insCallback, 0);
    //IMG_AddInstrumentFunction(imgMemCallback, 0);
    IMG_AddInstrumentFunction(imgLoadCallback, 0);
    IMG_AddUnloadFunction(imgUnloadCallback, 0);
    PIN_AddFiniFunction(finiCallback, 0);
    
    PIN_StartProgram();
    return -1;
}