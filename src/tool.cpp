#include <map>
#include <string>
#include <stdio.h>
#include <sys/syscall.h>

#include "errors.h"
#include "cfg.h"
#include "pin.H"

class ImgRegion
{
public:
    uint64_t startAddr;
    uint64_t endAddr;
    uint32_t imgId;
};

static std::vector<ImgRegion*> imgRegions;

KNOB< std::string > outputFolderKnob(KNOB_MODE_WRITEONCE, "pintool", "o", "output", "specify output folder name");
static FILE* codeDumpFile;
static FILE* cfgDotFile;
static FILE* imgFile;
static FILE* memReadFile;

// initialize this to some illegal value (not 0, not a small integer).
static uint32_t mainImgId = 999999;

static std::map<uint64_t, Instruction*> instrList;
static std::map<Jump, uint32_t> jumps;
static uint64_t prevAddr = 0;

// is the interpreted program (e.g. prog.py) running ? 
static bool progRunning = false; 

// counts number of reads at each memory address
static std::map<uint64_t, uint32_t> memReadCount;


// returns 0 for an unknown image ID
uint32_t getImgId(uint64_t addr)
{
    for (auto reg : imgRegions) {
        if (reg->startAddr <= addr && addr <= reg->endAddr) {
            return reg->imgId;
        }
    }
    return 0;
}

std::vector<uint64_t> searchBytes(uint8_t* bytes, uint64_t n, const std::vector<ImgRegion*>& regions)
{
    std::vector<uint64_t> res;
    for (ImgRegion* reg : regions) {
        printf("searching in 0x%lx -> 0x%lx\n", reg->startAddr, reg->endAddr);
        for (uint64_t addr = reg->startAddr; addr+n-1 <= reg->endAddr; addr++) {
            if (!memcmp(bytes, (uint8_t*)addr, n)) {
                res.push_back(addr);
            }
        }
    }
    return res;
}

// called each time we execute any instruction
// (before we actually execute it).
void increaseExecCount(Instruction* instr) 
{
    //fprintf(addrDumpFile, "0x%lx: <%u> %s\n",
    //    instr->addr, getImgId(instr->addr), instr->disassembly.c_str());
    (instr->execCount)++;
}

// called each time we execute a selected instruction
// (before we actually execute it).
void recordJump(uint64_t addr)
{
    jumps[Jump(prevAddr, addr)]++;
    prevAddr = addr;
}

void searchBytecode()
{
    uint8_t bytes[] = {
        0x65, 0x64, 0x64
    };
    std::vector<ImgRegion*> mainImgRegions;
    for (auto reg : imgRegions) {
        if (reg->imgId == mainImgId) {
            mainImgRegions.push_back(reg);
        }
    }
    auto positions = searchBytes(bytes, sizeof(bytes), mainImgRegions);
    for (uint64_t pos : positions) {
        printf("pos=0x%lx -> ", pos);
        for (uint64_t i = 0; i < 8; i++) {
            printf("%x ", *(uint8_t*)(pos + i));
        }
        printf("\n");
    }
    if (positions.size() == 0) {
        printf("didn't find a position\n");
    }
}

void dumpMemReads()
{
    // print areas of memory we accessed a lot 
    uint32_t memThreshold = 5000;
    
    uint64_t prevBigRead = 0;
    for (auto it = memReadCount.begin(); it != memReadCount.end(); it++) {
        uint64_t addr = it->first;
        uint32_t count = it->second;
        if (count >= memThreshold) {
            if (addr != prevBigRead + 1) {
                fprintf(memReadFile, "\n");
            }
            fprintf(memReadFile, "0x%lx: [%u] %x\n", addr, count, *(uint8_t*)addr);
            prevBigRead = addr;
        }
    }
}

void syscallEntry(ADDRINT scNum, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
    ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
    if (scNum == SYS_openat && !strcmp((char*)arg1, "tototo")) {
        progRunning = true;
        searchBytecode();
    }
    if (scNum == SYS_openat && !strcmp((char*)arg1, "tototo_after")) {
        progRunning = false;
        dumpMemReads();
    }
}

void recordMemoryRead(ADDRINT addr, UINT32 size, void* v)
{
    for (uint32_t i = 0; i < size; i++) {
        memReadCount[addr + i]++;
    }
}


// called by PIN each time we encounter an instruction for 
// the first time (and before we execute this instruction).
// WEIRDLY, pin can call this several times for the same instruction,
// and can call it for an instruction that will never be executed.
// WEIRDLIER, I have to call INS_InsertCall() each time this function is 
// executed on a given instruction, not just the first time.
void insPinCallback(INS ins, void* v)
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
    // only do the rest if the program is running
    if (!progRunning) {
        return;
    }
    Instruction* instr;
    auto it = instrList.find(INS_Address(ins));
    if (it == instrList.end()) {
        instr = new Instruction();
        instr->addr = INS_Address(ins);
        instr->size = INS_Size(ins);
        instr->execCount = 0;
        instr->disassembly = INS_Disassemble(ins);    
        // save a pointer to the instruction
        instrList[instr->addr] = instr;
    }
    else {
        instr = it->second;
    }
    // I have to call this every time, not only if we just created instr.
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)increaseExecCount, IARG_PTR, instr, IARG_END);
    if (getImgId(instr->addr) == mainImgId) {
        // record jumps
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordJump,
            IARG_UINT64, instr->addr, 
            IARG_END);
        // record memory reads
        uint32_t memOpCount = INS_MemoryOperandCount(ins);
        for (uint32_t memOp = 0; memOp < memOpCount; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                // predicated means the function is not called
                // if the predicate (e.g. for movcc) is false.
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)recordMemoryRead,
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
            fprintf(codeDumpFile, "0x%lx: [%u] %s\n", 
                instr->addr, instr->execCount, instr->disassembly.c_str());
        }
    }
}


void dumpCFG()
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
    cfg->filterBBs(9000, 4000);
    // exec counts now don't mean anything
    cfg->checkIntegrity(false);
    //cfg->mergeBlocks();
    cfg->checkIntegrity(false);
    cfg->writeDotGraph(cfgDotFile);

    fprintf(codeDumpFile, "Basic block count : %lu\n", cfg->getBasicBlocks().size());
}

// called by PIN at the end of the program.
// we can't write to stdout here since stdout might
// have been closed.
void finiPinCallback(int code, void* v)
{
    removeDeadInstrs();
    dumpInstrList();
    dumpCFG();
   
    // close the log files
    fclose(codeDumpFile);
    fclose(imgFile);
    fclose(cfgDotFile);
    fclose(memReadFile);
}

void imgLoadCallback(IMG img, void* v)
{
    fprintf(imgFile, "Loading %s, ID=%u\n", IMG_Name(img).c_str(), IMG_Id(img));
    for (uint32_t i = 0; i < IMG_NumRegions(img); i++) {
        ImgRegion* reg = new ImgRegion();
        reg->startAddr = IMG_RegionLowAddress(img, i);
        reg->endAddr = IMG_RegionHighAddress(img, i);
        reg->imgId = IMG_Id(img);
        imgRegions.push_back(reg);
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
    
    // add PIN callbacks
    INS_AddInstrumentFunction(insPinCallback, 0);
    IMG_AddInstrumentFunction(imgLoadCallback, 0);
    IMG_AddUnloadFunction(imgUnloadCallback, 0);
    PIN_AddFiniFunction(finiPinCallback, 0);
    
    PIN_StartProgram();
    return -1;
}