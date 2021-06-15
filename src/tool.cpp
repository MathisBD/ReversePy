#include <stdint.h>
#include <iostream>
#include <stdio.h>
#include <sys/syscall.h>
#include <vector> 
#include <utility>
#include <map>
#include <sys/stat.h>
#include <set>

#include "cfg.h"
#include "panic.h"
#include "pin.H"

class ImgRegion
{
public:
    uint64_t start;
    uint64_t end;
    uint32_t img_id; // zero value means unknown image id
    ImgRegion() {}
};


// the interpreted program (not the instrumented program)
static const char* interpProgName = "prog.py";

KNOB< std::string > outputFolderKnob(KNOB_MODE_WRITEONCE, "pintool", "o", "output", "specify output folder name");
static FILE* syscallFile;
static FILE* metricsFile;
static FILE* codeDumpFile;
static FILE* imgFile;
FILE* errorFile; // this is not static : other source files might need to write here

static uint32_t mainImgId;   // image id of the main executable
static bool openedProg = true; // did we open the interpreted program yet ?
static bool foundFloatIns = false;

static CFG cfg;
static std::set<std::pair<uint64_t, uint64_t>> jumps;
static uint64_t prevAddr;

// memory regions that contain a program image
static std::vector<ImgRegion*> imgRegions;

std::string syscall_name(int syscallNum)
{
    switch(syscallNum) {
#define syscode(x) case x: return #x;
    syscode(SYS_read);
    syscode(SYS_write);
    syscode(SYS_open);
    syscode(SYS_close);
    syscode(SYS_exit);
    syscode(SYS_mmap);
    syscode(SYS_mprotect);
    syscode(SYS_stat);
    syscode(SYS_fstat);
    syscode(SYS_lstat);
    syscode(SYS_poll);
    syscode(SYS_lseek);
    syscode(SYS_munmap);
    syscode(SYS_brk);
    syscode(SYS_rt_sigaction);
    syscode(SYS_rt_sigprocmask);
    syscode(SYS_rt_sigreturn);
    syscode(SYS_ioctl);
    syscode(SYS_pipe);
    syscode(SYS_select);
    syscode(SYS_dup);
    syscode(SYS_sigaltstack);
    syscode(SYS_exit_group);
    syscode(SYS_getcwd);
    syscode(SYS_readlink);
    syscode(SYS_fcntl);
    syscode(SYS_getdents64);
    syscode(SYS_openat);
    syscode(SYS_pread64);
    syscode(SYS_access);
    default: return "";
    }
}

// returns the image id of the image containing the address.
// returns 0 if no image contains it.
uint32_t findImgId(uint64_t addr)
{
    for (ImgRegion* reg : imgRegions) {
        if (reg->start <= addr && addr <= reg->end) {
            return reg->img_id;
        }
    }
    return 0;
}

/*void process_ins(uint64_t ip, std::string insDis, uint32_t insImgId)
{
    if (!openedProg) {
        return;
    }

    if (insImgId != last_inst_img_id) {
        if (last_inst_img_id != main_img_id) {
            fprintf(outFile, "%u\t%ld\n", last_inst_img_id, consInsCount);
        }
        consInsCount = 0;
        last_inst_img_id = insImgId;
    }
    
    consInsCount++;
    img_inst_count[insImgId]++;

    if (insImgId == main_img_id) {
        fprintf(outFile, "%lx\t%s\n", ip, insDis.c_str());
    }
}*/

void process_syscall(ADDRINT sNum, ADDRINT sArg0, ADDRINT sArg1, ADDRINT sArg2,
    ADDRINT sArg3, ADDRINT sArg4, ADDRINT sArg5)
{
    if (sNum == SYS_openat && !strcmp((char*)sArg1, interpProgName)) {
        openedProg = true;
    }
    if (!openedProg) {
        return;
    }

    fprintf(syscallFile, "[syscall] %s : %ld(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n", 
        syscall_name(sNum).c_str(),
        (long)sNum,
        (unsigned long)sArg0,
        (unsigned long)sArg1,
        (unsigned long)sArg2,
        (unsigned long)sArg3,
        (unsigned long)sArg4,
        (unsigned long)sArg5
    );
    if (sNum == SYS_openat) {
        fprintf(syscallFile, "\tfile=%s\n", (char*)sArg1);
    }
}

/*void process_syscall_ret(ADDRINT ret)
{
    if (!openedProg) {
        return;
    }
    fprintf(outFile, "\tsysret=0x%lx\n", (unsigned long)ret);
}

void syscallExit(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD sysStd, VOID* v)
{
    process_syscall_ret(PIN_GetSyscallReturn(ctx, sysStd));
}*/

void insExecuted(Instruction* instr, ADDRINT addr)
{
    instr->exec_count++;
    jumps.insert(std::make_pair(prevAddr, (uint64_t)addr));
    prevAddr = (uint64_t)addr;
}

void InstrumentIns(INS ins, void* v)
{
    if (INS_IsNop(ins)) {
        return;
    }
    uint32_t imgId = findImgId(INS_Address(ins));
    if (openedProg && imgId == mainImgId) {
        if (INS_Opcode(ins) == XED_ICLASS_DIVSD) {
            foundFloatIns = true;
        }
        Instruction* instr = new Instruction();
        instr->addr = INS_Address(ins);
        instr->size = INS_Size(ins);
        instr->disassembly = INS_Disassemble(ins);
        instr->afterFloatIns = foundFloatIns;
        cfg.addInstruction(instr);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)insExecuted,
            IARG_PTR, instr, 
            IARG_ADDRINT, INS_Address(ins),
            IARG_END);
    }

    if (INS_IsSyscall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)process_syscall,
            IARG_SYSCALL_NUMBER,
            IARG_SYSARG_VALUE, 0,
            IARG_SYSARG_VALUE, 1,
            IARG_SYSARG_VALUE, 2,
            IARG_SYSARG_VALUE, 3,
            IARG_SYSARG_VALUE, 4,
            IARG_SYSARG_VALUE, 5,
            IARG_END);
    }
}

void ImageLoad(IMG img, void* v)
{
    fprintf(imgFile, "Loading %s, ID is %u\n", IMG_Name(img).c_str(), IMG_Id(img));
    if (IMG_IsMainExecutable(img)) {
        mainImgId = IMG_Id(img);
    }
    for (uint32_t i = 0; i < IMG_NumRegions(img); i++) {
        ImgRegion* reg = new ImgRegion();
        reg->start = IMG_RegionLowAddress(img, i);
        reg->end = IMG_RegionHighAddress(img, i);
        reg->img_id = IMG_Id(img);
        imgRegions.push_back(reg);
        fprintf(imgFile, "\tregion %lx -> %lx\n", reg->start, reg->end);
    }
}

void ImageUnload(IMG img, void* v)
{
    fprintf(imgFile, "Unloading %s\n", IMG_Name(img).c_str());
}


void Fini(int32_t code, void* v)
{
    //uint32_t freqThreshold = 1;

    cfg.splitWithJumps(jumps);
    
    uint32_t instrCount = 0;
    uint32_t bbCount = 0; 

    std::vector<BasicBlock*> bbls = cfg.getBasicBlocks();
    for (BasicBlock* bb : bbls) {
        bbCount++;
        for (Instruction* instr : bb->instrs) {
            instrCount++;
            fprintf(codeDumpFile, "0x%lx\t[%u]\t%s\n", instr->addr, instr->exec_count, instr->disassembly.c_str());
        }
        fprintf(codeDumpFile, "\n");
    }


    fprintf(metricsFile, "Main Image Distinct Instructions : %u\n", instrCount);
    fprintf(metricsFile, "Main Image Basic Block Count : %u\n", bbCount);
    fprintf(metricsFile, "Found Float Instruction : %d\n", (int)foundFloatIns);

    fclose(syscallFile);
    fclose(metricsFile);
    fclose(codeDumpFile);
    fclose(imgFile);
    fclose(errorFile);
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    PIN_Init(argc, argv);
    PIN_SetSyntaxATT();

    std::string outputFolder = outputFolderKnob.Value().c_str();
    if (outputFolder[outputFolder.size() - 1] != '/') {
        outputFolder.push_back('/');
    }
    imgFile = fopen((outputFolder + "img_loading").c_str(), "w");
    syscallFile = fopen((outputFolder + "syscalls").c_str(), "w");
    metricsFile = fopen((outputFolder + "metrics").c_str(), "w");
    codeDumpFile = fopen((outputFolder + "code_dump").c_str(), "w");
    errorFile = fopen((outputFolder + "errors").c_str(), "w");

    //////////////////////////////////////////////

    /*CFG* cfg = new CFG();
    cfg->addInstruction(new Instruction(10, "A"));
    cfg->addInstruction(new Instruction(12, "B"));
    cfg->addInstruction(new Instruction(22, "D"));

    jumps.insert(std::make_pair(22, 10));
    jumps.insert(std::make_pair(10, 12));
    cfg->splitWithJumps(jumps);
    cfg->printBasicBlocks(codeDumpFile);
    
    fclose(syscallFile);
    fclose(metricsFile);
    fclose(codeDumpFile);
    fclose(imgFile);
    fclose(errorFile);
    return 0;*/
    /////////////////////////////////////////////

    INS_AddInstrumentFunction(InstrumentIns, 0);
    //PIN_AddSyscallExitFunction(syscallExit, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    IMG_AddUnloadFunction(ImageUnload, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return -1;
}