#include <map>
#include <string>
#include <stdio.h>

#include "cfg.h"
#include "pin.H"


KNOB< std::string > outputFolderKnob(KNOB_MODE_WRITEONCE, "pintool", "o", "output", "specify output folder name");
static FILE* codeDumpFile;
static std::map<uint64_t, Instruction*> instrList;
static std::map<Jump, uint32_t> jumps;
static uint64_t prevAddr = 0;

// called each time we execute an instruction
// (before we actually execute it).
void insExecuted(Instruction* instr)
{
    (instr->execCount)++;
    jumps[Jump(prevAddr, instr->addr)]++;
    prevAddr = instr->addr;
}

// called by PIN each time we encounter an instruction for 
// the first time (and before we execute this instruction).
// WEIRD BEHAVIOUR: this callback is sometimes called on instructions
// we will never execute, e.g. on the first few instructions under a conditional jump.
void insPinCallback(INS ins, void* v)
{
    if (INS_IsNop(ins)) {
        return;
    }
    Instruction* instr = new Instruction();
    instr->addr = INS_Address(ins);
    instr->size = INS_Size(ins);
    instr->execCount = 0;
    instr->disassembly = INS_Disassemble(ins);
    // save a pointer to the instruction
    instrList[instr->addr] = instr;

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)insExecuted,
        IARG_PTR, instr, IARG_END);
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
        fprintf(codeDumpFile, "0x%lx: [%u] %s\n", 
            instr->addr, instr->execCount, instr->disassembly.c_str());
    }
}

// called by PIN at the end of the program.
// we can't write to stdout here since stdout might
// have been closed.
void finiPinCallback(int code, void* v)
{
    removeDeadInstrs();
    dumpInstrList();

    std::vector<Instruction*> instrVect;
    for (auto it = instrList.begin(); it != instrList.end(); it++) {
        instrVect.push_back(it->second);
    }
    CFG* cfg = new CFG(instrVect, jumps);

    // close the log files
    fclose(codeDumpFile);
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
    
    // add PIN callbacks
    INS_AddInstrumentFunction(insPinCallback, 0);
    //IMG_AddInstrumentFunction(ImageLoad, 0);
    //IMG_AddUnloadFunction(ImageUnload, 0);
    PIN_AddFiniFunction(finiPinCallback, 0);

    PIN_StartProgram();
    return -1;
}