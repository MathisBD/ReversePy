#include "pin.H"
#include <stdint.h>
#include <iostream>
#include <fstream>

std::ofstream outFile;
KNOB< std::string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify file output name");


static uint64_t count = 0;

void on_instruction()
{
    count++;
}

void Instruction(INS ins, void* v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)on_instruction, IARG_END);
}

void Fini(int32_t code, void* v)
{
    outFile.setf(std::ios::showbase);
    outFile << "Count=" << count << std::endl;
    outFile.close();
}

int main(int argc, char* argv[])
{
    PIN_Init(argc, argv);
    
    outFile.open(KnobOutputFile.Value().c_str());
    
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return -1;
}