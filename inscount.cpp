#include "pin.h"
#include <stdint.h>
#include <stdio.h>

uint32_t count = 0;

void on_instruction()
{
    count++;
}

void Instruction(INS ins, void* v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)on_instruction, IARG_END);
}

void Fini(INT32 code, void* v)
{
    std::cerr << "cout" << icount << std::endl;
}

int main(int argc, char* argv[])
{
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return -1;
}