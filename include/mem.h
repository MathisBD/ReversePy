#pragma once

#include <stdio.h>
#include "pin.H"

class ImgRegion
{
public:
    uint64_t startAddr;
    uint64_t endAddr;
    uint32_t imgId;
};

extern uint32_t mainImgId;

uint32_t getImgId(uint64_t addr);
void recordMemoryRead(ADDRINT addr, UINT32 size, void* v);
void dumpMemReads(FILE* file);
void addImgRegion(ImgRegion* reg);
void searchForPyOpcodes();
void imgMemCallback(IMG img, void* v);