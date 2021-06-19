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
void increaseReadCount(uint64_t addr, uint64_t size);
void dumpMemReads(FILE* file);
void addImgRegion(ImgRegion* reg);
void searchForPyOpcodes();
void imgMemCallback(IMG img, void* v);