#pragma once
#include <stdio.h>
#include "pin.H"
#include "cfg.h"

class ImgRegion
{
public:
    uint64_t startAddr;
    uint64_t endAddr;
    uint32_t imgId;
};

extern uint32_t mainImgId;

uint32_t getImgId(uint64_t addr);
void addImgRegion(ImgRegion* reg);