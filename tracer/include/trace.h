#pragma once
#include <map>
#include <stdint.h>
#include <vector>
#include <string>
#include <fstream>
#include "pin.H"


class MemoryAccess
{
public:
    uint64_t addr;
    uint64_t size;
    uint64_t value;

    MemoryAccess();
    MemoryAccess(uint64_t addr_, uint64_t size_, uint64_t value_);

    void toJson(std::fstream& stream) const;
};

class TraceElement
{
public:
    // x86 opcodes of the instruction
    uint8_t opcodes[16];
    size_t opcodesCount;
    // list of register contents
    // before the instruction is executed
    std::pair<REG, uint64_t> regs[32];
    size_t regsCount;
    // the memory read from by the instruction
    MemoryAccess reads[16];
    size_t readsCount;

    void toJson(std::fstream& stream) const;
private:
    void opcodesToJson(std::fstream& stream) const;
    void regsToJson(std::fstream& stream) const;
    void readsToJson(std::fstream& stream) const;
};
