#pragma once
#include <map>
#include <stdint.h>
#include <vector>
#include <string>

class MemoryAccess
{
public:
    uint64_t addr;
    uint64_t size;
    uint64_t value;

    MemoryAccess(uint64_t addr_, uint64_t size_, uint64_t value_);

    std::string toJson() const;
};

class TraceElement
{
public:
    // x86 opcodes of the instruction
    std::vector<uint8_t> opcodes;
    // list of register contents (by name: e.g. "rax")
    // before the instruction is executed
    std::map<std::string, uint64_t> regs;
    // the memory read from by the instruction
    std::vector<MemoryAccess> reads;
    // the memory written to by the instruction
    std::vector<MemoryAccess> writes;

    std::string toJson() const;
};
