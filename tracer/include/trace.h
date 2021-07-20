#pragma once
#include <map>
#include <stdint.h>
#include <vector>
#include <string>
#include <fstream>
#include "pin.H"
#include "cfg.h"


class MemoryAccess
{
public:
    uint64_t addr;
    uint8_t size;
    uint64_t value;

    MemoryAccess();
    MemoryAccess(uint64_t addr_, uint8_t size_, uint64_t value_);

    void toJson(std::fstream& stream) const;
};

class TraceElement
{
public:
    Instruction* instr;
    // x86 opcodes of the instruction
    std::vector<uint8_t> opcodes;
    // list of register contents
    // before the instruction is executed
    std::vector<std::pair<REG, uint64_t>> regs;
    // the memory read from by the instruction
    std::vector<MemoryAccess> reads;
    // the memory written to by the instruction
    std::vector<MemoryAccess> writes;

    void toJson(std::fstream& stream) const;
private:
    void opcodesToJson(std::fstream& stream) const;
    void regsToJson(std::fstream& stream) const;
    void readsToJson(std::fstream& stream) const;
    void writesToJson(std::fstream& stream) const;
};

class Trace
{
public:
    std::map<uint64_t, Instruction*> instrList;
    std::map<Jump, uint32_t> jumps;
    std::vector<TraceElement> completeTrace;
    CFG* cfg;

    void addElement(const TraceElement& te);
    void recordJump(uint64_t from, uint64_t to);
    Instruction* findInstr(uint64_t addr);
    void addInstr(Instruction* instr);

    void removeDeadInstrs();
    void buildCFG();
};