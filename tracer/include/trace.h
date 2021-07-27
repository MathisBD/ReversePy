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
    // BEWARE : for write this is the value before the write,
    // not the value we write
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

    // if allRegs is false, only include the value of %rip
    void toJson(std::fstream& stream, bool allRegs) const;
private:
    void opcodesToJson(std::fstream& stream) const;
    void regsToJson(std::fstream& stream, bool allRegs) const;
    void readsToJson(std::fstream& stream) const;
    void writesToJson(std::fstream& stream) const;
};

class Trace
{
public:
    // instructions by address
    std::map<uint64_t, Instruction*> instrList;
    // the number of times each jump is taken
    std::map<Jump, uint32_t> jumps;
    std::vector<TraceElement> completeTrace;
    CFG* cfg;

    // address of the dispatch instruction (usually jmp %register)
    uint64_t dispatch;
    // address of all the fetch instructions (usually a movzxw or several movzwb)
    std::vector<uint64_t> fetches; 

    void addElement(const TraceElement& te);
    void recordJump(uint64_t from, uint64_t to);
    Instruction* findInstr(uint64_t addr) const;
    void addInstr(Instruction* instr);

    bool isFetch(uint64_t addr) const;

    void removeDeadInstrs();
    void buildCFG();
};