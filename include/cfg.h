#pragma once
#include <string>
#include <stdint.h>
#include <vector>
#include <map>

#include "pin.H"


class Instruction
{
public:
    uint64_t address; // each instruction has a different, unique address
    uint32_t exec_count; // number of times this instruction was executed
    uint32_t size;  // instruction size in bytes
    
    std::string disassembly;
    bool afterFloatIns;
    
    Instruction();
};

class BasicBlock
{
public:
    std::map<uint64_t, Instruction*> instrs;
    std::vector<BasicBlock*> nextBlocks;
    uint64_t lastInstrAddr;
    bool visited; // used by the CFG to do a DFS

    BasicBlock(Instruction* firstInstr);
}

class CFG:
{
public:
    CFG();
    Instruction* addInstruction(INS ins);
    // compute basic blocks according to the following jumps.
    void splitWithJumps(const std::unordered_set<std::pair<uint64_t, uint64_t>>& jumps);
private:
    std::unordered_map<uint64_t, BasicBlock*> bbByFirstAddr;
    std::unordered_map<uint64_t, std::vector<uint64_t>> jumpsFromAddr;
    std::unordered_map<uint64_t, std::vector<uint64_t>> jumpsToAddr;

    mergeBlockFront(BasicBlock* bb);
    splitDFS(BasicBlock* bb);
};