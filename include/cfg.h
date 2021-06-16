#pragma once
#include <string>
#include <stdint.h>
#include <vector>
#include <map>
#include <set>

#include "pin.H"


class Instruction
{
public:
    uint64_t addr; // each instruction has a different, unique address
    uint32_t exec_count; // number of times this instruction was executed
    uint32_t size;  // instruction size in bytes
    
    std::string disassembly;
    bool afterFloatIns;
    
    Instruction();
    Instruction(uint64_t addr, const std::string& dis);
};

class BasicBlock
{
public:
    std::vector<Instruction*> instrs;
    std::vector<BasicBlock*> nextBlocks;
    uint64_t lastInstrAddr;

    uint8_t dfsState; // used by the CFG to do a DFS
    uint32_t id; // used by the CFG
    std::set<BasicBlock*> reachable; // used by the CFG to prune unfrequent instructions

    BasicBlock(Instruction* firstInstr);
};

class CFG
{
public:
    CFG();
    void addInstruction(Instruction* instr);
    // compute basic blocks according to the following jumps.
    void splitWithJumps(const std::set<std::pair<uint64_t, uint64_t>>& jumps);
    std::vector<BasicBlock*> getBasicBlocks();
    void writeDotGraph(FILE* file);
    void pruneUnfrequentInstrs(uint32_t freqTheshold);
private:
    std::map<uint64_t, BasicBlock*> bbByFirstAddr;
    std::map<uint64_t, std::vector<uint64_t>> jumpsFromAddr;
    std::map<uint64_t, std::vector<uint64_t>> jumpsToAddr;
    uint32_t nextBbId;

    void mergeBlockFront(BasicBlock* bb);
    void splitDFS(BasicBlock* bb);
    void dotDFS(FILE* file, BasicBlock* bb);
    void pruneDFS(BasicBlock* org, BasicBlock* cur);
};