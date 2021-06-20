#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <stdio.h>


#define DFS_UNVISITED   0
#define DFS_VISITED     1
#define DFS_MERGED      2

class Instruction
{
public:
    uint64_t addr;
    uint32_t size;
    uint32_t execCount;
    uint32_t bytecodeReadCount;
    std::string disassembly;
};

class Edge;

class BasicBlock
{
public:
    std::vector<Instruction*> instrs;
    std::vector<Edge> prevBBs;
    std::vector<Edge> nextBBs;
    uint32_t dfsState;

    // requires the basic block to have at least one instruction
    uint64_t firstAddr();
};

class Edge
{
public:
    uint32_t execCount;
    BasicBlock* bb;
    Edge(uint32_t execCount_, BasicBlock* bb_);
    friend bool operator==(const Edge&, const Edge&);
};

class Jump
{
public:
    uint64_t fromAddr;
    uint64_t toAddr;
    Jump(uint64_t fromAddr_, uint64_t toAddr_);
    friend bool operator<(const Jump&, const Jump&);
};

class CFG
{
public:
    CFG(const std::vector<Instruction*>& instructions, 
        const std::map<Jump, uint32_t>& jumps);
    void mergeBlocks();
    void writeDotGraph(FILE* file);
    void checkIntegrity(bool checkExecCounts);
    std::vector<BasicBlock*> getBasicBlocks();
    void filterBBs(uint32_t bbFreqThreshold, uint32_t edgeFreqThreshold);
private: 
    std::vector<BasicBlock*> bbVect;
    void resetDfsStates();
    void mergeDFS(BasicBlock* bb);
};