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
    std::string disassembly;
};

class BasicBlock
{
public:
    std::vector<Instruction*> instrs;
    std::vector<BasicBlock*> prevBBs;
    std::vector<BasicBlock*> nextBBs;
    uint32_t dfsState;
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
private: 
    std::vector<BasicBlock*> bbVect;
    void resetDfsStates();
    void dotDFS(FILE* file, BasicBlock* bb);
    void mergeDFS(BasicBlock* bb);
};