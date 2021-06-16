#include <stdint.h>
#include <string>
#include <vector>
#include <map>

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
    std::vector<BasicBlock*> nextBBs;
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
    std::vector<BasicBlock*> bbList;
};