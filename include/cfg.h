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

class CFG
{
public:
    // creates a basic block for each single instruction
    CFG(const std::vector<uint32_t>& instructions);
    // merge basic blocks according to a given execution trace.
    // addressTrace : addresses of all successive instructions executed.
    mergeBBs(const std::vector<uint64_t> addressTrace);
    writeDotGraph(FILE* file);
private:
    std::map<uint64_t, BasicBlock*> bblByFirstAddr;
};