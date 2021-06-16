#include "cfg.h"
#include "errors.h"


Jump::Jump(uint64_t fromAddr_, uint64_t toAddr_)
{
    fromAddr = fromAddr_;
    toAddr = toAddr_;
}

// DON'T make this inline (compilation errors...)
bool operator<(const Jump& A, const Jump& B)
{
    return A.fromAddr < B.fromAddr ||  (A.fromAddr == B.fromAddr && A.toAddr < B.toAddr);
}

CFG::CFG(const std::vector<Instruction*>& instructions,
    const std::map<Jump, uint32_t>& jumps)
{ 
    std::map<uint64_t, std::vector<uint64_t>> jumpsFromAddr;
    std::map<uint64_t, BasicBlock*> bbByFirstAddr;

    // calculate jumps from each address
    for (auto it = jumps.begin(); it != jumps.end(); it++) {
        uint64_t from = it->first.fromAddr;
        uint64_t to = it->first.toAddr;
        jumpsFromAddr[from].push_back(to);
    }

    // construct trivial basic blocks
    for (auto instr : instructions) {
        BasicBlock* bb = new BasicBlock();
        bb->instrs.push_back(instr);

        bbList.push_back(bb);
        bbByFirstAddr[instr->addr] = bb;
    }
    
    // link the basic blocks
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        uint64_t addr = it->first;
        BasicBlock* bb = it->second;
        for (uint64_t toAddr : jumpsFromAddr[addr]) {
            assert(jumps.find(Jump(addr, toAddr)) != jumps.end());
            bb->nextBBs.push_back(bbByFirstAddr[toAddr]);
        }
    }
}


