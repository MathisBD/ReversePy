#include "cfg.h"
#include "panic.h"


#define DFS_UNVISITED   0
#define DFS_VISITED     1


Instruction::Instruction()
{
    addr = 0;
    exec_count = 0;
    size = 0;
    disassembly = "";
    afterFloatIns = false;
}

Instruction::Instruction(uint64_t addr_, const std::string& dis_)
{
    addr = addr_;
    exec_count = 0;
    size = 0;
    disassembly = dis_;
    afterFloatIns = false;

}

BasicBlock::BasicBlock(Instruction* firstInstr)
{
    instrs.push_back(firstInstr);
    lastInstrAddr = firstInstr->addr;
}


CFG::CFG()
{
}

void CFG::addInstruction(Instruction* instr)
{
    // create a trivial basic block containing only this instruction
    BasicBlock* bb = new BasicBlock(instr);
    bbByFirstAddr.insert(std::make_pair(instr->addr, bb));
}

void CFG::mergeBlockFront(BasicBlock* bb)
{
    while (true) {
        // get the next address
        auto nextAddrs = jumpsFromAddr.find(bb->lastInstrAddr);
        if (nextAddrs == jumpsFromAddr.end() && nextAddrs->second.size() == 0) {
            break;
        }
        if (nextAddrs->second.size() > 1) {
            break;
        }
        uint64_t nextAddr = nextAddrs->second[0];

        // check we are the only previous address
        auto prevAddrs = jumpsToAddr.find(nextAddr);
        if (prevAddrs == jumpsToAddr.end() || prevAddrs->second.size() == 0) {
            panic("[merge] no jumps to address 0x%lx\n", nextAddr);
        }
        if (prevAddrs->second.size() > 1) {
            break;
        }

        // get the next block
        auto nextBbIt = bbByFirstAddr.find(nextAddr);
        if (nextBbIt == bbByFirstAddr.end()) {
            panic("[merge] didn't find block starting at address 0x%lx\n", nextAddr);
        }
        BasicBlock* nextBb = nextBbIt->second;

        // merge with the next block
        for (Instruction* instr : nextBb->instrs) {
            bb->instrs.push_back(instr);
        }
        bb->lastInstrAddr = nextBb->lastInstrAddr;
        bbByFirstAddr.erase(nextBbIt);
    }
}

void CFG::splitDFS(BasicBlock* bb)
{
    bb->dfsState = DFS_VISITED;

    // first merge
    mergeBlockFront(bb);

    // get the next addresses
    auto nextAddrs = jumpsFromAddr.find(bb->lastInstrAddr);
    if (nextAddrs == jumpsFromAddr.end() || nextAddrs->second.size() == 0) {
        return;
    }

    // recurse on the next blocks
    for (uint64_t addr : nextAddrs->second) {
        auto it = bbByFirstAddr.find(addr);
        if (it == bbByFirstAddr.end()) {
            panic("[split] didn't find block starting at address 0x%lx\n", addr);
        }
        BasicBlock* nextBb = it->second;
        bb->nextBlocks.push_back(nextBb);

        // recurse
        if (nextBb->dfsState == DFS_UNVISITED) {
            splitDFS(nextBb);
        }
    }
}

/*static void printAddrVect(const std::vector<uint64_t> vect)
{   
    printf("( ");
    for (uint64_t addr : vect) {
        printf("0x%lx ", addr);
    }
    printf(")");
}*/

void CFG::splitWithJumps(const std::set<std::pair<uint64_t, uint64_t>>& jumps)
{
    jumpsFromAddr.clear();
    jumpsToAddr.clear();
    for (auto it = jumps.begin(); it != jumps.end(); it++) {
        uint64_t fromAddr = it->first;
        uint64_t toAddr = it->second;

        auto fromIt = jumpsFromAddr.find(fromAddr);
        if (fromIt == jumpsFromAddr.end()) {
            jumpsFromAddr.insert(std::make_pair(
                fromAddr, 
                std::vector<uint64_t>(1, toAddr)
            ));
        }
        else {
            fromIt->second.push_back(toAddr);
        }
        
        auto toIt = jumpsToAddr.find(toAddr);
        if (toIt == jumpsToAddr.end()) {
            jumpsToAddr.insert(std::make_pair(
                toAddr, 
                std::vector<uint64_t>(1, fromAddr)
            ));
        }
        else {
            toIt->second.push_back(fromAddr);
        }
    }

    /*auto it = jumpsFromAddr.find(10);
    if (it != jumpsFromAddr.end()) {
        printf("0x%lx -> ", 10UL);
        printAddrVect(it->second);
        printf("\n");
    }

    it = jumpsToAddr.find(12);
    if (it != jumpsToAddr.end()) {
        printAddrVect(it->second);
        printf(" -> 0x%lx\n", 12UL);
    }*/

    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        bb->dfsState = DFS_UNVISITED;
    }
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        if (bb->dfsState == DFS_UNVISITED) {
            splitDFS(bb);
        }
    }
}

std::vector<BasicBlock*> CFG::getBasicBlocks()
{
    std::vector<BasicBlock*> bbls;
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        bbls.push_back(it->second);
    }
    return bbls;
}