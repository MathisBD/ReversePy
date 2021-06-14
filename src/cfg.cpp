#include "cfg.h"

Instruction::Instruction()
{
    address = 0;
    exec_count = 0;
    size = 0;
    disassembly = "";
    afterFloatIns = false;
}

BasicBlock::BasicBlock(Instruction* firstInstr)
{
    instrs.insert({firstInstr->addr, firstInstr});
    lastInstrAddr = firstInstr->addr;
}


CFG::CFG()
{
}

Instruction* CFG::addInstruction(INS ins)
{
    Instruction* instr = new Instruction();
    instr->addr = INS_Address(ins);
    instr->disassembly = INS_Disassembly(ins);
    instr->size = INS_Size(ins);

    // create a trivial basic block containing only this instruction
    BasicBlock* bb = new BasicBlock(instr);
    bbByFirstAddr.insert({instr->addr, bb});

    return instr;
}

void CFG::mergeBlockFront(BasicBlock* bb)
{
    while (true) {
        // get the next address
        auto nextAddrs = jumpsFromAddr.find(bb->lastInstrAddr);
        if (nextAddrs == jumpsFromAddr.end() || nextAddrs->second.size() == 0) {
            // PANIC
        }
        if (nextAddrs->second.size() > 1) {
            break;
        }
        uint64_t nextAddr = nextAddrs->second[0];

        // check we are the only previous address
        auto prevAddrs = jumpsToAddr.find(nextAddr);
        if (prevAddrs == jumptToAddr.end() || prevAddrs->second.size() == 0) {
            // PANIC
        }
        if (prevAddrs->second.size() > 1) {
            break;
        }

        // get the next block
        auto nextBbIt = bbByFirstAddr.find(nextAddr);
        if (nextBbIt == bbByFirstAddr.end()) {
            // PANIC 
        }
        BasicBlock* nextBb = nextBbIt->second;

        // merge with the next block
        bb->instrs.merge(nextBb->instrs);
        bb->lastInstrAddr = nextBb->lastInstrAddr;
    }
}

void CFG::splitDFS(BasicBlock* bb)
{
    bb->visited = true;

    // first merge
    mergeBlockFront(bb);

    // get the next addresses
    auto nextAddrs = jumpsFromAddr.find(bb->lastInstrAddr);
    if (nextAddrs == jumpsFromAddr.end() || nextAddrs->second.size() == 0) {
        // PANIC
    }

    // recurse on the next blocks
    for (uint64_t addr : nextAddrs->second) {
        auto it = bbByFirstAddr.find(addr);
        if (it == bbByFirstAddr.end()) {
            // PANIC ?
        }
        BasicBlock* nextBb = it->second;
        bb->nextBlocks.push_back(nextBb);

        // recurse
        if (!nextBb->visited) {
            splitDFS(nextBb);
        }
    }
}

void CFG::splitWithJumps(const std::unordered_set<std::pair<uint64_t, uint64_t>>& jumps)
{
    jumpsFromAddr.clear();
    jumpsToAddr.clear();
    for (auto it = jumps.begin(); it != jumps.end(); it++) {
        auto from = jumpsFromAddr.find(it->first);
        if (from != jumpsFromAddr.end()) {
            from->second.push_back(it->second);
        }
        else {
            jumpsFromAddr.emplace(it->first, new std::vector({it->second}));
        }

        auto to = /////////
    }


    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        bb->visited = false;
    }
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        if (!bb->visited) {
            splitDFS(bb);
        }
    }
}