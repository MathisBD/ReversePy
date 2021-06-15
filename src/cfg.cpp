#include "cfg.h"
#include "panic.h"

Instruction::Instruction()
{
    addr = 0;
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
    instr->disassembly = INS_Disassemble(ins);
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
            panic("no jumps from address 0x%lx\n", bb->lastInstrAddr);
        }
        if (nextAddrs->second.size() > 1) {
            break;
        }
        uint64_t nextAddr = nextAddrs->second[0];

        // check we are the only previous address
        auto prevAddrs = jumpsToAddr.find(nextAddr);
        if (prevAddrs == jumpsToAddr.end() || prevAddrs->second.size() == 0) {
            panic("no jumps to address 0x%lx\n", nextAddr);
        }
        if (prevAddrs->second.size() > 1) {
            break;
        }

        // get the next block
        auto nextBbIt = bbByFirstAddr.find(nextAddr);
        if (nextBbIt == bbByFirstAddr.end()) {
            panic("didn't find block starting at address 0x%lx\n", nextAddr);
        }
        BasicBlock* nextBb = nextBbIt->second;

        // merge with the next block
        for (auto it = nextBb->instrs.begin(); it != nextBb->instrs.end(); it++) {
            bb->instrs.insert(std::make_pair(it->first, it->second ));
        }
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
        panic("no jumps from address 0x%lx\n", bb->lastInstrAddr);
    }

    // recurse on the next blocks
    for (uint64_t addr : nextAddrs->second) {
        auto it = bbByFirstAddr.find(addr);
        if (it == bbByFirstAddr.end()) {
            panic("didn't find block starting at address 0x%lx\n", addr);
        }
        BasicBlock* nextBb = it->second;
        bb->nextBlocks.push_back(nextBb);

        // recurse
        if (!nextBb->visited) {
            splitDFS(nextBb);
        }
    }
}

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
                std::vector<uint64_t>({toAddr})
            ));
        }
        else {
            fromIt->second.push_back(toAddr);
        }
        
        auto toIt = jumpsToAddr.find(toAddr);
        if (toIt == jumpsToAddr.end()) {
            jumpsToAddr.insert(std::make_pair(
                toAddr, 
                std::vector<uint64_t>({fromAddr})
            ));
        }
        else {
            toIt->second.push_back(fromAddr);
        }
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

void CFG::printBasicBlocks(FILE* file)
{
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        for (auto instrIt = bb->instrs.begin(); instrIt != bb->instrs.end(); instrIt++) {
            Instruction* instr = instrIt->second;
            fprintf(file, "0x%lx\t[%u]\t%s\n", instr->addr, instr->exec_count, instr->disassembly.c_str());
        }
        fprintf(file, "\n");
    }
}