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
    id = 0;
}


CFG::CFG()
{
    nextBbId = 0;
}

void CFG::addInstruction(Instruction* instr)
{
    // create a trivial basic block containing only this instruction
    BasicBlock* bb = new BasicBlock(instr);
    bb->id = nextBbId++;
    bbByFirstAddr.insert(std::make_pair(instr->addr, bb));
}

void CFG::pruneDFS(BasicBlock* bb)
{
    bb->dfsState = DFS_VISITED;

    for (auto it = bb->nextBlocks.begin(); it != bb->nextBlocks.end(); ) {
        if ((*it)->instrs[0]->exec_count == 0) {
            bb->nextBlocks.erase(it++);
        }
        else {
            it++;
        }
    }
    for (BasicBlock* nextBb : bb->nextBlocks) {
        if (nextBb->dfsState == DFS_UNVISITED) {
            pruneDFS(nextBb);
        }
    }
}

void CFG::pruneDeadCode()
{
    // remove all instructions we didn't execute
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); ) {
        BasicBlock* bb = it->second;
        if (bb->instrs[0]->exec_count == 0) {
            bbByFirstAddr.erase(it++);
        }
        else {
            it++;
        }
    }
    // set all nodes to unvisited
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        bb->dfsState = DFS_UNVISITED;
    }
    // visit every node
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        if (bb->dfsState == DFS_UNVISITED) {
            pruneDFS(bb);
        }
    }
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
    // set all nodes to unvisited
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        bb->dfsState = DFS_UNVISITED;
    }
    // visit every node
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


void CFG::dotDFS(FILE* file, BasicBlock* bb)
{
    bb->dfsState = DFS_VISITED;

    if (bb->instrs[0]->exec_count > 0) {
        fprintf(file, "\t%u [ label=\"", bb->id);
        for (auto instr : bb->instrs) {
            fprintf(file, "[%u] %s\\n", 
                instr->exec_count, instr->disassembly.c_str());
        }
        fprintf(file, "\"]\n");
    }

    for (auto nextBb : bb->nextBlocks) {
        if (bb->instrs[0]->exec_count > 0 && nextBb->instrs[0]->exec_count > 0) {
            fprintf(file, "\t%u -> %u\n", bb->id, nextBb->id);
        }
        if (nextBb->dfsState == DFS_UNVISITED) {
            dotDFS(file, nextBb);
        }
    }
}

void CFG::writeDotGraph(FILE* file)
{
    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        bb->dfsState = DFS_UNVISITED;
    }

    fprintf(file, "digraph {\n");
    fprintf(file, "\tnode [ shape=box ]\n");

    for (auto it = bbByFirstAddr.begin(); it != bbByFirstAddr.end(); it++) {
        BasicBlock* bb = it->second;
        if (bb->dfsState == DFS_UNVISITED) {
            dotDFS(file, bb);
        }
    }

    fprintf(file, "}\n");
}