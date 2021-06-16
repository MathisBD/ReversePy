#include "cfg.h"
#include "errors.h"


Jump::Jump(uint64_t fromAddr_, uint64_t toAddr_)
{
    fromAddr = fromAddr_;
    toAddr = toAddr_;
}

// DON'T make this inline (linking errors...)
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

        bbVect.push_back(bb);
        bbByFirstAddr[instr->addr] = bb;
    }
    
    // link the basic blocks
    for (BasicBlock* bb : bbVect) {
        uint64_t addr = bb->instrs[0]->addr;
        for (uint64_t toAddr : jumpsFromAddr[addr]) {
            // It is possible that the user didn't give us all of the instructions,
            // but still gave us all the jumps. Just ignore the jumps
            // that don't lead to code we have here.
            if (bbByFirstAddr.find(toAddr) != bbByFirstAddr.end()) {
                bb->nextBBs.push_back(bbByFirstAddr[toAddr]);
            }
        }
    }
}

void CFG::resetDfsStates()
{
    for (BasicBlock* bb : bbVect) {
        bb->dfsState = DFS_UNVISITED;
    }
}

void CFG::dotDFS(FILE* file, BasicBlock* bb)
{
    bb->dfsState = DFS_VISITED;

    // use the bb address as a unique identifier
    fprintf(file, "\t%lu[ label=\"", (uint64_t)bb);
    for (auto instr : bb->instrs) {
        fprintf(file, "0x%lx: %s\\l", instr->addr, instr->disassembly.c_str());
    }
    fprintf(file, "\" ]\n");

    for (auto nextBB : bb->nextBBs) {
        fprintf(file, "\t%lu -> %lu\n", (uint64_t)bb, (uint64_t)nextBB);
        if (nextBB->dfsState == DFS_UNVISITED) {
            dotDFS(file, nextBB);
        }
    }
}

void CFG::writeDotGraph(FILE* file)
{
    fprintf(file, "digraph {\n");
    fprintf(file, "\tsplines=ortho\n");
    fprintf(file, "\tnode[ shape=box ]\n");

    resetDfsStates();
    for (auto bb : bbVect) {
        if (bb->dfsState == DFS_UNVISITED) {
            dotDFS(file, bb);
        }
    }

    fprintf(file, "}\n");
}

