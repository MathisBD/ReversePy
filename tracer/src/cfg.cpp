#include "cfg.h"
#include "errors.h"
#include <algorithm>

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

Edge::Edge(uint32_t execCount_, BasicBlock* bb_)
{
    execCount = execCount_;
    bb = bb_;
}

bool operator==(const Edge& A, const Edge& B)
{
    return A.execCount == B.execCount && A.bb == B.bb;
}

uint64_t BasicBlock::firstAddr() const
{
    return instrs[0]->addr;
}

CFG::CFG()
{
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
            uint32_t count = jumps.find(Jump(addr, toAddr))->second;
            // It is possible that the user didn't give us all of the instructions,
            // but still gave us all the jumps. Just ignore the jumps
            // that don't lead to code we have here.
            if (bbByFirstAddr.find(toAddr) != bbByFirstAddr.end()) {
                bb->nextBBs.push_back(
                    Edge(count, bbByFirstAddr[toAddr])
                );
                bbByFirstAddr[toAddr]->prevBBs.push_back(
                    Edge(count, bb)
                );
            }
        }
    }
}

template<typename T>
bool vectContains(const std::vector<T>& vect, const T& x)
{
    return std::find(vect.begin(), vect.end(), x) != vect.end();
}

void CFG::checkIntegrity() const
{
    for (auto bb : bbVect) {
        // check block is non-empty
        if (bb->instrs.size() == 0) {
            panic("[CFG] empty basic block\n");
        }
        // check forward links
        for (auto edge : bb->nextBBs) {
            if (!vectContains(bbVect, edge.bb)) {
                panic("[CFG] didn't find basic block starting at 0x%lx\n",
                    edge.bb->firstAddr());
            }
            if (!vectContains(edge.bb->prevBBs, Edge(edge.execCount, bb))) {
                panic("[CFG] broken link between blocks starting at 0x%lx and 0x%lx\n",
                    bb->firstAddr(), edge.bb->firstAddr());
            }
        }
        // check backward links
        for (auto edge : bb->prevBBs) {
            if (!vectContains(bbVect, edge.bb)) {
                panic("[CFG] didn't find basic block starting at 0x%lx\n",
                    edge.bb->firstAddr());
            }
            if (!vectContains(edge.bb->nextBBs, Edge(edge.execCount, bb))) {
                panic("[CFG] broken link between blocks starting at 0x%lx and 0x%lx\n",
                    bb->firstAddr(), edge.bb->firstAddr());
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

std::string firstWord(const std::string& str)
{
    size_t i = str.find(' ');
    if (i == std::string::npos) {
        return str;
    }
    return str.substr(0, i);
}

bool contains(const std::vector<uint64_t>& vect, uint64_t x)
{
    for (uint64_t y : vect) {
        if (x == y) {
            return true;
        }
    }
    return false;
}

// dotty crashes if node labels are too long (it detects a stack smashing - 
// labels must be read into a stack allocated buffer without checking for size lol)
void CFG::dotDFS(FILE* file, uint32_t maxBBSize_, BasicBlock* currBB,
    const std::vector<uint64_t>& v)
{
    currBB->dfsState = DFS_VISITED;

    uint32_t maxBBSize = maxBBSize_;
    for (auto instr : currBB->instrs) {
        if (contains(v, instr->addr)) {
            maxBBSize = 1000;
            break;
        }
    }

    // use the bb struct address as a unique identifier
    fprintf(file, "\t%lu[ label=\"", (uint64_t)currBB);
    
    uint32_t prevPrinted = 0;
    for (uint32_t i = 0; i < currBB->instrs.size(); i++) {
        if (i < (maxBBSize/2) || i >= currBB->instrs.size() - (maxBBSize/2)) {
            if (i != prevPrinted + 1 && i > 0) {
                fprintf(file, ".....\\l");
            }
            //fprintf(file, "0x%lx\t(%u)\t%s\\l", currBB->instrs[i]->addr, 
            //    currBB->instrs[i]->execCount, currBB->instrs[i]->disassembly.c_str());
            fprintf(file, "%s\\l", currBB->instrs[i]->disassembly.c_str());
            prevPrinted = i;
        }
    }
    fprintf(file, "\" ]\n");

    for (auto edge : currBB->nextBBs) {
        fprintf(file, "\t%lu -> %lu\n", (uint64_t)currBB, (uint64_t)(edge.bb));
    }
    
    for (auto edge : currBB->nextBBs) {
        if (edge.bb->dfsState == DFS_UNVISITED) {
            dotDFS(file, maxBBSize_, edge.bb, v);
        }
    }

}

void CFG::writeDotHeader(FILE* file)
{
    fprintf(file, "digraph {\n");
    fprintf(file, "\tconcentrate=true\n");
    fprintf(file, "\tnode[ shape=box ]\n");
}

void CFG::writeDotFooter(FILE* file) 
{
    fprintf(file, "}\n");
}

void CFG::mergeDFS(BasicBlock* bb)
{
    bb->dfsState = DFS_VISITED;

    while (bb->nextBBs.size() == 1) {
        BasicBlock* nextBB = bb->nextBBs[0].bb;
        // the program is just a big loop
        if (nextBB == bb) {
            break;
        }
        if (nextBB->prevBBs.size() == 1) {
            // merge the next block into the current one
            for (auto instr : nextBB->instrs) {
                bb->instrs.push_back(instr);
            }
            // update forward links
            bb->nextBBs = nextBB->nextBBs;
            // CAREFUL: backward links to nextBB are no longer valid :
            // it's ok, we will reconstruct them after the DFS.
            // (we only need prevBBs.size() during the DFS, and
            // this stays correct).
            nextBB->dfsState = DFS_MERGED;
        }
        else {
            break;
        }
    }
    // recurse on the next blocks
    for (auto edge : bb->nextBBs) {
        if (edge.bb->dfsState == DFS_UNVISITED) {
            mergeDFS(edge.bb);
        }
    }
}

void CFG::mergeBlocks()
{
    // do the DFS
    resetDfsStates();
    for (auto bb : bbVect) {
        if (bb->dfsState == DFS_UNVISITED) {
            mergeDFS(bb);
        }
    }
    // delete any merged blocks
    std::vector<BasicBlock*> unmergedBBs;
    for (auto bb : bbVect) {
        if (bb->dfsState == DFS_MERGED) {
            delete bb;
        }
        else {
            unmergedBBs.push_back(bb);
        }
    }
    bbVect = unmergedBBs;
    // reconstruct backward links
    for (auto bb : bbVect) {
        bb->prevBBs.clear();
    }
    for (auto bb : bbVect) {
        for (auto edge : bb->nextBBs) {
            edge.bb->prevBBs.push_back(Edge(edge.execCount, bb));
        }
    }
}

std::vector<BasicBlock*> CFG::getBasicBlocks()
{
    return bbVect;
}

void eraseEdges(std::vector<Edge>& edges, uint32_t bbFreqThreshold, uint32_t edgeFreqThreshold)
{
    for (auto edgeIt = edges.begin(); edgeIt != edges.end();) {
        if (edgeIt->bb->instrs[0]->execCount < bbFreqThreshold ||
            edgeIt->execCount < edgeFreqThreshold) {
            edgeIt = edges.erase(edgeIt);    
        }
        else {
            edgeIt++;
        }
    }
}

void CFG::filterBBs(uint32_t bbFreqThreshold, uint32_t edgeFreqThreshold)
{
    // first remove the links
    for (auto bb : bbVect) {
        if (bb->instrs[0]->execCount >= bbFreqThreshold) {
            eraseEdges(bb->nextBBs, bbFreqThreshold, edgeFreqThreshold);
            eraseEdges(bb->prevBBs, bbFreqThreshold, edgeFreqThreshold);
        }
    }
    // then remove the basic blocks
    for (auto it = bbVect.begin(); it != bbVect.end();) {
        BasicBlock* bb = *it;
        if (bb->instrs[0]->execCount < bbFreqThreshold) {
            delete bb;
            it = bbVect.erase(it);
        }
        else {                
            it++;
        }
    }
}

CFG* CFG::deepCopy()
{
    CFG* cfg = new CFG();
    
    std::map<uint64_t, uint32_t> bbPosition;
    for (uint32_t i = 0; i < bbVect.size(); i++) {
        bbPosition[bbVect[i]->firstAddr()] = i;
    }
    // copy the instrs
    // make sure to copy the list of blocks in the same order.
    for (auto bb : bbVect) {
        BasicBlock* newBB = new BasicBlock();
        newBB->instrs = bb->instrs;
        cfg->bbVect.push_back(newBB);
    }
    // copy the edges 
    for (uint32_t i = 0; i < bbVect.size(); i++) {
        // forward edges
        for (auto edge : bbVect[i]->nextBBs) {
            auto newNextBB = cfg->bbVect[bbPosition[edge.bb->firstAddr()]];
            cfg->bbVect[i]->nextBBs.push_back(Edge(edge.execCount, newNextBB));
        }
        // backward edges 
        for (auto edge : bbVect[i]->prevBBs) {
            auto newPrevBB = cfg->bbVect[bbPosition[edge.bb->firstAddr()]];
            cfg->bbVect[i]->prevBBs.push_back(Edge(edge.execCount, newPrevBB));
        }  
    }
    return cfg;
}