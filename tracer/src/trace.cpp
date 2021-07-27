#include "trace.h"
#include <iostream>
#include "errors.h"
#include "mem.h"


MemoryAccess::MemoryAccess()
{
}

MemoryAccess::MemoryAccess(uint64_t addr_, uint8_t size_, uint64_t value_)
    : addr(addr_), size(size_), value(value_)
{
}

void MemoryAccess::toJson(std::fstream& stream) const 
{
    stream << "{ "
        << "\"addr\": \""     << addr               << "\", "
        << "\"size\": \""     << (uint32_t)size     << "\", "
        << "\"value\": \""    << value              << "\" }";
}



inline void TraceElement::regsToJson(std::fstream& stream, bool allRegs) const
{
    stream << "{ ";
    // only include RIP
    if (!allRegs) {
        for (size_t i = 0; i < regs.size(); i++) {
            REG reg = regs[i].first;
            if (reg == REG_RIP) {
                std::string name = REG_StringShort(reg);
                uint64_t val = regs[i].second;
                stream << "\"" << name << "\": \"" << val << "\"";
                break;
            }
        }
    }
    // include everyone
    else {
        for (size_t i = 0; i < regs.size(); i++) {
            REG reg = regs[i].first;
            std::string name = REG_StringShort(reg);
            uint64_t val = regs[i].second;
            if (i > 0) {
                stream << ", ";
            }
            stream << "\"" << name << "\": \"" << val << "\"";
        }
    }
    stream << " }";
}

inline void TraceElement::readsToJson(std::fstream& stream) const
{
    stream << "[ ";
    for (size_t i = 0; i < reads.size(); i++) {
        if (i > 0) {
            stream << ", ";
        }    
        reads[i].toJson(stream);    
    }
    stream << " ]";
}

// BEWARE : the write['value'] is the value before the write,
// not the value we write
inline void TraceElement::writesToJson(std::fstream& stream) const
{
    stream << "[ ";
    for (size_t i = 0; i < writes.size(); i++) {
        if (i > 0) {
            stream << ", ";
        }    
        writes[i].toJson(stream);    
    }
    stream << " ]";
}

inline void TraceElement::opcodesToJson(std::fstream& stream) const 
{
    stream << "[ ";
    for (size_t i = 0; i < opcodes.size(); i++) {
        if (i > 0) {
            stream << ", ";
        }
        // we have to convert because uint8_t is treated as a char
        // by streams.
        stream << "\"" << (uint32_t)(opcodes[i]) << "\"";
    }
    stream << " ]";
}

void TraceElement::toJson(std::fstream& stream, bool allRegs) const 
{
    stream << "{ \"opcodes\": "; 
    opcodesToJson(stream); 
    if (regs.size() > 0) {
        stream << ", \"regs\": ";
        regsToJson(stream, allRegs);
    }   
    if (reads.size() > 0) {
        stream << ", \"reads\": ";
        readsToJson(stream);
    }
    if (writes.size() > 0) {
        stream << ", \"writes\": ";
        writesToJson(stream);
    }
    stream << " }";
}

void Trace::addElement(const TraceElement& te)
{
    completeTrace.push_back(te);
}

void Trace::recordJump(uint64_t from, uint64_t to)
{
    jumps[Jump(from, to)]++;
}

Instruction* Trace::findInstr(uint64_t addr) const
{
    auto it = instrList.find(addr);
    if (it == instrList.end()) {
        return nullptr;
    }
    return it->second;
}

void Trace::addInstr(Instruction* instr)
{
    instrList[instr->addr] = instr;
}

bool Trace::isFetch(uint64_t addr) const
{
    for (uint64_t fetch : fetches) {
        if (addr == fetch) {
            return true;
        }
    }
    return false;
}

void Trace::removeDeadInstrs()
{
    for (auto it = instrList.begin(); it != instrList.end();) {
        if (it->second->execCount == 0) {
            delete it->second;
            instrList.erase(it++);
        }
        else {
            it++;
        }
    }
}

void Trace::buildCFG()
{
    std::vector<Instruction*> cfgInstrs;
    for (auto it = instrList.begin(); it != instrList.end(); it++) {
        Instruction* instr = it->second;
        if (isInPythonRegion(instr->addr)) {
            cfgInstrs.push_back(instr);
        }
    }
    cfg = new CFG(cfgInstrs, jumps);
    cfg->checkIntegrity();
    cfg->mergeBlocks();
    cfg->checkIntegrity();
}
