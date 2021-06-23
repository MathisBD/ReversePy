#include "trace.h"
#include <iostream>


MemoryAccess::MemoryAccess(uint64_t addr_, uint64_t size_, uint64_t value_)
    : addr(addr_), size(size_), value(value_)
{
}

void MemoryAccess::toJson(std::fstream& stream) const 
{
    stream << "{ "
        << "\"addr\": \""     << addr     << "\", "
        << "\"size\": \""     << size     << "\", "
        << "\"value\": \""    << value    << "\" }";
}

static inline void regsToJson(const std::map<std::string, uint64_t>& regs, std::fstream& stream)
{
    stream << "{ ";
    size_t i = 0;
    for (auto it = regs.begin(); it != regs.end(); it++) {
        std::string name = it->first;
        uint64_t val = it->second;
        if (i > 0) {
            stream << ", ";
        }
        stream << "\"" << name << "\": \"" << val << "\"";
        i++;
    }
    stream << " }";
}

static inline void memListToJson(const std::vector<MemoryAccess>& memList, std::fstream& stream)
{
    stream << "[ ";
    for (size_t i = 0; i < memList.size(); i++) {
        if (i > 0) {
            stream << ", ";
        }    
        memList[i].toJson(stream);    
    }
    stream << " ]";
}

static inline void opcodesToJson(const std::vector<uint8_t>& opcodes, std::fstream& stream)
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

void TraceElement::toJson(std::fstream& stream) const 
{
    stream << "{ \"opcodes\": "; 
    opcodesToJson(opcodes, stream); 
    
    stream << ", \"regs\": ";
    regsToJson(regs, stream);
        
    stream << ", \"reads\": ";
    memListToJson(reads, stream);

    stream << ", \"writes\": ";
    memListToJson(writes, stream);
    stream << " }";
}
