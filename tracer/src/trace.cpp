#include "trace.h"
#include <iostream>
#include "errors.h"


MemoryAccess::MemoryAccess()
{
}

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

inline void TraceElement::regsToJson(std::fstream& stream) const
{
    stream << "{ ";
    for (size_t i = 0; i < regsCount; i++) {
        REG reg = regs[i].first;
        std::string name = REG_StringShort(reg);
        uint64_t val = regs[i].second;
        if (i > 0) {
            stream << ", ";
        }
        stream << "\"" << name << "\": \"" << val << "\"";
    }
    stream << " }";
}

inline void TraceElement::readsToJson(std::fstream& stream) const
{
    stream << "[ ";
    for (size_t i = 0; i < readsCount; i++) {
        if (i > 0) {
            stream << ", ";
        }    
        reads[i].toJson(stream);    
    }
    stream << " ]";
}

inline void TraceElement::opcodesToJson(std::fstream& stream) const 
{
    stream << "[ ";
    for (size_t i = 0; i < opcodesCount; i++) {
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
    opcodesToJson(stream); 
    if (regsCount > 0) {
        stream << ", \"regs\": ";
        regsToJson(stream);
    }   
    if (readsCount > 0) {
        stream << ", \"reads\": ";
        readsToJson(stream);
    }
    stream << " }";
}
