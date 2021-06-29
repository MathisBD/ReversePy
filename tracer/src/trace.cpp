#include "trace.h"
#include <iostream>
#include "errors.h"


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

inline void TraceElement::regsToJson(std::fstream& stream) const
{
    stream << "{ ";
    for (size_t i = 0; i < regs.size(); i++) {
        std::string name = REG_StringShort((REG)(regs[i].first));
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
    for (size_t i = 0; i < reads.size(); i++) {
        if (i > 0) {
            stream << ", ";
        }    
        reads[i].toJson(stream);    
    }
    stream << " ]";
}

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

void TraceElement::toJson(std::fstream& stream) const 
{
    stream << "{ \"opcodes\": "; 
    opcodesToJson(stream); 
    if (regs.size() > 0) {
        stream << ", \"regs\": ";
        regsToJson(stream);
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
