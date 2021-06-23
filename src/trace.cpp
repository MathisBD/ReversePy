#include "trace.h"
#include <sstream>


MemoryAccess::MemoryAccess(uint64_t addr_, uint64_t size_, uint64_t value_)
    : addr(addr_), size(size_), value(value_)
{
}

std::string MemoryAccess::toJson() const 
{
    std::stringstream ss;
    ss  << std::hex << "{ "
        << "\"addr\": \""     << addr     << "\", "
        << "\"size\": \""     << size     << "\", "
        << "\"value\": \""    << value    << "\" }";
    return ss.str();
}

std::string regsToJson(const std::map<std::string, uint64_t>& regs)
{
    std::stringstream ss;
    ss << std::hex << "{ ";
    size_t i = 0;
    for (auto it = regs.begin(); it != regs.end(); it++) {
        std::string name = it->first;
        uint64_t val = it->second;
        if (i > 0) {
            ss << ", ";
        }
        ss << "\"" << name << "\": \"" << val << "\"";
        i++;
    }
    ss << " }";
    return ss.str();
}

std::string memListToJson(const std::vector<MemoryAccess>& memList)
{
    std::stringstream ss;
    ss << "[ ";
    for (size_t i = 0; i < memList.size(); i++) {
        if (i > 0) {
            ss << ", ";
        }    
        ss << memList[i].toJson();    
    }
    ss << " ]";
    return ss.str();
}

std::string opcodesToJson(const std::vector<uint8_t>& opcodes)
{
    std::stringstream ss;
    ss << std::hex << "[ ";
    for (size_t i = 0; i < opcodes.size(); i++) {
        if (i > 0) {
            ss << ", ";
        }
        // we have to convert because uint8_t is treated as a char
        // by streams.
        ss << "\"" << (uint32_t)(opcodes[i]) << "\"";
    }
    ss << " ]";
    return ss.str();
}

std::string TraceElement::toJson() const 
{
    std::stringstream ss;
    ss  << "{ "
        << "\"opcodes\": "  << opcodesToJson(opcodes)   << ", "
        << "\"regs\": "     << regsToJson(regs)         << ", "
        << "\"reads\": "    << memListToJson(reads)     << ", "
        << "\"writes\": "   << memListToJson(writes)    << " }";
    return ss.str();
}
