#pragma once
#include <stdint.h>
#include <string>


uint8_t opcodeFromBytecode(uint16_t instr);
uint8_t argFromBytecode(uint16_t instr);
std::string opcodeName(uint8_t opcode);