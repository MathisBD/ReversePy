#include "bytecode.h"



uint8_t opcodeFromBytecode(uint16_t instr)
{
    return instr & 0xFF;
}

uint8_t argFromBytecode(uint16_t instr)
{
    return instr >> 8;
}

// list pulled from https://github.com/python/cpython/blob/3.8/Lib/opcode.py
std::string opcodeName(uint8_t opcode)
{
    switch (opcode) {
    case 0x01: return "POP_TWO";
    case 0x0b: return "UNARY_NEGATIVE";
    case 0x16: return "BINARY_MODULO";
    case 0x17: return "BINARY_ADD";
    case 0x18: return "BINARY_SUBSTRACT";
    case 0x19: return "BINARY_SUBSCR";
    case 0x3e: return "BINARY_LSHIFT";
    case 0x3f: return "BINARY_RSHIFT";
    case 0x40: return "BINARY_AND";
    case 0x41: return "BINARY_XOR";
    case 0x42: return "BINARY_OR";
    case 0x43: return "INPLACE_POWER";
    case 0x44: return "GET_ITER";
    case 0x51: return "WITH_CLEANUP_START";
    case 0x53: return "RETURN_VALUE";
    case 0x57: return "POP_BLOCK";
    case 0x5a: return "STORE_NAME";
    case 0x5d: return "FOR_ITER";
    case 0x5f: return "STORE_ATTR";
    case 0x64: return "LOAD_CONST";
    case 0x65: return "LOAD_NAME";
    case 0x6a: return "LOAD_ATTR";
    case 0x6b: return "COMPARE_OP";
    case 0x6e: return "JUMP_FORWARD";
    case 0x71: return "JUMP_ABSOLUTE";
    case 0x72: return "POP_JUMP_IF_FALSE";
    case 0x73: return "POP_JUMP_IF_TRUE";
    case 0x74: return "LOAD_GLOBAL";
    case 0x7a: return "SETUP_FINALLY";
    case 0x7c: return "LOAD_FAST";
    case 0x7d: return "STORE_FAST";
    case 0x82: return "RAISE_VARARGS";
    case 0x83: return "CALL_FUNCTION";
    case 0x85: return "BUILD_SLICE";
    case 0x8d: return "CALL_FUNCTION_KW";
    case 0x90: return "EXTENDED_ARG";
    case 0x9b: return "FORMAT_VALUE";
    case 0x9d: return "BUILD_STRING";
    case 0xa0: return "LOAD_METHOD";
    case 0xa1: return "CALL_METHOD";
    default: return "";
    }
}