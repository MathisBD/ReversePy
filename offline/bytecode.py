

def opcodeFromBytecode(bc):
    return bc & 0xFF

def argFromBytecode(bc):
    return (bc >> 8) & 0xFF

# list pulled from https://github.com/python/cpython/blob/3.8/Lib/opcode.py
opcode_name_dict = {
    0x01: "POP_TWO",
    0x0b: "UNARY_NEGATIVE",
    0x16: "BINARY_MODULO",
    0x17: "BINARY_ADD",
    0x18: "BINARY_SUBSTRACT",
    0x19: "BINARY_SUBSCR",
    0x3e: "BINARY_LSHIFT",
    0x3f: "BINARY_RSHIFT",
    0x40: "BINARY_AND",
    0x41: "BINARY_XOR",
    0x42: "BINARY_OR",
    0x43: "INPLACE_POWER",
    0x44: "GET_ITER",
    0x51: "WITH_CLEANUP_START",
    0x53: "RETURN_VALUE",
    0x57: "POP_BLOCK",
    0x5a: "STORE_NAME",
    0x5d: "FOR_ITER",
    0x5f: "STORE_ATTR",
    0x64: "LOAD_CONST",
    0x65: "LOAD_NAME",
    0x6a: "LOAD_ATTR",
    0x6b: "COMPARE_OP",
    0x6e: "JUMP_FORWARD",
    0x71: "JUMP_ABSOLUTE",
    0x72: "POP_JUMP_IF_FALSE",
    0x73: "POP_JUMP_IF_TRUE",
    0x74: "LOAD_GLOBAL",
    0x7a: "SETUP_FINALLY",
    0x7c: "LOAD_FAST",
    0x7d: "STORE_FAST",
    0x82: "RAISE_VARARGS",
    0x83: "CALL_FUNCTION",
    0x85: "BUILD_SLICE",
    0x8d: "CALL_FUNCTION_KW",
    0x90: "EXTENDED_ARG",
    0x9b: "FORMAT_VALUE",
    0x9d: "BUILD_STRING",
    0xa0: "LOAD_METHOD",
    0xa1: "CALL_METHOD",
}
def opcodeName(opcode):
    if opcode in opcode_name_dict.keys():
        return opcode_name_dict[opcode]
    else:
        return ""