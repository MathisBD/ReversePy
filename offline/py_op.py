
def opcodeFromBytecode(bc):
    return bc & 0xFF

def argFromBytecode(bc):
    return (bc >> 8) & 0xFF

# list pulled from https://github.com/python/cpython/blob/3.8/Lib/opcode.py
# take care to use the file from the correct python version, as opcodes
# may change in between versions
opcode_name_dict = {
    0x01: "POP_TOP",
    0x02: "ROT_TWO",
    0x04: "DUP_TOP",
    0x0b: "UNARY_NEGATIVE",
    0x14: "BINARY_MULTIPLY",
    0x16: "BINARY_MODULO",
    0x17: "BINARY_ADD",
    0x18: "BINARY_SUBSTRACT",
    0x19: "BINARY_SUBSCR",
    0x37: "INPLACE_ADD",
    0x3e: "BINARY_LSHIFT",
    0x3f: "BINARY_RSHIFT",
    0x40: "BINARY_AND",
    0x41: "BINARY_XOR",
    0x42: "BINARY_OR",
    0x43: "INPLACE_POWER",
    0x44: "GET_ITER",
    0x47: "LOAD_BUILD_CLASS",
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
    0x84: "MAKE_FUNCTION",
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

# A python instruction.
# We can't keep the instruction whole trace in memory,
# as it wouldn't fit in RAM.
class PyOp:
    def __init__(self, trace):
        fetch = trace[0]
        found = 0
        if 'reads' in fetch.keys():
            for read in fetch['reads']:
                if int(read['size'], 16) == 2:
                    self.bc = int(read['value'], 16)
                    found += 1
        if found != 1:
            raise Exception("the trace doesn't have a valid fetch")
        
        self.opc = opcodeFromBytecode(self.bc)
        self.arg = argFromBytecode(self.bc) 
        self.regs = { reg: int(val, 16) for reg, val in fetch['regs'].items() }
        self.frame = -1
                    