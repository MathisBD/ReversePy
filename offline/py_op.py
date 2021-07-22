from collections import defaultdict

# list pulled from https://github.com/python/cpython/blob/3.8/Lib/opcode.py
# take care to use the file from the correct python version (i.e. git branch), 
# as opcodes may change in between versions
cpython_opc_name = defaultdict(lambda: "")

def def_op(name, op):
    cpython_opc_name[op] = name

def name_op(name, op):
    def_op(name, op)

def jrel_op(name, op):
    def_op(name, op)

def jabs_op(name, op):
    def_op(name, op)

# Instruction opcodes for compiled code
# Blank lines correspond to available opcodes

def_op('POP_TOP', 1)
def_op('ROT_TWO', 2)
def_op('ROT_THREE', 3)
def_op('DUP_TOP', 4)
def_op('DUP_TOP_TWO', 5)
def_op('ROT_FOUR', 6)

def_op('NOP', 9)
def_op('UNARY_POSITIVE', 10)
def_op('UNARY_NEGATIVE', 11)
def_op('UNARY_NOT', 12)

def_op('UNARY_INVERT', 15)

def_op('BINARY_MATRIX_MULTIPLY', 16)
def_op('INPLACE_MATRIX_MULTIPLY', 17)

def_op('BINARY_POWER', 19)
def_op('BINARY_MULTIPLY', 20)

def_op('BINARY_MODULO', 22)
def_op('BINARY_ADD', 23)
def_op('BINARY_SUBTRACT', 24)
def_op('BINARY_SUBSCR', 25)
def_op('BINARY_FLOOR_DIVIDE', 26)
def_op('BINARY_TRUE_DIVIDE', 27)
def_op('INPLACE_FLOOR_DIVIDE', 28)
def_op('INPLACE_TRUE_DIVIDE', 29)

def_op('GET_AITER', 50)
def_op('GET_ANEXT', 51)
def_op('BEFORE_ASYNC_WITH', 52)
def_op('BEGIN_FINALLY', 53)
def_op('END_ASYNC_FOR', 54)
def_op('INPLACE_ADD', 55)
def_op('INPLACE_SUBTRACT', 56)
def_op('INPLACE_MULTIPLY', 57)

def_op('INPLACE_MODULO', 59)
def_op('STORE_SUBSCR', 60)
def_op('DELETE_SUBSCR', 61)
def_op('BINARY_LSHIFT', 62)
def_op('BINARY_RSHIFT', 63)
def_op('BINARY_AND', 64)
def_op('BINARY_XOR', 65)
def_op('BINARY_OR', 66)
def_op('INPLACE_POWER', 67)
def_op('GET_ITER', 68)
def_op('GET_YIELD_FROM_ITER', 69)

def_op('PRINT_EXPR', 70)
def_op('LOAD_BUILD_CLASS', 71)
def_op('YIELD_FROM', 72)
def_op('GET_AWAITABLE', 73)

def_op('INPLACE_LSHIFT', 75)
def_op('INPLACE_RSHIFT', 76)
def_op('INPLACE_AND', 77)
def_op('INPLACE_XOR', 78)
def_op('INPLACE_OR', 79)
def_op('WITH_CLEANUP_START', 81)
def_op('WITH_CLEANUP_FINISH', 82)
def_op('RETURN_VALUE', 83)
def_op('IMPORT_STAR', 84)
def_op('SETUP_ANNOTATIONS', 85)
def_op('YIELD_VALUE', 86)
def_op('POP_BLOCK', 87)
def_op('END_FINALLY', 88)
def_op('POP_EXCEPT', 89)

HAVE_ARGUMENT = 90              # Opcodes from here have an argument:

name_op('STORE_NAME', 90)       # Index in name list
name_op('DELETE_NAME', 91)      # ""
def_op('UNPACK_SEQUENCE', 92)   # Number of tuple items
jrel_op('FOR_ITER', 93)
def_op('UNPACK_EX', 94)
name_op('STORE_ATTR', 95)       # Index in name list
name_op('DELETE_ATTR', 96)      # ""
name_op('STORE_GLOBAL', 97)     # ""
name_op('DELETE_GLOBAL', 98)    # ""
def_op('LOAD_CONST', 100)       # Index in const list
name_op('LOAD_NAME', 101)       # Index in name list
def_op('BUILD_TUPLE', 102)      # Number of tuple items
def_op('BUILD_LIST', 103)       # Number of list items
def_op('BUILD_SET', 104)        # Number of set items
def_op('BUILD_MAP', 105)        # Number of dict entries
name_op('LOAD_ATTR', 106)       # Index in name list
def_op('COMPARE_OP', 107)       # Comparison operator
name_op('IMPORT_NAME', 108)     # Index in name list
name_op('IMPORT_FROM', 109)     # Index in name list

jrel_op('JUMP_FORWARD', 110)    # Number of bytes to skip
jabs_op('JUMP_IF_FALSE_OR_POP', 111) # Target byte offset from beginning of code
jabs_op('JUMP_IF_TRUE_OR_POP', 112)  # ""
jabs_op('JUMP_ABSOLUTE', 113)        # ""
jabs_op('POP_JUMP_IF_FALSE', 114)    # ""
jabs_op('POP_JUMP_IF_TRUE', 115)     # ""

name_op('LOAD_GLOBAL', 116)     # Index in name list

jrel_op('SETUP_FINALLY', 122)   # Distance to target address

def_op('LOAD_FAST', 124)        # Local variable number
def_op('STORE_FAST', 125)       # Local variable number
def_op('DELETE_FAST', 126)      # Local variable number

def_op('RAISE_VARARGS', 130)    # Number of raise arguments (1, 2, or 3)
def_op('CALL_FUNCTION', 131)    # #args
def_op('MAKE_FUNCTION', 132)    # Flags
def_op('BUILD_SLICE', 133)      # Number of items
def_op('LOAD_CLOSURE', 135)
def_op('LOAD_DEREF', 136)
def_op('STORE_DEREF', 137)
def_op('DELETE_DEREF', 138)

def_op('CALL_FUNCTION_KW', 141)  # #args + #kwargs
def_op('CALL_FUNCTION_EX', 142)  # Flags

jrel_op('SETUP_WITH', 143)

def_op('LIST_APPEND', 145)
def_op('SET_ADD', 146)
def_op('MAP_ADD', 147)

def_op('LOAD_CLASSDEREF', 148)

def_op('EXTENDED_ARG', 144)

def_op('BUILD_LIST_UNPACK', 149)
def_op('BUILD_MAP_UNPACK', 150)
def_op('BUILD_MAP_UNPACK_WITH_CALL', 151)
def_op('BUILD_TUPLE_UNPACK', 152)
def_op('BUILD_SET_UNPACK', 153)

jrel_op('SETUP_ASYNC_WITH', 154)

def_op('FORMAT_VALUE', 155)
def_op('BUILD_CONST_KEY_MAP', 156)
def_op('BUILD_STRING', 157)
def_op('BUILD_TUPLE_UNPACK_WITH_CALL', 158)

name_op('LOAD_METHOD', 160)
def_op('CALL_METHOD', 161)
jrel_op('CALL_FINALLY', 162)
def_op('POP_FINALLY', 163)

del def_op, name_op, jrel_op, jabs_op

# list created by me, by running 
# dis.get_instructions() on sample programs
# with pypy
pypy_opc_name = defaultdict(lambda: "", {
    0x1: "POP_TOP",
    0x16: "BINARY_MODULO",
    0x37: "INPLACE_ADD",
    0x44: "GET_ITER",
    0x47: "LOAD_BUILD_CLASS",
    0x53: "RETURN_VALUE",
    0x57: "POP_BLOCK",
    0x5a: "STORE_NAME",
    0x5d: "FOR_ITER",
    0x64: "LOAD_CONST",
    0x65: "LOAD_NAME",
    0x6b: "COMPARE_OP",
    0x71: "JUMP_ABSOLUTE",
    0x72: "POP_JUMP_IF_FALSE",
    0x73: "POP_JUMP_IF_TRUE",
    0x78: "SETUP_LOOP",
    0x83: "CALL_FUNCTION",
    0x84: "MAKE_FUNCTION",
    0xa1: "CALL_METHOD",
    0xc9: "LOOKUP_METHOD",
})

# A python instruction.
# We can't keep the whole instruction trace in memory,
# as it wouldn't fit in RAM.
class PyOp:
    def __init__(self, bytes, regs):
        self.opc = bytes[0]
        self.arg = bytes[1] 
        self.regs = regs
        self.frame = -1
                    