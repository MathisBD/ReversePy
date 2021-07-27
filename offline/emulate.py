from triton import *
from py_op import *

triton_regs_by_name = {
    'rax':  REG.X86_64.RAX,
    'rbx':  REG.X86_64.RBX,
    'rcx':  REG.X86_64.RCX,
    'rdx':  REG.X86_64.RDX,
    'rdi':  REG.X86_64.RDI,
    'rsi':  REG.X86_64.RSI,
    'rbp':  REG.X86_64.RBP,
    'rsp':  REG.X86_64.RSP,
    'r8':   REG.X86_64.R8,
    'r9':   REG.X86_64.R9,
    'r10':  REG.X86_64.R10,
    'r11':  REG.X86_64.R11,
    'r12':  REG.X86_64.R12,
    'r13':  REG.X86_64.R13,
    'r14':  REG.X86_64.R14,
    'r15':  REG.X86_64.R15,
    'fs':   REG.X86_64.FS,
    'gs':   REG.X86_64.GS,
    'eflags': REG.X86_64.EFLAGS
}
def triton_reg(reg_name):
    if reg_name not in triton_regs_by_name:
        raise Exception("unknown register: %s" % reg_name)
    return triton_regs_by_name[reg_name]


def emulate(ti, trace):
    ctx = TritonContext(ARCH.X86_64)
    ctx.enableSymbolicEngine(False)
    ctx.enableTaintEngine(False)
    
    # setup the registers
    for reg in trace[0]['regs']:
        if reg != 'rip':
            val = int(trace[0]['regs'][reg], 16)
            ctx.setConcreteRegisterValue(ctx.getRegister(triton_reg(reg)), val)
    
    opc = ti.fetch_bytes(trace)[0]
    for i, instr in enumerate(trace):
        ins = Instruction()
        # get the opcodes
        opcodes = bytes([int(op, 16) for op in instr['opcodes']])
        ins.setOpcode(opcodes)
        # instruction address
        ins.setAddress(int(instr['regs']['rip'], 16))
        # setup the memory where it is read
        if 'reads' in instr:
            for read in instr['reads']:
                addr = int(read['addr'], 16)
                size = int(read['size'], 16)
                value = int(read['value'], 16)
                for s in range(size):
                    byt = (value >> (8*s)) & 0xff
                    ctx.setConcreteMemoryValue(addr + s, byt)
        # let triton do the thing
        ctx.processing(ins)
        # print the instruction    
        print("\t", ins)
        print("\t", instr)
