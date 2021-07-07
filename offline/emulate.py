from triton import *

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

"""
def build_triton_ins(instr, ctx):
    # create the instruction
    ins = Instruction()
    opcodes = TraceExtractor.instr_opcodes(instr)
    ins.setOpcode(opcodes)
    ins.setAddress(int(instr['regs']['rip'], 16))
    # setup the register values
    for name in instr['regs']:
        if name != 'rip':
            if name not in triton_regs_by_name:
                raise Exception("unknown register:", name)
            reg = triton_regs_by_name[name]
            val = int(instr['regs'][name], 16)
            ctx.setConcreteRegisterValue(ctx.getRegister(reg), val)
    # setup the memory where it is read
    if 'reads' in instr:
        for read in instr['reads']:
            addr = int(read['addr'], 16)
            size = int(read['size'], 16)
            value = int(read['value'], 16)
            ctx.setConcreteMemoryValue(MemoryAccess(addr, size), value)
    return ins 


def emulate_taint(trace):
    ctx = TritonContext(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.setMode(MODE.TAINT_THROUGH_POINTERS, True)

    for i, instr in enumerate(trace):
        ins = build_triton_ins(instr, ctx)
        ctx.processing(ins)
        if ins.isTainted():
            print('[+] ', end="")
        else:
            print('    ', end="")
        print(ins)
        #print("\t", instr['regs'])

        if i == 0:
            for (reg, _) in ins.getWrittenRegisters():
                if reg.getId() != REG.X86_64.RIP and \
                    reg.getId() != REG.X86_64.EFLAGS:
                    ctx.taintRegister(ctx.registers.edx)  
                    print("[+] Tainted", reg.getName()) 
"""

def emulate_ip_expr(trace, ti):
    ctx = TritonContext(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
    ctx.setMode(MODE.CONSTANT_FOLDING, True)
    ctx.enableSymbolicEngine(True)
    ctx.enableTaintEngine(False)
    
    # setup the registers
    for reg in trace[0]['regs']:
        if reg != 'rip':
            val = int(trace[0]['regs'][reg], 16)
            ctx.setConcreteRegisterValue(ctx.getRegister(triton_reg(reg)), val)
    # symbolize ip
    ctx.symbolizeRegister(ctx.getRegister(triton_reg(ti.ip)), 'ip')
    # symbolize the opcode argument
    arg_addr = 1 + int(trace[0]['regs'][ti.ip], 16)
    ctx.symbolizeMemory(MemoryAccess(arg_addr, 1), 'arg')

    print("[+] Emulating to get ip:")
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
                    if not ctx.isMemorySymbolized(addr + s):
                        byt = (value >> (8*s)) & 0xff
                        ctx.setConcreteMemoryValue(addr + s, byt)
        # let triton do the thing
        ctx.processing(ins)    
        print("\t", ins)

        """
        if i == 0:
            print("RDX:")
            print(hex(ctx.getConcreteRegisterValue(ctx.registers.rdx)))
            slicing = ctx.sliceExpressions(ctx.getSymbolicRegisters()[REG.X86_64.RDX])
            for k, v in slicing.items():
                print(v)
        """

        for se in ins.getSymbolicExpressions():
            se.setComment(str(ins))

        if i == len(trace)-1:
            # backward slice on ip
            ip_expr = ctx.getSymbolicRegister(ctx.getRegister(triton_reg(ti.ip)))
            # simplify the expression
            ip_expr = ctx.newSymbolicExpression(
                #ctx.simplify(ip_expr.getAst(), True),
                ip_expr.getAst(),
                'new ip'
            )
            slicing = ctx.sliceExpressions(ip_expr)
            print("[+] Slicing ip:")
            for k, v in sorted(slicing.items()):
                print("\t", v)
    