from trace import TraceExtractor
from triton import *
from trace import *
from bytecode import *
from collections import defaultdict

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


def emulate_trace(trace):
    ctx = TritonContext(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.setMode(MODE.TAINT_THROUGH_POINTERS, True)

    bc = te.get_bytecode(trace[0])
    opcode = opcodeFromBytecode(bc)
    arg = argFromBytecode(bc)

    for i, instr in enumerate(trace):
        ins = build_triton_ins(instr, ctx)
        ctx.processing(ins)
        if ins.isTainted():
            print('[+] ', end="")
        else:
            print('    ', end="")
        print(ins)

        if i == 0:
            for (reg, _) in ins.getWrittenRegisters():
                if reg.getId() != REG.X86_64.RIP and \
                    reg.getId() != REG.X86_64.EFLAGS:
                    ctx.taintRegister(ctx.registers.edx)  
                    print("[+] Tainted", reg.getName()) 
        #for expr in ins.getSymbolicExpressions():
        #    print('\t', expr)
        #print()a


if __name__ == "__main__":
    te = TraceExtractor("../tracer/output/traceDump", "../tracer/output/code_dump")
    te.calculate_stats(9000)
    #te.fetch_addr = 94056937240388
        
    opcodeTraces = defaultdict(lambda: [])
    for _ in range(200):
        trace = te.extract_trace()
        bc = te.get_bytecode(trace[0])
        opcode = opcodeFromBytecode(bc)
        arg = argFromBytecode(bc)
        opcodeTraces[opcode].append(trace)
        #print("%s: %x" % (opcodeName(opcode), arg))
        #for instr in trace:
        #    i = te.disassemble(instr)
        #    addr = te.instr_addr(instr)
        #    print("0x%lx: %s\t%s" % (addr, i.mnemonic, i.op_str))
    
    trace = opcodeTraces[0x64][0] # LOAD_CONST
    for instr in trace:
        i = te.disassemble(instr)
        addr = TraceExtractor.instr_addr(instr)
        print("0x%lx: %s\t%s" % (addr, i.mnemonic, i.op_str))
        for reg in instr['regs'].keys():
            val = instr['regs'][reg]
            print("\t%s: 0x%x" % (reg, int(val, 16)))

    #emulate_trace(trace)
    