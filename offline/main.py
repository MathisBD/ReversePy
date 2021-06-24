import triton as tri
from trace import *
from bytecode import *


if __name__ == "__main__":
    #ctx = tri.TritonContext(tri.ARCH.X86_64)
    te = TraceExtractor("../tracer/output/traceDump")
    #te.calculate_stats(9000)
    te.fetch_addr = 94499132524356
        
    for _ in range(1000):
        trace = te.extract_trace()
        bc = te.get_bytecode(trace[0])
        opcode = opcodeFromBytecode(bc)
        arg = argFromBytecode(bc)
        print("%s: %x" % (opcodeName(opcode), arg))
        #for instr in trace:
        #    i = te.disassemble(instr)
        #    addr = int(instr['regs']['rip'], 16)
        #    print("0x%lx: %s\t%s" % (addr, i.mnemonic, i.op_str))
    