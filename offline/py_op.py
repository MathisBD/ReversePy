# A python instruction.
# We can't keep the whole instruction trace in memory,
# as it wouldn't fit in RAM.
class PyOp:
    def __init__(self, bytes, regs):
        self.opc_addr, self.opc = bytes[0]
        self.arg_addr, self.arg = bytes[1] 
        self.regs = regs
        self.frame = -1
                    