from py_op import *
from actions import *
from trace_info import *
from collections import defaultdict


class Semantics:
    def __init__(self, ti):
        self.ti = ti
        # maps opcode -> list of actions
        self.actions = defaultdict(lambda: [])

    def compute(self):
        self.jmps()
        self.sp_ofs()

    def jmps(self):
        # jump offsets inside a block
        all_offsets = defaultdict(lambda: set())
        # does the opcode jump accross blocks ?
        block = defaultdict(lambda: False)

        for i in range(len(self.ti.py_ops) - 1):
            curr = self.ti.py_ops[i]
            next = self.ti.py_ops[i+1]
            if curr.block == next.block:
                ofs = next.regs[self.ti.ip] - curr.regs[self.ti.ip]
                if ofs != 0: 
                    all_offsets[curr.opc].add(ofs)
            else:
                #next_b = ti.blocks[]
                #if next_ip == min(next_b):
                block[curr.opc] = True

        for opc, offsets in all_offsets.items():
            for ofs in offsets:
                act = RelJmp(ofs)
                self.actions[opc].append(act)
            if block[opc]:
                act = BlockJmp()
                self.actions[opc].append(act)


    def sp_ofs(self):
        all_offsets = defaultdict(lambda: set())
        for i in range(len(self.ti.py_ops) - 1):
            curr = ti.py_ops[i]
            next = ti.py_ops[i+1]
            if i not in self.ti.frame_changes:
                ofs = next.regs[self.ti.sp] - curr.regs[self.ti.sp]
                if ofs != 0:
                    all_offsets[curr.opc].add(ofs)

        for opc, offsets in all_offsets.items():
            for ofs in offsets:
                act = SpOfs(ofs)
                self.actions[opc].append(act)


if __name__ == "__main__":
    # The trace file has one trace per line.
    # A trace consists of all instructions for a single py_op,
    # and is encoded as a json object.
    # You should generally avoid loading the entire trace file at once,
    # as it can (theoretically) be too big to fit in memory.
    # Using 'for line in file' is safe as it loads only one line at a time.
    ti = TraceInfo("../tracer/output/traceDump")
    ti.get_py_ops()
    ti.get_reg_values()
    ti.get_write_times()
    ti.detect_ptrs()
    ti.detect_frames()
    ti.detect_instr_blocks()

    """
    print()
    sem = Semantics(ti)
    sem.compute()
    for opc, actions in sem.actions.items():
        print("%s:" % opcodeName(opc))
        for act in actions:
            print("\t%s" % act)
    """
    
    print("[+] Instr blocks:")
    for i, bl in enumerate(ti.blocks):
        print("\t%d <0x%x ... 0x%x> :" % (i, min(bl), max(bl)), [hex(addr) for addr in sorted(bl)])

    print("[+] Block overlaps:")
    for i in range(len(ti.blocks)):
        for j in range(len(ti.blocks)):
            if i < j:
                a1, b1 = min(ti.blocks[i]), max(ti.blocks[i])
                a2, b2 = min(ti.blocks[j]), max(ti.blocks[j])
                if (a2 <= b1 and a1 <= b2) or (a1 <= b2 and a2 <= b1):
                    print("\tblocks %d and %d overlap!!!" % (i, j))

    print("[+] Bytecode:")
    for i, op in enumerate(ti.py_ops):
        if (i-1) in ti.frame_changes:
            print("\n\t%d: block=%d" % (i, op.block))
        
        print("\t0x%x: %s %d" % (op.regs[ti.ip], opcodeName(op.opc), op.arg))
    """
    for i, op in enumerate(ti.py_ops):
        if i in ti.frame_changes:
            print("%d: 0x%x: %s %d" % (i, op.regs[ti.ip], opcodeName(op.opc), op.arg)) 
    """