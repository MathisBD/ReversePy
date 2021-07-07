
from typing import DefaultDict
from py_op import *
from actions import *
from trace_info import *
from emulate import *
from collections import defaultdict
import os
import json

class Semantics:
    class StateDiff:
        def __init__(self, ip, new_ip, sp, new_sp, block, new_block, frame_changed, arg):
            self.ip = ip 
            self.new_ip = new_ip 
            self.sp = sp 
            self.new_sp = new_sp 
            self.block = block 
            self.new_block = new_block 
            self.frame_changed = frame_changed
            self.arg = arg 

    def __init__(self, ti):
        self.ti = ti
        self.opcodes = set(op.opc for op in ti.py_ops)
        # maps opcode -> list of state diffs
        self.diffs = defaultdict(lambda: [])
        # maps opcode -> list of compatible actions
        self.actions = defaultdict(lambda: [])

    def compute_diffs(self):
        for i in range(len(self.ti.py_ops) - 1):
            curr = self.ti.py_ops[i]
            next = self.ti.py_ops[i+1]
            diff = Semantics.StateDiff(
                ip = curr.regs[self.ti.ip],
                new_ip = next.regs[self.ti.ip],
                sp = curr.regs[self.ti.sp],
                new_sp = next.regs[self.ti.sp],
                block = curr.block,
                new_block = next.block,
                frame_changed = (i in self.ti.frame_changes),
                arg = curr.arg
            )
            self.diffs[curr.opc].append(diff)

    def compute_actions(self):
        for opc in self.opcodes:
            actions = []
            actions.append(self.jmp_rel(self.diffs[opc]))
            actions.append(self.jmp_rel_arg(self.diffs[opc]))
            #actions.append(self.jmp_abs(self.diffs[opc]))
            self.actions[opc] = list(filter(
                lambda a: a is not None,
                actions
            ))

    def jmp_rel(self, diffs):
        offsets = []
        for d in diffs:
            if d.block != d.new_block:
                return None
            offsets.append(d.new_ip - d.ip)

        for ofs in offsets:
            if ofs != offsets[0]:
                return None 
        return JmpRel(offsets[0])

    def jmp_rel_arg(self, diffs):
        offsets = []
        for d in diffs:
            if d.block != d.new_block:
                return None
            offsets.append(d.new_ip - d.ip - d.arg)

        for ofs in offsets:
            if ofs != offsets[0]:
                return None 
        return JmpRelArg(offsets[0])

    """
    def compute_jmps(self):
        
        all_changes = defaultdict(lambda: [])
        # does the opcode jump accross blocks ?
        block = defaultdict(lambda: False)

        for i in range(len(self.ti.py_ops) - 1):
            curr = self.ti.py_ops[i]
            next = self.ti.py_ops[i+1]
            if curr.block == next.block:
                ofs = next.regs[self.ti.ip] - curr.regs[self.ti.ip]
                all_offsets[curr.opc].add(ofs)
            else:
                block[curr.opc] = True

        for opc in self.opcodes:
            if len(all_offsets[opc]) == 1 and not block[opc]:
                ofs = list(all_offsets[opc])[0]
                act = RelJmp(ofs)
                self.actions[opc].append(act)
            if len(all_offsets[opc]) == 0 and block[opc]:
                act = BlockJmp()
                self.actions[opc].append(act)


    def sp_ofs(self):
        all_offsets = defaultdict(lambda: set())
        for i in range(len(self.ti.py_ops) - 1):
            curr = ti.py_ops[i]
            next = ti.py_ops[i+1]
            if i not in self.ti.frame_changes:
                ofs = next.regs[self.ti.sp] - curr.regs[self.ti.sp]
                all_offsets[curr.opc].add(ofs)

        for opc in self.opcodes:
            if len(all_offsets[opc]) == 1:
                ofs = list(all_offsets[opc])[0]
                act = SpOfs(ofs)
                self.actions[opc].append(act)
    """

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
    trace = None
    ti.file.seek(0, os.SEEK_SET)
    for i, line in enumerate(ti.file):
        trace = json.loads(line)
        op = PyOp(trace)
        if opcodeName(op.opc) == "JUMP_FORWARD":
        #if opcodeName(op.opc) == "LOAD_NAME":
            break

    assert(trace is not None)
    emulate_ip_expr(trace, ti)
    """

    
    print("[+] Semantic actions for each opcode")
    sem = Semantics(ti)
    sem.compute_diffs()
    sem.compute_actions()
    for opc, actions in sem.actions.items():
        count = len(set(d.ip for d in sem.diffs[opc]))
        print("\t%s (observed at %d locations):" % (opcodeName(opc), count))
        for act in actions:
            print("\t\t%s" % act)
    
    
    print("[+] Instr blocks:")
    for i, bl in enumerate(ti.blocks):
        print("\t%d <0x%x ... 0x%x> :" % (i, min(bl), max(bl)), [hex(addr) for addr in sorted(bl)])

    # Blocks should be contiguous memory regions,
    # and thus not overlap.
    print("[+] Checking block overlaps")
    for i in range(len(ti.blocks)):
        for j in range(len(ti.blocks)):
            if i < j:
                a1, b1 = min(ti.blocks[i]), max(ti.blocks[i])
                a2, b2 = min(ti.blocks[j]), max(ti.blocks[j])
                if (a2 <= b1 and a1 <= b2) or (a1 <= b2 and a2 <= b1):
                    print("\tblocks %d and %d overlap!!!" % (i, j))

    # I assume every block has a single entry point,
    # is it always the instruction with lowest address in the block ?
    print("[+] Checking block entry-points")
    first_ins = [-1 for _ in range(len(ti.blocks))]
    for op in ti.py_ops:
        if first_ins[op.block] == -1:
            first_ins[op.block] = op.regs[ti.ip]
    for i in range(len(ti.blocks)):
        if first_ins[i] != min(ti.blocks[i]):
            print("\tBlock %d: first=0x%x, min=0x%x" % (i, first_ins[i], min(ti.blocks[i])))


    print("[+] Bytecode:")
    for i, op in enumerate(ti.py_ops):
        if (i-1) in ti.frame_changes:
            print("\n\t%d: block=%d" % (i, op.block))
        print("\t0x%x: %s %d" % (op.regs[ti.ip], opcodeName(op.opc), op.arg))
    
    for i, op in enumerate(ti.py_ops):
        if i in ti.frame_changes:
            print("%d: 0x%x: %s %d" % (i, op.regs[ti.ip], opcodeName(op.opc), op.arg)) 
    