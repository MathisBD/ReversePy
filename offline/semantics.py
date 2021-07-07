
from typing import DefaultDict
from py_op import *
from actions import *
from trace_info import *
from emulate import *
from collections import defaultdict
import os
import json

class Semantics:
    # the maximum absolute value of the offset in jump actions
    MAX_JUMP_OFS = 0x04
    # same but for sp actions
    MAX_SP_OFS = 0x16
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
            # the value sp takes the next time
            # control flow returns to self.block
            self.next_block_sp = None 

    def __init__(self, ti):
        self.ti = ti
        self.opcodes = set(op.opc for op in ti.py_ops)
        # maps opcode -> list of state diffs
        self.diffs = defaultdict(lambda: [])
        # maps opcode -> list of compatible actions
        self.actions = defaultdict(lambda: [])

    def compute_diffs(self):
        # forward pass : collect basic data
        all_diffs = []
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
            all_diffs.append(diff)

        # backward pass : compute next_block_sp
        sp = [None for _ in range(len(self.ti.blocks))]
        for d in reversed(all_diffs):
            d.next_block_sp = sp[d.block]
            sp[d.block] = d.sp

    def first_action(self, opc, methods):
        for meth in methods:
            act = meth(self.diffs[opc])
            if act is not None:
                self.actions[opc].append(act)
                return

    def compute_actions(self):
        for opc in self.opcodes:
            # jumps (order matters)
            self.first_action(opc, [
                self.jmp_rel,
                self.jmp_rel_arg,
                self.jmp_abs,
                self.jmp_cond
            ])  
            # stack offset
            self.first_action(opc, [
                self.sp_ofs,
                self.sp_ofs_plus_arg,
                self.sp_ofs_minus_arg
            ])

    def jmp_rel(self, diffs):
        offsets = []
        for d in diffs:
            if d.block != d.new_block:
                return None
            offsets.append(d.new_ip - d.ip)

        if abs(offsets[0]) > Semantics.MAX_JUMP_OFS:
            return None

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

        if abs(offsets[0]) > Semantics.MAX_JUMP_OFS:
            return None
            
        for ofs in offsets:
            if ofs != offsets[0]:
                return None 
        return JmpRelArg(offsets[0])

    def jmp_abs(self, diffs):
        offsets = []
        for d in diffs:
            if d.block != d.new_block:
                return None 
            block_start = min(self.ti.blocks[d.block])
            offsets.append(d.new_ip - d.arg - block_start)

        if abs(offsets[0]) > Semantics.MAX_JUMP_OFS:
            return None
            
        for ofs in offsets:
            if ofs != offsets[0]:
                return None 
        return JmpAbs(offsets[0])

    # suppose diffs[0] is ip <- ip + k
    def jmp_cond_A(self, diffs):
        ofs = diffs[0].new_ip - diffs[0].ip
        abs_offsets = []
        for d in diffs:
            if d.block != d.new_block:
                return None 
            if d.new_ip - d.ip != ofs:
                # then d must be ip <- block-start + arg + k2
                block_start = min(self.ti.blocks[d.block])
                abs_offsets.append(d.new_ip - block_start - d.arg)
        
        if len(abs_offsets) == 0:
            return None
        if abs(abs_offsets[0]) > Semantics.MAX_JUMP_OFS:
            return None
            
        for abs_ofs in abs_offsets:
            if abs_ofs != abs_offsets[0]:
                return None
        return JmpCond(
            ofs_rel = ofs, 
            ofs_abs = abs_offsets[0]
        )

    # suppose diffs[0] is ip <- block-start + arg + k
    def jmp_cond_B(self, diffs):
        block_start = min(self.ti.blocks[diffs[0].block])
        abs_ofs = diffs[0].new_ip - block_start - diffs[0].arg
        offsets = []
        for d in diffs:
            if d.block != d.new_block:
                return None 
            block_start = min(self.ti.blocks[d.block])
            if d.new_ip - block_start - d.arg != abs_ofs:
                # then d must be ip <- ip + k2
                offsets.append(d.new_ip - d.ip)
        
        if len(offsets) == 0:
            return None
        if abs(offsets[0]) > Semantics.MAX_JUMP_OFS:
            return None
            
        for ofs in offsets:
            if ofs != offsets[0]:
                return None 
        return JmpCond(
            ofs_rel = offsets[0], 
            ofs_abs = abs_ofs
        )

    def jmp_cond(self, diffs):
        jmpA = self.jmp_cond_A(diffs)
        if jmpA is not None:
            return jmpA 
        return self.jmp_cond_B(diffs)
            
    def sp_ofs(self, diffs):
        offsets = []
        for d in diffs:
            if d.frame_changed:
                return None 
            offsets.append(d.new_sp - d.sp)

        if abs(offsets[0]) > Semantics.MAX_SP_OFS:
            return None

        for ofs in offsets:
            if ofs != offsets[0]:
                return None 
        return SpOfs(offsets[0])

    def sp_ofs_minus_arg(self, diffs):
        offsets = []
        for d in diffs:
            if d.frame_changed:
                return None
            offsets.append(d.new_sp - d.sp + 8*d.arg)

        if abs(offsets[0]) > Semantics.MAX_SP_OFS:
            return None
            
        for ofs in offsets:
            if ofs != offsets[0]:
                return None 
        return SpOfsMinusArg(offsets[0])
    
    def sp_ofs_plus_arg(self, diffs):
        offsets = []
        for d in diffs:
            if d.frame_changed:
                return None
            offsets.append(d.new_sp - d.sp - 8*d.arg)

        if abs(offsets[0]) > Semantics.MAX_SP_OFS:
            return None
            
        for ofs in offsets:
            if ofs != offsets[0]:
                return None 
        return SpOfsPlusArg(offsets[0])


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

    """
    for d in sem.diffs[0x83]: # CALL_FUNCTION
        print("sp=0x%x\targ=%d\tnext_block_sp=0x%x\tofs=0x%x" %
            (d.sp, d.arg, d.next_block_sp, d.next_block_sp - d.sp + 8*d.arg))
    """
    
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
    