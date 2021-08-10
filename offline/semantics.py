
from typing import DefaultDict
from py_op import *
from actions import *
from trace_info import *
#from emulate import *
from collections import defaultdict
import os
import json
from pypy_opcodes import pypy_opc_name 
from cpython_opcodes import cpython_opc_name


def all_equal(vals):
    if len(vals) == 0:
        return True 
    for v in vals:
        if v != vals[0]:
            return False 
    return True

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
            # the value sp takes the next time
            # control flow returns to self.block
            #self.next_block_sp = None 

    def __init__(self, ti):
        self.ti = ti
        self.opcodes = set(op.opc for op in ti.py_ops)
        # maps opcode -> list of state diffs
        self.diffs = defaultdict(lambda: [])
        # maps opcode -> semantic action or None
        self.ip_action = dict()
        self.sp_action = dict()
        # the maximum absolute value of the offset in jump actions
        self.MAX_JUMP_OFS = 2 * ti.ip_align
        # same but for sp actions
        self.MAX_SP_OFS = 2 * ti.sp_align

    def compute_diffs(self):
        # forward pass : collect basic data
        all_diffs = []
        print("\tlen(sp_vals)=%d\tlen(ip_vals)=%d\tlen(py_ops)=%d" %
            (len(self.ti.sp_vals), len(self.ti.ip_vals), len(self.ti.py_ops)))
        for i in range(len(self.ti.py_ops) - 1):
            curr = self.ti.py_ops[i]
            next = self.ti.py_ops[i+1]
            diff = Semantics.StateDiff(
                ip = self.ti.ip_vals[i],
                new_ip = self.ti.ip_vals[i+1],
                sp = self.ti.sp_vals[i],
                new_sp = self.ti.sp_vals[i+1],
                block = curr.block,
                new_block = next.block,
                frame_changed = (i in self.ti.frame_changes),
                arg = curr.arg
            )
            self.diffs[curr.opc].append(diff)
            all_diffs.append(diff)

        # backward pass : compute next_block_sp
        #sp = [None for _ in range(len(self.ti.blocks))]
        #for d in reversed(all_diffs):
        #    d.next_block_sp = sp[d.block]
        #    sp[d.block] = d.sp

    def first_action(self, opc, methods):
        for meth in methods:
            act = meth(self.diffs[opc])
            if act is not None:
                return act 
        return None 

    def compute_actions(self):
        for opc in self.opcodes:
            # jumps (order matters)
            self.ip_action[opc] = self.first_action(opc, [
                self.jmp_rel,
                self.jmp_rel_arg,
                self.jmp_abs,
                self.jmp_cond
            ])  
            # stack offset (order matters)
            self.sp_action[opc] = self.first_action(opc, [
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

        if abs(offsets[0]) > self.MAX_JUMP_OFS:
            return None
        if not all_equal(offsets):
            return None 
        return JmpRel(offsets[0])

    def jmp_rel_arg(self, diffs):
        offsets = []
        for d in diffs:
            if d.block != d.new_block:
                return None
            offsets.append(d.new_ip - d.ip - d.arg)

        if abs(offsets[0]) > self.MAX_JUMP_OFS:
            return None
            
        if not all_equal(offsets):
            return None
        return JmpRelArg(offsets[0])

    def jmp_abs(self, diffs):
        offsets = []
        for d in diffs:
            if d.block != d.new_block:
                return None 
            block_start = min(self.ti.blocks[d.block])
            offsets.append(d.new_ip - d.arg - block_start)

        if abs(offsets[0]) > self.MAX_JUMP_OFS:
            return None
        if not all_equal(offsets):
            return None
        return JmpAbs(offsets[0])

    # suppose diffs[0] is ip <- ip + k
    def jmp_cond_A(self, diffs):
        ofs = diffs[0].new_ip - diffs[0].ip
        abs_offsets = []

        if abs(ofs) > self.MAX_JUMP_OFS:
            return None

        for d in diffs:
            if d.block != d.new_block:
                return None 
            if d.new_ip - d.ip != ofs:
                # then d must be ip <- block-start + arg + k2
                block_start = min(self.ti.blocks[d.block])
                abs_offsets.append(d.new_ip - block_start - d.arg)
        
        if len(abs_offsets) == 0:
            return None
        if abs(abs_offsets[0]) > self.MAX_JUMP_OFS:
            return None            
        if not all_equal(abs_offsets):
            return None
        return JmpCond(
            ofs_rel = ofs, 
            ofs_abs = abs_offsets[0]
        )

    # suppose diffs[0] is ip <- block-start + arg + k
    def jmp_cond_B(self, diffs):
        block_start = min(self.ti.blocks[diffs[0].block])
        abs_ofs = diffs[0].new_ip - block_start - diffs[0].arg

        if abs(abs_ofs) > self.MAX_JUMP_OFS:
            return None

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
        if abs(offsets[0]) > self.MAX_JUMP_OFS:
            return None
        if not all_equal(offsets):
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
            # we don't have enough data for this diff
            # to matter : skip it
            if d.new_sp is None or d.sp is None:
                continue
            offsets.append(d.new_sp - d.sp)

        if len(offsets) == 0:
            return None 
        if abs(offsets[0]) > self.MAX_SP_OFS:
            return None
        if not all_equal(offsets):
            return None 
        return SpOfs(offsets[0])

    def sp_ofs_minus_arg(self, diffs):
        offsets = []
        for d in diffs:
            if d.frame_changed:
                return None
            # we don't have enough data for this diff
            # to matter : skip it
            if d.new_sp is None or d.sp is None:
                continue
            offsets.append(d.new_sp - d.sp + self.ti.sp_align*d.arg)

        if len(offsets) == 0:
            return None 
        if abs(offsets[0]) > self.MAX_SP_OFS:
            return None
        if not all_equal(offsets):
            return None 
        return SpOfsMinusArg(self.ti.sp_align, offsets[0])
    
    def sp_ofs_plus_arg(self, diffs):
        offsets = []
        for d in diffs:
            if d.frame_changed:
                return None
            # we don't have enough data for this diff
            # to matter : skip it
            if d.new_sp is None or d.sp is None:
                continue
            offsets.append(d.new_sp - d.sp - self.ti.sp_align*d.arg)
        
        if len(offsets) == 0:
            return None 
        if abs(offsets[0]) > self.MAX_SP_OFS:
            return None  
        if not all_equal(offsets):
            return None 
        return SpOfsPlusArg(self.ti.sp_align, offsets[0])


def get_trace(ti, opc):
    ti.file.seek(0, os.SEEK_SET)
    for i, line in enumerate(ti.file):
        if ti.py_ops[i].opc == opc:
            trace = json.loads(line)
            return trace
    return None

def get_opc_name_table():
    version = ""
    for i in range(len(sys.argv)):
        if sys.argv[i] == "--opcodes":
            assert i+1 < len(sys.argv)
            version = sys.argv[i+1]
            break
    if version == "":
        raise Exception("expected command line option --opcodes")

    if version == "cpython":
        return cpython_opc_name
    elif version == "pypy":
        return pypy_opc_name
    else:
        raise Exception("unknown opcodes version : %s" % version)

def escape_latex(s):
    esc = ""
    i = 0
    while i < len(s):
        if s[i] == '_':
            esc += "\\_"
            i += 1          
        else:
            esc += s[i]
            i += 1 
    return esc

def print_latex_actions(sem):
    for opc in sem.opcodes:
        ip_act = sem.ip_action[opc]
        sp_act = sem.sp_action[opc]
        if ip_act is None and sp_act is None:
            continue
        print("\\hline")
        print("%s & %s & %s\\\\" % (
            escape_latex(opc_name[opc]), 
            ip_act.latex() if ip_act is not None else "",
            sp_act.latex() if sp_act is not None else ""
        ))
    print("\\hline")
   
if __name__ == "__main__":
    opc_name = get_opc_name_table()
    # The trace file has one trace per line.
    # A trace consists of all instructions for a single py_op,
    # and is encoded as a json object.
    # You should generally avoid loading the entire trace file at once,
    # as it can (theoretically) be too big to fit in memory.
    # Using 'for line in file' is safe as it loads only one line at a time.
    ti = TraceInfo("../tracer/output/traceDump")
    with open("../tracer/output/fetch_dispatch", 'r') as fd_file:
        fd = json.load(fd_file)
    ti.get_fetch_dispatch(fd)
    print("[+] CFG info:")
    print("\tdispatch addr = 0x%x" % ti.dispatch)
    print("\tfetch addrs =", [hex(addr) for addr in ti.fetches])

    ti.get_py_ops()
    ti.get_reg_stats()
    ti.detect_frames()
    ti.get_ip_values()
   
    """
    trace = get_trace(ti, 1) # POP_TWO
    print("[+] Emulating trace of POP")
    mem = ti.get_initial_mem(trace)
    for addr, byte in mem.items():
        print("0x%x: 0x%x" % (addr, byte))
    emulate(ti, trace)
    """

    ti.get_sp_values()
    ti.detect_instr_blocks()

    
    #for op in ti.py_ops:
    #    print("0x%x: %s %d" % (op.opc_addr, opc_name[op.opc], op.arg))

    print("[+] Semantic actions for each opcode")
    sem = Semantics(ti)
    sem.compute_diffs()
    sem.compute_actions()

    # print the actions in latex table form
    print_latex_actions(sem)
    
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
    for op, ip in zip(ti.py_ops, ti.ip_vals):
        if first_ins[op.block] == -1:
            first_ins[op.block] = ip
    for i in range(len(ti.blocks)):
        if first_ins[i] != min(ti.blocks[i]):
            print("\tBlock %d: first=0x%x, min=0x%x" % (i, first_ins[i], min(ti.blocks[i])))

    print("[+] Bytecode:")
    for i, op in enumerate(ti.py_ops):
        if (i-1) in ti.frame_changes:
            print("\n\t%d: block=%d" % (i, op.block))
        print("\t", end="")
        for fp in ti.fps:
            print("%s=0x%x" % (fp, ti.reg_vals[fp][i]), end=" ")
 
        print("\t0x%x: %s(%d) %d" % (ti.ip_vals[i], 
            opc_name[op.opc], op.opc, op.arg))
    