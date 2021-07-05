import json
from py_op import *
import os 
from unionfind import *

# calculate the greatest power of two that divides
# every value in a list
def max_align(vals):
    def is_aligned(vals, d):
        for v in vals:
            if v % d != 0:
                return False 
        return True
    def only_zeros(vals):
        for v in vals:
            if v != 0:
                return False 
        return True
    # edge cases
    if len(vals) == 0:
        return 0
    if only_zeros(vals):
        return 0
    # main loop
    d = 1
    while True:
        if is_aligned(vals, 2*d):
            d *= 2
        else:
            return d

# Calculate the maximum number of 
# consecutive increases by a number in 'deltas'.
# Example: for the values [18, 4, 6, 8, 5, 7, 16, 14, 5],
# and deltas=[2], the max streak is 2 and corresponds to [4, 6, 8].
def max_delta_streak(l, deltas):
    max_streak = 0
    curr_streak = 0
    prev_val = -1

    for val in l:
        # continue the streak
        if (val - prev_val) in deltas and prev_val != -1:
            curr_streak += 1 
            max_streak = max(max_streak, curr_streak)
        # reset the streak
        else:
            curr_streak = 0
        prev_val = val
    return max_streak

def big_change_indices(l, threshold):
    indices = []
    for i in range(len(l)-1):
        if abs(l[i+1] - l[i]) >= threshold:
            indices.append(i)
    return indices 

class TraceInfo:
    def __init__(self, trace_path):
        self.file = open(trace_path, 'r')
        self.regs = [
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
        ]
        self.py_ops = []        # the list of all py_ops the program contains
        self.ip = ''            # instruction pointer 
        self.sp = ''            # stack pointer
        self.fp = ''            # frame pointer(s) 
        self.frame_changes = [] # indices of the instructions that change the frame

    def __del__(self):
        self.file.close()

    def get_py_ops(self):
        self.file.seek(0, os.SEEK_SET)
        for line in self.file:
            trace = json.loads(line)
            self.py_ops.append(PyOp(trace))

    def get_reg_values(self):
        # reg values
        self.reg_vals = { reg: [] for reg in self.regs }
        self.file.seek(0, os.SEEK_SET)
        for line in self.file:
            trace = json.loads(line)
            for reg in self.regs:
                val = int(trace[0]['regs'][reg], 16)
                self.reg_vals[reg].append(val)
        # reg changes
        self.reg_changes = dict()
        for reg in self.regs:
            self.reg_changes[reg] = set(big_change_indices(self.reg_vals[reg], 100))
                
    def get_write_times(self):
        # last_write[addr] is the index of the last py_op that writes to addr
        self.last_write = dict()

        def add_write(write, time):
            addr = int(write['addr'], 16)
            size = int(write['size'], 16)
            for i in range(size):
                if (addr + i) in self.last_write and time > self.last_write[addr + i]:
                    self.last_write[addr + i] = time
                else:
                    self.last_write[addr + i] = time

        self.file.seek(0, os.SEEK_SET)
        for i, line in enumerate(self.file):
            trace = json.loads(line)
            for instr in trace:
                if 'writes' in instr.keys():
                    for write in instr['writes']:
                        add_write(write, i)                

    def detect_ptrs(self):
        stack_ptr_candidates = set()
        instr_ptr_candidates = set()
        # If I add 0, the frame pointers (that stay the same for 
        # long periods of time) would be included too.
        stack_ofs = [-16, -8, 8, 16] 
        instr_ofs = [2]
        print("[+] Reg info :")
        for reg in self.regs:
            # basic stats
            distinct_count = len(set(self.reg_vals[reg]))
            align = max_align(self.reg_vals[reg])
            max_stack_streak = max_delta_streak(self.reg_vals[reg], stack_ofs)
            max_instr_streak = max_delta_streak(self.reg_vals[reg], instr_ofs)
            # overwrite : we write to an address after reg points to it
            overwrite_count = 0
            for r_i, addr in enumerate(self.reg_vals[reg]):
                if addr in self.last_write:
                    w_i = self.last_write[addr]
                    if w_i >= r_i:
                        overwrite_count += 1
            print("\t%s: \talign=0x%02x\tdistinct values=%6d\tmax_stack_streak=%6d\tmax_instr_streak=%6d\toverwrite count=%6d" % \
                (reg, align, distinct_count, max_stack_streak, max_instr_streak, overwrite_count))
            # instr pointer ?
            if align >= 2 and distinct_count > 10 and max_instr_streak > 10 and overwrite_count == 0:
                instr_ptr_candidates.add(reg)
            # stack pointer ?
            # don't be too greedy for the max_stack_streak, I excluded 0 from the possible offsets
            if align >= 8 and distinct_count > 10 and max_stack_streak > 10 and overwrite_count > 10:
                stack_ptr_candidates.add(reg)
        
        # stack pointer
        print("[+] Stack ptr candidates: ", stack_ptr_candidates)
        if len(stack_ptr_candidates) != 1:
            print("\tDidn't find the stack pointer ! Aborting.")
            return
        self.sp = list(stack_ptr_candidates)[0]

        # instr pointer
        if self.sp in instr_ptr_candidates:
            instr_ptr_candidates.remove(self.sp)
        print("[+] Instr ptr candidates: ", instr_ptr_candidates)
        if len(instr_ptr_candidates) != 1:
            print("\tDidn't find the instruction pointer ! Continuing.")

            # try to match the big changes of the stack pointer and of the instr pointer
            print("[+] Big reg changes :")
            print("\t%s:\t" % self.sp, sorted(self.reg_changes[self.sp])[:50])
            diff = dict()
            for reg in instr_ptr_candidates:
                # ^ is symmetric difference
                diff[reg] = self.reg_changes[reg] ^ self.reg_changes[self.sp]
                print("\t%s:\t" % reg, sorted(self.reg_changes[reg])[:50])
                print("\t\tdiff count= %d" % len(diff[reg]))
            instr_ptr_candidates = set(filter(
                lambda reg: len(diff[reg]) / float(len(self.reg_changes[self.sp]) + len(self.reg_changes[reg])) < 0.2,
                instr_ptr_candidates
            ))

            print("[+] Instr ptr candidates: ", instr_ptr_candidates)
            if len(instr_ptr_candidates) != 1:
                print("\tDidn't find the instruction pointer ! Aborting.")
                return 

        self.ip = list(instr_ptr_candidates)[0]
        
    def detect_frames(self):
        # frame changes
        # for recursive functions, the frame changes but only sp (not ip) changes
        self.frame_changes = self.reg_changes[self.sp]
        print("[+] Frame changes :", sorted(self.frame_changes)[:50])
        
        # try to detect the frame pointer
        change_count = { reg: 0 for reg in self.regs }
        stay_count = { reg: 0 for reg in self.regs }
        for reg in self.regs:
            for i in range(len(self.py_ops) - 1):
                d = self.reg_vals[reg][i+1] - self.reg_vals[reg][i]
                # we want the value to change
                if i in self.frame_changes:
                    if d != 0:
                        change_count[reg] += 1
                # we want the value to stay the same
                else:
                    if d == 0:
                        stay_count[reg] += 1 
        goal_change_count = len(self.frame_changes)
        goal_stay_count = len(self.py_ops) - len(self.frame_changes) - 1 # -1 because we don't count the last py_op
        print("\tgoal_change_count=%d\tgoal_stay_count=%d" % (goal_change_count, goal_stay_count))
        frame_ptr_candidates = set()
        for reg in self.regs:
            if change_count[reg] / float(goal_change_count) > 0.8 and \
                stay_count[reg] / float(goal_stay_count) > 0.8:
                frame_ptr_candidates.add(reg)
                print("\t%s:\tchange=%d\tstay=%d" % (reg, change_count[reg], stay_count[reg]))

        print("[+] Frame ptr candidates: ", frame_ptr_candidates)
        self.fps = list(frame_ptr_candidates)
    
    # Partition the python instructions into blocks according
    # to their address in memory.
    # Ideally we want the instruction blocks to match functions 
    # (i.e. each function corresponds to a single block), 
    # but we may only be able to associate a function with several 
    # (non-overlapping) instruction blocks. It should hold that 
    # a block is included in a function.
    def detect_instr_blocks(self):
        addrs = set()
        for op in self.py_ops:
            ip = op.regs[self.ip]
            addrs.add(ip)
        u = UnionFind(addrs)
        # instructions in the same frame are in the same block
        for i in range(len(self.py_ops) - 1):
            if i not in self.frame_changes:
                curr = self.py_ops[i].regs[self.ip]
                next = self.py_ops[i+1].regs[self.ip]
                u.union(curr, next)
        # instructions close together in memory are in the same block
        sorted_addrs = sorted(addrs)
        for i in range(len(sorted_addrs) - 1):
            curr = sorted_addrs[i]
            next = sorted_addrs[i+1]
            if next - curr <= 100:
                u.union(curr, next)
        # get the blocks
        self.blocks = u.get_sets()
        
        # calculate the block of each py_op
        def block_idx(ins_addr):
            for i, b in enumerate(self.blocks):
                if ins_addr in b:
                    return i
            raise Exception("Invalid instruction address: 0x%x" % ins_addr)
        for op in self.py_ops:
            op.block = block_idx(op.regs[self.ip])