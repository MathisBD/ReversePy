import json
from typing import NamedTuple
from bytecode import *
from emulate import *
import os 

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
        self.bytecode = []      # the list of all opcodes+args the program contains
        self.ip = ''            # instruction pointer 
        self.sp = ''            # stack pointer
        self.fp = ''            # frame pointer(s) 
        self.frame_changes = [] # indices of the instructions that change the frame

    def __del__(self):
        self.file.close()

    def get_bytecode(self):
        self.file.seek(0, os.SEEK_SET)
        for line in self.file:
            trace = json.loads(line)
            fetch = trace[0]
            found = 0
            if 'reads' in fetch.keys():
                for read in fetch['reads']:
                    if int(read['size'], 16) == 2:
                        bytecode = int(read['value'], 16)
                        opc = opcodeFromBytecode(bytecode)
                        arg = argFromBytecode(bytecode) 
                        self.bytecode.append((opc, arg))
                        found += 1
            if found != 1:
                raise Exception("the trace doesn't have a valid fetch")

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
        # last_write[addr] is the index of the last bytecode that writes to addr
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
        stack_ofs = [-16, -8, 0, 8, 16]
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
            print("\t%s:\t" % self.sp, sorted(self.reg_changes[self.sp]))
            diff = dict()
            for reg in instr_ptr_candidates:
                # ^ is symmetric difference
                diff[reg] = self.reg_changes[reg] ^ self.reg_changes[self.sp]
                print("\t%s:\t" % reg, sorted(self.reg_changes[reg]))
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
        self.frame_changes = self.reg_changes[self.sp] & self.reg_changes[self.ip]
        print("[+] Frame changes :", sorted(self.frame_changes))
        # try to detect the frame pointer
        change_count = { reg: 0 for reg in self.regs }
        stay_count = { reg: 0 for reg in self.regs }
        for reg in self.regs:
            for i in range(len(self.bytecode) - 1):
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
        goal_stay_count = len(self.bytecode) - len(self.frame_changes) - 1 # -1 because we don't count the last opcode
        print("\tgoal_change_count=%d\tgoal_stay_count=%d" % (goal_change_count, goal_stay_count))
        frame_ptr_candidates = set()
        for reg in self.regs:
            if change_count[reg] / float(goal_change_count) > 0.8 and \
                stay_count[reg] / float(goal_stay_count) > 0.8:
                frame_ptr_candidates.add(reg)
                print("\t%s:\tchange=%d\tstay=%d" % (reg, change_count[reg], stay_count[reg]))

        print("[+] Frame ptr candidates: ", frame_ptr_candidates)
        for reg in frame_ptr_candidates:
            print("\t%s changes:" % reg)
            for i in sorted(self.frame_changes):
                print("\t\t%d: 0x%x -> 0x%x (delta=%x)" % 
                    (i, self.reg_vals[reg][i], self.reg_vals[reg][i+1], 
                    self.reg_vals[reg][i+1] - self.reg_vals[reg][i]))
        
        self.fp = list(frame_ptr_candidates)


if __name__ == "__main__":
    # The trace file has one trace per line.
    # A trace consists of all instructions for a single bytecode,
    # and is encoded as a json object.
    # You should generally avoid loading the entire trace file at once,
    # as it can (theoretically) be too big to fit in memory.
    # Using 'for line in file' is safe as it loads only one line at a time.
    ti = TraceInfo("../tracer/output/traceDump")
    # bytecode
    ti.get_bytecode()
    """
    for i, bc in enumerate(ti.bytecode):
        opc, arg = bc
        print("%d: %s %x" % (i, opcodeName(opc), arg))  
    """
    # registers
    ti.get_reg_values()
    ti.get_write_times()
    ti.detect_ptrs()
    ti.detect_frames()
    