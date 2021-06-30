import json
from bytecode import * 
from triton import *
from emulate import *
import os 

def get_regs_values(file, regs):
    # maps : reg -> list of (initial) reg values
    reg_vals = { reg: [] for reg in regs }
    file.seek(0, os.SEEK_SET)
    for line in file:
        trace = json.loads(line)
        for reg in regs:
            val = int(trace[0]['regs'][reg], 16)
            reg_vals[reg].append(val)
    return reg_vals 


def get_write_addresses(file):
    addresses = set()

    def add_write(write):
        addr = int(write['addr'], 16)
        size = int(write['size'], 16)
        for i in range(size):
            addresses.add(addr + i)

    file.seek(0, os.SEEK_SET)
    for line in file:
        trace = json.loads(line)
        for instr in trace:
            if 'writes' in instr.keys():
                for write in instr['writes']:
                    add_write(write)                
    return addresses

# calculate the greatest power of two that divides
# every pairwise difference
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

def get_bytecode(trace):
    fetch = trace[0]
    if 'reads' in fetch.keys():
        for read in fetch['reads']:
            if int(read['size'], 16) == 2:
                bytecode = int(read['value'], 16)
                return opcodeFromBytecode(bytecode), argFromBytecode(bytecode) 
    raise Exception("the trace doesn't have a valid fetch")

def big_change_indices(l, threshold):
    indices = []
    for i in range(len(l)-1):
        if abs(l[i+1] - l[i]) >= threshold:
            indices.append(i)
    return indices 

def detect_regs(file):
    regs = [
        'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
    ]
    # values taken by each register
    reg_vals = get_regs_values(file, regs)
    # addresses we wrote to
    write_addrs = get_write_addresses(file)

    stack_ptr_candidates = set()
    instr_ptr_candidates = set()
    stack_ofs = [-16, -8, 0, 8, 16]
    instr_ofs = [2]
    print("[+] Reg info :")
    for reg in regs:
        # basic stats
        distinct_count = len(set(reg_vals[reg]))
        align = max_align(reg_vals[reg])
        write_count = len(
            write_addrs.intersection(set(reg_vals[reg]))
        )
        max_stack_streak = max_delta_streak(reg_vals[reg], stack_ofs)
        max_instr_streak = max_delta_streak(reg_vals[reg], instr_ofs)
        print("\t%s: \talign=0x%02x\tdistinct values=%6d\tmax_stack_streak=%6d\tmax_instr_streak=%6d\twrite count=%6d" % \
            (reg, align, distinct_count, max_stack_streak, max_instr_streak, write_count))
        # instr pointer ?
        if align >= 2 and distinct_count > 10 and max_instr_streak > 10 and write_count == 0:
            instr_ptr_candidates.add(reg)
        # stack pointer ?
        if align >= 8 and distinct_count > 10 and max_stack_streak > 100 and write_count > 0:
            stack_ptr_candidates.add(reg)
    
    # stack pointer
    print("[+] Stack ptr candidates: ", stack_ptr_candidates)
    if len(stack_ptr_candidates) != 1:
        print("\tDidn't find the stack pointer ! Aborting.")
        return
    stack_ptr = list(stack_ptr_candidates)[0]

    # instr pointer
    if stack_ptr in instr_ptr_candidates:
        instr_ptr_candidates.remove(stack_ptr)
    print("[+] Instr ptr candidates: ", instr_ptr_candidates)
    if len(instr_ptr_candidates) != 1:
        print("\tDidn't find the instruction pointer ! Continuing.")

    # try to match the big changes of the stack pointer and of the instr pointer
    print("[+] Big reg changes :")
    stack_changes = set(big_change_indices(reg_vals['r15'], 100))
    print("\t%s:\t" % stack_ptr, sorted(stack_changes))
    diff = dict()
    reg_changes = dict()
    for reg in instr_ptr_candidates:
        reg_changes[reg] = set(big_change_indices(reg_vals[reg], 500))
        diff[reg] = reg_changes[reg].symmetric_difference(stack_changes)
        print("\t%s:\t" % reg, sorted(reg_changes[reg]), end="")
        print("\tdiff count= %d" % len(diff[reg]))
    instr_ptr_candidates = set(filter(
        lambda reg: len(diff[reg]) / float(len(stack_changes) + len(reg_changes[reg])) < 0.2,
        instr_ptr_candidates
    ))
    print("[+] Instr ptr candidates: ", instr_ptr_candidates)
    if len(instr_ptr_candidates) != 1:
        print("\tDidn't find the instruction pointer ! Aborting.")
        return 
    instr_ptr = list(instr_ptr_candidates)[0]
    
    return stack_ptr, instr_ptr



if __name__ == "__main__":
    # The trace file has one trace per line.
    # A trace consists of all instructions for a single bytecode,
    # and is encoded as a json object.
    # You should generally avoid loading the entire trace file at once,
    # as it can (theoretically) be too big to fit in memory.
    # Using 'for line in file' is safe as it loads only one line at a time.
    with open("../tracer/output/traceDump", "r") as file:
        #traces = opcodeTraces["113"] # JUMP_ABSOLUTE
        #emulate_taint(traces[0])
        """
        for line in file:
            trace = json.loads(line)
            opc, arg = get_bytecode(trace)
            print("%s: %x" % (opcodeName(opc), arg))
        """
        stack_ptr, instr_ptr = detect_regs(file)
        print("[+] Stack ptr=%s\tInstr ptr=%s" % (stack_ptr, instr_ptr))
        