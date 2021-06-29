import json
from bytecode import * 
from triton import *
from emulate import *

def get_regs_values(opcodeTraces):
    # maps : reg -> list of (initial) reg values,
    # only counting traces that actually use the register,
    # i.e. read it of write to it
    reg_vals = {
        'rax': [],
        'rbx': [],
        'rcx': [],
        'rdx': [],
        'rsi': [],
        'rdi': [],
        'rsp': [],
        'rbp': [],
        'r8': [],
        'r9': [],
        'r10': [],
        'r11': [],
        'r12': [],
        'r13': [],
        'r14': [],
        'r15': []
    }
    for opc in opcodeTraces.keys():
        for reg in reg_vals.keys():
            reg_vals[reg].append(0)

        for trace in opcodeTraces[opc]:
            for reg in reg_vals.keys():
                val = int(trace[0]['regs'][reg], 16)
                reg_vals[reg].append(val)
    return reg_vals 


def get_write_addresses(opcodeTraces):
    addresses = set()

    def add_write(write):
        addr = int(write['addr'], 16)
        size = int(write['size'], 16)
        for i in range(size):
            addresses.add(addr + i)

    for opc in opcodeTraces.keys():
        for trace in opcodeTraces[key]:
            for instr in trace:
                if instr['writes'] is not None:
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

if __name__ == "__main__":
    with open("opcode_traces.json", "r") as file:
        opcodeTraces = json.load(file)

        traces = opcodeTraces["113"] # JUMP_ABSOLUTE
        emulate_taint(traces[0])
        """
        reg_vals = get_regs_values(opcodeTraces)
        for reg in reg_vals.keys():
            align = max_align(reg_vals[reg])
            if align > 1:
                count = len(list(set(reg_vals[reg])))
                print("%s: 0x%x (distinct values: %d)" % (reg, align, count))
        """
        """
        reg_vals = get_regs_values(opcodeTraces)
        print('values taken by r15:')
        for val in reg_vals['r15']:
            print("%x" % val)
        """