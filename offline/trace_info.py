import json
from py_op import *
import os 
from unionfind import *
import sys

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

# extract the i-th byte from an integer
def extract_byte(val, i):
    return (val >> (8*i)) & 0xFF

class TraceInfo:
    def __init__(self, trace_path):
        self.file = open(trace_path, 'r')
        # the registers to look at for sp/ip/fp.
        self.regs = [
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'  
        ]
        self.bytecodes = []     # the list of all unordered bytecodes (opc + arg) read by each py_op
        self.py_ops = []        # the list of all py_ops the program contains
        self.ip_vals = []       # instruction pointer values before each opcode 
        self.sp_vals = []       # stack pointer values before each opcode
        self.frame_changes = [] # indices of the opcodes that change the frame

    def __del__(self):
        self.file.close()

    def get_fetch_dispatch(self, fd):
        self.dispatch = int(fd['dispatch'], 16)
        self.fetches = { int(fetch, 16) for fetch in fd['fetches'] }
     
    # get the bytes that are fetched from memory,
    # and check they are contiguous
    def fetch_bytes(self, trace):
        # get the (mem_addr, byte) pairs
        bytes = []
        for instr in trace:
            addr = int(instr['regs']['rip'], 16)
            if addr in self.fetches:
                for read in instr['reads']:
                    rsize = int(read['size'], 16)
                    raddr = int(read['addr'], 16)
                    rval = int(read['value'], 16)
                    if rsize <= 2:
                        for i in range(rsize):
                            bytes.append((raddr + i, extract_byte(rval, i)))
        # check they are contiguous
        bytes.sort(key = lambda x: x[0])
        raddrs, rvals = zip(*bytes)
        for i in range(len(raddrs) - 1):
            if raddrs[i+1] - raddrs[i] != 1:
                raise Exception("Fetch reads non-contiguous bytes from memory")
        # return the bytes in the order they are laid-out in memory
        return rvals

    def get_py_ops(self):
        self.file.seek(0, os.SEEK_SET)
        for line in self.file:
            trace = json.loads(line)
            bytes = self.fetch_bytes(trace)
            regs = { reg: int(val, 16) for reg, val in trace[0]['regs'].items() }
            self.py_ops.append(PyOp(bytes, regs))

    def get_reg_stats(self):
        # reg values
        self.reg_vals = { reg: [] for reg in self.regs }
        self.file.seek(0, os.SEEK_SET)
        for line in self.file:
            trace = json.loads(line)
            for reg in self.regs:
                val = int(trace[0]['regs'][reg], 16)
                self.reg_vals[reg].append(val)
        # reg changes
        self.reg_big_changes = dict()
        for reg in self.regs:
            self.reg_big_changes[reg] = set(big_change_indices(self.reg_vals[reg], 100))
        # distinct values
        self.distinct_vals = dict()
        for reg in self.regs:
            self.distinct_vals[reg] = len(set(self.reg_vals[reg]))
        # alignment
        self.align = dict()
        for reg in self.regs:
            self.align[reg] = max_align(self.reg_vals[reg])

        print("[+] Register stats")
        for reg in self.regs:
            print("\t%s: align=0x%x\tdistinct=%d" % (reg, self.align[reg], self.distinct_vals[reg]))

    def detect_frames(self):
        # This seems to work : each time there is a change in the 
        # python frame, there is also a change in the C frame 
        # (and vice versa).
        self.frame_changes = self.reg_big_changes['rsp']

        # try to detect the frame pointers :
        # a frame pointer's value should change exactly when the frame changes
        change_count = defaultdict(lambda: 0)
        stay_count = defaultdict(lambda: 0)
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
        
        print("[+] Detecting frame pointers")
        print("\tgoal_change_count=%d\tgoal_stay_count=%d" % (goal_change_count, goal_stay_count))
        fp_candidates = set()
        for reg in self.regs:
            if change_count[reg] / goal_change_count > 0.9 and \
                stay_count[reg] / goal_stay_count > 0.9:
                fp_candidates.add(reg)
                print("\t%s:\tchange=%d\tstay=%d" % (reg, change_count[reg], stay_count[reg]))

        self.fps = list(fp_candidates)
        print("[+] Frame pointers: ", self.fps)
    
    def detect_ip(self):
        print("[+] Detecting ip")
        ip_candidates = set()
        # try regs
        for reg in self.regs:
            if self.align[reg] < 2:
                continue
            if self.distinct_vals[reg] < 10:
                continue 
            # a 2-byte aligned ip is expected to increment by 2
            # a 1-byte aligned ip is expected to increment by 1
            offsets = [self.align[reg]]
            streak = max_delta_streak(self.reg_vals[reg], offsets)
            if streak < 10:
                continue 
            # ip should have big changes at frame changes.
            # ^ is symmetric difference (for sets).
            diff = len(self.reg_big_changes[reg] ^ self.frame_changes)
            if diff / len(self.reg_big_changes[reg] | self.frame_changes) > 0.2:
                continue
            ip_candidates.add(reg)
        # TODO : if we didn't find any candidate, maybe look in a memory cell instead
        # of registers ?
        if len(ip_candidates) != 1:
            print("[-] ip candidates in registers:", ip_candidates)
            print("\taborting")
            sys.exit(-1)
        # get the values that ip takes
        ip_reg = list(ip_candidates)[0]
        print("\tfound an ip register : %s" % ip_reg)
        self.ip_vals = self.reg_vals[ip_reg]

    def detect_sp(self):
        print("[+] Detecting sp")
        sp_candidates = set()
        # try regs
        for reg in self.regs:
            if self.align[reg] > 8:
                continue
            if self.distinct_vals[reg] < 10:
                continue
            # an 8-byte aligned sp is expected to increment by small multiples of 8
            # a 1-byte aligned sp is expected to increment by small multiples of 1
            # I didn't include 0 in the offsets so that we don't mistake a frame pointer for sp.
            offsets = [ofs * self.align[reg] for ofs in [-2, -1, 1, 2]]
            streak = max_delta_streak(self.reg_vals[reg], offsets)
            if streak < 10:
                continue 
            # sp should have big changes at frame changes
            diff = len(self.reg_big_changes[reg] ^ self.frame_changes)
            if diff / len(self.reg_big_changes[reg] | self.frame_changes) > 0.2:
                continue
            sp_candidates.add(reg)
        # Too many registers passed the conditions
        if len(sp_candidates) > 1:
            print("\tsp candidates in registers:", sp_candidates)
            print("\taborting")
            sys.exit(-1)
        # We found sp !
        if len(sp_candidates) == 1:
            sp_reg = list(sp_candidates)[0]
            self.sp_vals = self.reg_vals[sp_reg]
            print("\tfound an sp register : %s" % sp_reg)
            return 
        # TODO : detect sp in memory cells

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
            # arbitrary interval (found by trial and error).
            # higher or lower violates the constraints that:
            #   - blocks should not overlap
            #   - a block's entrypoint should be at its minimal address
            if next - curr <= 32: 
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