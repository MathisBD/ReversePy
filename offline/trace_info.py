import json
from py_op import *
import os 
from unionfind import *
import sys

# calculate the greatest power of two that divides
# every value in a list, except the None values
def max_align(vals):
    def is_aligned(vals, d):
        for v in vals:
            if v is not None and v % d != 0:
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
    if len(set(vals)) == 1 and vals[0] is None:
        return 0
    if only_zeros(vals):
        return 0
    # main loop
    d = 1
    while d <= 64:
        if is_aligned(vals, 2*d):
            d *= 2
        else:
            return d
    return d

"""
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
"""

def big_change_indices(l, threshold):
    indices = []
    for i in range(len(l)-1):
        if abs(l[i+1] - l[i]) >= threshold:
            indices.append(i)
    return indices 

# extract the i-th byte from an integer
def extract_byte(val, i):
    return (val >> (8*i)) & 0xFF

def all_equal(vals):
    if len(vals) == 0:
        return True 
    for v in vals:
        if v != vals[0]:
            return False 
    return True 

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
        # return the (mem_addr, byte) list
        return bytes

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
        self.frame_changes = set(big_change_indices(
            self.reg_vals['rsp'],
            100
        ))

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
            # frame pointers are aligned on a machine word boundary (8 bytes)
            if change_count[reg] / goal_change_count > 0.9 and \
                stay_count[reg] / goal_stay_count > 0.9 and \
                self.align[reg] >= 8:
                fp_candidates.add(reg)
                print("\t%s:\tchange=%d\tstay=%d" % (reg, change_count[reg], stay_count[reg]))

        self.fps = list(fp_candidates)
        print("\tframe pointers: ", self.fps)
    
    def get_ip_values(self):
        # It doesn't get any simpler than this.
        for op in self.py_ops:
            self.ip_vals.append(op.opc_addr)
        self.ip_align = max_align(self.ip_vals)

    def is_possible_sp(self, vals):
        align = max_align(vals)
        if align > 8: 
            return False
        if len(set(vals)) < 10:
            return False 
        # an 8-byte aligned sp is expected to increment by small multiples of 8
        # a 1-byte aligned sp is expected to increment by small multiples of 1
        # I didn't include 0 in the offsets so that we don't mistake a frame pointer for sp.
        offsets = [ofs * align for ofs in [-2, -1, 1, 2]]
        max_streak = 0
        curr_streak = 0
        pops = 0
        nones = 0
        for i in range(len(vals) - 1):
            # frame changes break the relationships between
            # the values of sp
            if i in self.frame_changes:
                continue 
            if vals[i] is None:
                nones += 1
                continue 
            if vals[i+1] is None:
                continue
            # update the offset streak
            if (vals[i+1] - vals[i]) in offsets:
                curr_streak += 1
                max_streak = max(max_streak, curr_streak)
            else:
                curr_streak = 0
            # update the pop count
            if vals[i+1] - vals[i] == -align:
                pops += 1
        # sp should be read/written most of the time
        if nones / float(len(vals)) >= 0.5:
            return False 
        # a reasonnable proportion of the opcodes should
        # pop the stack (e.g. all arithmetic operations do)
        if pops / float(len(vals)) < 0.1:
            return False 
        if max_streak < 10:
            return False 
        return True 
        
    # returns the initial contents of all the 8-byte ALIGNED memory 
    # accessed by an opcode trace
    def get_initial_mem(self, trace):
        mem = dict()
        def update_mem(access):
            addr = int(access['addr'], 16)
            val = int(access['value'], 16)
            if addr % 8 == 0 and addr not in mem:
                mem[addr] = val

        for instr in trace:
            if 'reads' in instr:
                for read in instr['reads']:
                    update_mem(read)
            if 'writes' in instr:
                for write in instr['writes']:
                    update_mem(write)
        return mem

    # returns the list of values taken by each memory cell
    # that is at a fixed offset from a frame pointer.
    # e.g.: if %esp and %ebx are frame pointers, this returns 
    # the values taken in 0(%esp), 8(%esp), 16(%esp), 24(%esp), ...  
    # and in 0(%ebx), 8(%ebx), ...
    def get_frame_mem(self, ofs_count):
        # vals[fp][ofs][i] is the value taken by [fp + 8*ofs] before opcode i.
        vals = dict()
        for fp in self.fps:
            vals[fp] = []
            for ofs in range(ofs_count):
                vals[fp].append([])
        # return all the (fp, ofs) pairs that correspond to a memory address
        def all_fp_ofs(i, addr):
            for fp in self.fps:
                base = self.reg_vals[fp][i]
                assert base % 8 == 0
                q = (addr - base) // 8
                r = (addr - base) % 8
                if r == 0 and 0 <= q < ofs_count:
                    yield fp, q 

        # go through the whole trace
        self.file.seek(0)
        for i, line in enumerate(self.file):
            trace = json.loads(line)
            # values we read/write
            mem = self.get_initial_mem(trace)
            for addr in mem:
                for fp, ofs in all_fp_ofs(i, addr):
                    assert len(vals[fp][ofs]) == i
                    vals[fp][ofs].append(mem[addr])
            # unknown values
            for fp in self.fps:
                for ofs in range(ofs_count):
                    assert len(vals[fp][ofs]) in [i, i+1]
                    # we don't have the value yet
                    if len(vals[fp][ofs]) == i:
                        v = None 
                        # try to reuse the previous value
                        """
                        addr = self.reg_vals[fp][i] + 8*ofs
                        if i > 0 and self.reg_vals[fp][i] == self.reg_vals[fp][i-1] and
                            not written[i-1][addr]:
                            v = vals[fp][ofs][i-1] 
                        """
                        vals[fp][ofs].append(v)
        return vals 
        

    def get_sp_values(self):
        print("[+] Detecting sp")
        # try registers 
        count = 0
        for reg in self.regs:
            if self.is_possible_sp(self.reg_vals[reg]):
                print("\tSp candidate in reg %s" % reg)
                self.sp_vals = self.reg_vals[reg]
                self.sp_align = max_align(self.sp_vals)
                count += 1
        if count == 1:
            print("\tFound sp in register !")
            return 
        # try memory cells
        count = 0
        vals = self.get_frame_mem(10)
        for fp in self.fps:
            for ofs in range(len(vals[fp])):
                if self.is_possible_sp(vals[fp][ofs]):
                    print("\tSp candidate at [%s + 0x%x]" % (fp, 8*ofs))
                    self.sp_vals = vals[fp][ofs]
                    self.sp_align = max_align(self.sp_vals)
                    count += 1
        if count == 1:
            print("Found sp in memory cell!")
            return 
        print("[-] Didn't find sp! aborting")
        sys.exit(-1)

    # Partition the python instructions into blocks according
    # to their address in memory.
    # Ideally we want the instruction blocks to match functions 
    # (i.e. each function corresponds to a single block), 
    # but we may only be able to associate a function with several 
    # (non-overlapping) instruction blocks. It should hold that 
    # a block is included in a function.
    def detect_instr_blocks(self):
        u = UnionFind(self.ip_vals)
        # instructions in the same frame are in the same block
        for i in range(len(self.py_ops) - 1):
            if i not in self.frame_changes:
                u.union(self.ip_vals[i], self.ip_vals[i+1])
        # instructions close together in memory are in the same block
        sorted_addrs = sorted(self.ip_vals)
        for i in range(len(sorted_addrs) - 1):
            curr = sorted_addrs[i]
            next = sorted_addrs[i+1]
            # arbitrary interval (found by trial and error).
            # higher or lower violates the constraints that:
            #   - blocks should not overlap
            #   - a block's entrypoint should be at its minimal address
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
        for op, ip in zip(self.py_ops, self.ip_vals):
            op.block = block_idx(ip)