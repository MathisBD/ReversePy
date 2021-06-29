import capstone as cap
import os
import json
from collections import defaultdict

class TraceExtractor:
    def __init__(self, trace_path, code_path):
        self.trace_file = open(trace_path, "r")
        self.code_file = open(code_path, "r")
        self.md = cap.Cs(cap.CS_ARCH_X86, cap.CS_MODE_64)
        self.exec_count = defaultdict(lambda: 0)
        self.fetch_addr = 0
        self.reached_trace_eof = False 

    def __del__(self):
        self.trace_file.close()
        self.code_file.close()

    @staticmethod
    def instr_addr(instr):
        return int(instr['regs']['rip'], 16)

    @staticmethod
    def instr_opcodes(instr):
        return bytes([int(op, 16) for op in instr['opcodes']])

    def disassemble(self, instr):
        opcodes = bytes([int(op, 16) for op in instr['opcodes']])
        cs_instrs = list(self.md.disasm(opcodes, 0x0))

        if len(cs_instrs) != 1:
            raise ValueError("opcodes %s don't correspond to an instruction" % str(opcodes))
        
        return cs_instrs[0]
        
    # possible fetch : movzx that reads a 2 bytes value from memory
    def is_possible_fetch(self, instr):
        i = self.disassemble(instr)
        if i.mnemonic == "movzx":
            if 'reads' in instr:
                for read in instr['reads']:
                    if int(read['size'], 16) == 2:
                        return True
        return False

    def calculate_stats(self, fetch_freq_threshold):
        # calculate exec counts
        self.code_file.seek(0, os.SEEK_SET)
        code = json.load(self.code_file)
        for key in code.keys():
            addr = int(key, 16)
            self.exec_count[addr] = code[key]['exec_count']
        # get the fetch
        fetches = set()
        self.trace_file.seek(0, os.SEEK_SET)
        for line in self.trace_file:
            instr = json.loads(line)
            addr = TraceExtractor.instr_addr(instr)
            if self.is_possible_fetch(instr) and self.exec_count[addr] >= fetch_freq_threshold:
                fetches.add(addr)
            
        fetches = list(fetches)
        print("[+] Possible fetches :", fetches)
        if len(fetches) != 1:
            raise Exception("didn't find the interpreter fetch")
        self.fetch_addr = fetches[0]
        self.trace_file.seek(0, os.SEEK_SET)

    # get the bytecode read by a fetch instruction
    def get_bytecode(self, instr):
        bytecodes = set()
        for read in instr['reads']:
            if int(read['size'], 16) == 2:
                bc = int(read['value'], 16) & 0xFFFF
                bytecodes.add(bc)
        bytecodes = list(bytecodes)
        if len(bytecodes) != 1:
            raise Exception("fetch instruction reads more than one 2-byte memory location")
        return bytecodes[0]
    
    def skip_to_fetch(self):
        while True:
            line = self.trace_file.readline()
            # no fetch left
            if len(line) == 0:
                raise Exception("skip_to_fetch: reached end of file")
            instr = json.loads(line)
            if TraceExtractor.instr_addr(instr) == self.fetch_addr:
                return instr

    # extract a single opcode trace from the trace dump file
    def extract_trace(self):
        # a trace should start with a fetch :
        # otherwise, skip to the next fetch
        fetch = self.skip_to_fetch()

        trace = [fetch]
        while True:
            ofs = self.trace_file.tell()
            line = self.trace_file.readline()
            # end of file
            if len(line) == 0:
                self.reached_trace_eof = True
                return trace
            instr = json.loads(line)
            if TraceExtractor.instr_addr(instr) == self.fetch_addr:
                self.trace_file.seek(ofs, os.SEEK_SET)
                return trace 
            trace.append(instr)
