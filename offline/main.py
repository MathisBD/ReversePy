import triton as tri
import sys
sys.path.append('/usr/lib')
import capstone as cap
import os
import json
from collections import defaultdict

class TraceExtractor:
    def __init__(self, file_path, fetch_freq_threshold):
        self._file = open(file_path, "r")
        self._md = cap.Cs(cap.CS_ARCH_X86, cap.CS_MODE_64)
        self._exec_count = defaultdict(lambda: 0)
        self._fetch_addr = 0
        self._fetch_freq_threshold = fetch_freq_threshold

    def __del__(self):
        self._file.close()

    def _disassemble(self, instr):
        opcodes = bytes([int(op, 16) for op in instr['opcodes']])
        cs_instrs = list(self._md.disasm(opcodes, 0x0))

        if len(cs_instrs) != 1:
            raise ValueError("opcodes %s don't correspond to an instruction" % str(opcodes))
        
        return cs_instrs[0]
        
    # possible fetch : movzx that reads a 2 bytes value from memory
    def _is_possible_fetch(self, instr):
        i = self._disassemble(instr)
        if i.mnemonic == "movzx":
            if 'reads' in instr:
                for read in instr['reads']:
                    if int(read['size'], 16) == 2:
                        #print("%s\t%s" % (i.mnemonic, i.op_str))
                        return True
        return False

    def _calculate_stats(self):
        self._file.seek(0, os.SEEK_SET)
        fetches = set()
        for i, line in enumerate(self._file):
            instr = json.loads(line)
            addr = int(instr['regs']['rip'], 16)
            # increase exec count
            self._exec_count[addr] += 1
            # determine if this is a possible fetch
            #print("0x%x: %s" % (addr, opcodes))
            if self._is_possible_fetch(instr):
                fetches.add(addr)

            if i % 100000 == 0:
                print(i)
        
        fetches = filter(
            lambda fetch: self._exec_count[fetch] >= self._fetch_freq_threshold, 
            fetches)
        fetches = list(fetches)

        print("[+] Possible fetches :", fetches)
        if len(fetches) != 1:
            raise Exception("didn't find the interpreter fetch")
        self._fetch_addr = fetches[0]
            
    # extract a single opcode trace from the trace dump file
    def extract_trace(self):
        self._calculate_stats()
        #self._fetch_addr = 94499132524356
        self._file.seek(0, os.SEEK_SET)
        for line in self._file:
            instr = json.loads(line)
            if int(instr['regs']['rip'], 16) == self._fetch_addr:
                i = self._disassemble(instr)
                print("%s\t%s" % (i.mnemonic, i.op_str))
                break



if __name__ == "__main__":
    te = TraceExtractor("../tracer/output/traceDump", 9000)
    #ctx = tri.TritonContext(tri.ARCH.X86_64)
    te.extract_trace()
    