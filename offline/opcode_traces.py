from trace import TraceExtractor
from trace import *
from bytecode import *
from collections import defaultdict
import json 

# this is a bit long to execute (a few minutes)
def generate_opcode_traces(file, max_traces_per_opcode):
    te = TraceExtractor("../tracer/output/traceDump", "../tracer/output/code_dump")
    #te.calculate_stats(9000)
    te.fetch_addr = 94509679728452
        
    # generate opcode traces
    opcodeTraces = defaultdict(lambda: [])
    while True:
        trace = te.extract_trace()
        if te.reached_trace_eof:
            # don't save the last trace, it may contain
            # a lot of extra instructions not part of the vm loop
            break 
        bc = te.get_bytecode(trace[0])
        opcode = opcodeFromBytecode(bc)
        if len(opcodeTraces[opcode]) < max_traces_per_opcode and \
            len(trace) < 1000:
            opcodeTraces[opcode].append(trace)

    # save the opcode traces
    json.dump(dict(opcodeTraces), file)
        

if __name__ == "__main__":
    with open("opcode_traces.json", "w") as file:
        generate_opcode_traces(file, 20)