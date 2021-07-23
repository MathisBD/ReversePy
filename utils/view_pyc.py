import sys
import marshal
import dis

def view_py_opcodes(path):
    file = open(path, 'r')
    instrs = dis.get_instructions(file.read())
    for instr in instrs:
        print(hex(instr.opcode), instr.opname,
            hex(instr.arg) if instr.arg is not None else 0)


def view_pyc_file(path):
    file = open(path, 'rb')
    file.read(16) # header
    code = marshal.load(file)
    dis.dis(code)
    file.close()


if __name__ == '__main__':
    #view_pyc_file(sys.argv[1])
    view_py_opcodes(sys.argv[1])