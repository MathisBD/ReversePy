import sys
import marshal
import dis


def view_pyc_file(path):
    """Read and display a content of the Python`s bytecode in a pyc-file."""
    file = open(path, 'rb')
    file.read(16) # header
    code = marshal.load(file)
    dis.disassemble(code)
    file.close()


if __name__ == '__main__':
    view_pyc_file(sys.argv[1])