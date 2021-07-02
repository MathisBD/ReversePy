import py_compile
import dis 

def func(f, i):
    return f.write("%d" % i)

print(dis.dis(func))
