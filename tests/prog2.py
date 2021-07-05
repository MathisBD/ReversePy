
def func(f, i):
    return f.write("%d" % i)

# An example program to analyze
f = open("tototo", "w")
for i in range(1000):
    func(f, i)