
def fact(n):
    if n <= 0:
        return 1
    return n * fact(n-1)

def func(f, i):
    return f.write("%d" % i)

print(fact(5))

# An example program to analyze
f = open("tototo", "w")
for i in range(1000):
    func(f, i)