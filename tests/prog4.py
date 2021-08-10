class Toto:
    def __init__(self):
        self.x = 42
    def do_stuff(self, y):
        self.x += y * self.get_stuff()[0]
    def get_stuff(self):
        return (self.x, self.x + 1)

f = open("file", "w")
for i in range(100):
    t = Toto()
    if i % 2 == 1:
        x = 0
        while x < 10:
            t.do_stuff(3)
            x += 2
            f.write(str(x))
        x = t.get_stuff()[1]
    else:
        if not t:
            t.do_stuff(5)
