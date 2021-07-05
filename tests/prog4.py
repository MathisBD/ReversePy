class Toto:
    def __init__(self):
        self.x = 42
    
    def do_stuff(self, y):
        self.x += y * self.get_stuff()

    def get_stuff(self):
        return self.x

for i in range(1000):
    t = Toto()
    t.do_stuff(3)
print("hi")
