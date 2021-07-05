
class Action:
    pass

# IP <- IP + k
class RelJmp(Action):
    def __init__(self, ofs):
        self.ofs = ofs
    def __repr__(self):
        if self.ofs >= 0:
            return "ip <- ip + 0x%x" % self.ofs
        else: 
            return "ip <- ip - 0x%x" % abs(self.ofs)
            
# IP <- entry(block k)
class BlockJmp(Action):
    def __repr__(self):
        return "ip <- new-block"

# SP <- SP + k
class SpOfs(Action):
    def __init__(self, ofs):
        self.ofs = ofs 
    def __repr__(self):
        if self.ofs >= 0:
            return "sp <- sp + 0x%x" % self.ofs 
        else:
            return "sp <- sp - 0x%x" % abs(self.ofs)
     
# SP[i-1] <- SP[i-1] OP SP[i]
class StackArith(Action):
    pass
# etc



class FrameAction:
    pass 
