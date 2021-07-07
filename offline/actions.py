
class Action:
    pass

def format_offset(ofs):
    if ofs >= 0:
        return "+ 0x%x" % ofs 
    else:
        return "- 0x%x" % abs(ofs)

# IP <- IP + k
class JmpRel(Action):
    def __init__(self, ofs):
        self.ofs = ofs
    def __repr__(self):
        return "ip <- ip %s" % format_offset(self.ofs)

# IP <- IP + arg + k
class JmpRelArg(Action):
    def __init__(self, ofs):
        self.ofs = ofs
    def __repr__(self):
        return "ip <- ip + arg %s" % format_offset(self.ofs)
       
# IP <- block-start + arg + k
class JmpAbs(Action):
    def __init__(self, ofs):
        self.ofs = ofs 
    def __repr__(self):
        return "ip <- block-start + arg %s" % format_offset(self.ofs)

# IP <- EITHER (IP + k1) OR (IP + arg + k2)
class JmpCond(Action):
    def __init__(self, ofs_rel, ofs_rel_arg):
        self.ofs_rel = ofs_rel 
        self.ofs_rel_arg = ofs_rel_arg
    def __repr__(self):
        return "ip <- EITHER ip %s OR ip + arg %s" % \
            (format_offset(self.ofs_rel), format_offset(self.ofs_rel_arg))


"""
# IP <- entry(block)
class BlockJmp(Action):
    def __repr__(self):
        return "ip <- new-block"
"""

# SP <- SP + k
class SpOfs(Action):
    def __init__(self, ofs):
        self.ofs = ofs 
    def __repr__(self):
        return "sp <- sp %s" % format_offset(self.ofs)

# SP <- SP + arg + k
class SpOfsPlusArg(Action):
    def __init__(self, ofs):
        self.ofs = ofs 
    def __repr__(self):
        return "sp <- sp + arg %s" % format_offset(self.ofs)
        
# SP <- SP - arg + k
class SpOfs(Action):
    def __init__(self, ofs):
        self.ofs = ofs 
    def __repr__(self):
        return "sp <- sp - arg %s" % format_offset(self.ofs)
        