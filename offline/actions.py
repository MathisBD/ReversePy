
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

# IP <- EITHER (IP + k1) OR (block-start + arg + k2)
class JmpCond(Action):
    def __init__(self, ofs_rel, ofs_abs):
        self.ofs_rel = ofs_rel 
        self.ofs_abs = ofs_abs
    def __repr__(self):
        return "ip <- EITHER ip %s OR block-start + arg %s" % \
            (format_offset(self.ofs_rel), format_offset(self.ofs_abs))


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

# SP <- SP + A*arg + k
# A is the alignment of SP (e.g. : 8 or 1)
class SpOfsPlusArg(Action):
    def __init__(self, align, ofs):
        self.ofs = ofs
        self.align = align 
    def __repr__(self):
        return "sp <- sp + %d*arg %s" % (self.align, format_offset(self.ofs))
        
# SP <- SP - A*arg + k
# A is the alignment of SP (e.g. : 8 or 1)
class SpOfsMinusArg(Action):
    def __init__(self, align, ofs):
        self.ofs = ofs
        self.align = align 
    def __repr__(self):
        return "sp <- sp - %d*arg %s" % (self.align, format_offset(self.ofs))
        