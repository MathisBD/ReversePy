from collections import defaultdict


class UnionFind:
    def __init__(self, vals):
        self.parent = { v: v for v in vals }

    # get a representant of the set i is in
    def find(self, i):
        if i == self.parent[i]:
            return i
        p = self.find(self.parent[i])
        self.parent[i] = p
        return p

    # merge the sets that contain i and j
    def union(self, i, j):
        pi = self.find(i)
        pj = self.find(j)
        if pi != pj:
            self.parent[pi] = pj 
        
    # return the list of all sets in the structure
    def get_sets(self):
        bag = defaultdict(lambda: set())
        for i in self.parent.keys():
            bag[self.find(i)].add(i)
        return list(bag.values())