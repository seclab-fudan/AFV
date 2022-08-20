from collections import OrderedDict
from typing import Dict, List


class SliceResult(object):
    def __init__(self, flow: List[int], tags: Dict[int, bool]):
        self.flow = flow
        self.tags = OrderedDict(tags)

    def __str__(self):
        return self.flow.__str__() + "\n" + self.tags.__str__() + "\n"

    def __repr__(self):
        return self.flow.__str__() + "\n" + self.tags.__str__() + "\n"

    def __lt__(self, other):
        assert isinstance(other, SliceResult)
        FLAG = True
        for (k1, v1), (k2, v2) in zip(self.tags.items(), other.tags.items()):
            if k1 != k2:
                return k1 < k2
            else:
                if v1 != v2:
                    return v1 < v2
                else:
                    continue

    @staticmethod
    def _sort(a, b):
        return a.keys() > b.keys()

    def to_lineno(self, neo4j_engine):
        neo4j_engine.get_node_itself()
