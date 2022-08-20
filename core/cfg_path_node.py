import py2neo


class CFGPathNode(object):
    def __init__(self, node: py2neo.Node, parent_node: py2neo.Node, edge_property=None):
        self.node = node
        self.parent_node = parent_node
        self.edge_property = edge_property if edge_property is not None else {}

    def __str__(self):
        return f"{self.parent_node.__str__()} -> {self.node.__str__()} with property {self.edge_property}"

    def __eq__(self, other):
        return self.node == other.node \
               and self.parent_node == other.parent_node \
               and self.edge_property == other.edge_property

    def __hash__(self):
        return hash((self.node, self.parent_node))
