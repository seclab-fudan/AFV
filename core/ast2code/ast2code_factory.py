from typing import List, Union

import py2neo

from .symbolic_tracking import SymbolicTracking


class Ast2CodeFactory(object):
    @staticmethod
    def extract_code(analyzer, feeder: Union[List, int, py2neo.Node]):
        if isinstance(feeder, List) and feeder.__len__() == 0:
            raise IndexError("feeder must contain at least one node")
        st = SymbolicTracking(analyzer)
        if isinstance(feeder, List) and isinstance(feeder[0], int):
            res = ""
            for node_id in feeder:
                _res = st.extract_code(analyzer.get_node_itself(node_id))
                if _res != "":
                    res += _res + "\n"
            return res
        elif isinstance(feeder, List) and isinstance(feeder[0], py2neo.Node):
            res = ""
            for node_id in feeder:
                _res = st.extract_code(analyzer.get_node_itself(node_id))
                if _res != "":
                    res += _res + "\n"
            return res
        elif isinstance(feeder, py2neo.Node):
            return st.extract_code(feeder)
        elif isinstance(feeder, int):
            return st.extract_code(analyzer.get_node_itself(feeder))
