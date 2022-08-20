import logging
from typing import Tuple

import py2neo

from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.neo4j_engine.steps import AbstractStep

logger = logging.getLogger(__name__)


class RangeStep(AbstractStep):
    def __init__(self, parent: Neo4jEngine):
        super().__init__(parent, "range_step")
        assert isinstance(self.parent, Neo4jEngine)

        self.__range_cache = {}

    def get_general_node_range(self, node: py2neo.Node, use_cache=True) -> Tuple[int, int]:
        parent_node = self.parent.ast_step.get_parent_node(node, ignore_error_flag=True)
        node_hash = f"{self.get_general_node_range.__name__}{node.identity.__str__()} "
        if node_hash not in self.__range_cache.keys():
            if node[NODE_TYPE] in {TYPE_FOREACH}:
                end_id = self.parent.cfg_step.find_successors(node)[-1][NODE_INDEX]
                if end_id > node[NODE_INDEX]:
                    node_range = (node[NODE_INDEX], end_id)
                    self.__range_cache[node_hash] = node_range
                else:
                    raise NotImplementedError()
            elif node[NODE_TYPE] in {TYPE_WHILE}:
                pass
                raise NotImplementedError()
            elif parent_node is not None and parent_node[NODE_TYPE] in {TYPE_IF_ELEM}:
                if self.parent.cfg_step.find_successors(node).__len__() == 0:
                    logger.fatal(f"no flows to node for node {node}")
                    node_range = (parent_node[NODE_INDEX], parent_node[NODE_INDEX] + 500)
                else:
                    node_range = (
                            parent_node[NODE_INDEX], self.parent.cfg_step.find_successors(node)[-1][NODE_INDEX] - 1)
                self.__range_cache[node_hash] = node_range
            else:
                reg_function = [i for i in self.__dir__() if not i.__str__().startswith("_")]
                if "get_{}_node_range".format(node[NODE_TYPE].lower()) not in reg_function:
                    node_range = (node[NODE_INDEX], self.parent.ast_step.filter_child_nodes(node)[-1][NODE_INDEX])
                else:
                    node_range = eval("self.get_{}_node_range(node)".format(node[NODE_TYPE].lower()))
                self.__range_cache[node_hash] = node_range
        return self.__range_cache[node_hash]

    def get_if_code_range(self, node: py2neo.Node) -> Tuple[int, int]:
        pass

    def get_ast_func_decl_range(self, node: py2neo.Node) -> Tuple[int, int]:
        assert node[NODE_TYPE] == TYPE_FUNC_DECL
        RR = self.parent.basic_step.match_first(LABEL_AST,
                                                **{NODE_FILEID: node[NODE_FILEID], NODE_LINENO: node[NODE_ENDLINENO]})
        if not RR:
            RR = self.parent.basic_step.match_first(LABEL_AST, **{NODE_FILEID: node[NODE_FILEID],
                                                                  NODE_LINENO: node[NODE_ENDLINENO] - 1})
        if not RR:
            logger.fatal("endlineno is wriong or need enhancement")
        end_line_root_node = self.parent.ast_step.get_root_node(RR)
        last_node = self.parent.ast_step.find_child_nodes(end_line_root_node)[-1]
        return node[NODE_INDEX], last_node[NODE_INDEX]

    def get_ast_method_range(self, node: py2neo.Node) -> Tuple[int, int]:
        assert node[NODE_TYPE] == TYPE_METHOD
        RR = self.parent.basic_step.match_first(LABEL_AST,
                                                **{NODE_FILEID: node[NODE_FILEID], NODE_LINENO: node[NODE_ENDLINENO]})
        if not RR:
            RR = self.parent.basic_step.match_first(LABEL_AST, **{NODE_FILEID: node[NODE_FILEID],
                                                                  NODE_LINENO: node[NODE_ENDLINENO] - 1})
        if not RR:
            logger.fatal("endlineno is wriong or need enhancement")
        end_line_root_node = self.parent.ast_step.get_root_node(RR)
        last_node = self.parent.ast_step.filter_child_nodes(end_line_root_node)[-1]
        return node[NODE_INDEX], last_node[NODE_INDEX]
