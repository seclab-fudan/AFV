import json
import logging
import os.path
from typing import Dict, List, Set, Tuple, Union

import py2neo

from config.path import STORAGE_PATH
from core.anchor_node import AnchorNode
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.modified_line import ModifiedLine
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.range_step import RangeStep

logger = logging.getLogger(__name__)

COMMON_NODE_TYPES = [
        TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL,
        TYPE_NEW,
        TYPE_INCLUDE_OR_EVAL,
        TYPE_ECHO, TYPE_PRINT, TYPE_EXIT
]

TRAVERSAL_REPORT_THRESHOLD = 2
CONFIG_TAINT_DYNAMIC_CALL_FLAG = True

FUNCTION_MODEL = {
        7: ["include", "require", "include_once", "require_once"],
        2: ["file", "file_get_contents", "readfile", "fopen"],
        1: ["unlink", "rmdir"],
        12: ["file_put_contents", "fopen", "fwrite"],
        10: ["echo", "print", "print_r", "die"],
        4: ["exec", "passthru", "proc_open", "system", "shell_exec", "popen", "pcntl_exec"],
        3: ["eval", 'create_function', 'assert', 'array_map', 'preg_replace'],
        6: ["copy", "fopen", "move_uploaded_file", "rename"],
        13: ["header", ],
        8: ["unserialize", ],
        9: ["pg_query", "pg_send_query", "pg_prepare", "mysql_query", "mysqli_prepare", "mysqli_query",
            "mysqli_real_query", ]
}


class AnchorFinderConfigure(object):
    def __init__(self, level: Union[int, Dict] = None):
        default_level = 0
        if level is None:
            level = default_level
        self.__level = level
        self.__default_config = {
                0: {'__callee_depth': 0b0001},
                1: {'__callee_depth': 0b0011}}
        self.__max_level = max(self.__default_config.keys())
        if isinstance(level, int):
            assert level in self.__default_config.keys()
            self.__callee_depth = self.__default_config[level]['__callee_depth']
        elif isinstance(level, Dict):
            self.__callee_depth = \
                level.pop('__callee_depth',
                          self.__default_config[default_level]['__callee_depth'])

    @property
    def configure_level(self) -> int:
        return self.__level

    @property
    def configure_max_level(self) -> int:
        return self.__max_level

    @property
    def rule_callee_depth(self) -> int:
        return self.__callee_depth


class CacheCenter(object):
    def __init__(self):
        self.already_traversal_node = {}
        self.already_detect_functions = {}
        self.already_visit_pdg_node = set()
        self.already_taint_edge: List[Tuple] = []

    def clear_cache(self):
        self.__init__()

    def update_already_taint_edge(self, start, end):
        self.already_taint_edge.append((start, end))
        self.already_taint_edge.sort(key=lambda x: x[0])

    def is_taint_by_cfg(self, node_id):
        for _range in self.already_taint_edge:
            if _range[0] <= node_id <= _range[1]:
                return True
        return False

    def update_already_detect_functions(self, node_hash, value):
        if node_hash not in self.already_detect_functions.keys():
            self.already_detect_functions[node_hash] = value
        else:
            self.already_detect_functions[node_hash] = value | self.already_detect_functions[node_hash]


class AcnhorNodeList(Set):
    def __init__(self):
        super(AcnhorNodeList, self).__init__()

    def add(self, __object, analyzer: Neo4jEngine) -> None:
        ADD_FLAG = True
        _obj_ast = analyzer.basic_step.get_node_itself(__object.node_id)
        vars = analyzer.code_step.find_variables(_obj_ast)
        if vars.__len__() >= 1:
            def_nodes = analyzer.pdg_step.find_def_nodes(_obj_ast)
            _flag = 0
            for def_node in def_nodes:
                if def_node[NODE_TYPE] in {TYPE_ASSIGN, TYPE_ASSIGN_OP, TYPE_ASSIGN_REF}:
                    src_var = analyzer.code_step.get_node_code(analyzer.ast_step.get_ith_child_node(def_node, 0))
                    if src_var in vars:
                        if analyzer.ast_step.get_ith_child_node(def_node, 1)[NODE_TYPE] in COMMON_VAR_TYPES:
                            _flag |= (1 << (vars.index(src_var)))
                        else:
                            _flag &= ((1 << vars.__len__()) - 1) ^ (1 << (vars.index(src_var)))
            if _flag == (1 << vars.__len__()) - 1:
                ADD_FLAG = False
        if ADD_FLAG:
            old_len = self.__len__()
            super(AcnhorNodeList, self).add(__object)
            new_len = self.__len__()


class AnchorFinder(object):
    def __compile_anchor_functions(self, vuln_type: int):
        if isinstance(vuln_type, int) or (isinstance(vuln_type, str) and vuln_type.isdigit()):
            assert int(vuln_type) in FUNCTION_MODEL.keys(), f'[*] the vuln type id {vuln_type} not in list'
            self.anchor_functions = FUNCTION_MODEL[int(vuln_type)]
        else:
            raise NotImplementedError(f"error type for vuln_type  {type(vuln_type)}")

    def __init__(self, analysis_framework: Neo4jEngine, git_repository, commit_id,
                 vuln_type: int,
                 select_file: Union[str] = None, config_level=None, cve_id=None):
        self.__vt = None
        self.analyzer = analysis_framework
        self.analyzer.range_step = RangeStep(self.analyzer)
        self.patch_commit_id = commit_id
        self.git_repository = git_repository
        self.potential_anchor_nodes: AcnhorNodeList[AnchorNode] = AcnhorNodeList()
        self.anchor_functions = []
        self.__compile_anchor_functions(vuln_type)
        self.patch_analysis_result: Dict[str, List[ModifiedLine]] = \
            json.load(object_hook=lambda x: ModifiedLine(**x) if 'lineno' in x.keys() else x,
                      fp=open(os.path.join(STORAGE_PATH, 'patch_analysis_result', f'res_{commit_id}.json')))
        if select_file is not None:
            self.patch_analysis_result = {k: v for k, v in self.patch_analysis_result.items() if k in select_file}
        self.__cache_center = CacheCenter()
        self.__delay_nodes = []
        self.configure = AnchorFinderConfigure(config_level)
        self.cve_id = cve_id if cve_id is not None else "CVE-0000-0000"
        self._f_insert = lambda n, judge_type=0b0001, loc=-1: self.potential_anchor_nodes.add(
                AnchorNode.from_node_instance(
                        n, judge_type=judge_type, git_repository=self.git_repository,
                        version=f"{self.patch_commit_id}_prepatch",
                        func_name=self.analyzer.code_step.get_node_code(n), param_loc=loc,
                        file_name=self.analyzer.fig_step.get_belong_file(n),
                        cve_id=self.cve_id
                ), self.analyzer
        )

    def _find_outside_exit_identifier(self, cycle_exit_identifier, input_node):
        for _cycle_exit_identifier in cycle_exit_identifier:
            if input_node == _cycle_exit_identifier[0]:
                input_node = self._find_outside_exit_identifier(cycle_exit_identifier, _cycle_exit_identifier[1])
        return input_node

    def forward_cfg_traversal(self, node, cycle_exit_identifier=None, parent_cfg_node=None, node_range=None):
        if node_range is None:
            node_range = [0, 0xfeef]
        if cycle_exit_identifier is None:
            cycle_exit_identifier = {(-0xcaff, -0xcaff)}

        if node_range[0] > node[NODE_INDEX] or node[NODE_INDEX] > node_range[1]:
            return None
        if node is None or node.labels.__str__() != ":" + LABEL_AST:
            return None
        node = self._find_outside_exit_identifier(cycle_exit_identifier, node)
        if node[NODE_LINENO] is None:
            return None

        if parent_cfg_node is not None:
            if node[NODE_LINENO] < parent_cfg_node[NODE_LINENO]:
                if node[NODE_LINENO] == 1 and node[NODE_TYPE] == TYPE_NULL:
                    return
            if parent_cfg_node[NODE_INDEX] not in self.__cache_center.already_traversal_node:
                self.__cache_center.already_traversal_node[parent_cfg_node[NODE_INDEX]] = 1
            else:
                self.__cache_center.already_traversal_node[parent_cfg_node[NODE_INDEX]] += 1

            if self.__cache_center.already_traversal_node[parent_cfg_node[NODE_INDEX]] >= TRAVERSAL_REPORT_THRESHOLD:
                return

        parent_node = self.analyzer.ast_step.get_parent_node(node)

        if parent_node[NODE_TYPE] in {TYPE_WHILE}:
            for _node in self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES):
                self.slice_func_in_line(_node)
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[1].end_node))
                self.forward_cfg_traversal(node=cfg_rel.end_node,
                                           parent_cfg_node=cfg_rel.start_node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0:
            for _node in self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES):
                self.slice_func_in_line(_node)

            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel_true, cfg_rel_false = cfg_rels
                self.forward_cfg_traversal(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cycle_exit_identifier=cycle_exit_identifier,
                        node_range=node_range
                )
                self.forward_cfg_traversal(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cycle_exit_identifier=cycle_exit_identifier,
                        node_range=node_range
                )
            elif cfg_rels == 1:
                cfg_rel_true, cfg_rel_false = cfg_rels
                self.forward_cfg_traversal(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cycle_exit_identifier=cycle_exit_identifier,
                        node_range=node_range
                )
                self.forward_cfg_traversal(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cycle_exit_identifier=cycle_exit_identifier,
                        node_range=node_range
                )
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_FOR} and node[NODE_CHILDNUM] == 1:
            for _node in self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES):
                self.slice_func_in_line(_node)

            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add(
                        (self.analyzer.ast_step.get_ith_child_node(parent_node, i=2), cfg_rels[1].end_node))

                self.forward_cfg_traversal(node=cfg_rel.end_node,
                                           parent_cfg_node=cfg_rel.start_node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
            else:
                pass
        elif node[NODE_TYPE] in {TYPE_FOREACH}:
            for __node in self.analyzer.ast_step.find_child_nodes(node):
                if __node[NODE_TYPE] == TYPE_STMT_LIST: continue
                self.slice_func_in_line(__node)

            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                if cfg_rels[0]['flowLabel'] == 'complete':
                    complete_index, next_index = 0, 1
                else:
                    complete_index, next_index = 1, 0
                cfg_rel = cfg_rels[next_index]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[complete_index].end_node))
                self.forward_cfg_traversal(node=cfg_rel.end_node,
                                           parent_cfg_node=cfg_rel.start_node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_TRY}:
            raise NotImplementedError()
        elif parent_node[NODE_TYPE] in {TYPE_SWITCH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels[-1][CFG_EDGE_FLOW_LABEL] == 'default':
                cfg_rels[-1][
                    CFG_EDGE_FLOW_LABEL] = f"! ( in_array( {TMP_PARAM_FOR_SWITCH},{[i[CFG_EDGE_FLOW_LABEL] for i in cfg_rels[:-2]]}) )"
            for index in range(cfg_rels.__len__()):
                self.forward_cfg_traversal(node=cfg_rels[index].end_node,
                                           parent_cfg_node=cfg_rels[index].start_node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
        else:
            self.slice_func_in_line(node)
            if node[NODE_TYPE] == TYPE_RETURN:
                arg_node = self.analyzer.ast_step.find_function_arg_node_list(node)[-1]
                if self.analyzer.code_step.find_variables(arg_node, VAR_TYPES_EXCLUDE_CONST_VAR):
                    self.__delay_nodes.append(node)
            cfg_next_node = self.analyzer.cfg_step.find_successors(node)
            if cfg_next_node.__len__() == 1:
                pass
            elif cfg_next_node.__len__() == 0:
                return
            else:
                pass
            cfg_next_node = cfg_next_node[-1]
            if node[NODE_TYPE] in {TYPE_EXIT}:
                self.forward_cfg_traversal(node=cfg_next_node, parent_cfg_node=None,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
            else:
                self.forward_cfg_traversal(node=cfg_next_node, parent_cfg_node=node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)

    def _anchor_function_analysis(self, node: py2neo.Node, TAINT_DYNAMIC_CALL_FLAG: bool = None) -> int:
        if node[NODE_TYPE] in {TYPE_ECHO, TYPE_PRINT}:
            if self.anchor_functions == FUNCTION_MODEL[10]:
                nn = self.analyzer.ast_step.filter_child_nodes(_node=node, node_type_filter=VAR_TYPES_EXCLUDE_CONST_VAR)
                if nn.__len__() >= 1:
                    return 0b10
                else:
                    return 0b00
            else:
                return 0b00
        elif node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL} \
                and node[NODE_FLAGS][-1] in \
                {FLAG_EXEC_INCLUDE, FLAG_EXEC_INCLUDE_ONCE, FLAG_EXEC_REQUIRE, FLAG_EXEC_REQUIRE_ONCE}:
            if self.anchor_functions == FUNCTION_MODEL[7]:
                return 0b10
            else:
                return 0b00
        elif node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL} \
                and node[NODE_FLAGS][-1] in {FLAG_EXEC_EVAL}:
            if self.anchor_functions == FUNCTION_MODEL[4]:
                return 0b10
            else:
                return 0b00
        code = self.analyzer.code_step.get_node_code(node)
        if code in self.anchor_functions:
            return 0b10
        if code in PHP_BUILT_IN_FUNCTIONS and node[NODE_TYPE] == TYPE_CALL:
            return 0b00
        if node[NODE_TYPE] in {TYPE_NEW, TYPE_STATIC_CALL, TYPE_CALL, TYPE_METHOD_CALL}:
            if self.analyzer.cg_step.find_decl_nodes(node):
                return 0b01
            elif self.anchor_functions == FUNCTION_MODEL[9] \
                    and self.analyzer.code_step.get_node_code(node) in {"SelectLimit", "Execute"}:
                return 0b10
            else:
                return 0b00
        return 0b00

    def anchor_function_analysis(self, node, current_level=1, TAINT_DYNAMIC_CALL_FLAG: bool = True):
        if current_level >= self.configure.rule_callee_depth:
            return 0b00
        assert node[NODE_TYPE] in {TYPE_FUNC_DECL, TYPE_METHOD}
        node_hash = f"{node[NODE_INDEX]}::{self.analyzer.code_step.get_node_code(node)}"
        if node_hash in self.__cache_center.already_detect_functions.keys():
            return self.__cache_center.already_detect_functions[node_hash]
        nodes_todo_analysis = self.analyzer.ast_step.filter_child_nodes(node, max_depth=100,
                                                                        node_type_filter=COMMON_NODE_TYPES)
        if nodes_todo_analysis.__len__() == 0:
            self.__cache_center.update_already_detect_functions(node_hash, 0b00)

        for node_todo_analysis in nodes_todo_analysis:
            result = self._anchor_function_analysis(node_todo_analysis, TAINT_DYNAMIC_CALL_FLAG=TAINT_DYNAMIC_CALL_FLAG)
            if result == 0b00:
                self.__cache_center.update_already_detect_functions(node_hash, 0b00)
            elif result == 0b01 and self.analyzer.cg_step.find_decl_nodes(node_todo_analysis):
                _f = self.anchor_function_analysis(self.analyzer.cg_step.find_decl_nodes(node_todo_analysis)[-1],
                                                   current_level + 1, )
                self.__cache_center.update_already_detect_functions(node_hash, _f)
            elif result == 0b01 and not self.analyzer.cg_step.find_decl_nodes(node_todo_analysis):
                self.__cache_center.update_already_detect_functions(node_hash, 0b00)
            elif result == 0b10:
                self.__cache_center.update_already_detect_functions(node_hash, 0b10)
            else:
                raise NotImplementedError()
        return self.__cache_center.already_detect_functions[node_hash]

    def slice_func_in_line(self, node) -> bool:
        nodes_todo_analysis = self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES)
        for node_todo_analysis in nodes_todo_analysis:
            flag = self._anchor_function_analysis(node_todo_analysis, )
            if flag == 0b00:
                continue
            elif flag == 0b10:
                self._f_insert(node_todo_analysis, )
            elif flag == 0b01:
                res = self.anchor_function_analysis(self.analyzer.cg_step.find_decl_nodes(node_todo_analysis)[-1])
                if res == 0b10:
                    self._f_insert(node_todo_analysis, )
        return True

    def forward_pdg_traversal(self, node):
        _node = self.analyzer.get_ast_root_node(node)
        if _node.identity in self.__cache_center.already_visit_pdg_node:
            return
        else:
            self.__cache_center.already_visit_pdg_node.add(_node.identity)
        self.slice_func_in_line(_node)

        if node[NODE_TYPE] == TYPE_RETURN:
            arg_node = self.analyzer.ast_step.find_function_arg_node_list(node)[-1]

            if self.analyzer.code_step.find_variables(arg_node, VAR_TYPES_EXCLUDE_CONST_VAR):
                self.__delay_nodes.append(node)

        _reach_to_nodes = self.analyzer.pdg_step.find_use_nodes(_node)
        if _reach_to_nodes.__len__() == 0:
            return

        for _reach_to_node in _reach_to_nodes:
            self.forward_pdg_traversal(_reach_to_node)

    def traversal_initiation(self, node) -> Tuple[List[py2neo.Node], List[py2neo.Node]]:
        result_cfg_pdg_begin_lines = []
        result_pdg_begin_lines = []
        node = self.analyzer.get_node_itself(node)
        if node[NODE_TYPE] in {TYPE_THROW}:
            node = self.analyzer.ast_step.get_child_node(node)
        parent_node = self.analyzer.ast_step.get_parent_node(node)
        if node[NODE_TYPE] in {TYPE_ASSIGN, TYPE_ASSIGN_OP, TYPE_ASSIGN_REF}:
            rr = self.analyzer.pdg_step.find_use_nodes(node)
            if not rr:
                l_var = self.analyzer.ast_step.get_child_node(node)
                if l_var[NODE_TYPE] == TYPE_DIM and self.analyzer.code_step.get_ast_dim_code(l_var).endswith("[]"):
                    start, end = self.analyzer.range_step.get_general_node_range(
                            self.analyzer.get_node_itself(node[NODE_FUNCID]))
                    for _node, in self.analyzer.basic_step.run(
                            "MATCH (B:AST)-[:PARENT_OF]->(C:AST) "
                            f"WHERE B.type = '{TYPE_VAR}'"
                            f" AND C.code = '{self.analyzer.code_step.get_ast_dim_code(l_var).rstrip('[]').lstrip('$')}'"
                            f" AND B.id>={start} and B.id <= {end} "
                            f" RETURN B;"
                    ):
                        result_pdg_begin_lines.append(_node)
            else:
                result_pdg_begin_lines.append(node)
            rr = []
        elif parent_node[NODE_TYPE] in {TYPE_THROW}:
            rr = []
        elif (parent_node[NODE_TYPE] in {TYPE_FOR} and node[NODE_CHILDNUM] == 1) or \
                (parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0) or \
                (node[NODE_TYPE] in {TYPE_FOREACH}) or \
                (node[NODE_TYPE] in {TYPE_WHILE}):
            start, end = self.analyzer.range_step.get_general_node_range(node)
            self.__cache_center.update_already_taint_edge(start, end)
            rr = [node]
        elif node[NODE_TYPE] in {TYPE_EXIT}:
            if self.anchor_functions == FUNCTION_MODEL[10] and node[NODE_TYPE] in {TYPE_EXIT}:
                self._f_insert(node, 0b0001, 0)
            self.slice_func_in_line(node)
            rr = self.analyzer.cfg_step.find_successors(node)
        elif node[NODE_TYPE] in {TYPE_CALL, TYPE_STATIC_CALL, TYPE_METHOD_CALL, TYPE_NEW}:
            if self.analyzer.cg_step.find_decl_nodes(node):
                is_anchor_function = self.anchor_function_analysis(self.analyzer.cg_step.find_decl_nodes(node)[0])
                if is_anchor_function:
                    self._f_insert(node, 0b0010, -1)
            rr = []
        elif node[NODE_TYPE] in {TYPE_UNSET, TYPE_ECHO, TYPE_PRINT}:
            for _node in self.analyzer.ast_step.find_child_nodes(node):
                self.slice_func_in_line(_node)
            rr = []
        else:
            rr = []
        result_cfg_pdg_begin_lines.extend(rr)
        global_vars = self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=[TYPE_DIM], )
        rr = [i for i in global_vars if
              self.analyzer.code_step.get_ast_dim_body_code(i) in {"_POST", "_GET", "_FILE", "_SESSION", "_COOKIE"}]
        result_cfg_pdg_begin_lines.extend(rr)
        if self.analyzer.code_step.get_node_code(node) in self.anchor_functions \
                and self.analyzer.ast_step.get_function_arg_node_cnt(node) >= 1 \
                and self.analyzer.code_step.find_variables(node, VAR_TYPES_EXCLUDE_CONST_VAR):
            self._f_insert(node, 0b0001, 0)
        elif node[NODE_TYPE] == TYPE_RETURN:
            self.__delay_nodes.append(node)
        elif self.analyzer.basic_step.get_node_itself(node[NODE_FUNCID])[NODE_TYPE] in {TYPE_FUNC_DECL, TYPE_METHOD}:
            for x in self.analyzer.ast_step.find_function_return_expr(
                    self.analyzer.basic_step.get_node_itself(node[NODE_FUNCID])):
                if x[NODE_INDEX] >= node[NODE_INDEX]:
                    self.__delay_nodes.append(x)
        return result_pdg_begin_lines, result_cfg_pdg_begin_lines

    def traversal(self):
        for file, affect_line in self.patch_analysis_result.items():
            traversal_structure_pure_pdg: List[py2neo.Node] = []
            traversal_structure_cfg_pdg: List[py2neo.Node] = []
            for affect_node in affect_line:
                pure_pdg, cfg_pdg = self.traversal_initiation(affect_node.root_node, )
                traversal_structure_pure_pdg.extend(pure_pdg)
                traversal_structure_cfg_pdg.extend(cfg_pdg)
            traversal_structure_pure_pdg = sorted(set(traversal_structure_pure_pdg), key=lambda x: x.identity)
            traversal_structure_cfg_pdg = sorted(set(traversal_structure_cfg_pdg), key=lambda x: x.identity)
            for node in traversal_structure_pure_pdg:
                self.forward_pdg_traversal(node)
            for node in traversal_structure_cfg_pdg:
                if node.labels.__str__() == ":Artificial": continue
                _range = self.analyzer.range_step.get_general_node_range(node)
                self.forward_cfg_traversal(node, node_range=_range)
            if self.potential_anchor_nodes.__len__() == 0:
                if self.__delay_nodes.__len__() >= 1 \
                        and self.configure.configure_level == self.configure.configure_max_level:
                    for i in self.__delay_nodes:
                        if i[NODE_TYPE] != TYPE_RETURN: continue
                        arg_node = self.analyzer.ast_step.find_function_arg_node_list(i)[-1]
                        if self.analyzer.code_step.find_variables(arg_node, VAR_TYPES_EXCLUDE_CONST_VAR):
                            self._f_insert(i, 0b1000, 0)
        return not (self.potential_anchor_nodes.__len__() == 0 and
                    self.configure.configure_level < self.configure.configure_max_level)
