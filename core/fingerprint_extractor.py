import logging

import networkx as nx
import py2neo

from core.anchor_node import AnchorNode
from core.cfg_path_node import CFGPathNode
from core.helper import StorageHelper
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *

logger = logging.getLogger(__name__)


class FingerprintExtractor(object):
    def __init__(self, anchor_node: AnchorNode, analyzer: Neo4jEngine, commit_id):
        self.analyzer = analyzer
        self.FLAG_A = True
        self.slice_result = []
        self.slice_conditions = {}
        self.anchor_node = anchor_node
        self.commit_id = commit_id
        self.anchor_node_ast = None
        self.far_node = None
        self.pdg_digraph = nx.DiGraph()
        self.cfg_digraph = nx.DiGraph()
        self.taint_param = set()
        self.__backup_anchor_node_id = -1

    def clear_cache(self):
        self.FLAG_A = True
        self.slice_result = []
        self.slice_conditions = {}
        self.anchor_node_ast = None
        self.far_node = None
        self.pdg_digraph = nx.DiGraph()
        self.cfg_digraph = nx.DiGraph()
        self.taint_param = set()

    def run(self, verbose=0):
        self.do_backward_slice(verbose=verbose)
        self.do_forward_path_exploration(verbose=verbose)
        self.anchor_node.node_id = self.__backup_anchor_node_id
        self.storage_result_fingerprint()

    def storage_result_fingerprint(self):
        fingerprint_series = set()
        for k in self.pdg_digraph.nodes.keys():
            fingerprint_series.add(k)

        for k, v in self.cfg_digraph.nodes.items():
            if 'is_control_node' in v.keys() and v['is_control_node']:
                fingerprint_series.add(k)
        fingerprint_series = sorted(fingerprint_series)
        StorageHelper. \
            store_series(self.anchor_node, fingerprint_series,
                         readable=[self.analyzer.get_node_itself(i)[NODE_LINENO] \
                                   for i in fingerprint_series])
        self.fingerprint_series = fingerprint_series

    def do_backward_slice(self, verbose=0):
        self.__backup_anchor_node_id = self.anchor_node.node_id

        taint_param = set()
        if self.anchor_node_ast is None:
            self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
        self._do_backward_slice(self.anchor_node_ast, None, self.anchor_node_ast[NODE_INDEX], taint_param)
        self.far_node = min(self.pdg_digraph.nodes.keys())
        self.taint_param = taint_param

    def _do_backward_slice(self, node, parent_node=None, id_threshold=0xff, taint_param: set = None):
        if node is None:
            return None
        if node[NODE_INDEX] > id_threshold:
            return None
        self.pdg_digraph.add_node(
                node[NODE_INDEX], add_rels="PDG", root_node_id=node[NODE_INDEX], lineno=node[NODE_LINENO],
        )
        if parent_node is not None:
            assert taint_param is not None
            if self.pdg_digraph.has_edge(node[NODE_INDEX], parent_node[NODE_INDEX]):
                return
            else:
                self.pdg_digraph.add_edge(
                        node[NODE_INDEX], parent_node[NODE_INDEX], add_rels='PDG', tant_param=taint_param
                )
        else:
            if not self.analyzer.cfg_step.has_cfg(node):
                node = self.analyzer.ast_step.get_root_node(node)
                if node[NODE_TYPE] in {TYPE_IF, TYPE_IF_ELEM, TYPE_WHILE, TYPE_DO_WHILE}:
                    node = self.analyzer.get_control_node_condition(node)

        def_nodes = self.analyzer.pdg_step.find_def_nodes(node)
        if node in def_nodes:
            def_nodes.pop(def_nodes.index(node))
        for pdg_parent in def_nodes:
            if pdg_parent[NODE_TYPE] == TYPE_PARAM:
                continue
            if pdg_parent[NODE_INDEX] > id_threshold: continue
            if parent_node is None:
                self._do_backward_slice(pdg_parent, parent_node=node, id_threshold=pdg_parent[NODE_INDEX],
                                        taint_param=taint_param)
            else:
                var = self.analyzer.neo4j_graph.relationships.match([pdg_parent, node],
                                                                    r_type=DATA_FLOW_EDGE).first()['var']
                taint_param.add(var)
                self._do_backward_slice(pdg_parent, parent_node=node, id_threshold=pdg_parent[NODE_INDEX],
                                        taint_param=taint_param)

    def do_forward_path_exploration(self, verbose=0):
        far_node_ast = self.analyzer.get_node_itself(self.far_node)

        if self.anchor_node_ast[NODE_LINENO] == far_node_ast[NODE_LINENO]:
            return

        cfg_path = set()
        cycle_exit_identifier = set()
        self._do_forward_path_exploration(node=far_node_ast, cfg_path=cfg_path, parent_cfg_node=None,
                                          threshold=[far_node_ast[NODE_INDEX], self.anchor_node_ast[NODE_INDEX]],
                                          cycle_exit_identifier=cycle_exit_identifier)
        for cfg_path_node in cfg_path:
            end = cfg_path_node.node
            start = cfg_path_node.parent_node
            if end[NODE_INDEX] > self.anchor_node_ast[NODE_INDEX] and end[NODE_LINENO] > self.anchor_node_ast[
                NODE_LINENO]:
                continue
            edge_property = cfg_path_node.edge_property
            self.cfg_digraph.add_node(start[NODE_INDEX], lineno=start[NODE_LINENO], type=start[NODE_TYPE])
            self.cfg_digraph.add_node(end[NODE_INDEX], lineno=end[NODE_LINENO], type=end[NODE_TYPE])
            if 'flowLabel' in edge_property.keys():
                if edge_property['flowLabel'] == '1':
                    edge_property['flowLabel'] = 'True'
                elif edge_property['flowLabel'] == '0':
                    edge_property['flowLabel'] = 'False'
            self.cfg_digraph.add_edge(start[NODE_INDEX], end[NODE_INDEX], **edge_property)

        for node_id, out_degree in list(self.cfg_digraph.out_degree):
            if out_degree >= 2:
                if out_degree == 2:
                    self.cfg_digraph.nodes[node_id]["is_control_node"] = True
                else:
                    self.cfg_digraph.nodes[node_id]['is_control_node'] = True
                    if self.analyzer.get_ast_parent_node(
                            self.analyzer.get_node_itself(node_id))[NODE_TYPE] == TYPE_SWITCH:
                        pass
        for _node_id in (k for k, v in self.cfg_digraph.nodes.items() if 'is_control_node' in v.keys()):
            _control_node_instance = self.analyzer.get_node_itself(_node_id)
            self._do_control_root_param_fix(_control_node_instance, None, _node_id, set())

    def _do_control_root_param_fix(self, node, parent_node=None, id_threshold=0xff, taint_param: set = None):
        if node is None:
            return None
        if node[NODE_INDEX] > id_threshold:
            return None
        self.pdg_digraph.add_node(node[NODE_INDEX])
        if parent_node is not None:
            assert taint_param is not None
            self.pdg_digraph.add_edge(
                    node[NODE_INDEX], parent_node[NODE_INDEX], add_rels='PDG',
            )
        node = self.analyzer.get_ast_root_node(node)
        def_nodes = self.analyzer.pdg_step.find_def_nodes(node)
        if node in def_nodes:
            def_nodes.pop(def_nodes.index(node))
        for def_node in def_nodes:
            if def_node[NODE_INDEX] > id_threshold: continue
            var = self.analyzer.neo4j_graph.relationships.match([def_node, node],
                                                                r_type=DATA_FLOW_EDGE).first()['var']
            if parent_node is None:
                taint_param.add(var)
            self._do_control_root_param_fix(def_node, parent_node=node, id_threshold=def_node[NODE_INDEX],
                                            taint_param=taint_param)

    def do_result_collection(self):
        return self.slice_conditions, self.slice_result

    def _do_forward_path_exploration(self, node: py2neo.Node, cfg_path: set,
                                     threshold=None,
                                     parent_cfg_node: py2neo.Node = None,
                                     cycle_exit_identifier: set = None, **kwargs):
        if cycle_exit_identifier is None:
            cycle_exit_identifier = {(-0xcaff, -0xcaff)}
        if threshold is None:
            threshold = [-0xff, 0xffff]

        threshold_bottom, threshold_upper = threshold

        if node is None or node.labels.__str__() != ":" + LABEL_AST:
            return None
        if node[NODE_INDEX] < threshold_bottom or node[NODE_INDEX] > threshold_upper:
            return None
        node = self._find_outside_exit_identifier(cycle_exit_identifier, node)
        if node[NODE_LINENO] is None:
            return None

        if parent_cfg_node is not None:
            obj = CFGPathNode(node=node, parent_node=parent_cfg_node, edge_property=kwargs.pop('edge_property', None))
            if node[NODE_LINENO] < parent_cfg_node[NODE_LINENO]:
                pass
            if obj not in cfg_path:
                cfg_path.add(obj)
            else:
                return

        parent_node = self.analyzer.ast_step.get_parent_node(node)

        if parent_node[NODE_TYPE] in {TYPE_WHILE}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[1].end_node))
                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_path=cfg_path,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel_true, cfg_rel_false = cfg_rels
                self._do_forward_path_exploration(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cfg_path=cfg_path, cycle_exit_identifier=cycle_exit_identifier,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_true['flowLabel']},
                )
                self._do_forward_path_exploration(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cfg_path=cfg_path, cycle_exit_identifier=cycle_exit_identifier,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_false['flowLabel']},
                )
            elif cfg_rels == 1:
                cfg_rel_true, cfg_rel_false = cfg_rels
                self._do_forward_path_exploration(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cfg_path=cfg_path, cycle_exit_identifier=cycle_exit_identifier,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_true['flowLabel']},
                )
                self._do_forward_path_exploration(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cfg_path=cfg_path, cycle_exit_identifier=cycle_exit_identifier,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_false['flowLabel']},
                )
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_FOR} and node[NODE_CHILDNUM] == 1:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add(
                        (self.analyzer.ast_step.get_ith_child_node(parent_node, i=2), cfg_rels[1].end_node))

                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_path=cfg_path,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif node[NODE_TYPE] in {TYPE_FOREACH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                if cfg_rels[0]['flowLabel'] == 'complete':
                    complete_index, next_index = 0, 1
                else:
                    complete_index, next_index = 1, 0
                cfg_rel = cfg_rels[next_index]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[complete_index].end_node))
                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_path=cfg_path,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_TRY}:
            pass
        elif parent_node[NODE_TYPE] in {TYPE_SWITCH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels[-1][CFG_EDGE_FLOW_LABEL] == 'default':
                cfg_rels[-1][
                    CFG_EDGE_FLOW_LABEL] = f"! ( in_array( {TMP_PARAM_FOR_SWITCH},{[i['flowLabel'] for i in cfg_rels[:-2]]}) )"
            for index in range(cfg_rels.__len__()):
                self._do_forward_path_exploration(node=cfg_rels[index].end_node, cfg_path=cfg_path,
                                                  parent_cfg_node=cfg_rels[index].start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper],
                                                  edge_property={"flowLabel": f"\'{cfg_rels[index]['flowLabel']}\'"})
        else:
            cfg_next_node = self.analyzer.cfg_step.find_successors(node)
            if cfg_next_node.__len__() == 0:
                return
            cfg_next_node = cfg_next_node[-1]
            if node[NODE_TYPE] in {TYPE_EXIT}:
                self._do_forward_path_exploration(node=cfg_next_node, cfg_path=cfg_path, parent_cfg_node=None,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                self._do_forward_path_exploration(node=cfg_next_node, cfg_path=cfg_path, parent_cfg_node=node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])

    def _find_outside_exit_identifier(self, cycle_exit_identifier, input_node):
        for _cycle_exit_identifier in cycle_exit_identifier:
            if input_node == _cycle_exit_identifier[0]:
                input_node = self._find_outside_exit_identifier(cycle_exit_identifier, _cycle_exit_identifier[1])
        return input_node
