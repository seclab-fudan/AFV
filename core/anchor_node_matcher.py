import copy
import logging
import re
from typing import Union

import py2neo

from config import FILE_NAME_COMMON_PREFIX
from core.anchor_node import AnchorNode, BaseNode, get_specify_parent_node
from core.ast2code import Ast2CodeFactory
from core.fingerprint_extractor import FingerprintExtractor
from core.helper import StorageHelper, StringMatcher
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *

logger = logging.getLogger(__name__)


class AnchorNodeMatcher(object):
    def __init__(self, high_version_anchor: Union[AnchorNode, BaseNode],
                 high_version_analyzer: Neo4jEngine,
                 low_version_analyzer: Neo4jEngine,
                 high_version_prefix: str,
                 low_version_prefix: str,
                 node_trace_function=StorageHelper.get_series):
        self.low_version_prefix = low_version_prefix
        self.high_version_prefix = high_version_prefix
        self.high_version_analyzer = high_version_analyzer
        self.low_version_analyzer = low_version_analyzer
        self.node_trace_function = node_trace_function
        self.high_version_node_trace = self.node_trace_function(high_version_anchor)
        self.low_version_node_traces = []
        self.high_version_anchor = high_version_anchor
        self.low_version_anchor = copy.deepcopy(high_version_anchor)
        self.low_version_anchor.version = low_version_prefix[low_version_prefix.index("-") + 1:]
        self.low_version_anchor.node_id = -1
        self.high_version_buffer = ""
        self.low_version_buffers = []
        self.match_score = []
        self.match_index = -1
        self.node_type = None

    @staticmethod
    def __get_func_or_file_name(analyzer: Neo4jEngine, node: py2neo.Node):
        rt_value = ""
        top_node = analyzer.basic_step.get_node_itself(node[NODE_FUNCID])
        if top_node[NODE_TYPE] in {TYPE_METHOD, TYPE_FUNC_DECL}:
            rt_value = analyzer.code_step.get_node_code(top_node)
        elif top_node[NODE_TYPE] in {TYPE_TOPLEVEL}:
            rt_value = re.sub(FILE_NAME_COMMON_PREFIX, "", top_node[NODE_NAME])
        elif top_node[NODE_TYPE] in {TYPE_CLOSURE}:
            rt_value = "anonymous_function"
        assert rt_value != ""
        return rt_value

    def node_filter(self, _potential_anchor_nodes):
        potential_anchor_nodes = []
        arg = sorted(
            self.high_version_analyzer.code_step.find_variables(
                self.high_version_analyzer.get_node_itself(self.high_version_anchor.node_id),
                target_type=VAR_TYPES_EXCLUDE_CONST_VAR))
        func_or_file_name = AnchorNodeMatcher.__get_func_or_file_name(
            self.high_version_analyzer,
            self.high_version_analyzer.get_node_itself(self.high_version_anchor.node_id))
        self.high_version_analyzer.clear_cache()
        _args = map(lambda x: sorted(
            self.low_version_analyzer.code_step.find_variables(x,
                                                               target_type=VAR_TYPES_EXCLUDE_CONST_VAR)),
                    _potential_anchor_nodes)
        _func_or_file_name = map(lambda x: AnchorNodeMatcher.__get_func_or_file_name(self.low_version_analyzer, x),
                                 _potential_anchor_nodes)
        for _arg, _func_name, _potential_anchor_node in zip(_args, _func_or_file_name, _potential_anchor_nodes):
            if func_or_file_name == _func_name and _arg == arg:
                potential_anchor_nodes.append(_potential_anchor_node)
        return potential_anchor_nodes

    def run_with_fingerprint(self, commit_id, verbose=1, overwrite_low_buffer=True,
                             node_type=None, abstract_level=0):
        self.node_type = node_type
        potential_anchor, reason = self.match_node()

        if potential_anchor is not None:
            potential_anchor = self.node_filter(potential_anchor)
            if potential_anchor.__len__() == 0:
                reason = f"NO FUNC {self.high_version_anchor.func_name}"

        if potential_anchor is not None and potential_anchor.__len__() > 0:
            potential_anchor_ids = [i[NODE_INDEX] for i in potential_anchor]
            self.compare_node_with_fingerprint(potential_anchor, verbose=verbose, overwrite=overwrite_low_buffer,
                                               abstract_level=abstract_level, commit_id=commit_id)
        else:
            potential_anchor_ids = []

        open(StorageHelper.get_node_matching_storage(self.low_version_anchor), 'a').write(
            f"{self.high_version_anchor.version},"
            f"{self.high_version_anchor.node_id},"
            f"{self.low_version_anchor.version},"
            f"{self.low_version_anchor.node_id},"
            f"\"{potential_anchor_ids}\","
            f"\"{self.match_score}\","
            f"\"{reason}\","
            f"{int(__import__('time').time())}"
            f"\n"
        )

    def compare_node_with_fingerprint(self, potential_anchors, commit_id, overwrite=True, verbose=0,
                                      abstract_level=0):
        self.high_version_buffer = "".join(
            Ast2CodeFactory.extract_code(
                self.high_version_analyzer,
                self.high_version_analyzer.get_node_itself(node_id)
            ) + "\n" for node_id in self.high_version_node_trace
        )
        self.high_version_analyzer.clear_cache()
        fingerprint_extractor = FingerprintExtractor(anchor_node=self.low_version_anchor,
                                                     analyzer=self.low_version_analyzer, commit_id=commit_id)
        for potential_anchor in potential_anchors:
            fingerprint_extractor.clear_cache()
            fingerprint_extractor.anchor_node.node_id = potential_anchor[NODE_INDEX]
            fingerprint_extractor.anchor_node.get_more_info(fingerprint_extractor.analyzer)
            fingerprint_extractor.anchor_node_ast = None
            low_version_buffer = ""
            try:
                fingerprint_extractor.run()
                low_version_buffer = "".join(
                    Ast2CodeFactory.extract_code(
                        self.low_version_analyzer,
                        self.low_version_analyzer.get_node_itself(node_id)
                    ) + "\n" for node_id in fingerprint_extractor.fingerprint_series
                )
            except Exception as e:
                logger.fatal(e)
            self.low_version_buffers.append(low_version_buffer)

        self.match_score = StringMatcher.similarity_array(org_str=self.high_version_buffer,
                                                          given=self.low_version_buffers,
                                                          prehandle_func=StringMatcher.fingerprint_pre_handler)
        self.match_index = self.match_score.index(max(self.match_score))
        self.low_version_anchor.node_id = potential_anchors[self.match_index][NODE_INDEX]

    def match_node(self):
        high_version_file = self.high_version_anchor.file_name
        self.high_version_analyzer.clear_cache()
        self.low_version_anchor.file_name = high_version_file.replace(self.high_version_prefix,
                                                                      self.low_version_prefix)
        return self._match_low_version_potential_node()

    def _match_low_version_potential_node(self):
        self.high_version_analyzer.clear_cache()
        top_file_node = self.low_version_analyzer.fig_step.get_file_name_node(self.high_version_anchor.file_name)
        if top_file_node is None:
            return None, ""
        fileid = top_file_node[NODE_FILEID]
        anchor_node = self.high_version_anchor
        if {anchor_node.func_name} & {'include', 'include_once', 'require', 'require_once', 'eval'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_INCLUDE_OR_EVAL)
        elif {anchor_node.func_name} & {'echo'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_ECHO)
        elif {anchor_node.func_name} & {'print'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_PRINT)
        elif {anchor_node.func_name} & {'die', 'exit'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_EXIT)
        elif {anchor_node.func_name} & {'return'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_RETURN)
        else:
            nodes = []
            if "::" in anchor_node.func_name:
                func_name = anchor_node.func_name[anchor_node.func_name.index("::") + "::".__len__():]
            elif "->" in anchor_node.func_name:
                func_name = anchor_node.func_name[anchor_node.func_name.index("->") + "->".__len__():]
            else:
                func_name = anchor_node.func_name
            _nodes = self.low_version_analyzer.match(fileid=fileid, code=func_name)
            for _n in _nodes:
                __n = get_specify_parent_node(self.low_version_analyzer, _n, FUNCTION_CALL_TYPES)
                if __n is not None:
                    nodes.append(__n)
        potential_anchor = []
        for node in nodes:
            cnt = self.low_version_analyzer.ast_step.get_function_arg_node_cnt(node)
            if cnt - 1 < max(self.low_version_anchor.param_loc):
                continue
            if self.node_type is not None:
                if self.node_type == node[NODE_TYPE]:
                    if self.node_type == TYPE_ECHO:
                        if self.low_version_analyzer. \
                                ast_step.get_function_arg_ith_node(node, 0)[NODE_TYPE] == TYPE_STRING:
                            continue
                    potential_anchor.append(node)
        if potential_anchor.__len__() == 0:
            return None, "NO FUNC " + self.low_version_anchor.func_name
        return potential_anchor, ""
