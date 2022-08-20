import json
import logging
import os
import sys

import pandas as pd

from config import DATA_INPUT_PATH, GIT_URL_DICT
from core.anchor_node_finder import AnchorFinder
from core.anchor_node_matcher import AnchorNodeMatcher
from core.fingerprint_extractor import FingerprintExtractor
from core.helper import StorageHelper, StringFilter
from core.neo4j_connector_center import Neo4jConnectorCenter
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.patch_analyzer import PatchAnalyzer
from core.patch_extender import PatchExtender

logger = logging.getLogger(__name__)
cve_id = sys.argv[1]
version = sys.argv[2]

report = lambda value: logger.info(f"The version {version} of {cve_id} is {value}")


def main():
    obj = json.load(fp=open(os.path.join(DATA_INPUT_PATH, "cve.json"), 'r', encoding='utf-8'))
    if cve_id in obj['Piwigo']:
        repository_name = "Piwigo"
    else:
        repository_name = "mantisbt"
    cve_obj = obj[repository_name][cve_id]
    logger.info(f"[*] Start analyzing whether {cve_id} affect {version} in {repository_name}")
    pe = PatchExtender(repository_name=repository_name, fixing_commits=cve_obj['fixing_commits'])
    pe.run()
    matrix = []
    pe.result_patched = pe.result_patched & set(StorageHelper.get_github_tag_versions_in_gt(repository_name))
    if version in pe.result_patched:
        report("unaffected")
        sys.exit(0)
    else:
        for fixing_commit in pe.result_similar:
            rt = run(_map_key_1=f"{repository_name}-{fixing_commit}_prepatch",
                     _map_key_2=f"{repository_name}-{version}",
                     _map_key_3=f"{repository_name}-{fixing_commit}_postpatch",
                     vuln_type=cve_obj['vuln_type'])
            matrix.extend(rt)
    if min(matrix) == -1.0:
        logger.info("error in processing , please check your neo4j connector")
    else:
        if max(matrix) > 0.9999:
            report("affected")
        elif 0.0 <= max(matrix) < 0.0001:
            report("unaffected")
        else:
            report("unknown")


def run(_map_key_1, _map_key_2, _map_key_3, vuln_type):
    git_repository, __ = StringFilter.filter_map_key_to_git_repository_and_version(_map_key_1)
    node_mapping_path = StorageHelper.get_node_matching_storage(git_repository)
    commit_id = StringFilter.filter_normalized_commit_id(__)
    analyzer_pre = Neo4jEngine.from_dict(
            Neo4jConnectorCenter.from_map(_map_key_1)
    )
    analyzer_post = Neo4jEngine.from_dict(
            Neo4jConnectorCenter.from_map(_map_key_3)
    )
    analyzer_target = Neo4jEngine.from_dict(
            Neo4jConnectorCenter.from_map(_map_key_2)
    )
    patch_analyzer = PatchAnalyzer(analyzer_pre, analyzer_post,
                                   commit_url=GIT_URL_DICT[git_repository] + '/commit/' + commit_id,
                                   commit_id=commit_id, cve_id=cve_id)
    patch_analyzer.run_result()
    default_config_level, is_find_flag = 0, False
    anchor_node_list = []
    while not is_find_flag:
        potential_anchor_finder = AnchorFinder(analyzer_pre,
                                               commit_id=commit_id,
                                               vuln_type=vuln_type,
                                               git_repository=git_repository,
                                               config_level=default_config_level,
                                               cve_id=cve_id)
        is_find_flag = potential_anchor_finder.traversal()
        if not is_find_flag:
            default_config_level += 1
        anchor_node_list = potential_anchor_finder.potential_anchor_nodes
    _score_matrix = []
    for anchor_node in anchor_node_list:
        fp_extractor = FingerprintExtractor(
                anchor_node=anchor_node,
                analyzer=analyzer_pre,
                commit_id=commit_id
        )
        fp_extractor.run()
        anchor_node_matcher = AnchorNodeMatcher(
                high_version_anchor=anchor_node,
                high_version_analyzer=analyzer_pre,
                low_version_analyzer=analyzer_target,
                high_version_prefix=_map_key_1,
                low_version_prefix=_map_key_2,
        )
        node_ast = analyzer_pre.get_node_itself(anchor_node.node_id)
        anchor_node_matcher.run_with_fingerprint(overwrite_low_buffer=False, node_type=node_ast[NODE_TYPE],
                                                 commit_id=commit_id)
        node_mapping = pd.read_csv(node_mapping_path)
        _low_anchor_node = node_mapping[
            (node_mapping['low_version'] == version)
            & (node_mapping['high_version'] == anchor_node.version)
            & (node_mapping['high_version_node_id'] == anchor_node.node_id)
            ].sort_values('timestamp')
        if _low_anchor_node.__len__() == 0:
            _score_matrix.append(-1.0)
        else:
            low_anchor_obj = _low_anchor_node.iloc[-1]
            if low_anchor_obj.low_version_node_id == -1:
                _score_matrix.append(0.0)
            else:
                max_score = max(eval(low_anchor_obj.match_score))
                _score_matrix.append(max_score)
    return _score_matrix


if __name__ == '__main__':
    main()
