import json
import logging
import os
import re

logger = logging.getLogger(__name__)

import Levenshtein
from typing import Union, List, Set
from config import STORAGE_PATH, DATA_INPUT_PATH
from core.anchor_node import BaseNode
from copy import deepcopy
from core.patch_modified_files_analyzer import PatchModifiedFilesAnalyzer


class StorageHelper(object):
    @staticmethod
    def get_patch_modified_files_in_cve(repository_name, cve_id):
        data_feeder = json.load(
                fp=open(os.path.join(DATA_INPUT_PATH, 'cve.json'), 'r', encoding='utf-8'))
        return PatchModifiedFilesAnalyzer.find_all_modified_files(repository_name,
                                                                  data_feeder[repository_name][cve_id][
                                                                      'fixing_commits'])

    @staticmethod
    def get_github_tag_versions_in_gt(repository_name) -> set:
        target_index = ["MantisBT", "Piwigo"]
        index = list(map(lambda x: x.lower(), target_index)).index(repository_name)
        return set(json.load(
                fp=open(os.path.join(DATA_INPUT_PATH, target_index[index] + "_versions" + ".json"), 'r',
                        encoding='utf-8')))

    @staticmethod
    def compile_path(anchor_node: BaseNode, base_path=STORAGE_PATH):
        path = os.path.join(base_path, anchor_node.git_repository, anchor_node.version,
                            f"{anchor_node.node_id}")
        create_dir_if_exists(path)
        return path

    @staticmethod
    def get_node_matching_storage(anchor_node: Union[BaseNode, str]):
        if isinstance(anchor_node, BaseNode):
            git_repository = anchor_node.git_repository
        elif isinstance(anchor_node, str):
            git_repository = anchor_node
        else:
            raise TypeError(f"{type(anchor_node)} is not allowed")

        path = os.path.join(STORAGE_PATH, git_repository)
        create_dir_if_exists(path)
        if not os.path.exists(
                os.path.join(path, 'node_mapping.csv')
        ):
            with open(os.path.join(path, 'node_mapping.csv'), encoding='utf8', mode='w') as f:
                f.write(
                        "high_version,high_version_node_id,low_version,low_version_node_id,potential_anchor_ids,match_score,reason,timestamp\n"
                )
        return os.path.join(path, f"node_mapping.csv")

    @staticmethod
    def get_series(anchor_node: BaseNode) -> list:
        path = StorageHelper.compile_path(anchor_node)
        file_name = os.path.join(path, f'series-{anchor_node.node_id}.json')
        return json.load(fp=open(file_name, 'r'))

    @staticmethod
    def store_series(anchor_node: BaseNode, obj: Union[List, Set], readable=None) -> bool:
        path = StorageHelper.compile_path(anchor_node)
        file_name = os.path.join(path, f'series-{anchor_node.node_id}.json')
        with open(file_name, 'w') as f:
            json.dump(obj=sorted(obj), fp=f)
        return True


class StringMatcher(object):
    @staticmethod
    def similarity_array(org_str: str, given: List[str], method="jaro", prehandle_func=None) -> List[float]:
        if prehandle_func is not None:
            org_str = prehandle_func(org_str)
            given = prehandle_func(given)
        score_vector = [Levenshtein.jaro(org_str, i) for i in given]
        return score_vector

    @staticmethod
    def fingerprint_pre_handler(org_str: Union[str, List[str]]):
        __t1 = re.compile(r'\s', re.M)
        remove_html_code = lambda x: StringFilter.replace_html_entity(x)
        change_same_string = lambda x: StringFilter.replace_abbreviation(x)
        remove_white_code = lambda x: re.sub(__t1, "", x)
        replace_lower_content = lambda x: x.lower()
        if isinstance(org_str, str):
            org_str = replace_lower_content(org_str)
            org_str = remove_html_code(org_str)
            org_str = change_same_string(org_str)
            org_str = remove_white_code(org_str)
            return org_str
        elif isinstance(org_str, list):
            src_str = []
            for _org_str in org_str:
                _org_str = replace_lower_content(_org_str)
                _org_str = remove_html_code(_org_str)
                _org_str = change_same_string(_org_str)
                _org_str = remove_white_code(_org_str)
                src_str.append(_org_str)
            return src_str


class StringFilter(object):
    HTML_ENTITY_TBL = [
            (" ", "&nbsp;", "&#160;"),
            ("<", "&lt;", "&#60;"),
            (">", "&gt;", "&#62;"),
            ("&", "&amp;", "&#38;"),
            ("\"", "&quot;", "&#34;"),
            ("'", "&apos;", "&#39;"),
    ]

    ABBREVIATION_TBL = [
            ("does not", "doesn't"),
            ("do not", "don't"),
            ("must not", "mustn't"),
            ("should not", "shouldn't"),
            ("can not", "can't"),
            ("is not", "isn't"),
            ("are not", "aren't"),
    ]

    @staticmethod
    def replace_abbreviation(string: str) -> str:
        for raw, r1 in StringFilter.ABBREVIATION_TBL:
            string.replace(r1, raw)
        return string

    @staticmethod
    def replace_html_entity(string: str) -> str:
        for raw, r1, r2 in StringFilter.HTML_ENTITY_TBL:
            string.replace(r1, raw)
            string.replace(r2, raw)
        return string

    @staticmethod
    def filter_normalized_commit_id(commit_id: str) -> str:
        return commit_id.replace("_prepatch", "").replace("_postpatch", "")

    @staticmethod
    def filter_map_key_to_git_repository_and_version(map_key):
        index = map_key.index('-')
        return map_key[:index], map_key[index + 1:]

    @staticmethod
    def filter_git_account_and_repository(input):
        res = deepcopy(input)
        try:
            import re
            res = re.findall(
                    r"https://github.com/(.*?)/(.*?)/", res
            )
            res = res[0]
            git_account, git_repository = res
            return git_account, git_repository
        except Exception as e:
            return None, None


def create_dir_if_exists(PATH: str or list):
    if isinstance(PATH, str):
        dir_path = PATH
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
    if isinstance(PATH, list):
        for _path in PATH:
            create_dir_if_exists(_path)


def remove_file_if_exists(PATH: str or list):
    if isinstance(PATH, str):
        if os.path.exists(PATH):
            os.remove(PATH)
    if isinstance(PATH, list):
        for _path in PATH:
            if os.path.exists(_path):
                os.remove(_path)


def check_str_in_list(string: str, iterable: List[str]):
    if not isinstance(string, str):
        return False
    if string == '':
        logger.info("empty string will not be checked !")
        return False
    for it in iterable:
        if string in it:
            return True
    return False


def check_list_in_str(string: str, iterable: List[str]):
    if not isinstance(string, str):
        return False
    if string == '':
        logger.info("empty string will not be checked !")
        return False
    for it in iterable:
        if it in string:
            return True
    return False
