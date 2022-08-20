import os
import re

import git

from config import REPOSITORY_CODE_PATH
from core.patch_modified_files_analyzer import PatchModifiedFilesAnalyzer


class Commit:
    def __init__(self, commit):
        self.title = commit.message.split('\n')[0]
        self.message = commit.message
        self.commit_mentioned = re.findall(r'cherry.*pick.*([0-9a-f]{40})', self.message)
        self.commit_mentioned += re.findall(r'cp ([0-9a-f]{7})', self.title)

    def __str__(self):
        return '\n'.join([self.title, self.message, ','.join(self.commit_mentioned)])


def SimilarDetectionByCommitMessage(commit, patch_commit):
    a = Commit(commit)
    b = Commit(patch_commit)
    if len(a.message) > 2 and len(b.message) > 2 and (
            a.message.startswith(b.message) or b.message.startswith(a.message)):
        return True
    else:
        for h in a.commit_mentioned + b.commit_mentioned:
            if h.startswith(patch_commit.hexsha) or patch_commit.hexsha.startswith(h) \
                    or h.startswith(commit.hexsha) or commit.hexsha.startswith(h):
                return True


def BranchSelection(repo, patch_commit):
    tags = re.split(r'[\s]+', repo.git.tag('--sort=taggerdate'))
    tags = [t for t in tags
            if repo.commit(t).committed_datetime >= patch_commit.committed_datetime
            and re.findall(r'(RC|rc|beta)', t) == []]
    _d = {}
    branches = []
    for t in tags:
        branch_info = repo.git.branch("-r", "--contains", repo.commit(t).hexsha)
        if branch_info not in _d.keys():
            _d[branch_info] = []
        _d[branch_info].append(t)
    for v in _d.values():
        branches.append(sorted(v, key=lambda x: repo.commit(x).committed_datetime)[-1])
    if 'do-not-use-github-releases' in branches:
        branches.remove('do-not-use-github-releases')
        for b in ['release-1.2.20', 'release-2.1.3']:
            if repo.commit(b).committed_datetime >= patch_commit.committed_datetime:
                branches.append(b)
    return branches


def FindSimilarPatch(repo, patch_commit_hexsha, patched_file):
    patch_commit = repo.commit(patch_commit_hexsha)
    patch_related = set()
    already_searched = set()
    branches = BranchSelection(repo, patch_commit)
    for branch in branches:
        for c in repo.iter_commits(rev=branch):
            if c.hexsha not in already_searched:
                if SimilarDetectionByCommitMessage(c, patch_commit):
                    patch_related.add(c.hexsha)
                    break
                else:
                    diff_flag = True
                    for file in patched_file:
                        if not file in c.stats.files.keys():
                            diff_flag = False
                            break
                        diff_res = repo.git.diff(patch_commit_hexsha, c.hexsha, '--', file)
                        if diff_res != '':
                            if 'Merge branch' not in c.message or patch_commit not in c.parents:
                                diff_flag = False
                                break
                            diff_lines = re.findall(r"\@\@ \-([\d]+),.*\+([\d]+),.*\@\@", diff_res)
                            modified_lines = re.findall(r"\@\@ \-([\d]+),.*\+([\d]+),.*\@\@",
                                                        repo.git.show(patch_commit_hexsha))
                            if not (len(diff_lines) == 1 and len(modified_lines) == 1
                                    and diff_lines[0][0] == diff_lines[0][1] and modified_lines[0][0] ==
                                    modified_lines[0][1]
                                    and abs(int(diff_lines[0][0]) - int(modified_lines[0][0])) > 5):
                                diff_flag = False
                                break

                    if diff_flag:
                        patch_related.add(c.hexsha)
                        break
                    else:
                        already_searched.add(c.hexsha)
    return patch_related


def TagDetermine(repo, patch_related):
    res = []
    tags = re.split(r'[\s]+', repo.git.tag('--sort=taggerdate'))
    for tag in tags:
        commit_history = [c.hexsha for c in repo.iter_commits(rev=tag)]
        for c in patch_related:
            if c in commit_history:
                res.append(tag)
                break
    return res


class PatchExtender(object):
    def __init__(self, repository_name, fixing_commits):
        self.repository_name = repository_name
        self.fixing_commits = fixing_commits
        self.result_similar = set()
        self.result_patched = set()

    def run(self):
        repo = git.Repo(os.path.join(REPOSITORY_CODE_PATH, self.repository_name))
        for fixing_commit in self.fixing_commits:
            try:
                modified_files = PatchModifiedFilesAnalyzer.find_modified_files(self.repository_name, fixing_commit)
                patch_related = FindSimilarPatch(repo, fixing_commit, modified_files)
                patch_related.add(fixing_commit)
            except Exception as e:
                print(e)
                patch_related = set(fixing_commit)
            self.result_similar = set(self.result_similar).union(set(patch_related))
            _res = TagDetermine(repo, patch_related)
            self.result_patched = set(self.result_patched).union(set(_res))

    def get_result(self):
        return self.result_similar, self.result_patched
