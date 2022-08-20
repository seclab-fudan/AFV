import re

GIT_REPOSITORY_TO_ACCOUNT_MAP = {
    "mantisbt": "mantisbt",
    "Piwigo": "Piwigo",
}
GIT_ACCOUNT_TO_REPOSITORY_MAP = {V: K for K, V in GIT_REPOSITORY_TO_ACCOUNT_MAP.items()}

GIT_URL = "https://github.com/"
GIT_URL_DICT = {git_repository: f"https://github.com/{git_account}/{git_repository}" for git_repository, git_account
                in GIT_REPOSITORY_TO_ACCOUNT_MAP.items()}

PHP_EXTENSION = ["php", "inc", "phtml"]

FILE_NAME_COMMON_PREFIX = re.compile("(/opt/AFV/SourceCode/prepatch_and_postpatch/.*?/)"
                                     "|(/opt/AFV/SourceCode/Piwigo/.*?/)"
                                     "|(/opt/AFV/SourceCode/mantisbt/.*?/)")
