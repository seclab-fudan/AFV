import os

__all__ = ["CONFIG_PATH",
           "LOG_PATH",
           "STORAGE_PATH",
           "SOURCE_CODE_PATH",
           "REPOSITORY_CODE_PATH",
           "DATA_INPUT_PATH",
           "TOOLS_PATH",
           "NEO4J_CONFIGURE_MAP_PATH",
           "PWD"
           ]

CONFIG_PATH = os.path.realpath(os.path.dirname(__file__))

PWD = os.path.realpath(".")

LOG_PATH = os.path.join(PWD, 'log')
STORAGE_PATH = os.path.join(PWD, "storage")
SOURCE_CODE_PATH = os.path.join(PWD, "afv_meta", "source_code_cache")
REPOSITORY_CODE_PATH = os.path.join(PWD, "afv_meta", "repository_cache")
TOOLS_PATH = os.path.join(PWD, 'tool_chain')
DATA_INPUT_PATH = os.path.join(PWD, 'dataset')
NEO4J_CONFIGURE_MAP_PATH = os.path.join(CONFIG_PATH, 'neo4j.json')


def __create_dir_if_exists(PATH: str or list):
    if isinstance(PATH, str):
        dir_path = PATH
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
    if isinstance(PATH, list):
        for _path in PATH:
            __create_dir_if_exists(_path)


__create_dir_if_exists([
        LOG_PATH,
        STORAGE_PATH,
        DATA_INPUT_PATH,
        REPOSITORY_CODE_PATH,
        SOURCE_CODE_PATH
])

for application, clone_command in [
        ["Piwigo", "git clone https://github.com/Piwigo/Piwigo"],
        ["mantisbt", "git clone https://github.com/mantisbt/mantisbt"],
]:
    if not os.path.exists(os.path.join(REPOSITORY_CODE_PATH, application)):
        print(os.path.join(REPOSITORY_CODE_PATH, application), "not exist", "clone it")
        os.chdir(REPOSITORY_CODE_PATH)
        os.system(clone_command)
