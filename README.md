# Source Code and Dataset of AFV

We introduce the structure of the directory and describe the usage of AFV.

## 1. File Descriptions

* `config/` directory contains the configuration files for AFV, including database connection settings, global variables, and logging files.

* `core/` directory contains the source code of AFV.

* `dataset/` directory contains our dataset (CVEs, versions, ground truth) and the results of AFV and baselines on the dataset.

* `databases/` directory contains the dumped neo4j files for the demo cases.

* `afv_main.py` is the launcher of AFV.

## 2. Usage of AFV

### Step 1: Setting the Environment

**1) Check OS Version**

```shell
-> % lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.5 LTS
Release:        18.04
Codename:       bionic
```

**2) Check Python Version**
```shell
-> % python --version
Python 3.9.12
```

**3) Check Java Version**
```shell
-> % java -version
openjdk version "1.8.0_312"
OpenJDK Runtime Environment (build 1.8.0_312-8u312-b07-0ubuntu1~18.04-b07)
OpenJDK 64-Bit Server VM (build 25.312-b07, mixed mode)
```

**4) Install the Dependencies**
```shell
-> % pip3 install -r requirements.txt
```

**5) Install Neo4j**
Download and install Neo4j with version `community-3.3.2` at `https://dist.neo4j.org/neo4j-community-3.3.2-unix.tar.gz`.

### Step 2: Preparing Neo4j and AFV

**1) Construct Neo4j Database**

To perform the analysis for a CVE-version pair, you need to construct the Code Property Graphs for the required commits (including the pre-patch commits, post-patch commits, and the target commits) and import them to Neo4j.

You can follow the instructions at `https://github.com/malteskoruppa/phpjoern` to construct the code property graph database for a commit.

**2) Configure Neo4j & AFV**

Next, you should edit the configuration files of Neo4j and AFV to ensure that AFV can properly connect to the database.

For Neo4j, you can edit its configuration file (usually in`/path/to/neo4j/conf/neo4j.conf`). Please pay attention to these statements:
```
dbms.connector.http.listen_address=:PORT_A
dbms.connector.bolt.listen_address=:PORT_B
```

For AFV,  you can edit the `config/neo4j.json` file to set up its connections to Neo4j. The content should be looked like the following:
```json5
{
  // ...
  "version-name": {
    "NEO4J_HOST": "localhost",
    "NEO4J_PORT": PORT_A,
    "NEO4J_USERNAME": "neo4j",
    "NEO4J_PASSWORD": "neo4j",
    "NEO4J_DATABASE": "neo4j",
    "NEO4J_PROTOCOL": "http"
  }
  //...
}
```
> Note that the listening ports of the Neo4j (e.g., PORT_A and PORT_B) should not be occupied and keep consistent with the AFV configuration.

**Demo Cases**

To ease the testing, we have prepared a demo case. In this case, we use AFV to check whether two versions of MantisBT `release-1.1.0` and `release-2.2.0` are affected by `CVE-2017-6799`.

We have prepared the Neo4j databases for the corresponding code commits that are needed for the demo case in `databases/`. Besides, we also provide a script `databases/prepare_database.py` for you to set up the Neo4j and AFV with these databases.

> Note that the Neo4j databases are quite large, we only attach the needed ones to run this demo case. You could prepare others using the instructions described above.

Run the following commands to finish the setup for the demo case:
```shell
-> % cd databases/
-> % python prepare_database.py
...
[+] connect to mantisbt-1677251434b6e8b2be8f1d4376a3e78f7be14d95_postpatch successfully
[+] connect to mantisbt-1677251434b6e8b2be8f1d4376a3e78f7be14d95_prepatch successfully
[+] connect to mantisbt-f2f856193760e63eed3e06b031f56c742e7642d7_postpatch successfully
[+] connect to mantisbt-f2f856193760e63eed3e06b031f56c742e7642d7_prepatch successfully
[+] connect to mantisbt-release-1.1.0 successfully
[+] connect to mantisbt-release-2.2.0 successfully
[*] afv test case database import and start successfully
```

> Note that these Neo4j databases will use ports from 40000 to 40012, make sure that these ports have not been used by other applications.

### Step 3: Running AFV

Before running AFV, you should start the Neo4j database (if it has not been started).
```shell
-> %  /path/to/neo4j/bin/neo4j start
```

Then, run AFV with the following commands:
```shell
python afv_main.py <CVE-ID> <target_version>
```

Take our demo case as an example. You can run it with the following command:
```shell
-> % python afv_main.py CVE-2017-6799 release-1.1.0
[*] Start analyzing whether CVE-2017-6799 affect release-1.1.0 in mantisbt
The version release-1.1.0 of CVE-2017-6799 is unaffected
```

```shell
-> % python afv_main.py CVE-2017-6799 release-2.2.0
[*] Start analyzing whether CVE-2017-6799 affect release-2.2.0 in mantisbt
The version release-2.2.0 of CVE-2017-6799 is affected
```

The results show that version `release-2.2.0` of MantisBT is affected by CVE-2017-6799, while version `release-1.1.0` is unaffected.

