import json
import os
import time

import py2neo

DUMPED_NEO4J = [
        "mantisbt-1677251434b6e8b2be8f1d4376a3e78f7be14d95_postpatch.dump",
        "mantisbt-1677251434b6e8b2be8f1d4376a3e78f7be14d95_prepatch.dump",
        "mantisbt-f2f856193760e63eed3e06b031f56c742e7642d7_postpatch.dump",
        "mantisbt-f2f856193760e63eed3e06b031f56c742e7642d7_prepatch.dump",
        "mantisbt-release-1.1.0.dump",
        "mantisbt-release-2.2.0.dump",
]

for x in DUMPED_NEO4J:
    assert os.path.exists(x), f"{x} must be exists"

if os.path.exists(os.path.join(".", "neo4j-community-3.3.2")):
    print("[+] Check neo4j-community-3.3.2 exists")
else:
    print("[-] Check neo4j-community-3.3.2 not exists")
    os.system("wget  https://dist.neo4j.org/neo4j-community-3.3.2-unix.tar.gz ")
    os.system("tar -zxvf neo4j-community-3.3.2-unix.tar.gz")

result_list = {}
for dumped_file, port in zip(DUMPED_NEO4J, range(40000, 40000 + DUMPED_NEO4J.__len__() * 2, 2)):
    connector_name, extension = os.path.splitext(dumped_file)
    os.system(f"cp -r ./neo4j-community-3.3.2 ./{connector_name}")
    os.system(
            f'sed  -i "s/#dbms.connector.bolt.listen_address=:7687/dbms.connector.bolt.listen_address=:{port}/g" {connector_name}/conf/neo4j.conf')
    os.system(
            f'sed  -i "s/dbms.connector.https.enabled=true/dbms.connector.https.enabled=false/g" {connector_name}/conf/neo4j.conf')
    os.system(
            f'sed  -i "s/#dbms.connector.http.listen_address=:7474/dbms.connector.http.listen_address=:{port + 1}/g" {connector_name}/conf/neo4j.conf')
    os.system(
            f'sed  -i "s/#dbms.security.auth_enabled=false/dbms.security.auth_enabled=false/g" {connector_name}/conf/neo4j.conf')
    os.system(
            f'sed  -i "s/#dbms.connectors.default_listen_address=0.0.0.0/dbms.connectors.default_listen_address=0.0.0.0/g" {connector_name}/conf/neo4j.conf')
    os.system(
            f"{connector_name}/bin/neo4j-admin load --from {dumped_file}  --force"
    )
    io = os.popen(
            f"{connector_name}/bin/neo4j start"
    ).read()
    time.sleep(10)
    io = os.popen(
            f"tail -n 20 {connector_name}/logs/neo4j.log"
    ).read()
    print(io)
    result_list[connector_name] = {
            "NEO4J_HOST": "localhost",
            "NEO4J_PORT": int(port) + 1,
            "NEO4J_USERNAME": "neo4j",
            "NEO4J_PASSWORD": "123",
            "NEO4J_DATABASE": "neo4j",
            "NEO4J_PROTOCOL": "http",
    }
json.dump(
        fp=open('../config/neo4j.json', 'w'),
        obj=result_list,
        indent=1,
)

print("[-] waiting for 30s to make sure neo4j opened")
for i in range(0, 10):
    time.sleep(3)
    print('\r' + "." * i, end="")
for connector_name, graph_map in result_list.items():
    try:
        neo4j_graph = py2neo.Graph(f"{graph_map['NEO4J_PROTOCOL']}://"
                                   f"{graph_map['NEO4J_HOST']}:{graph_map['NEO4J_PORT']}",
                                   user=graph_map['NEO4J_USERNAME'].__str__(),
                                   password=graph_map['NEO4J_PASSWORD'].__str__())
        neo4j_graph.nodes.get(1)
        print(f"[+] connect to {connector_name} successfully")
    except Exception as e:
        print(e)
        print(f"[-] connect to {connector_name} failed, \n"
              f"make sure system JAVA version must be 8 and the port from 40000 to 40012 shouldn't be used")
print("[*] afv test case database import and start successfully")
