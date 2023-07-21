from kubernetes import client, config, watch
import os, json

config.load_kube_config(config_file='config-100')
os.system("clear")

v1 = client.CoreV1Api()
podsFromApi = v1.list_pod_for_all_namespaces()
svcsFromApi = v1.list_service_for_all_namespaces()
nodesFromApi = v1.list_node()
pods = {}
svcs = {}
nodes = {}

for pod in podsFromApi.items:
    pods[pod.status.pod_ip] = {
        "namespace": pod.metadata.namespace,
        "name": pod.metadata.name,
        "node_name": pod.spec.node_name,
        "node_ip": pod.status.host_ip,
    }

for svc in svcsFromApi.items:
    svcs[svc.metadata.name] = {
        "namespace": pod.metadata.namespace,
        "node_name": pod.spec.node_name,
        "node_ip": pod.status.host_ip,
    }

for node in nodesFromApi.items:
    nodes[node.status.addresses[0].address] = node.metadata.name

jsonFile = json.dumps({
    "pods": pods,
    "svcs": svcs,
    "nodes": nodes
})

with open('pcap/clusterinfo.json', 'w') as f:
    f.write(jsonFile)

# clusterinfo.json
# {
#     "pods": {
#         "10.233.71.52": {
#             "namespace": "default",
#             "name": "curl",
#             "node_name": "node3",
#             "node_ip": "192.168.122.102"
#         }
#         ...
#     },
#     "svcs": {
#         "hello": {
#             "namespace": "openfaas",
#             "node_name": "node1",
#             "node_ip": "192.168.122.100"
#         }
#         ...
#     },
#     "nodes": {
#         "192.168.122.100": "node1",
#         "192.168.122.101": "node2",
#         "192.168.122.102": "node3"
#         ...
#     }
# }