import networkx as nx

def find_attack_path(graph, start, goal):
    return nx.shortest_path(graph, start, goal)

graph = nx.Graph()
graph.add_edges_from([
    ("low_priv_user", "sudo"),
    ("sudo", "root"),
    ("low_priv_user", "unpatched_kernel"),
    ("unpatched_kernel", "root")
])

path = find_attack_path(graph, "low_priv_user", "root")
print(f"Optimal attack path: {path}")

