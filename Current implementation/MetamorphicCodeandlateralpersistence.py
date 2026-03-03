import random

def obfuscate_code(original_code):
    keywords = {"print": "output", "import": "load", "exec": "run_code"}
    obfuscated = original_code
    
    for k, v in keywords.items():
        obfuscated = obfuscated.replace(k, v)
    
    return obfuscated

# Example payload
original_payload = 'print("Red Team Simulation Active")'
mutated_payload = obfuscate_code(original_payload)

exec(mutated_payload)  # Self-executing metamorphic code

import networkx as nx

graph = nx.Graph()
graph.add_edges_from([
    ("low_priv_user", "sudo"),
    ("sudo", "root"),
    ("low_priv_user", "unpatched_kernel"),
    ("unpatched_kernel", "root")
])

def find_attack_path(start, goal):
    return nx.shortest_path(graph, start, goal)

# AI Calculates Best Attack Path
attack_path = find_attack_path("low_priv_user", "root")
print(f"AI Chose Attack Path: {attack_path}")

import networkx as nx

graph = nx.Graph()
graph.add_edges_from([
    ("low_priv_user", "sudo"),
    ("sudo", "root"),
    ("low_priv_user", "unpatched_kernel"),
    ("unpatched_kernel", "root")
])

def find_attack_path(start, goal):
    return nx.shortest_path(graph, start, goal)

# AI Calculates Best Attack Path
attack_path = find_attack_path("low_priv_user", "root")
print(f"AI Chose Attack Path: {attack_path}")

