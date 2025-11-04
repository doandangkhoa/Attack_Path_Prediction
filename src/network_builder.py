import networkx as nx
import random

def create_sample_network():
    """
    Original fixed network — small demo graph
    """
    graph = {
        'A': {'B': 2, 'C': 5},
        'B': {'C': 1, 'D': 4},
        'C': {'D': 2, 'E': 3},
        'D': {'F': 1},
        'E': {'F': 5},
        'F': {}
    }
    G = nx.DiGraph()
    for u in graph:
        for v, w in graph[u].items():
            G.add_edge(u, v, weight=w)
    return G


def create_linear_network(n=6):
    """
    Create a linear chain: A -> B -> C -> ... -> N
    """
    G = nx.DiGraph()
    nodes = [chr(ord('A') + i) for i in range(n)]
    for i in range(n - 1):
        G.add_edge(nodes[i], nodes[i + 1], weight=random.randint(1, 10))
    return G


def create_star_network(center='A', num_branches=5):
    """
    Create a star topology: center connects to all leaves.
    """
    G = nx.DiGraph()
    for i in range(num_branches):
        leaf = chr(ord('B') + i)
        w1, w2 = random.randint(1, 10), random.randint(1, 10)
        G.add_edge(center, leaf, weight=w1)
        G.add_edge(leaf, center, weight=w2)  # optional bidirectional
    return G


def create_mesh_network(n=4, p=0.4):
    """
    Create random mesh (Erdős–Rényi-like) directed graph.
    n: number of nodes
    p: probability of edge between any pair
    """
    G = nx.DiGraph()
    nodes = [chr(ord('A') + i) for i in range(n)]
    for u in nodes:
        for v in nodes:
            if u != v and random.random() < p:
                G.add_edge(u, v, weight=random.randint(1, 10))
    return G


def create_scenario(scenario_name="sample"):
    """
    Factory function: return graph based on scenario name
    """
    if scenario_name == "sample":
        return create_sample_network()
    elif scenario_name == "linear":
        return create_linear_network()
    elif scenario_name == "star":
        return create_star_network()
    elif scenario_name == "mesh":
        return create_mesh_network()
    else:
        raise ValueError(f"Unknown scenario: {scenario_name}")


if __name__ == "__main__":
    # quick test
    for name in ["sample", "linear", "star", "mesh"]:
        G = create_scenario(name)
        print(f"\n--- Scenario: {name} ---")
        print("Nodes:", list(G.nodes()))
        print("Edges with weights:")
        for u, v, d in G.edges(data=True):
            print(f"  {u} -> {v}, weight={d['weight']}")
