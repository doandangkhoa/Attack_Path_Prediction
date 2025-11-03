import networkx as nx

def create_sample_network():
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

if __name__ == "__main__":
    G = create_sample_network()
    print("Nodes:", G.nodes())
    print("Edges with weights:")
    for u, v, d in G.edges(data=True):
        print(u, v, d)