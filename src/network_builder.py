import networkx as nx

def create_sample_network():
    """
    Return a small undirected weighted graph for testing.
    Nodes: A,B,C,D,E
    Edge weights represent attack 'cost' (lower -> easier).
    """
    G = nx.Graph()
    edges = [
        ("A","B",2),
        ("A","C",5),
        ("B","C",1),
        ("B","D",2),
        ("C","D",3),
        ("C","E",1),
        ("D","E",2),
    ]
    G.add_weighted_edges_from(edges)  # sets attribute 'weight'
    return G

if __name__ == "__main__":
    G = create_sample_network()
    print("Nodes:", G.nodes())
    print("Edges with weights:")
    for u, v, d in G.edges(data=True):
        print(u, v, d)