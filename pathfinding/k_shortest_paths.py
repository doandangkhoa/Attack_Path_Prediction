import networkx as nx
from itertools import islice

# Yen's algorithm

def top_k_shortest_paths(graph, source, target, k=3, cutoff=None, weight='weight'):
    # k : number of paths, cutoff : maximum nodes per path
    # initial directed graph by networkx from graph
    G = nx.DiGraph()
    
    for u in graph:
        for v, w in graph[u].items():
            G.add_edge(u, v, weight=w)
            
    try:
        # generate simple paths by sorting following increased total weight 
        generator = nx.shortest_simple_paths(G, source, target, weight=weight)
        
        # take k simple paths from generator
        if cutoff is None:
            return list(islice(generator, k))
        else:
        # limited the number of nodes per path
            resultSet = [] # set of satisfactory paths
            for path in generator:
                if len(path) <= cutoff:
                    resultSet.append(path)
                if len(path) >= k: # k paths
                    break
            return resultSet
    except(nx.NetworkXNoPath, nx.NodeNotFound): # path doesnt exist
        return []
        