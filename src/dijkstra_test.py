
from network_builder import create_sample_network
import networkx as nx

G = create_sample_network()
src, dst = "A", "E"
path = nx.dijkstra_path(G, src, dst, weight='weight')
length = nx.dijkstra_path_length(G, src, dst, weight='weight')
print(f"Shortest path {src} -> {dst}: {path} (total cost {length})")
