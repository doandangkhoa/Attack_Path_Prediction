
import matplotlib.pyplot as plt
import networkx as nx
from network_builder import create_sample_network

G = create_sample_network()
pos = nx.spring_layout(G, seed=42)
edge_labels = nx.get_edge_attributes(G, 'weight')
nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=800)
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
plt.title("Sample Network")
plt.savefig("plots/network_example.png")
print("Saved plots/network_example.png")
# plt.show()  # optional to display
