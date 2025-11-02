
import matplotlib.pyplot as plt
import networkx as nx 
from network_builder import create_sample_network

# create graph
G = create_sample_network()

# create coordinate for nodes
pos = nx.spring_layout(G, seed=42) # seed=42 --> fixed position 
edge_labels = nx.get_edge_attributes(G, 'weight') # take edge's weight 

# draw graph 
nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=800)
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels) # adding weight label on each edge

# saving image to file
plt.title("Sample Network")
plt.savefig("plots/network_example.png")
print("Saved plots/network_example.png")
# plt.show()  # optional to display

