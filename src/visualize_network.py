import networkx as nx
import matplotlib.pyplot as plt
import os
from src.pathfinding.k_shortest_paths import top_k_shortest_paths
from src.network_builder import create_sample_network


def draw_graph_with_path(G, path, output_link):
    position = nx.spring_layout(G, seed=42)
    plt.figure(figsize=(6,4))
    
    # draw nodes and edges
    nx.draw(G, position, with_labels=True, node_color='lightblue', node_size=800, arrows=True)
    edge_labels = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_edge_labels(G, position, edge_labels=edge_labels)
    
    # highlight path edges
    if path and len(path) > 1:
        path_edges = list(zip(path, path[1:]))
        
        # Highlight path edges with RED, THICK lines, and ARROWS
        # Note: 'node_size' is included to help NetworkX correctly place the arrowheads
        nx.draw_networkx_edges(
            G, position, edgelist=path_edges, 
            width=3.5, 
            edge_color='red', 
            arrows=True, 
            arrowstyle='->', 
            arrowsize=20, 
            node_size=800  # Crucial for correct arrow positioning
        )
        
        # Get ONLY the edge labels for the path
        path_labels = {edge: edge_labels[edge] for edge in path_edges}
        
        # Draw the path's edge labels (weights) in RED over the existing black labels
        nx.draw_networkx_edge_labels(
            G, position, 
            edge_labels=path_labels, 
            font_color='black', 
            font_size=12,
            bbox={'facecolor':'white', 'alpha':0.6, 'edgecolor':'none'} # Add a background to make red text "bloom"
        )
    plt.title("Graph - highlighted path")
    plt.tight_layout()
    os.makedirs(os.path.dirname(output_link), exist_ok=True)
    plt.savefig(output_link)
    plt.close()
    print(f"saved {output_link}")

if __name__ == "__main__":
    G = create_sample_network()
    candidates = top_k_shortest_paths(G, 'A', 'F', k=3)
    for index, path in enumerate(candidates, 1):
        output_link = f"plots/path_candidate_{index}.png"
        draw_graph_with_path(G, path, output_link)