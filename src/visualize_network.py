import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import os
from src.pathfinding.k_shortest_paths import top_k_shortest_paths
from src.network_builder import build_random_network
import random

def draw_graph_with_path(G, path=None, output_link="plots/path_candidate_{index}.png", layout="spring"):
    # Chọn layout và tăng khoảng cách
    if layout == "kamada":
        pos = nx.kamada_kawai_layout(G)
    elif layout == "shell":
        pos = nx.shell_layout(G)
    elif layout == "spectral":
        pos = nx.spectral_layout(G)
    else:
        pos = nx.spring_layout(G, seed=42, k=2.0)  # tăng k để giãn node

    plt.figure(figsize=(10, 8))  # tăng kích thước hình tổng thể

    # Màu node theo vai trò
    role_colors = {
        'client': '#A0CBE2',
        'server': '#FFDD57',
        'firewall': '#FF6F61',
        'router': '#B0E57C',
        'unknown': '#CCCCCC'
    }
    node_colors = [
        role_colors.get(G.nodes[n].get('role', 'unknown'), '#CCCCCC')
        for n in G.nodes()
    ]

    # Vẽ node và cạnh
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=500)  # giảm node_size
    nx.draw_networkx_labels(G, pos, font_size=9)  # giảm font
    nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle='->', width=1.0, arrowsize=12)  # giảm arrowsize
    edge_labels = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    # Vẽ đường đi nổi bật
    if path and len(path) > 1:
        path_edges = list(zip(path, path[1:]))
        nx.draw_networkx_edges(
            G, pos, edgelist=path_edges,
            width=3.0, edge_color='red',
            arrows=True, arrowstyle='->', arrowsize=16
        )
        path_labels = {
        edge: edge_labels[edge]
        for edge in path_edges if edge in edge_labels
        }

        nx.draw_networkx_edge_labels(
        G, pos,
        edge_labels=path_labels,
        font_color='red',
        font_size=10,
        bbox=dict(facecolor='white', edgecolor='none', alpha=0.8)
    )


    # Chú thích vai trò
    legend_elements = [
        Patch(facecolor=color, label=role.capitalize())
        for role, color in role_colors.items()
    ]
    plt.legend(handles=legend_elements, loc='upper left', frameon=True)

    plt.title("Network Graph with Highlighted Path", fontsize=12)
    plt.tight_layout()
    os.makedirs(os.path.dirname(output_link), exist_ok=True)
    plt.savefig(output_link)
    plt.close()
    print(f"✅ Saved {output_link}")
    
if __name__ == "__main__":
    G = build_random_network(n_nodes=15)

    # Ví dụ chọn src/dst tạm thời để kiểm thử
    src_candidates = [n for n, d in G.nodes(data=True) if d.get('role') == 'client']
    dst_candidates = [n for n, d in G.nodes(data=True) if d.get('role') == 'server']
    if src_candidates and dst_candidates:
        src = random.choice(src_candidates)
        dst = random.choice(dst_candidates)
        candidates = top_k_shortest_paths(G, src, dst, k=3)
        for index, path in enumerate(candidates, 1):
            output_link = f"plots/path_candidate_{index}.png"
            draw_graph_with_path(G, path, output_link)
    else:
        print("⚠️ Không tìm thấy client hoặc server để tạo đường đi.")
