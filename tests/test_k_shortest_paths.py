from src.network_builder import create_sample_network
from pathfinding.k_shortest_paths import top_k_shortest_paths


if __name__ == "__main__":
    graph = create_sample_network()
    paths = top_k_shortest_paths(graph, 'A', 'F', k=4)
    print("Top K paths from A to F:")
    for i, path in enumerate(paths, 1):
        print(f"{i}: {path}")
