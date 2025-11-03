
from pathfinding.k_shortest_paths import top_k_shortest_paths

graph = {
    'A': {'B': 2, 'C': 5},
    'B': {'C': 1, 'D': 4},
    'C': {'D': 2, 'E': 3},
    'D': {'F': 1},
    'E': {'F': 5},
    'F': {}
}

if __name__ == "__main__":
    paths = top_k_shortest_paths(graph, 'A', 'F', k=4)
    print("Top K paths from A to F:")
    for i, path in enumerate(paths, 1):
        print(f"{i}: {path}")
