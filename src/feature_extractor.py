def extract_features(candidate_path, graph, shortest_path_len):
    """
    Return: dict of features for a candidate path.
    - candidate_path: list of nodes (['A','B','C',...])
    - graph: networkx.Graph/DiGraph
    - shortest_path_len: length (number of nodes) of the shortest candidate path
    """
    if not candidate_path or len(candidate_path) < 2:
        # no edges on path -> return default zeros
        return {
            'path_length': len(candidate_path),
            'edge_count': 0,
            'total_weight': 0.0,
            'avg_weight': 0.0,
            'max_weight': 0.0,
            'min_weight': 0.0,
            'deviation_from_shortest': abs(len(candidate_path) - shortest_path_len)
        }

    weights = []
    for i in range(len(candidate_path) - 1):
        u, v = candidate_path[i], candidate_path[i + 1]
        edge_data = graph.get_edge_data(u, v)
        if edge_data is None:
            # Edge missing: treat as very large cost (or you can raise)
            # Here we choose to assign a large penalty so path is unlikely
            w = 1e6
        else:
            w = edge_data.get('weight', 1)
        weights.append(w)

    total_weight = sum(weights)
    edge_count = len(weights)
    avg_weight = total_weight / edge_count if edge_count > 0 else 0.0

    features = {
        'path_length': len(candidate_path),
        'edge_count': edge_count,
        'total_weight': total_weight,
        'avg_weight': avg_weight,
        'max_weight': max(weights) if weights else 0.0,
        'min_weight': min(weights) if weights else 0.0,
        'deviation_from_shortest': abs(len(candidate_path) - shortest_path_len)
    }
    return features
