def extract_features(candidate_path, graph, shortest_path_len):
    weights = []
    for i in range(len(candidate_path)-1):
        edge_data = graph.get_edge_data(candidate_path[i], candidate_path[i+1])
        if edge_data is None:
            raise ValueError(f"Edge ({candidate_path[i]}, {candidate_path[i+1]}) not in graph")
        weights.append(edge_data.get('weight', 1))  # default 1 nếu không có 'weight'
    
    total_weight = sum(weights)
    features = {
        'path_length': len(candidate_path),
        'total_weight': total_weight,
        'avg_weight': total_weight / (len(candidate_path)-1),
        'max_weight': max(weights),
        'min_weight': min(weights),
        'deviation_from_shortest': abs(len(candidate_path) - shortest_path_len)
    }
    return features
