def extract_features(graph, candidate_path, shortest_path_length):
    
    # candidate_path[i] = source node
    total_weight = sum(graph[candidate_path[i]][candidate_path[i + 1]] for i in range(len(candidate_path) - 1))
    path_weights = [graph[candidate_path[i]] for i in range(candidate_path) - 1]
    
    features = {
        'path_length': len(candidate_path),
        'total_weight': total_weight,
        'avg_weight':total_weight / (len(candidate_path) - 1),
        'max_weight': max(path_weights),
        'min_weight': min(path_weights),
        'deviation_from_shortest': len(candidate_path) - shortest_path_length
    }
    return features