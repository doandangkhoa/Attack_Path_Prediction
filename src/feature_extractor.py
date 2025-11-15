import numpy as np
from collections import Counter

def extract_features(candidate_path, graph, shortest_path_len, role_weights=None):
    """
    Trích xuất đặc trưng cho một đường đi trong đồ thị.
    """
    if not candidate_path or len(candidate_path) < 2:
        return {
            'path_length': len(candidate_path),
            'total_weight': 0.0,
            'avg_weight': 0.0,
            'deviation_from_shortest': abs(len(candidate_path) - shortest_path_len),
            'std_weight': 0.0,
            'firewall_crossings': 0,
            'role_entropy': 0.0,
            'role_score': 0
        }

    weights = []
    for u, v in zip(candidate_path[:-1], candidate_path[1:]):
        edge_data = graph.get_edge_data(u, v)
        w = edge_data['weight'] if edge_data and 'weight' in edge_data else 1e6
        weights.append(w)

    total_weight = sum(weights)
    avg_weight = total_weight / len(weights)
    std_weight = np.std(weights)

    if role_weights is None:
        role_weights = {
            'client': 1,
            'server': 5,
            'firewall': -3,
            'router': 0,
            'unknown': 0
        }

    roles = []
    firewall_crossings = 0
    role_score = 0

    for node in candidate_path:
        role = graph.nodes[node].get('role', 'unknown')
        roles.append(role)
        if role == 'firewall':
            firewall_crossings += 1
        role_score += role_weights.get(role, 0)

    role_counts = Counter(roles)
    total_roles = sum(role_counts.values())
    role_entropy = -sum(
        (count / total_roles) * np.log2(count / total_roles)
        for count in role_counts.values() if count > 0
    )

    return {
        'path_length': len(candidate_path),
        'total_weight': total_weight,
        'avg_weight': avg_weight,
        'deviation_from_shortest': abs(len(candidate_path) - shortest_path_len),
        'std_weight': round(std_weight, 3),
        'firewall_crossings': firewall_crossings,
        'role_entropy': round(role_entropy, 3),
        'role_score': role_score
    }