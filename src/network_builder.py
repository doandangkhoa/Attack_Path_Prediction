import networkx as nx
import random
from collections import Counter

def assign_roles(G, role_distribution=None):
    """
    Gán role và security_level cho từng node trong đồ thị G.
    """
    random.seed(42)
    nodes = list(G.nodes())

    if role_distribution is None:
        role_distribution = {
            'client': 0.4,
            'server': 0.15,       # bao gồm cả database
            'firewall': 0.2,
            'router': 0.25
        }
    roles = list(role_distribution.keys())
    probs = list(role_distribution.values())
    total = sum(probs)
    probs = [p / total for p in probs]

    for node in nodes:
        role = random.choices(roles, weights=probs, k=1)[0]
        G.nodes[node]['role'] = role



def build_random_network(n_nodes=10, edge_prob=0.4, weight_range=(1, 11), firewall_penalty=3):
    """
    Tạo đồ thị mạng ngẫu nhiên có trọng số, vai trò node, và penalty khi đi qua firewall.
    """
    random.seed(42)
    
    G = nx.DiGraph()
    temp_nodes = [i for i in range(n_nodes)]
    G.add_nodes_from(temp_nodes)
    assign_roles(G)

    # đổi tên node theo vai trò
    mapping = {}
    role_counters = {'client':0, 'server':0, 'firewall':0, 'router':0}
    
    for node in temp_nodes:
        role = G.nodes[node]['role']
        role_counters[role] += 1
        prefix = role[0]
        new_name = f"{prefix}{role_counters[role]}"
        mapping[node] = new_name
    
    # áp dụng đổi tên nx  
    G = nx.relabel_nodes(G, mapping)
    
    # Gán lại vai trò vào node mới
    for new_node in G.nodes():
        role_char = new_node[0]
        role_map = {'c': 'client', 's': 'server', 'f': 'firewall', 'r': 'router'}
        G.nodes[new_node]['role'] = role_map[role_char]

    # Tạo cạnh ngẫu nhiên với trọng số
    nodes = list(G.nodes())
    for u in nodes:
        for v in nodes:
            if u != v and random.random() < edge_prob:
                # random < edge_prob --> tạo cạnh 
                base_weight = random.randint(*weight_range)

                # Nếu đích là firewall → tăng trọng số để mô phỏng penalty
                if G.nodes[v]['role'] == 'firewall':
                    base_weight += firewall_penalty

                G.add_edge(u, v, weight=base_weight)

    return G

def build_sample_network():
    """
    Tạo đồ thị mẫu đơn giản để kiểm thử thuật toán và mô hình.
    """
    graph = {
        'A': {'B': 2, 'C': 5},
        'B': {'C': 1, 'D': 4},
        'C': {'D': 2, 'E': 3},
        'D': {'F': 1},
        'E': {'F': 5},
        'F': {}
    }
    G = nx.DiGraph()
    for u in graph:
        for v, w in graph[u].items():
            G.add_edge(u, v, weight=w)
    assign_roles(G)
    return G

def display_network_info(G, name=""):
    print(f"\n--- Network: {name} ---")
    print("Nodes with roles and security levels:")
    role_counts = Counter()
    for node, data in G.nodes(data=True):
        role = data.get('role', 'unknown')
        sec = data.get('security_level', '?')
        role_counts[role] += 1
        print(f"  {node}: role={role}, security_level={sec}")
    print("Role distribution:", dict(role_counts))

    print("\nEdges with weights:")
    for u, v, d in G.edges(data=True):
        print(f"  {u} -> {v}, weight={d['weight']}")

if __name__ == "__main__":
    scenarios = {
        "sample": build_sample_network(),
        "random": build_random_network(n_nodes=20),
    }

    for name, G in scenarios.items():
        display_network_info(G, name)