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


def build_random_network(n_nodes=15, edge_prob=0.4, weight_range=(1, 11), firewall_penalty=50):
    """
    Tạo đồ thị mạng phân cấp (Hub-based):
    - Sử dụng Erdos-Renyi để tạo khung xương.
    - Node nhiều kết nối nhất -> Router/Firewall (Hub).
    - Node ít kết nối -> Client/Server (Edge).
    - Đảm bảo Router/Firewall luôn nằm trên đường đi chính.
    """
    # 1. Tạo khung xương đồ thị vô hướng (Undirected) để tính toán Degree
    # edge_prob=0.3 giúp tạo đồ thị đủ dày đặc
    G_temp = nx.erdos_renyi_graph(n=n_nodes, p=edge_prob, seed=42)
    
    # Đảm bảo đồ thị liên thông (không bị đứt đoạn)
    while not nx.is_connected(G_temp):
        seed = random.randint(1, 1000)
        G_temp = nx.erdos_renyi_graph(n=n_nodes, p=edge_prob, seed=seed)

    # 2. Phân vai dựa trên "Độ bậc" (Degree - số lượng kết nối)
    degrees = dict(G_temp.degree())
    # Sắp xếp node từ nhiều kết nối nhất đến ít nhất
    sorted_nodes = sorted(degrees, key=degrees.get, reverse=True)
    
    # Tính toán số lượng từng loại
    num_routers = max(2, int(n_nodes * 0.2))    # Top 20% là Router
    num_firewalls = max(2, int(n_nodes * 0.2))  # 20% tiếp theo là Firewall
    
    routers = sorted_nodes[:num_routers]
    firewalls = sorted_nodes[num_routers : num_routers + num_firewalls]
    
    remaining = sorted_nodes[num_routers + num_firewalls:]
    # Trộn ngẫu nhiên đám node rìa để chia Client/Server
    random.shuffle(remaining)
    
    split_idx = int(len(remaining) * 0.75)
    
    # Safety check: Đảm bảo luôn có ít nhất 1 Server để làm đích đến (trừ khi remaining quá ít)
    if split_idx == len(remaining) and len(remaining) > 0:
        split_idx -= 1
    clients = remaining[:split_idx]
    servers = remaining[split_idx:]
    
    # Gán role tạm thời vào G_temp (để mapping)
    for n in G_temp.nodes():
        if n in routers: role = 'router'
        elif n in firewalls: role = 'firewall'
        elif n in clients: role = 'client'
        else: role = 'server'
        G_temp.nodes[n]['role'] = role

    # 3. Tạo Mapping đổi tên (0 -> r1, 1 -> c1...)
    mapping = {}
    counters = {'client': 0, 'server': 0, 'firewall': 0, 'router': 0}
    prefixes = {'client': 'c', 'server': 's', 'firewall': 'f', 'router': 'r'}
    
    for n in G_temp.nodes():
        role = G_temp.nodes[n]['role']
        counters[role] += 1
        new_name = f"{prefixes[role]}{counters[role]}"
        mapping[n] = new_name

    # 4. Xây dựng đồ thị Có hướng (DiGraph) cuối cùng
    G_final = nx.DiGraph()
    
    # Thêm node với tên mới và role
    for old_n, new_name in mapping.items():
        role = G_temp.nodes[old_n]['role']
        G_final.add_node(new_name, role=role)
        
    # Thêm cạnh và trọng số
    # Chuyển mỗi cạnh vô hướng thành 2 cạnh có hướng (2 chiều)
    for u, v in G_temp.edges():
        u_new, v_new = mapping[u], mapping[v]
        
        # Tạo cạnh chiều xuôi (u -> v)
        w1 = random.randint(*weight_range)
        if G_final.nodes[v_new]['role'] == 'firewall': # Nếu đích là firewall
            w1 += firewall_penalty
        G_final.add_edge(u_new, v_new, weight=w1)
        
        # Tạo cạnh chiều ngược (v -> u)
        w2 = random.randint(*weight_range)
        if G_final.nodes[u_new]['role'] == 'firewall': # Nếu đích là firewall
            w2 += firewall_penalty
        G_final.add_edge(v_new, u_new, weight=w2)

    return G_final


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