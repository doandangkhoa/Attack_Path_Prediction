import networkx as nx
import random
from collections import Counter

def build_random_network(n_nodes=15, edge_prob=0.4, weight_range=(1, 11), firewall_penalty=50, seed=None):
    """
    Tạo đồ thị mạng phân cấp (Hub-based):
    - Sử dụng Erdos-Renyi để tạo khung xương.
    - Node nhiều kết nối nhất -> Router/Firewall (Hub).
    - Node ít kết nối -> Client/Server (Edge).
    - Đảm bảo Router/Firewall luôn nằm trên đường đi chính.
    """
    # xử lí seed
    if seed is not None:
        random.seed(seed)
        
    # 1. Tạo khung xương đồ thị vô hướng (Undirected) để tính toán Degree
    G_temp = nx.erdos_renyi_graph(n=n_nodes, p=edge_prob, seed=seed)
    
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


if __name__ == "__main__":
    scenarios = {
        "random": build_random_network(n_nodes=15),
    }