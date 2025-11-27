# generating simular data of attacker for train baseline
import csv
import random
import os
import math
import numpy as np
import pandas as pd
from src.pathfinding.k_shortest_paths import top_k_shortest_paths
from src.network_builder import build_random_network
from src.feature_extractor import extract_features

OUTPUT_FILE = "data/generated_paths_full.csv"
N_GRAPHS = 200
SAMPLES_PER_GRAPH = 5
K_PATHS = 5

def softmax(x):
    # nomolize outputs to prohibility distribution
    # purpose : make data more diverse for training
    e_x = np.exp(x - np.max(x)) # lấy tất cả phần tử trừ đi phần tử max để tránh tràn số vì hàm e mũ có thể rất lớn
                                # vẫn giữ được tỉ lệ xác suất giữa các phần tử  
    return e_x / e_x.sum()


def attacker_policy(features_list, alpha=1.5, beta=1.0, gamma=1.0, rank_w=1.5, noise=0.1, temperature=0.1):
    scores = []
    for f in features_list:
        score = (-alpha * f["total_weight"] 
                 - beta * f["path_length"] 
                 + gamma * f["role_score"] 
                 + rank_w * (1 / f["rank"])
                 + random.gauss(0, noise))
        scores.append(score)
    
    # làm nhọn phân phối xác suất ==> model dễ nhận biết hơn
    scores = np.array(scores) / temperature
    # convert real value to prohibility
    probs = softmax(np.array(scores))
    return probs # prohibility np array of paths


def generate_dataset():
    """
    Sinh dữ liệu huấn luyện mô phỏng hành vi attacker bằng policy softmax.
    """
    dataset = []
    for graph_idx in range(N_GRAPHS):
        current_n_nodes = random.randint(15, 25)
        graph = build_random_network(n_nodes=current_n_nodes, seed=None)
        nodes = list(graph.nodes())
        # filter target role
        clients = [node for node in nodes if graph.nodes[node].get('role') == 'client']
        servers = [node for node in nodes if graph.nodes[node].get('role') == 'server']
        if not clients or not servers:
            continue
        for _ in range(SAMPLES_PER_GRAPH):
            # initialize 
            src = random.choice(clients)
            dst = random.choice(servers)
            
            candidates = top_k_shortest_paths(graph, src, dst, k=K_PATHS)
            if not candidates:
                continue
            
            shortest_len = len(candidates[0])

            # Trích xuất đặc trưng cho từng đường
            features_list = []
            for rank, p in enumerate(candidates):
                # Truyền rank (bắt đầu từ 1) và role_weights vào
                feat = extract_features(p, graph, shortest_len, rank=rank+1)
                features_list.append(feat)
            
            # strategic 
            probs = attacker_policy(features_list)

            # Xác suất attacker chọn đường nào(random with bias)
            chosen_index = np.random.choice(len(candidates), p=probs) # chọn ngẫu nhiên dựa trên xác suất của các ứng viên 
            
            # saving data for trainning data
            for i, f in enumerate(features_list):
                f["label"] = 1 if i == chosen_index else 0  # attacker chọn đường này
                f["src"] = src
                f["dst"] = dst
                f["path"] = " -> ".join(str(n) for n in candidates[i])
                f["probability"] = round(float(probs[i]), 4)
                dataset.append(f)

    os.makedirs("data", exist_ok=True) # tạo thư mục 'data' nếu nó chưa tồn tại

    if dataset:
        df = pd.DataFrame(dataset)
        
        # (đưa label ra cuối)
        cols = [c for c in df.columns if c != "label"] + ["label"]
        df = df[cols]
        
        df.to_csv(OUTPUT_FILE, index=False) # xóa dữ liệu cũ ghi đè dữ liệu mới
        print(f"\n✅ Xong! Dataset đã lưu tại: {OUTPUT_FILE}")
        print(f"📊 Tổng số mẫu (rows): {len(df)}")
    else:
        print("⚠️ Không sinh được dữ liệu nào. Hãy kiểm tra lại logic đồ thị.")


if __name__ == "__main__":
    random.seed(42)
    np.random.seed(42)
    
    generate_dataset()
