import csv
import random
import os
import math
import numpy as np
import pandas as pd
from src.pathfinding.k_shortest_paths import top_k_shortest_paths
from src.network_builder import build_random_network
from src.feature_extractor import extract_features


def softmax(x):
    # nomolize outputs to prohibility distribution
    # goal : make data more diverse for training
    e_x = np.exp(x - np.max(x)) # lấy tất cả phần tử trừ đi phần tử max để tránh tràn số vì hàm e mũ có thể rất lớn
                                # vẫn giữ được tỉ lệ xác suất giữa các phần tử 
    return e_x / e_x.sum()


def attacker_policy(features_list, alpha=1.0, beta=0.5, noise=0.1):
    """
    Chọn đường đi theo softmax(-alpha * weight - beta * length + noise)
    => Đường ngắn và nhẹ hơn sẽ có xác suất cao hơn.
    """
    scores = []
    for f in features_list:
        # scoring formula : hàm đánh giá chất lượng đường đi 
        # alpha, beta : trọng số đánh giá mức độ quan trọng của thuộc tính 
        # gaussian noise : làm cho lựa chọn mang tính ngẫu nhiên giống thực tế hơn 
        score = -alpha * f["total_weight"] - beta * f["path_length"] + random.gauss(0, noise)
        scores.append(score)
        
    # convert real value to prohibility
    probs = softmax(np.array(scores))
    return probs # prohibility np array of paths


def recycle_data():
    random.seed(42)
    np.random.seed(42)
    
def run_simulator(n_samples=200, k=3):
    """
    Sinh dữ liệu huấn luyện mô phỏng hành vi attacker bằng policy softmax.
    """
    # recycle_data()
    
    graph = build_random_network(40)
    nodes = list(graph.nodes())
    dataset = []

    # filter target role
    clients = [node for node in nodes if graph.nodes[node].get('role') == 'client']
    servers = [node for node in nodes if graph.nodes[node].get('role') == 'server']
    if not clients or not servers:
        print("Không có đủ client/server để mô phỏng.")
        return
    for _ in range(n_samples):
        # initialize 
        src = random.choice(clients)
        dst = random.choice(servers)
        
        candidates = top_k_shortest_paths(graph, src, dst, k=k)
        if not candidates:
            continue
        
        if len(candidates) < k: continue
        
        shortest_len = len(candidates[0])

        # Trích xuất đặc trưng cho từng đường
        features_list = [extract_features(p, graph, shortest_len) for p in candidates]
        
        # strategic 
        probs = attacker_policy(features_list, alpha=1.0, beta=0.3, noise=0.15)

        # Xác suất attacker chọn đường nào(random with bias)
        chosen_index = np.random.choice(len(candidates), p=probs) # chọn ngẫu nhiên dựa trên xác suất của các ứng viên 
        
        # generating data for trainning data
        for i, f in enumerate(features_list):
            f["label"] = 1 if i == chosen_index else 0  # attacker chọn đường này
            f["src"] = src
            f["dst"] = dst
            f["path"] = " -> ".join(str(n) for n in candidates[i])
            f["probability"] = round(float(probs[i]), 3)
            dataset.append(f)

    os.makedirs("data", exist_ok=True)

    if dataset:
        keys = dataset[0].keys()
        with open("data/generated_paths.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(dataset)

        print(f"Dataset saved to data/generated_paths.csv ({len(dataset)} samples)")
    else:
        print("No valid paths generated. Try increasing graph connectivity or n_samples.")


if __name__ == "__main__":
    for i in range(10):
        run_simulator(n_samples=100, k=4)
        os.rename("data/generated_paths.csv", f"data/generated_paths_batch{i + 1}.csv")
    dfs = [pd.read_csv(f"data/generated_paths_batch{i + 1}.csv") for i in range(10)]
    full_df = pd.concat(dfs, ignore_index=True)
    full_df.to_csv("data/generated_paths_full.csv", index=False)
