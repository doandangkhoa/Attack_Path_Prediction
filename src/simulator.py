import csv
import random
import os
import math
import numpy as np
from src.pathfinding.k_shortest_paths import top_k_shortest_paths
from src.network_builder import create_sample_network, create_scenario
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
        score = -alpha * f["total_weight"] - beta * f["path_length"] + random.gauss(0, noise)
        scores.append(score)
        
    # convert real value to prohibility
    probs = softmax(np.array(scores))
    return probs # prohibility np array of paths


def run_simulator(n_samples=200, k=4):
    """
    Sinh dữ liệu huấn luyện mô phỏng hành vi attacker bằng policy softmax.
    """
    graph = create_scenario()
    nodes = list(graph.nodes())
    dataset = []

    for _ in range(n_samples):
        # initialize 
        src, dst = random.sample(nodes, 2)
        candidates = top_k_shortest_paths(graph, src, dst, k=k)
        if not candidates:
            continue
            
        shortest_len = len(candidates[0])

        # Trích xuất đặc trưng cho từng đường
        features_list = [extract_features(p, graph, shortest_len) for p in candidates]
        probs = attacker_policy(features_list, alpha=1.0, beta=0.3, noise=0.15)

        # Xác suất attacker chọn đường nào(random with bias)
        chosen_index = np.random.choice(len(candidates), p=probs) # chọn ngẫu nhiên dựa trên xác suất của các ứng viên 
        
        # generating data for trainning data
        for i, f in enumerate(features_list):
            f["label"] = 1 if i == chosen_index else 0  # attacker chọn đường này
            f["src"] = src
            f["dst"] = dst
            f["path"] = " -> ".join(candidates[i])
            f["probability"] = round(float(probs[i]), 3)
            dataset.append(f)

    os.makedirs("data", exist_ok=True)

    if dataset:
        keys = dataset[0].keys()
        with open("data/generated_paths.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(dataset)

        print(f" Dataset saved to data/generated_paths.csv ({len(dataset)} samples)")
    else:
        print(" No valid paths generated. Try increasing graph connectivity or n_samples.")


if __name__ == "__main__":
    run_simulator(n_samples=100000, k=4)
