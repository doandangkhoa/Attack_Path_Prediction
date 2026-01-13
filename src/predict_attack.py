import numpy as np
import pandas as pd
import joblib
import os
import json

from src.pathfinding.k_shortest_paths import top_k_shortest_paths
from src.feature_extractor import extract_features

MODEL_PATH = "models/rf_baseline.pkl"
METRICS_PATH = "models/metrics.json"

def load_resources():
    """Tải model và threshold từ file."""
    model = None
    threshold = 0.5
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"⚠️ Không thể load model tại {MODEL_PATH}: {e}")

    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r") as f:
                data = json.load(f)
                threshold = data.get("optimal_threshold", 0.5)
        except:
            pass

    return model, threshold


def predict_attack(graph, src, dst, k=5, mode="argmax"):
    """
    Dự đoán đường tấn công dựa trên mô hình ML mới (Policy Oracle + Chaos layer).
    
    Args:
        graph : networkx.DiGraph
        src   : node nguồn
        dst   : node đích
        k     : số đường đi top-k
        mode  : 'argmax' hoặc 'softmax'
    
    Returns:
        dict: Thông tin về đường đi, xác suất, risk score, label dự đoán, features
    """
    model, threshold = load_resources()
    if model is None:
        return None

    # 1. Lấy top-k đường đi
    paths = top_k_shortest_paths(graph, src, dst, k=k)
    if not paths:
        return None

    # 2. Tính baseline weight (đường ngắn nhất)
    base_weight = sum(graph[u][v].get("weight", 1000) for u, v in zip(paths[0][:-1], paths[0][1:]))

    # 3. Trích xuất features cho tất cả đường đi
    features_list = []
    for i, path in enumerate(paths):
        feat = extract_features(path, graph, base_weight, rank=i+1)
        features_list.append(feat)

    # 4. Chuyển sang DataFrame & chuẩn hóa cột
    df_features = pd.DataFrame(features_list)

    try:
        train_cols = list(model.feature_names_in_)
    except AttributeError:
        # Fallback cho model cũ
        train_cols = [
            # --- STRUCTURE ---
        'path_length',

        # --- WEIGHT ---
        'total_weight',
        'avg_weight',
        'min_weight',
        'std_weight',
        'deviation_weight',

        # --- DETECTION ---
        'total_detection',
        'avg_detection',
        'max_detection',

        # --- ATTACK BEHAVIOR ---
        'exploit_count',
        'security_controls',
        'privilege_gain',

        # --- CONTEXT ---
        'role_score',
        'has_admin_access',
        'is_admin_source',
        'has_bastion',
        'has_mfa',

        # --- COMPOSITE ---
        'risk_factor'
        ]

    for col in train_cols:
        if col not in df_features.columns:
            df_features[col] = 0

    X_pred = df_features[train_cols]

    # 5. Dự đoán xác suất attack
    try:
        real_probs = model.predict_proba(X_pred)[:, 1]
    except Exception as e:
        print(f"⚠️ Predict failed: {e}")
        real_probs = np.zeros(len(paths))

    # 6. Chọn đường đi
    if mode == "softmax":
        exp_scores = np.exp(real_probs * 5)
        selection_probs = exp_scores / exp_scores.sum()
        chosen_idx = np.random.choice(len(paths), p=selection_probs)
    else:
        chosen_idx = np.argmax(real_probs)

    # Clip giá trị hiển thị để UI đẹp
    display_probs = np.clip(real_probs, 0.0, 0.99)

    is_attack = real_probs[chosen_idx] >= threshold

    return {
        "paths": paths,
        "rf_probs": display_probs.tolist(),
        "chosen_index": int(chosen_idx),
        "rank": chosen_idx + 1,
        "is_attack": bool(is_attack),
        "risk_score": float(display_probs[chosen_idx]),
        "threshold_used": float(threshold),
        "best_path": paths[chosen_idx],
        "features": features_list
    }
