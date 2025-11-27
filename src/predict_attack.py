import numpy as np
import joblib
from src.pathfinding.k_shortest_paths import top_k_shortest_paths
from src.feature_extractor import extract_features
from src.simulator import softmax

MODEL_PATH = "models/rf_baseline.pkl"

def load_model(model_path=MODEL_PATH):
    try:
        return joblib.load(model_path)
    except Exception as e:
        print(f"[ERROR] Canot load model: {e}")
        return None

def predict_attack(graph, src, dst, k=3, rank = 0, mode="softmax"):
    # 0. load model
    model = load_model()
    if model is None:
        print("Model not found")
        return None
    
    # 1. retrieve top-k-shortest paths
    paths = top_k_shortest_paths(graph, src, dst, k=k)
    if not paths:
        print("Không tìm thấy đường đi")
        return None
    
    shortest_len = len(paths[0])
    rf_probs = []
    features_list = []
    # 2. Extract features + model predict
    for i, p in enumerate(paths):
        feat = extract_features(p, graph, shortest_len, rank=i + 1)
        features_list.append(feat)
        X = np.array([[
            feat["rank"],
            feat["path_length"],
            feat["total_weight"],
            feat["avg_weight"],
            feat["deviation_from_shortest"],
            feat["std_weight"],
            feat["firewall_crossings"],
            feat["role_entropy"],
            feat["role_score"],
        ]])
        try:
            prob = float(model.predict_proba(X)[0][1])
        except:
            prob = float(model.predict(X)[0])
        rf_probs.append(prob)
        
    # 3. Sofmax RF probs --> distribution
    soft_probs = softmax(np.array(rf_probs))
    
    # 4. Choose best path
    if mode == "softmax":
        chosen_idx = np.random.choice(len(paths), p=soft_probs)
    else:
        chosen_idx = int(np.argmax(soft_probs))
    best_path = paths[chosen_idx]
    
    # 5. Return everything
    return {
        "rank": rank,
        "paths": paths,
        "rf_probs": rf_probs,
        "softmax_probs": soft_probs,
        "best_path": best_path,
        "chosen_index": chosen_idx,
        "features": features_list
    }