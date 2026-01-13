import random
import numpy as np
import pandas as pd
import networkx as nx
import os

# =========================
# CONFIGURATION
# =========================
N_GRAPHS = 400
SAMPLES_PER_GRAPH = 15
K_PATHS = 10
OUTPUT_FILE = "data/generated_attack_paths_policy_oracle.csv"

# =========================
# UTILITY
# =========================
def softmax(x):
    e_x = np.exp(x - np.max(x))
    return e_x / e_x.sum()

def path_weight(path, G):
    return sum(G[u][v].get("weight", 1000) for u, v in zip(path[:-1], path[1:]))

def is_valid_endpoint(G, node):
    role = G.nodes[node].get("role", "")
    return role not in ["firewall", "switch", "router", "security", "gateway"]

def select_attack_sources(G):
    nodes = []
    for n, d in G.nodes(data=True):
        if not is_valid_endpoint(G, n): 
            continue
        role = d.get("role", "")
        layer = d.get("layer", "")
        if layer == "External" and role == "client":
            nodes.append(n)
        if role == "client":
            nodes.append(n)
    return list(set(nodes))

def select_attack_targets(G):
    targets = []
    for n, d in G.nodes(data=True):
        if not is_valid_endpoint(G, n):
            continue
        role = d.get("role", "")
        label = str(d.get("label", "")).lower()
        if role in ["server", "identity", "database"]:
            targets.append(n)
        elif "admin" in label:
            targets.append(n)
    return list(set(targets))

# =========================
# PATHFINDING
# =========================
def top_k_shortest_paths(G, src, dst, k=5):
    try:
        return list(nx.shortest_simple_paths(G, src, dst, weight="weight"))[:k]
    except:
        return []

# =========================
# BEHAVIOR MODELS (NO LABELING)
# =========================
def attacker_behavior(features_list, mode="random"):
    """
    Chỉ chọn path theo chiến thuật. KHÔNG gán nhãn.
    """
    if mode == "random":
        mode = random.choice(["stealth", "aggressive", "privilege"])

    if mode == "stealth":
        w_cost, w_exploit, w_priv, w_detect = 0.2, 6.0, 4.0, 8.0
    elif mode == "aggressive":
        w_cost, w_exploit, w_priv, w_detect = 0.8, 12.0, 5.0, 0.5
    elif mode == "privilege":
        w_cost, w_exploit, w_priv, w_detect = 0.4, 6.0, 15.0, 3.0

    scores = []
    for f in features_list:
        total_w = f.get("total_weight", 1000)
        exploit = f.get("exploit_count", 0)
        priv = f.get("privilege_gain", 0)
        detect = f.get("max_detection", 0)

        score = (
            - w_cost * total_w
            + w_exploit * exploit
            + w_priv * priv
            - w_detect * detect
        )
        scores.append(score)

    probs = softmax(np.array(scores))
    idx = np.random.choice(len(features_list), p=probs)
    return idx, mode

def user_behavior(features_list):
    """
    User thường chọn đường ngắn/đơn giản.
    """
    top_n = min(3, len(features_list))
    return random.randint(0, top_n - 1)

def noisy_behavior(features_list):
    """
    Actor nhiễu: chọn hoàn toàn ngẫu nhiên.
    """
    return random.randint(0, len(features_list) - 1)

# =========================
# POLICY ORACLE (LABELING)
# =========================
def policy_oracle(f, G, src, dst):
    """
    Gán nhãn dựa trên RỦI RO (policy-based), không phụ thuộc actor.
    label: 1 = Attack / Policy Violation, 0 = Normal
    Có stochastic boundary để tránh ML học vẹt rule.
    """
    risk = 0.0

    # --- Rule 1: Exploit usage
    if f.get("exploit_count", 0) > 0:
        risk += 3.0

    # --- Rule 2: Privilege escalation
    if f.get("privilege_gain", 0) >= 2:
        risk += 2.0

    # --- Rule 3: Crown Jewels (DB / Identity)
    target_role = G.nodes[dst].get("role", "unknown")
    if target_role in ["database", "identity"]:
        if f.get("has_bastion", 0) == 0:
            risk += 3.0
        if f.get("has_mfa", 1) == 0:
            risk += 1.5

    # --- Rule 4: Structural anomaly
    if f.get("role_entropy", 0) > 1.5 and f.get("total_weight", 0) > 120:
        risk += 1.0

    # --- Rule 5: Detection footprint
    if f.get("max_detection", 0) > 7:
        risk += 1.0

    # --- Rule 6: External → Internal access (VPN / Misconfig)
    src_layer = G.nodes[src].get("layer")
    dst_layer = G.nodes[dst].get("layer")

    if src_layer == "External" and dst_layer == "Internal":
        # Dùng feature thay vì string path
        has_vpn = f.get("has_vpn", 0)
        has_mfa = f.get("has_mfa", 0)
        has_bastion = f.get("has_bastion", 0)
        is_misconfig = f.get("is_misconfig", 0)

        if has_vpn:
            if has_mfa:
                risk += 0.5
            else:
                risk += 2.0

            if has_bastion:
                risk -= 0.5

            if f.get("privilege_gain", 0) >= 2:
                risk += 2.0

            if is_misconfig:
                risk += 3.0
        else:
            risk += 4.0

    # --- STOCHASTIC BOUNDARY (ANTI-MEMORIZATION)
    threshold = 5.0
    noise = np.random.normal(0, 0.8)

    return 1 if (risk + noise) >= threshold else 0

# =========================
# MAIN GENERATOR (POLICY ORACLE ARCH)
# =========================
def generate_dataset(build_graph_fn, extract_features_fn):
    dataset = []
    print(f"🚀 Generating dataset with Policy Oracle ({N_GRAPHS} graphs)...")

    for _ in range(N_GRAPHS):
        # 1) ENVIRONMENT
        G = build_graph_fn(seed=None)

        sources = select_attack_sources(G)
        targets = select_attack_targets(G)
        if not sources or not targets:
            continue

        for _ in range(SAMPLES_PER_GRAPH):
            src = random.choice(sources)
            dst = random.choice(targets)
            if src == dst:
                continue

            try:
                # 2) CANDIDATE PATHS
                candidates = top_k_shortest_paths(G, src, dst, k=K_PATHS)
                if not candidates:
                    continue

                shortest_w = path_weight(candidates[0], G)

                # 3) FEATURES
                features_list = []
                for rank, path in enumerate(candidates):
                    f = extract_features_fn(path, G, shortest_w, rank=rank+1)
                    features_list.append(f)

                # 4) BEHAVIOR (NO LABEL)
                behavior = random.choice(["attacker", "user", "noise"])
                if behavior == "attacker":
                    idx, attack_mode = attacker_behavior(features_list, mode="random")
                elif behavior == "user":
                    idx = user_behavior(features_list)
                    attack_mode = "none"
                else:
                    idx = noisy_behavior(features_list)
                    attack_mode = "none"

                f = features_list[idx]

                # 5) POLICY ORACLE (LABELING)
                label = policy_oracle(f, G, src, dst)

                # 6) SAVE SAMPLE
                f["label"] = label
                f["src"] = src
                f["dst"] = dst
                f["type"] = "ATTACK" if label == 1 else "NORMAL"
                f["attack_mode"] = attack_mode
                f["actor"] = behavior   # KHÔNG dùng để train

                dataset.append(f)

            except Exception:
                continue

    # =========================
    # SAVE
    # =========================
    if dataset:
        os.makedirs("data", exist_ok=True)
        df = pd.DataFrame(dataset)
        df = df.fillna(0)
        df.to_csv(OUTPUT_FILE, index=False)

        print("\n✅ DATASET GENERATED (POLICY ORACLE)")
        print(f"📊 Total samples: {len(df)}")
        print(f"🔴 Attack (1): {len(df[df['label']==1])}")
        print(f"🟢 Normal (0): {len(df[df['label']==0])}")
        print("🔍 Actor breakdown (NOT for training):")
        print(df['actor'].value_counts())
        print(f"💾 Saved to: {OUTPUT_FILE}")
    else:
        print("⚠️ No data generated.")

# =========================
# EXECUTION (TEST)
# =========================
if __name__ == "__main__":
    try:
        from src.network_builder import build_random_policy_oracle_graph
        from src.feature_extractor import extract_features
        generate_dataset(build_random_policy_oracle_graph, extract_features)
    except ImportError:
        print("❌ Cannot import project modules. Run from project root:")
        print("python -m src.data_generator_policy_oracle")
