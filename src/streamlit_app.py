
import streamlit as st
import networkx as nx
import numpy as np
from pyvis.network import Network
import streamlit.components.v1 as components
import joblib
import itertools
import json
import os
from network_builder import build_random_network
from feature_extractor import extract_features
from pathfinding.k_shortest_paths import top_k_shortest_paths
from simulator import run_simulator
st.set_page_config(layout="wide", page_title="ML Path Prediction Demo")

MODEL_PATH = "models/rf_baseline.pkl"
METRICS_PATH = "models/metrics.json"
os.makedirs("models", exist_ok=True)
os.makedirs("data", exist_ok=True)

# -------------------------
# Utilities
# -------------------------

def pyvis_graph(G, highlight_paths=None, best_path=None):
    net = Network(height="650px", width="100%", bgcolor="white", font_color="black")
    net.force_atlas_2based()

    for n, d in G.nodes(data=True):
        role = d.get("role","router")
        color = {
            "client": "#b8f2e6",
            "server": "#bde0fe",
            "firewall": "#ffb5a7",
            "router": "#f0efeb"
        }.get(role,"#f0efeb")
        net.add_node(n, label=n, title=f"{n} ({role})", color=color)

    for u,v,d in G.edges(data=True):
        net.add_edge(u,v, title=str(d.get("weight",1)))

    if highlight_paths:
        for p in highlight_paths:
            for a,b in zip(p[:-1],p[1:]):
                net.add_edge(a,b, color="red", width=4)

    if best_path:
        for a,b in zip(best_path[:-1],best_path[1:]):
            net.add_edge(a,b, color="gold", width=6)

    html_path = "data/graph_vis.html"
    net.save_graph(html_path)
    return html_path

# -------------------------
# Load model & metrics
# -------------------------
def load_model(model_path):
    if os.path.exists(model_path):
        try: return joblib.load(MODEL_PATH)
        except: return None
    return None

def load_metrics(metrics_path):
    if os.path.exists(METRICS_PATH):
        try: return json.load(open(METRICS_PATH,"r"))
        except: return None
    return None

# -------------------------
# Main UI
# -------------------------
st.title("🔍 Machine Learning Path Prediction Demo")

G = build_random_network(20)
model = load_model(MODEL_PATH)
metrics = load_metrics(METRICS_PATH)

left, right = st.columns([1.5,2.5])

with left:
    st.header("⚙️ Settings")
    nodes = list(G.nodes())

    src = st.selectbox("Source node (client)", nodes, index=0)
    dst = st.selectbox("Target node (server)", nodes, index=len(nodes)-1)

    k = st.slider("Top-K paths", 1, 8, 4)

    st.write("---")
    if model:
        st.success("ML model loaded ✨")
    else:
        st.warning("Không tìm thấy model (models/rf_model.pkl)")

    if metrics:
        st.subheader("📊 Model Metrics")
        st.metric("Accuracy", f"{metrics.get('accuracy',0):.3f}")
        st.metric("F1-score", f"{metrics.get('f1',0):.3f}")
    else:
        st.info("Chưa có metrics — hãy thêm models/metrics.json")

with right:
    st.header("🔎 ML Path Prediction Visualization")

    if src == dst:
        st.warning("Source và Target phải khác nhau")
    else:
        paths = top_k_shortest_paths(G, src, dst, k)
        if not paths:
            st.error("Không tìm thấy đường đi.")
        else:
            probs = []
            shortest_len = len(paths[0])
            for p in paths:
                feat = extract_features(p, G, shortest_len)
                if model:
                    X = np.array([[
                        feat["total_weight"],
                        feat["path_length"],
                        feat["avg_weight"],
                        feat["deviation_from_shortest"],
                        feat["std_weight"],
                        feat["firewall_crossings"],
                        feat["role_entropy"],
                        feat["role_score"]
                    ]])
                    
                    try:
                        prob = float(model.predict_proba(X)[0][1])
                    except:
                        prob = None
                else:
                    prob = None
                probs.append(prob)
            # Best path = ML argmax
            best_idx = int(np.argmax([p if p is not None else -1 for p in probs])) if model else 0
            best_path = paths[best_idx]

            st.subheader("Danh sách Top-K Paths")

            for i, p in enumerate(paths):
                col1, col2 = st.columns([4,1])
                with col1:
                    st.write(f"**#{i+1}:** {' → '.join(p)}")
                with col2:
                    if probs[i] is not None:
                        st.metric("Prob", f"{probs[i]:.3f}")

            st.write("---")
            st.subheader("🎯 Best Path (ML Prediction)")
            st.success(" → ".join(best_path))

            html_file = pyvis_graph(G, highlight_paths=paths, best_path=best_path)
            components.html(open(html_file, "r", encoding="utf-8").read(), height=650)

st.write("---")

