import streamlit as st
import numpy as np
from pyvis.network import Network
import streamlit.components.v1 as components
import json
import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.network_builder import build_random_network
from src.predict_attack import predict_attack


# ==========================================
# Streamlit config
st.set_page_config(layout="wide", page_title="ML Path Prediction Demo")

MODEL_PATH = "models/rf_baseline.pkl"
METRICS_PATH = "models/metrics.json"

os.makedirs("models", exist_ok=True)
os.makedirs("data", exist_ok=True)


# ==========================================
# Utilities — Graph visualize
def pyvis_graph(G, highlight_paths=None, best_path=None):
    net = Network(height="650px", width="100%", bgcolor="white", font_color="black")
    net.force_atlas_2based()

    # 1. Thêm các nút (Nodes) - Giữ nguyên
    for n, d in G.nodes(data=True):
        role = d.get("role", "router")
        color = {
            "client": "#b8f2e6",
            "server": "#fefbbd",
            "firewall": "#ef8d7a",
            "router": "#737676"
        }.get(role, "#6C6C6A")

        net.add_node(n, label=n, title=f"{n} ({role})", color=color)

    # 2. Xây dựng thuộc tính cho các cạnh (Edges)
    edge_props = {}
    
    # --- 2a. Thêm thuộc tính mặc định (Giữ nguyên) ---
    for u, v, d in G.edges(data=True):
        edge_key = (u, v)
        if edge_key not in edge_props:
            edge_props[edge_key] = {
                "u": u, "v": v, "color": "#E0E0E0", "width": 2,
                "title": str(d.get("weight", 1)), "arrows": None
            }
        if (v, u) not in edge_props:
             edge_props[(v, u)] = {
                "u": v, "v": u, "color": "#E0E0E0", "width": 2,
                "title": str(d.get("weight", 1)), "arrows": None
            }

    # --- 2b. Cập nhật Top-K (Giữ nguyên) ---
    if highlight_paths:
        for p in highlight_paths:
            for a, b in zip(p[:-1], p[1:]):
                edge_key = (a, b) 
                if edge_key in edge_props:
                    edge_props[edge_key]["color"] = "red"
                    edge_props[edge_key]["width"] = 3
                    edge_props[edge_key]["arrows"] = "to"
                
                # Chúng ta sẽ xử lý cạnh ngược (màu xám) ở Step 3
                # nên không cần xóa nó ở đây.

    # --- 2c. Cập nhật Best path (Giữ nguyên) ---
    if best_path:
        for a, b in zip(best_path[:-1], best_path[1:]):
            edge_key = (a, b) 
            if edge_key in edge_props:
                edge_props[edge_key]["color"] = "gold"
                edge_props[edge_key]["width"] = 7
                edge_props[edge_key]["arrows"] = "to"
    
    # Set này sẽ lưu các cạnh VÔ HƯỚNG (frozenset) đã được vẽ
    drawn_undirected_edges = set() 
    
    # Tách các cạnh thành 2 nhóm: highlighted (có mũi tên) và default (không)
    highlighted_props = []
    default_props = []
    
    for props in edge_props.values():
        if props["arrows"] is not None:
            highlighted_props.append(props)
        else:
            default_props.append(props)

    # --- 3a. Vẽ tất cả các cạnh HIGHLIGHTED (đỏ/vàng) TRƯỚC ---
    for props in highlighted_props:
        u, v = props["u"], props["v"]
        net.add_edge(
            u, v, 
            title=props["title"], 
            color=props["color"], 
            width=props["width"],
            arrows=props["arrows"]
        )
        # Đánh dấu cạnh VÔ HƯỚNG này là đã được vẽ
        drawn_undirected_edges.add(frozenset([u, v]))

    # --- 3b. Vẽ các cạnh DEFAULT (xám) CHỈ KHI chúng chưa được vẽ ---
    for props in default_props:
        u, v = props["u"], props["v"]
        edge_key = frozenset([u, v])
        
        # Chỉ vẽ cạnh xám này nếu phiên bản vô hướng của nó
        # CHƯA được vẽ (dưới dạng highlighted)
        if edge_key not in drawn_undirected_edges:
            net.add_edge(
                u, v, 
                title=props["title"], 
                color=props["color"], 
                width=props["width"],
                arrows=props["arrows"] # sẽ là None
            )
            # Đánh dấu là đã vẽ (để tránh vẽ trùng 2 cạnh xám)
            drawn_undirected_edges.add(edge_key)

    html_path = "data/graph_vis.html"
    net.save_graph(html_path)
    return html_path

# ==========================================
# Load metrics
# ==========================================
def load_metrics(metrics_path):
    if os.path.exists(metrics_path):
        try:
            return json.load(open(metrics_path, "r"))
        except:
            return None
    return None


# ==========================================
# MAIN UI
# ==========================================
st.title("🔍 Machine Learning Path Prediction Demo")

G = build_random_network(15)

metrics = load_metrics(METRICS_PATH)

left, right = st.columns([1.5, 2.5])


# ------------------------------
# LEFT PANEL — SETTINGS
# ------------------------------
with left:
    st.header("⚙️ Pre-configurations")

    nodes = list(G.nodes())
    clients = [node for node in nodes if G.nodes[node].get('role') == 'client']
    servers = [node for node in nodes if G.nodes[node].get('role') == 'server']
    src = st.selectbox("Source node (client)", clients, index=0)
    dst = st.selectbox("Target node (server)", servers, index=len(servers) - 1)

    k = st.slider("Top-K paths", 1, 10, 4)

    st.write("---")

    st.subheader("📊 Model Metrics")
    if metrics:
        st.metric("Accuracy", f"{metrics.get('accuracy',0):.3f}")
        st.metric("F1-score", f"{metrics.get('f1',0):.3f}")
    else:
        st.info("Chưa có metrics trong models/metrics.json")


# ------------------------------
# RIGHT PANEL — VISUALIZATION
# ------------------------------
with right:
    st.header("🔎 ML Path Prediction Visualization")

    if src == dst:
        st.warning("Source và Target phải khác nhau")
    else:
        result = predict_attack(G, src, dst, k=k, mode="sofmax")

        if result is None:
            st.error("Không tìm thấy đường đi.")
        else:
            paths = result["paths"]
            rf_probs = result["rf_probs"]
            soft_probs = result["softmax_probs"]
            best_path = result["best_path"]

            # Top-K candidate listing
            st.subheader("Danh sách Top-K Paths")

            for i, p in enumerate(paths):
                col1, col2, col3 = st.columns([4, 1, 1])

                with col1:
                    st.write(f"**#{i+1}:** {' → '.join(p)}")

                with col2:
                    st.metric("RF Prob", f"{rf_probs[i]:.3f}")

                with col3:
                    st.metric("Softmax", f"{soft_probs[i]:.3f}")

            # Best path (ML predicted)
            st.write("---")
            st.subheader("🎯 Best Path (ML Prediction)")
            st.success(" → ".join(best_path))

            # Draw interactive graph
            # ===============================
            html_file = pyvis_graph(G, highlight_paths=paths, best_path=best_path)
            components.html(open(html_file, "r", encoding="utf-8").read(), height=650)

st.write("---")
st.caption("Demo built with ML + Pathfinding + Streamlit 🔥")
