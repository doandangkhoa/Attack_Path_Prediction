# app.py
import streamlit as st
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib import cm
import json
import os
import itertools
from collections import deque
import time
import joblib  # for loading RF model if exists

# -----------------------
# Helpers
# -----------------------
st.set_page_config(layout="wide", page_title="Hybrid Dijkstra + ML Demo")

REQ_MODEL_PATH = "models/rf_model.pkl"

def ensure_dirs():
    os.makedirs("models", exist_ok=True)
    os.makedirs("data", exist_ok=True)
ensure_dirs()

# basic dijkstra step generator on a given graph and start node
def dijkstra_steps(G, start):
    visited = set()
    distances = {n: float('inf') for n in G.nodes}
    prev = {n: None for n in G.nodes}
    distances[start] = 0
    steps = []

    while True:
        unvisited = {n: distances[n] for n in G.nodes if n not in visited}
        if not unvisited:
            break
        current = min(unvisited, key=unvisited.get)
        # If current distance is inf, remaining nodes unreachable
        if distances[current] == float('inf'):
            steps.append((current, dict(distances), dict(prev)))
            break
        visited.add(current)
        steps.append((current, dict(distances), dict(prev)))
        for nbr, data in G[current].items():
            w = data.get("weight", 1)
            nd = distances[current] + w
            if nd < distances[nbr]:
                distances[nbr] = nd
                prev[nbr] = current
        if len(visited) == len(G.nodes):
            break
    return steps, prev

def reconstruct_path(prev, start, target):
    if target not in prev:
        return []
    path = []
    cur = target
    while cur is not None:
        path.insert(0, cur)
        cur = prev[cur]
    return path if path and path[0] == start else []

def draw_graph(G, pos=None, highlight_nodes=None, highlight_path=None, figsize=(6,5)):
    if pos is None:
        pos = nx.spring_layout(G, seed=42)
    fig, ax = plt.subplots(figsize=figsize)
    node_colors = []
    for n in G.nodes:
        if highlight_nodes and n in highlight_nodes:
            node_colors.append("orange")
        elif highlight_path and n in highlight_path:
            node_colors.append("tab:green")
        else:
            node_colors.append("lightgrey")
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=800, ax=ax)
    nx.draw_networkx_labels(G, pos, ax=ax)
    # edges
    edge_colors = []
    widths = []
    for u, v in G.edges():
        if highlight_path and u in highlight_path and v in highlight_path:
            edge_colors.append("tab:green")
            widths.append(2.5)
        else:
            edge_colors.append("grey")
            widths.append(1.0)
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors, width=widths, ax=ax)
    # labels
    labels = nx.get_edge_attributes(G, "weight")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, ax=ax)
    ax.set_axis_off()
    return fig, pos

def top_k_paths_nx(G, source, target, k=3, cutoff=None):
    try:
        generator = nx.shortest_simple_paths(G, source, target, weight="weight")
        paths = list(itertools.islice(generator, k))
        return paths
    except Exception as e:
        return []

def graph_to_json(G):
    data = {"nodes": list(G.nodes), "edges": []}
    for u, v, d in G.edges(data=True):
        data["edges"].append({"u": u, "v": v, "weight": d.get("weight", 1)})
    return data

def json_to_graph(data):
    G = nx.Graph()
    for n in data.get("nodes", []):
        G.add_node(n)
    for e in data.get("edges", []):
        G.add_edge(e["u"], e["v"], weight=float(e.get("weight", 1)))
    return G

def extract_features_simple(G, path):
    # simple features: total_weight, path_len, avg_weight, max_weight
    weights = []
    for a, b in zip(path[:-1], path[1:]):
        w = G[a][b].get("weight", 1)
        weights.append(w)
    total = sum(weights) if weights else 0.0
    avg = total / len(weights) if weights else 0.0
    mx = max(weights) if weights else 0.0
    return {
        "total_weight": total,
        "path_len": len(path) - 1,
        "avg_weight": avg,
        "max_weight": mx
    }

# try load model
def load_model_if_exists(path=REQ_MODEL_PATH):
    if os.path.exists(path):
        try:
            model = joblib.load(path)
            return model
        except Exception as e:
            st.warning(f"Không thể load model từ {path}: {e}")
            return None
    return None

# -----------------------
# Layout: left control, right canvas
# -----------------------
st.title("🔎 Hybrid Dijkstra + ML — Interactive Demo")

left, right = st.columns([1,2])

with left:
    st.header("Graph controls")
    # initialize graph in session_state
    if "G_json" not in st.session_state:
        # default small example
        G0 = nx.Graph()
        edges = [
            ('A','B',4),('A','C',2),('B','C',1),
            ('B','D',5),('C','D',8),('C','E',10),
            ('D','E',2),('D','Z',6),('E','Z',3)
        ]
        for u,v,w in edges:
            G0.add_edge(u,v,weight=w)
        st.session_state.G_json = graph_to_json(G0)
    # controls to add/remove nodes/edges
    G = json_to_graph(st.session_state.G_json)

    st.subheader("Add node / edge")
    new_node = st.text_input("Node name (single token)", value="", key="new_node")
    if st.button("Add node"):
        if new_node:
            if new_node in G.nodes:
                st.warning("Node đã tồn tại")
            else:
                G.add_node(new_node)
                st.session_state.G_json = graph_to_json(G)
                st.rerun()

    u = st.text_input("Edge u (from)", key="edge_u")
    v = st.text_input("Edge v (to)", key="edge_v")
    w = st.text_input("Weight (number)", value="1", key="edge_w")
    if st.button("Add / Update edge"):
        if u and v:
            try:
                ww = float(w)
            except:
                ww = 1.0
            G.add_edge(u, v, weight=ww)
            st.session_state.G_json = graph_to_json(G)
            st.rerun()

    st.write("---")
    st.subheader("Remove")
    rem_node = st.text_input("Remove node", key="rem_node")
    if st.button("Remove node"):
        if rem_node in G.nodes:
            G.remove_node(rem_node)
            st.session_state.G_json = graph_to_json(G)
            st.rerun()
        else:
            st.warning("Node không tồn tại")

    rem_edge_u = st.text_input("Remove edge u", key="rem_eu")
    rem_edge_v = st.text_input("Remove edge v", key="rem_ev")
    if st.button("Remove edge"):
        if rem_edge_u and rem_edge_v and G.has_edge(rem_edge_u, rem_edge_v):
            G.remove_edge(rem_edge_u, rem_edge_v)
            st.session_state.G_json = graph_to_json(G)
            st.rerun()
        else:
            st.warning("Edge không tồn tại")

    st.write("---")
    # save/load graph
    st.subheader("Save / Load graph")
    filename = st.text_input("Filename (data/xxx.json)", value="data/graph_demo.json")
    col1, col2 = st.columns(2)
    if col1.button("Save graph"):
        data = graph_to_json(G)
        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            st.success(f"Saved to {filename}")
        except Exception as e:
            st.error(f"Lỗi khi lưu: {e}")
    if col2.button("Load graph"):
        try:
            with open(filename, "r") as f:
                data = json.load(f)
            st.session_state.G_json = data
            st.rerun()
        except Exception as e:
            st.error(f"Lỗi khi load: {e}")

    st.write("---")
    st.subheader("Demo settings")
    nodes = list(G.nodes)
    if not nodes:
        st.warning("Graph trống — thêm vài node trước.")
    start = st.selectbox("Start node", nodes, index=0 if nodes else 0, key="start_sel")
    target = st.selectbox("Target node", nodes, index=len(nodes)-1 if nodes else 0, key="target_sel")
    k = st.number_input("Top-K candidates", min_value=1, max_value=20, value=3, step=1)
    autoplay_interval = st.slider("Auto-play interval (secs)", 0.2, 2.0, 1.0, step=0.1)

    st.write("---")
    st.subheader("Model (optional)")
    model = load_model_if_exists()
    if model:
        st.success("RandomForest model loaded (models/rf_model.pkl). Hybrid predictions active.")
    else:
        st.info("No model found at models/rf_model.pkl → ML ranking disabled. Put model file to enable.")

    st.write("---")
    st.caption("Tip: you can edit graph, save then run the interactive Dijkstra on the right panel.")

with right:
    st.header("Canvas & Algorithm")
    G = json_to_graph(st.session_state.G_json)
    pos = nx.spring_layout(G, seed=42)

    # Top-K candidate paths
    paths = []
    if start in G.nodes and target in G.nodes and start != target:
        paths = top_k_paths_nx(G, start, target, k=k)
    st.subheader("Top-K candidate paths")
    if not paths:
        st.info("Không tìm được path (kiểm tra nodes/edges).")
    else:
        # show table of candidates with basic features and ML score if model exists
        rows = []
        for i, p in enumerate(paths):
            feat = extract_features_simple(G, p)
            prob = None
            if model:
                # adapt features to model input (order must match your training). We'll assume columns in this order:
                X = [[feat["total_weight"], feat["path_len"], feat["avg_weight"], feat["max_weight"]]]
                try:
                    # if classifier with predict_proba
                    prob = float(model.predict_proba(X)[0][1]) if hasattr(model, "predict_proba") else float(model.predict(X)[0])
                except Exception:
                    prob = None
            rows.append((i+1, " → ".join(p), feat, prob))
        # display
        for idx, path_str, feat, prob in rows:
            colA, colB = st.columns([3,1])
            with colA:
                st.markdown(f"**#{idx}** {path_str}")
                st.write(feat)
            with colB:
                if prob is not None:
                    st.metric("ML prob", f"{prob:.3f}")
                else:
                    st.write("")
        st.write("---")

    # Choose which candidate to step through (default best by Dijkstra shortest length)
    st.subheader("Step-through Dijkstra on selected candidate")
    if paths:
        sel_idx = st.number_input("Select candidate # to step through", min_value=1, max_value=len(paths), value=1, step=1)
        sel_path = paths[sel_idx-1]
        # Build subgraph induced by nodes in selected path for clarity (or step on full G)
        subG = G  # stepping on full graph gives more realistic Dijkstra; use subgraph if you prefer
        # build steps lazily and store in session
        if "dijkstra_steps" not in st.session_state or st.session_state.get("dijkstra_key") != f"{start}_{sel_idx}":
            steps, prev = dijkstra_steps(subG, start)
            st.session_state.dijkstra_steps = steps
            st.session_state.dijkstra_prev = prev
            st.session_state.dijkstra_key = f"{start}_{sel_idx}"
            st.session_state.step_idx = 0
            st.session_state.auto_play = False

        steps = st.session_state.dijkstra_steps
        prev = st.session_state.dijkstra_prev

        # controls
        c1, c2, c3, c4 = st.columns([1,1,1,1])
        if c1.button("⏮️ Reset"):
            st.session_state.step_idx = 0
            st.session_state.auto_play = False
        if c2.button("◀️ Back"):
            st.session_state.step_idx = max(0, st.session_state.step_idx - 1)
        if c3.button("⏭️ Next"):
            st.session_state.step_idx = min(len(steps)-1, st.session_state.step_idx + 1)
        if c4.button("▶️ Auto"):
            st.session_state.auto_play = not st.session_state.auto_play

        # auto-play handling
        if st.session_state.auto_play:
            placeholder = st.empty()
            for i in range(st.session_state.step_idx, len(steps)):
                st.session_state.step_idx = i
                curr_node, dist_map, prev_map = steps[i]
                with placeholder.container():
                    st.subheader(f"Bước {i+1}/{len(steps)} — đang xét: `{curr_node}`")
                    fig, pos = draw_graph(G, pos=pos, highlight_nodes={curr_node}, highlight_path=sel_path)
                    st.pyplot(fig)
                    st.write("Khoảng cách tạm thời (distance map):")
                    st.write(dist_map)
                    final_path = reconstruct_path(prev_map, start, target)
                    if final_path:
                        st.success(f"Current best path to `{target}`: {' → '.join(final_path)}")
                    else:
                        st.info("Chưa có đường dẫn hợp lệ tới đích.")
                time.sleep(autoplay_interval)
            st.session_state.auto_play = False

        # display current step
        idx = st.session_state.step_idx
        curr_node, dist_map, prev_map = steps[idx]
        st.subheader(f"Bước {idx+1}/{len(steps)} — đang xét: `{curr_node}`")
        # draw graph highlighting current node and the selected candidate path
        fig, pos = draw_graph(G, pos=pos, highlight_nodes={curr_node}, highlight_path=sel_path)
        st.pyplot(fig)

        # display distance table and reconstructed path to target using current prev_map
        st.write("Khoảng cách tạm thời (distance map):")
        st.write(dist_map)
        # reconstruct path using prev_map
        final_path = reconstruct_path(prev_map, start, target)
        if final_path:
            st.success(f"Current best path to `{target}` (by prev pointers): {' → '.join(final_path)}")
        else:
            st.info("Chưa có đường dẫn hợp lệ tới đích theo prev pointers hiện tại.")

    # show full graph at bottom
    st.write("---")
    st.subheader("Full graph preview")
    fig2, _ = draw_graph(G, pos=pos, highlight_nodes=None, highlight_path=None, figsize=(6,4))
    st.pyplot(fig2)

st.write("----")
st.caption("Built for demo — you can extend features (save steps as GIF, load real model, add heuristics A*).")
