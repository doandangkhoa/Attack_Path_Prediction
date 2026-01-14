import streamlit as st
import numpy as np
import pandas as pd
from pyvis.network import Network
import streamlit.components.v1 as components
import json
import os, sys

# Thêm đường dẫn để import module từ thư mục gốc
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.network_builder import build_random_policy_oracle_graph
from src.build_network_demo import build_demo_network
from src.predict_attack import predict_attack
from src.explainability import analyze_path

# ==========================================
# 1. PAGE CONFIG & CSS
# ==========================================
st.set_page_config(
    layout="wide", 
    page_title="CyberSec Path Analysis Dashboard",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# CSS tùy chỉnh để giao diện đẹp hơn
st.markdown("""
<style>
    div[data-testid="stMetric"] {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #dcdcdc;
    }
    h1 { color: #2c3e50; }
    div[data-testid="stDataFrame"] { width: 100%; }
</style>
""", unsafe_allow_html=True)

MODEL_PATH = "models/rf_baseline.pkl"
METRICS_PATH = "models/metrics.json"
os.makedirs("models", exist_ok=True)
os.makedirs("data", exist_ok=True)

# ==========================================
# 2. UTILITIES
# ==========================================
def load_metrics(metrics_path):
    if os.path.exists(metrics_path):
        try:
            return json.load(open(metrics_path, "r"))
        except:
            return None
    return None

def pyvis_graph(G, highlight_paths=None, best_path=None, source=None, destination=None, positions=None):
    net = Network(height="650px", width="100%", bgcolor="#ffffff", font_color="black", directed=True)
    
    # --- 1. SETUP NODES (Giữ nguyên) ---
    for n, d in G.nodes(data=True):
        role = d.get("role", "unknown")
        label = d.get("label", str(n))
        
        color_map = {
            "client":   "#74b9ff", "server":   "#ffeaa7", "switch":   "#dfe6e9",
            "firewall": "#f32828", "router":   "#a29bfe", "security": "#eb8760",
            "identity": "#6c5ce7",
        }
        bg_color = color_map.get(role, "#b2bec3") 

        if n == source:
            color = {"background": bg_color, "border": "#ff0000", "highlight": {"background": bg_color, "border": "#ff0000"}}
            size = 45; border_width = 2; title = f"SOURCE: {label}"
        elif n == destination:
            color = {"background": bg_color, "border": "#ff0000", "highlight": {"background": bg_color, "border": "#ff0000"}}
            size = 45; border_width = 2; title = f"TARGET: {label}"
        else:
            color = bg_color; size = 25 if role not in ['switch', 'router'] else 20
            border_width = 2; title = f"{label} ({role})\nLayer: {d.get('layer','N/A')}"

        net.add_node(n, label=label, title=title, color=color, size=size, borderWidth=border_width)

    # --- 2. SETUP EDGES (TỐI ƯU HÓA HIỂN THỊ) ---
    edge_props = {}
    drawn_undirected = set()

    for u, v, d in G.edges(data=True):
        edge_type = d.get("type", "infrastructure")
        weight = d.get("weight", 1)
        
        # Mặc định
        arrows_config = None
        edge_dash = False
        edge_width = 1
        edge_color = "#b2bec3" 
        
        # Smooth mặc định: Để 'dynamic' để Vis.js tự né tránh các node
        # Thay vì set cứng False/True, ta dùng dynamic cho đẹp
        smooth_config = {"type": "continuous", "roundness": 0.05}

        if edge_type in ["exploit", "ad_attack"]:
            edge_color = "#ff4d4d"; edge_width = 2; edge_dash = True
            arrows_config = "to"
            # Đường tấn công cho cong nhiều hơn chút để tách biệt
            smooth_config = {"type": "curvedCW", "roundness": 0.2}
            
        elif edge_type == "authorized":
            edge_color = "#00b894"; edge_width = 2
            arrows_config = "to"
            smooth_config = {"type": "curvedCW", "roundness": 0.2}
            
        elif edge_type == "privilege":
            edge_color = "#e84393"; edge_width = 3
            arrows_config = "to"
            smooth_config = {"type": "curvedCW", "roundness": 0.2}
            
        else:
            # Infrastructure (Hạ tầng)
            if frozenset([u, v]) in drawn_undirected: continue
            drawn_undirected.add(frozenset([u, v]))
            edge_color = "#bdc3c7"; edge_width = 3 
            arrows_config = None
            # Hạ tầng cho thẳng hoặc cong nhẹ "continuous" để trông cứng cáp
            smooth_config = {"type": "continuous", "roundness": 0}

        title_str = f"Type: {edge_type}\nCost: {weight}"
        
        edge_key = (u, v)
        edge_props[edge_key] = {
            "u": u, "v": v, 
            "color": edge_color, "width": edge_width, "title": title_str, 
            "dashes": edge_dash, "arrows": arrows_config, "smooth": smooth_config
        }

    # --- 3. OVERRIDE BEST PATH ---
    if best_path:
        for i in range(len(best_path) - 1):
            u, v = best_path[i], best_path[i+1]
            
            override = {
                "color": "#000000", "width": 7, "dashes": False, "arrows": "to", "shadow": True,
                # Cong nhẹ để nổi lên trên
                "smooth": {'type': 'curvedCW', 'roundness': 0.15} 
            }

            if (u, v) in edge_props:
                edge_props[(u, v)].update(override)
            elif (v, u) in edge_props:
                # Nếu đi ngược đường hạ tầng, vẽ đường mới đè lên
                edge_props[(u, v)] = {
                    "u": u, "v": v, "title": "ATTACK PATH", **override
                }

    # --- 4. DRAW FINAL EDGES ---
    for props in edge_props.values():
        net.add_edge(props["u"], props["v"], title=props["title"], color=props["color"], 
                     width=props["width"], dashes=props["dashes"], arrows=props["arrows"], 
                     smooth=props["smooth"])

    # ==========================================
    # 5. CẤU HÌNH PHYSICS (QUAN TRỌNG NHẤT)
    # ==========================================
    # Sử dụng thuật toán Barnes Hut với lực đẩy cực mạnh để tách node
    net.barnes_hut(
        gravity=-2500,          # Giảm lực đẩy (Từ -8000 xuống -2500) để node gần nhau hơn
        central_gravity=0.5,    # Tăng lực hút về tâm (0.3 -> 0.5) để đồ thị không bị trôi
        spring_length=120,      # Dây ngắn lại (250 -> 120) cho gọn
        spring_strength=0.04,   # Dây cứng hơn một chút
        damping=0.09,
        overlap=0.5             # Vẫn giữ chống chồng lấn (0.5 là mức cân bằng)
    )
    
    # Nếu muốn hiển thị bảng điều chỉnh physics trực tiếp trên web để nghịch (Debug)
    # net.show_buttons(filter_=['physics']) 

    if positions:
        for i, node in enumerate(net.nodes):
            nid = node['id']
            if nid in positions:
                net.nodes[i]['x'] = positions[nid]['x']
                net.nodes[i]['y'] = positions[nid]['y']
                net.nodes[i]['fixed'] = True
        net.toggle_physics(False)
    else:
        net.toggle_physics(True)
    
    html_path = "data/graph_vis.html"
    net.save_graph(html_path)
    
    node_positions = {}
    for node in net.nodes:
        nid = node.get('id')
        if nid and 'x' in node and 'y' in node:
            node_positions[nid] = {'x': node['x'], 'y': node['y']}
    
    return html_path, node_positions if node_positions else None

# ==========================================
# 3. MAIN DASHBOARD LOGIC
# ==========================================

# --- 0. Khởi tạo Session State ---
if 'graph_state' not in st.session_state:
    np.random.seed(42) 
    st.session_state['base_G'] = build_random_policy_oracle_graph()
    st.session_state['current_G'] = st.session_state['base_G'].copy()
    st.session_state['defense_history'] = None 
    st.session_state['sim_result'] = None # Biến lưu kết quả chạy
    st.session_state['highlighted_path_idx'] = None  # Track which path is highlighted
    st.session_state['graph_positions'] = None  # Store graph layout positions
    st.session_state['graph_state'] = True

def get_node_label(node_id):
    if node_id in G.nodes:
        return G.nodes[node_id].get('label', node_id)
    return node_id

def format_path_short(path_list):
    """Rút gọn hiển thị đường đi: A -> ... -> Z"""
    if len(path_list) <= 3:
        return " ➝ ".join(path_list)
    return f"{path_list[0]} ➝ ... ({len(path_list)-2} hops) ... ➝ {path_list[-1]}"

# --- A. Sidebar: Control Panel ---
with st.sidebar:
    st.title(" Control Panel")
    
    with st.container(border=True):
        st.caption("🌐 Network Topology")
        topology_type = st.selectbox(
            "Select Topology Type:",
            ["build_random_policy_oracle_graph", "build_demo_network"],
            index=0
        )
        if st.button("🔄 New Graph", use_container_width=True):
            if topology_type == "build_random_policy_oracle_graph":
                new_G = build_random_policy_oracle_graph()
            elif topology_type == "build_demo_network":
                new_G = build_demo_network()
                
            st.session_state['base_G'] = new_G
            st.session_state['current_G'] = st.session_state['base_G'].copy()
            st.session_state['defense_history'] = None
            st.session_state['sim_result'] = None
            st.rerun()
            
        G = st.session_state['current_G']
        nodes = list(G.nodes())
        
        # CẬP NHẬT FILTER: Mở rộng phạm vi Source
        # Bây giờ Hacker có thể bắt đầu từ: Client, Router (bị hack), hoặc Partner VPN
        clients = [n for n in nodes if G.nodes[n].get('role') in ['client', 'router', 'partner']]
        
        # CẬP NHẬT FILTER: Mở rộng phạm vi Target
        # Target có thể là: Server, Database, hoặc Identity (Active Directory)
        target_roles = ['server', 'identity', 'database']
        servers = [n for n in nodes if G.nodes[n].get('role') in target_roles]
        
        # Fallback nếu list rỗng (tránh lỗi UI)
        if not clients: clients = nodes[:1]
        if not servers: servers = nodes[-1:]
    
    with st.form("simulation_form"):
        st.markdown("### ⚔️ Attack Scenario")
        col_src, col_dst = st.columns(2)
        with col_src:
            c_idx = 0 if len(clients) > 0 else None
            src = st.selectbox("Source", clients, index=c_idx, format_func=get_node_label)
        with col_dst:
            s_idx = len(servers) - 1 if len(servers) > 0 else None
            dst = st.selectbox("Target", servers, index=s_idx, format_func=get_node_label)
            
        with st.expander("⚙️ Algorithm Settings"):
            k = st.slider("Top-K Paths", 1, 10, 5) 
            mode = st.radio("Selection Strategy", [ "argmax", "softmax"])

        st.divider()
        submitted = st.form_submit_button("RUN SIMULATION", type="primary", use_container_width=True)

    # --- XỬ LÝ LOGIC KHI NHẤN NÚT ---
    if submitted:
        if src and dst and src != dst:
            result = predict_attack(G, src, dst, k=k, mode=mode)

            if result is None or "paths" not in result or len(result["paths"]) == 0:
                st.error("❌ Không tồn tại đường đi hợp lệ giữa Source và Target.")
                st.session_state['sim_result'] = None
            else:
                st.session_state['sim_result'] = result
                st.session_state['src'] = src
                st.session_state['dst'] = dst

                # 👉 AI chọn đường nguy hiểm nhất, không phải đường ngắn nhất
                if result.get("chosen_index") is not None:
                    st.session_state['highlighted_path_idx'] = result["chosen_index"]
                else:
                    st.session_state['highlighted_path_idx'] = 0
        else:
            st.error("⚠️ Invalid Source or Target.")
            st.session_state['sim_result'] = None


# ==========================================
# 4. GIAO DIỆN CHÍNH (TABBED INTERFACE)
# ==========================================
st.title("Network Path Prediction System")

# Tạo 2 tab: 1 để chạy Demo, 1 để xem báo cáo kỹ thuật
tab1, tab2 = st.tabs(["Live Simulation", "Model Performance"])

# --- TAB 1: LIVE SIMULATION ---
with tab1:
    if st.session_state['sim_result'] is None:
        # Trạng thái chờ
        st.info("👋 Chào mừng! Hãy chọn Source/Target ở thanh bên trái và nhấn **'RUN SIMULATION'** để bắt đầu.")
        st.subheader("🌐 Current Network Topology")
        html_file, positions = pyvis_graph(st.session_state['current_G'], source=st.session_state.get('src'), destination=st.session_state.get('dst'))
        components.html(open(html_file, "r", encoding="utf-8").read(), height=600)
    else:
        # Lấy kết quả
        result = st.session_state['sim_result']
        G = st.session_state['current_G']
        chosen_idx = result["chosen_index"]
        
        # ==========================================
        # PHẦN 1: VISUALIZATION & RANKING TABLE (2 CỘT)
        # ==========================================
        col_viz, col_table = st.columns([2.5, 1.5])
        
        # Cột Trái: Đồ thị
        with col_viz:
            st.subheader("🌐 Network Topology Map")
            src_node = st.session_state.get('src')
            dst_node = st.session_state.get('dst')
            
            # Get the path to highlight based on current selection
            highlighted_idx = st.session_state.get('highlighted_path_idx', chosen_idx)
            highlight_path = result["paths"][highlighted_idx] if highlighted_idx is not None else result["best_path"]
            
            # Use cached positions to maintain graph layout, or generate new ones on first render
            positions = st.session_state.get('graph_positions')
            html_file, new_positions = pyvis_graph(G, best_path=highlight_path, source=src_node, destination=dst_node, positions=positions)
            
            # Store positions on first render for subsequent updates (only if we got valid positions)
            if positions is None and new_positions:
                st.session_state['graph_positions'] = new_positions
            
            components.html(open(html_file, "r", encoding="utf-8").read(), height=650, scrolling=False)

        # Cột Phải: Threat Analysis + Ranking Table
        with col_table:
            st.subheader("Threat Analysis")
            
            # Lấy index của đường đang xem
            current_view_idx = st.session_state.get('highlighted_path_idx', chosen_idx)
            
            # Lấy điểm AI Score của đường đó
            rf_conf = result['rf_probs'][current_view_idx]
            best_feat = result["features"][current_view_idx]
            
            # Đánh giá mức độ rủi ro
            if rf_conf > 0.9:
                risk_label, risk_color, icon = "CRITICAL", "#d63031", "🔥"
            elif rf_conf > 0.6:
                risk_label, risk_color, icon = "HIGH", "#e17055", "⚠️"
            elif rf_conf > 0.3:
                risk_label, risk_color, icon = "MEDIUM", "#e1e349", "⚠️"
            else:
                risk_label, risk_color, icon = "SAFE", "#00b894", "🛡️"
            
            # Header động
            header_text = "POTENTIAL ATTACK" if current_view_idx == chosen_idx else f"ANALYZING PATH #{current_view_idx + 1}"
                
            st.markdown(f"""
            <div style="padding: 15px; border-radius: 10px; background-color: #f0f2f6; border-left: 8px solid {risk_color}; text-align: center;">
                <p style="margin: 0; font-size: 14px; color: #636e72; font-weight: bold; text-transform: uppercase;">{header_text}</p>
                <h2 style="margin:5px 0; color: {risk_color}; font-size: 20px;">{icon} {risk_label}</h2>
                <p style="margin: 5px 0 0 0; font-size: 14px; color: #636e72;">AI Confidence Score</p>
                <h1 style="margin:0; font-size: 32px; color: #2d3436;">{rf_conf:.1%}</h1>
            </div>
            """, unsafe_allow_html=True)
            
            # ================================
            # RISK DIMENSION BREAKDOWN
            # ================================
            st.subheader("Candidate Path Overview")

            df_data = []

            for i, p in enumerate(result["paths"]):
                feat = result["features"][i]
                rf_prob = result['rf_probs'][i]

                total_weight = sum([G[u][v].get("weight", 0) for u, v in zip(p[:-1], p[1:])])
                is_selected = "⭐" if i == chosen_idx else f"#{i+1}"

                # Các trục rủi ro chính
                cost_score = total_weight
                detection_score = feat.get("total_detection", 0)
                detection_prob = (detection_score / 704) * 100
                exploit_score = feat.get("exploit_count", 0)
                privilege_score = feat.get("privilege_gain", 0)

                df_data.append({
                    "Rank": i + 1,
                    "Selection": is_selected,
                    "AI Score": rf_prob,
                    "Detectionable": detection_prob,
                    "Exploit": exploit_score,
                    "Privilege": privilege_score,
                    "Cost": total_weight,
                    "Path Index": i,
                    "Full Path": " ➝ ".join(p)
                })

            df = pd.DataFrame(df_data)

            # ================================
            # HIỂN THỊ BẢNG TỔNG QUÁT
            # ================================
            st.dataframe(
                df[["Rank", "AI Score", "Cost", "Detectionable", "Exploit", "Privilege"]],
                column_config={
                    "AI Score": st.column_config.ProgressColumn(
                        "AI Threat Score",
                        format="%.2f",
                        min_value=0,
                        max_value=1,
                        width="medium"
                    ),
                    "Cost": st.column_config.NumberColumn(
                        "Effort (Cost)",
                        help="Độ khó thực hiện. Thấp = dễ tấn công"
                    ),
                    "Detectionable": st.column_config.NumberColumn(
                        "Stealthy",
                        format="%.0f%%",
                        min_value=0,
                        max_value=1,
                        help="Mức độ bị IDS/EDR phát hiện. Cao = dễ bị phát hiện"
                    ),
                    "Exploit": st.column_config.NumberColumn(
                        "Exploit Steps",
                        help="Số bước khai thác lỗ hổng"
                    ),
                    "Privilege": st.column_config.NumberColumn(
                        "Privilege Impact",
                        help="Mức độ leo thang đặc quyền"
                    ),
                },
                hide_index=True,
                use_container_width=True,
                height=300
            )
            
            # Nút xem chi tiết
            st.markdown("**View Route:**")
            button_cols = st.columns(len(df_data))
            for col, (idx, row) in zip(button_cols, df.iterrows()):
                with col:
                    btn_label = "⭐" if int(row['Path Index']) == chosen_idx else f"{int(row['Rank'])}"
                    if st.button(btn_label, key=f"view_path_{int(row['Path Index'])}", 
                               help=row['Full Path'], use_container_width=True):
                        st.session_state['highlighted_path_idx'] = int(row['Path Index'])
                        st.rerun()
        st.divider()

        highlighted_idx = st.session_state.get('highlighted_path_idx', chosen_idx)
        selected_path = result["paths"][highlighted_idx]

        analysis = analyze_path(G, selected_path, ai_confidence=rf_conf)

        # 2. Hiển thị Card Tổng quan (HTML/CSS)
        st.markdown(f"""
        <div style="
            background-color: white; 
            padding: 20px; 
            border-radius: 10px; 
            border: 1px solid #e0e0e0; 
            border-left: 10px solid; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        ">
            <h3 style="margin-top: 0;display: flex; align-items: center;">
                Summary
            </h3>
            <p style="font-size: 16px; color: #2d3436; margin-bottom: 5px;">
                <strong> {analysis['summary']} </strong>
            </p>
            <div style="margin-top: 10px; font-size: 14px; color: #636e72;">
                <strong>Attack Phases Involved:</strong> <span style="background-color: #f1f2f6; padding: 2px 8px; border-radius: 4px;">{', '.join(analysis['phases'])}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # 3. Hiển thị Metrics (3 Cột)
        m1, m2, m3 = st.columns(3)
        m1.metric("Exploit Steps", analysis['exploit_count'], help="Số bước tấn công khai thác lỗ hổng")
        m2.metric("Privileged/Auth Access", analysis['auth_count'], help="Số bước sử dụng quyền hạn (nguy cơ Insider Threat)")
        m3.metric("Total Path Cost", f"{sum(step['weight'] for step in analysis['steps'])}", help="Tổng trọng số (Độ khó) của đường đi")

        # 4. Bảng chi tiết từng bước (Step-by-Step Table)
        st.subheader("Step-by-Step Execution Flow")

        rows = []
        for i, step in enumerate(analysis["steps"], 1):
            # Tạo icon cho cột Type để dễ nhìn
            type_icon = "➡️"
            if step["type"] in ["exploit", "rce_exploit", "sqli", "phishing"]: type_icon = "💣"
            elif step["type"] == "authorized": type_icon = "🔑"
            elif step["type"] in ["privilege", "priv_esc"]: type_icon = "⚡"
            elif step["type"] == "misconfig": type_icon = "🛠️"

            rows.append({
                "Step": i,
                "From": get_node_label(step["from"]), # Dùng hàm helper lấy tên hiển thị
                "To": get_node_label(step["to"]),
                "Action": f"{type_icon} {step['type'].upper()}",
                "Phase": step["phase"],
                "Details": step["description"]
            })

        df_steps = pd.DataFrame(rows)

        st.dataframe(
            df_steps,
            column_config={
                "Step": st.column_config.NumberColumn("Step", width="small"),
                "From": st.column_config.TextColumn("Source", width="small"),
                "To": st.column_config.TextColumn("Destination", width="small"),
                "Action": st.column_config.TextColumn("Action Type", width="small"),
                "Phase": st.column_config.TextColumn("Kill Chain Phase", width="medium"),
                "Details": st.column_config.TextColumn("Analysis", width="large"),
            },
            hide_index=True,
            use_container_width=True
        )
        
# --- TAB 2: MODEL PERFORMANCE (BÁO CÁO KỸ THUẬT) ---
with tab2:
    st.header("🧠 Model Evaluation Metrics")
    metrics = load_metrics(METRICS_PATH)
    
    if metrics:
        # KPIs
        k1, k2, k3 = st.columns(3)
        k1.metric("Accuracy", f"{metrics['accuracy']:.2%}")
        k2.metric("F1-Score", f"{metrics['f1']:.2%}")
        
        # Tính Recall
        cm = metrics['confusion_matrix'] 
        tn, fp = cm[0][0], cm[0][1]
        fn, tp = cm[1][0], cm[1][1]
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        k3.metric("Recall (Sensitivity)", f"{recall:.2%}", delta="Security Critical")

        st.divider()
        
        # Confusion Matrix & Explain
        c1, c2 = st.columns([1, 1.5])
        with c1:
            st.subheader("Confusion Matrix")
            # Sửa lại vị trí hiển thị trong bảng cho đúng chuẩn Sklearn
            # Hàng 1: TN (Góc trái trên), FP (Góc phải trên)
            # Hàng 2: FN (Góc trái dưới), TP (Góc phải dưới)
            cm_data = pd.DataFrame(
                [[f"TN: {tn}", f"FP: {fp}"], 
                 [f"FN: {fn}", f"TP: {tp}"]],
                index=["Thực tế: An toàn (0)", "Thực tế: Tấn công (1)"],
                columns=["AI đoán: An toàn (0)", "AI đoán: Tấn công (1)"]
            )
            st.table(cm_data)
            
        with c2:
            st.subheader("📝 Giải thích chỉ số")
            st.markdown(f"""
            - **True Positive ({tp}):** Số lần AI **bắt đúng** đường tấn công.
            - **True Negative ({tn}):** Số lần AI xác nhận đúng đường an toàn.
            - **False Positive ({fp}) - Báo động giả:** AI báo là tấn công, nhưng thực tế là an toàn. .
            - **False Negative ({fn}) - Bỏ lọt:** AI báo là an toàn, nhưng thực tế là tấn công. .
            """)

        # Feature Importance
        st.divider()
        st.subheader("⭐ Feature Importance")
        if 'feature_importance' in metrics:
            feat_df = pd.DataFrame(list(metrics['feature_importance'].items()), columns=['Feature', 'Importance'])
            feat_df = feat_df.sort_values(by='Importance', ascending=False)
            st.bar_chart(feat_df.set_index('Feature'))
    else:
        st.warning("⚠️ Chưa có dữ liệu huấn luyện. Hãy chạy file 'train_model.py' trước.")