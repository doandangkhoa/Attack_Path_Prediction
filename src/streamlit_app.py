import streamlit as st
import numpy as np
import pandas as pd 
from pyvis.network import Network
import streamlit.components.v1 as components
import plotly.graph_objects as go
import json
import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.network_builder import build_random_network
from src.predict_attack import predict_attack

# ==========================================
# 1. PAGE CONFIG & CSS (Làm đẹp Dashboard)
# ==========================================
st.set_page_config(
    layout="wide", 
    page_title="CyberSec Path Analysis Dashboard",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# Custom CSS để làm đẹp các metrics và layout
st.markdown("""
<style>
    /* Chỉnh màu nền cho metric */
    div[data-testid="stMetric"] {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #dcdcdc;
    }
    /* Chỉnh tiêu đề */
    h1 {
        color: #2c3e50;
    }
    /* Chỉnh bảng */
    div[data-testid="stDataFrame"] {
        width: 100%;
    }
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

def pyvis_graph(G, highlight_paths=None, best_path=None):
    # Cấu hình đồ thị với physics tốt hơn cho dashboard
    net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="black")
    # net.force_atlas_2based(gravity=-50) # Tinh chỉnh physics nếu cần
    
    # 1. Nodes
    for n, d in G.nodes(data=True):
        role = d.get("role", "router")
        color = {
            "client": "#b8f2e6",
            "server": "#fefbbd",
            "firewall": "#ef8d7a",
            "router": "#97c2fc"
        }.get(role, "#6C6C6A")
        
        # Thêm icon hoặc hình dạng nếu muốn dashboard đẹp hơn (tùy chọn)
        net.add_node(n, label=n, title=f"{n} ({role})", color=color, size=20)

    # 2. Edge Properties Setup
    edge_props = {}
    
    # 2a. Default Edges
    for u, v, d in G.edges(data=True):
        edge_key = (u, v)
        if edge_key not in edge_props:
            edge_props[edge_key] = {"u": u, "v": v, "color": "#E0E0E0", "width": 1, "title": str(d.get("weight", 1)), "arrows": None}
        if (v, u) not in edge_props:
             edge_props[(v, u)] = {"u": v, "v": u, "color": "#E0E0E0", "width": 1, "title": str(d.get("weight", 1)), "arrows": None}

    # 2b. Highlight Paths
    if highlight_paths:
        for p in highlight_paths:
            for a, b in zip(p[:-1], p[1:]):
                edge_key = (a, b)
                if edge_key in edge_props:
                    edge_props[edge_key].update({"color": "#ff4b4b", "width": 3, "arrows": "to"})

    # 2c. Best Path
    if best_path:
        for a, b in zip(best_path[:-1], best_path[1:]):
            edge_key = (a, b)
            if edge_key in edge_props:
                edge_props[edge_key].update({"color": "#f1c40f", "width": 6, "arrows": "to"})

    # 3. Draw Edges (Logic Fix)
    drawn_undirected = set()
    highlighted_props = [p for p in edge_props.values() if p["arrows"] is not None]
    default_props = [p for p in edge_props.values() if p["arrows"] is None]

    for props in highlighted_props:
        net.add_edge(props["u"], props["v"], title=props["title"], color=props["color"], width=props["width"], arrows=props["arrows"])
        drawn_undirected.add(frozenset([props["u"], props["v"]]))

    for props in default_props:
        if frozenset([props["u"], props["v"]]) not in drawn_undirected:
            net.add_edge(props["u"], props["v"], title=props["title"], color=props["color"], width=props["width"], arrows=None)
            drawn_undirected.add(frozenset([props["u"], props["v"]]))

    # Tắt physics sau khi load để node không bị trôi (tốt cho dashboard)
    net.toggle_physics(True) 
    html_path = "data/graph_vis.html"
    net.save_graph(html_path)
    return html_path

# ==========================================
# 3. MAIN DASHBOARD LOGIC
# ==========================================

# --- 0. Khởi tạo Session State ---
if 'graph_state' not in st.session_state:
    np.random.seed(42) 
    st.session_state['base_G'] = build_random_network(15, seed=42)
    st.session_state['current_G'] = st.session_state['base_G'].copy()
    st.session_state['defense_history'] = None 
    st.session_state['graph_state'] = True

# --- A. Sidebar: Control Panel ---
with st.sidebar:
    st.title("🎛️ Control Panel")
    
    # --- PHẦN 1: QUẢN LÝ TOPOLOGY (HỆ THỐNG) ---
    with st.container(border=True):
        st.caption("🌐 Network Topology")
        # Nút Reset tách biệt hẳn ra ngoài
        if st.button("🔄 New Random Graph", use_container_width=True):
            st.session_state['base_G'] = build_random_network(15) # Tạo mới hoàn toàn
            st.session_state['current_G'] = st.session_state['base_G'].copy()
            st.session_state['defense_history'] = None
            st.rerun()
            
        # Lấy dữ liệu đồ thị hiện tại
        G = st.session_state['current_G']
        nodes = list(G.nodes())
        clients = [n for n in nodes if G.nodes[n].get('role') == 'client']
        servers = [n for n in nodes if G.nodes[n].get('role') == 'server']
        # Các node có thể đặt firewall (trừ Client/Server để demo rõ hơn)
        potential_firewalls = [n for n in nodes if G.nodes[n].get('role') not in ['client', 'server']]

    # --- BẮT ĐẦU FORM CẤU HÌNH CHÍNH ---
    with st.form("simulation_form"):
        
        # --- PHẦN 2: KỊCH BẢN TẤN CÔNG (RED TEAM) ---
        st.markdown("### ⚔️ Attack Scenario")
        
        col_src, col_dst = st.columns(2)
        with col_src:
            c_idx = 0 if len(clients) > 0 else None
            src = st.selectbox("Source", clients, index=c_idx, help="Attacker Node")
        with col_dst:
            s_idx = len(servers) - 1 if len(servers) > 0 else None
            dst = st.selectbox("Target", servers, index=s_idx, help="Victim Node")
            
        # Gom các cài đặt thuật toán vào Expander cho gọn
        with st.expander("⚙️ Algorithm Settings"):
            st.caption("Tinh chỉnh tham số mô hình AI")
            k = st.slider("Top-K Paths", 1, 10, 5) 
            mode = st.radio("Selection Strategy", ["softmax", "argmax"], 
                           captions=["Mô phỏng ngẫu nhiên (Hacker)", "Chọn đường tốt nhất (Robot)"])

        st.divider()

        # --- PHẦN 3: KỊCH BẢN PHÒNG THỦ (BLUE TEAM) ---
        st.markdown("### 🛡️ Defense Strategy")
        
        # Hiển thị trạng thái hiện tại rõ ràng
        current_defense = st.session_state.get('defense_history', None)
        
        if current_defense:
            st.warning(f"🔒 Active Firewall at: **{current_defense}**", icon="⚠️")
            # Logic hiển thị danh sách chọn
            defense_options = ["Keep Current"] + ["🛑 REMOVE FIREWALL"] + [n for n in potential_firewalls if n != current_defense]
            idx_def = 0 
        else:
            st.info("✅ No Active Firewall", icon="🟢")
            defense_options = ["None"] + potential_firewalls
            idx_def = 0

        defense_node_selection = st.selectbox(
            "Deploy/Remove Firewall:", 
            defense_options,
            index=idx_def,
            help="Đặt Firewall sẽ tăng trọng số cạnh (+50), buộc kẻ tấn công đổi hướng."
        )

        st.markdown("") # Spacer
        submitted = st.form_submit_button("🚀 RUN SIMULATION", type="primary", use_container_width=True)


    # --- XỬ LÝ LOGIC KHI NHẤN NÚT RUN ---
    if submitted:
        # 1. Xử lý logic phòng thủ (Blue Team)
        # Chỉ chạy logic nếu người dùng không chọn "Keep Current" (Giữ nguyên)
        if defense_node_selection != "Keep Current":
            
            # Reset về đồ thị gốc sạch sẽ để tính toán lại từ đầu
            G = st.session_state['base_G'].copy()
            
            # Case A: Gỡ bỏ Firewall
            if defense_node_selection == "None" or defense_node_selection == "🛑 REMOVE FIREWALL":
                st.session_state['defense_history'] = None
                if current_defense is not None:
                    st.toast("Firewall has been removed.", icon="🔓")
            
            # Case B: Thêm Firewall Mới
            else:
                target_node = defense_node_selection
                # Tăng trọng số cực mạnh
                for u, v in G.edges(target_node):
                    G[u][v]['weight'] = G[u][v].get('weight', 1) + 50 
                    
                # 2. Đổi Role node thành Firewall (Logic hiển thị) 
                G.nodes[target_node]['role'] = 'firewall' 
                
                st.session_state['defense_history'] = target_node
                st.toast(f"Firewall deployed at {target_node}!", icon="🛡️")

            # Lưu trạng thái mới
            st.session_state['current_G'] = G

        # 2. Chạy logic tấn công (Red Team)
        if src and dst and src != dst:
            result = predict_attack(G, src, dst, k=k, mode=mode)
        else:
             st.error("Invalid Source or Target.")
             result = None
        
# --- B. Load Metrics ---
metrics = load_metrics(METRICS_PATH)
acc = metrics.get('accuracy', 0) if metrics else 0
f1 = metrics.get('f1', 0) if metrics else 0

# --- C. Main Content ---
st.title("🛡️ Network Path Prediction System")

# Run logic
if submitted or True: # Chạy lần đầu mặc định
    if src == dst:
        st.error("⚠️ Source và Target phải khác nhau!")
        result = None
    else:
        result = predict_attack(G, src, dst, k=k, mode=mode)

# --- D. KPI Row (Top Dashboard) ---
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric(label="Model Accuracy", value=f"{acc:.1%}", delta="Baseline")
with col2:
    st.metric(label="Model F1-Score", value=f"{f1:.3f}")
with col3:
    if result:
        # Lấy xác suất cao nhất
        best_prob = max(result["rf_probs"])
        st.metric(label="Highest Threat Prob", value=f"{best_prob:.1%}", delta_color="inverse")
    else:
        st.metric(label="Highest Threat Prob", value="N/A")
with col4:
    if result:
        st.metric(label="Paths Analyzed", value=len(result["paths"]))
    else:
        st.metric(label="Paths Analyzed", value="0")

st.divider()

# --- E. Visualization Split View ---
if result:
    # Chia layout: 70% Graph (Trái), 30% Details (Phải)
    col_viz, col_data = st.columns([2.2, 1]) 
    
    # 1. Cột Trái: Đồ thị (Giữ nguyên)
    with col_viz:
        st.subheader("🌐 Network Topology Map")
        html_file = pyvis_graph(G, highlight_paths=result["paths"], best_path=result["best_path"])
        components.html(open(html_file, "r", encoding="utf-8").read(), height=610, scrolling=False)

    with col_data:
        st.subheader("🎯 Attack Strategy Analysis")
        
        chosen_idx = result["chosen_index"]
        best_feat = result["features"][chosen_idx]
        all_feats = result["features"]
        
        # --- 1. ĐÁNH GIÁ RỦI RO (RISK METER) ---
        rf_conf = result['rf_probs'][chosen_idx]
        
        if rf_conf > 0.8:
            risk_label, risk_color, icon = "CRITICAL", "#ff4b4b", "🔥" # Đỏ
        elif rf_conf > 0.5:
            risk_label, risk_color, icon = "HIGH", "#ffa421", "⚠️"     # Cam
        else:
            risk_label, risk_color, icon = "MEDIUM", "#0083c9", "🛡️"   # Xanh
            
        st.markdown(f"""
        <div style="padding: 15px; border-radius: 8px; background-color: #f0f2f6; border-left: 6px solid {risk_color}; margin-bottom: 20px;">
            <h3 style="margin:0; color: {risk_color}; font-size: 24px;">{icon} {risk_label} THREAT</h3>
            <p style="margin: 5px 0 0 0; font-size: 16px;">AI Confidence: <b>{rf_conf:.1%}</b></p>
        </div>
        """, unsafe_allow_html=True)

        # --- 2. HIỂN THỊ ROUTE (MỚI THÊM VÀO) ---
        st.markdown("#### 📍 Execution Path")
        path_str = " → ".join(result["best_path"])
        # Dùng st.code để làm nổi bật đường dẫn
        st.code(path_str, language="text")

        # --- 3. GIẢI THÍCH TẠI SAO (INSIGHTS) ---
        st.markdown("#### 🔍 AI Reasoning")
        
        # A. Phân tích về Weight (Hiệu quả)
        other_weights = [f['total_weight'] for i, f in enumerate(all_feats) if i != chosen_idx]
        avg_weight = np.mean(other_weights) if other_weights else best_feat['total_weight']
        weight_diff = avg_weight - best_feat['total_weight']
        
        if weight_diff > 5:
            st.write(f"⚡ **Efficiency:** This path is significantly faster/cheaper ({weight_diff:.1f} pts) than average alternatives.")
        elif weight_diff < -10:
            st.write(f"🐢 **Forced Detour:** Attacker is forced to take a longer path (Cost +{abs(weight_diff):.1f}) to avoid defenses.")
        else:
            st.write(f"⚖️ **Balanced:** This path offers the best trade-off between cost and risk.")

        # B. Phân tích về Security (Firewall/Server)
        if best_feat['firewall_crossings'] > 0:
            st.warning(f"🔓 **Breach:** Bypasses {best_feat['firewall_crossings']} Firewall(s).")
        elif best_feat['role_score'] > 5:
            st.error("🎯 **Target:** Direct access to High-Value Asset (Server).")
        
        # C. Phân tích Rank
        if best_feat['rank'] == 1:
            st.info("🥇 **Top Choice:** Mathematically the shortest path available.")
        else:
            st.info(f"🥈 **Strategic Shift:** Not the shortest (Rank {best_feat['rank']}), likely chosen to evade detection.")

        st.divider()

        # --- 4. BẢNG SO SÁNH (COMPARISON TABLE) ---
        st.subheader("📊 Candidate Ranking")
        
        df_data = []
        for i, p in enumerate(result["paths"]):
            path_str = " → ".join(p)
            if len(path_str) > 50:
                display_path = f"{p[0]} ... {p[-1]} ({len(p)} hops)"
            else:
                display_path = path_str
                
            w = sum([G[u][v].get("weight", 0) for u, v in zip(p[:-1], p[1:])])
            is_selected = "✅" if i == chosen_idx else ""
            
            df_data.append({
                "Select": is_selected,
                "Rank": i+1,
                "Route": display_path,
                "Full_Route": path_str,
                "Weight": w,
                "Threat Score": result['softmax_probs'][i],
                "RF Prob": result['rf_probs'][i]
            })
        
        df = pd.DataFrame(df_data)
        
        st.dataframe(
            df, 
            hide_index=True,
            column_config={
                "Select": st.column_config.TextColumn("Select", width="small"),
                "Rank": st.column_config.NumberColumn("Rank", format="#%d", width="small"),
                "Route" : st.column_config.TextColumn("Candidate Route",width="medium", help="Đường đi cụ thể"),
                "Full_Route": None, # hidden
                "Weight": st.column_config.NumberColumn("Weight", format="%d", width="small"),
                "Threat Score": st.column_config.ProgressColumn("Threat Score", format="%.2f", min_value=0, max_value=1),
                "RF prob": st.column_config.NumberColumn("Raw Prob", format="%.2f")
            },
            use_container_width=True
        )

