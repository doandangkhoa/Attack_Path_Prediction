import numpy as np
from collections import Counter

def extract_features(candidate_path, graph, shortest_path_weight, rank=0, role_weights=None):
    """
    Edge = {weight, detection, privilege}
    [UPDATED] Hỗ trợ logic Bastion Host và MFA detection.
    """

    # ==========================================================
    # 1. HANDLE INVALID PATH
    # ==========================================================
    if not candidate_path or len(candidate_path) < 2:
        return {
            'rank': 0, 'path_length': 0,
            'total_weight': 0.0, 'avg_weight': 0.0, 'min_weight': 0.0, 'std_weight': 0.0,
            'total_detection': 0.0, 'avg_detection': 0.0, 'max_detection': 0.0,
            'exploit_count': 0, 'security_controls': 0,
            'firewall_crossings': 0, 'role_entropy': 0.0, 'role_score': 0,
            'has_admin_access': 0, 'is_admin_source': 0,
            'privilege_gain': 0, 'risk_factor': 0.0
        }

    # ==========================================================
    # 2. EDGE-LEVEL ANALYSIS (WEIGHT / DETECTION / PRIVILEGE)
    # ==========================================================
    weights = []
    detections = []
    exploit_count = 0
    privilege_gain = 0
    security_controls = 0
    
    # [NEW] Biến phạt điểm nếu truy cập trực tiếp nguy hiểm
    direct_access_penalty = 0 

    for u, v in zip(candidate_path[:-1], candidate_path[1:]):
        edge_data = graph.get_edge_data(u, v, default={})

        weight = edge_data.get('weight', 1000)
        detection = edge_data.get('detection', 0)
        privilege = edge_data.get('privilege', 0)
        
        # [NEW] Lấy thông tin MFA và Loại cạnh
        etype = edge_data.get('type', 'normal')
        has_mfa = edge_data.get('mfa', False)

        weights.append(weight)
        detections.append(detection)
        privilege_gain += privilege

        # exploit nếu edge có type=exploit hoặc weight rất nhỏ
        if etype == 'exploit' or weight <= 5:
            exploit_count += 1

        # đi qua thiết bị kiểm soát?
        # [UPDATED] Bastion cũng được tính là security control
        v_role = graph.nodes[v].get("role", "unknown")
        if v_role in ["firewall", "security"]:
            security_controls += 1
            
        # [NEW] Logic phát hiện rủi ro truy cập: Admin đi thẳng vào DB/Identity mà không MFA
        # Nếu đích đến là Crown Jewels (DB, AD)
        if v_role in ['database', 'identity']:
            # Nếu là đường authorized nhưng không có MFA -> PHẠT NẶNG
            if etype == 'authorized' and not has_mfa:
                direct_access_penalty += 50

    total_weight = sum(weights)
    avg_weight = total_weight / len(weights)
    std_weight = np.std(weights)
    min_weight = min(weights)

    total_detection = sum(detections)
    avg_detection = total_detection / len(detections)
    max_detection = max(detections)

    # ==========================================================
    # 3. NODE-LEVEL ANALYSIS (ROLES & CONTEXT)
    # ==========================================================
    if role_weights is None:
        role_weights = {
            'client': 1, 'server': 5, 'firewall': -5,
            'router': 0, 'switch': 0, 'security': -8,
            'unknown': 0
        }

    roles = []
    firewall_crossings = 0
    role_score = 0
    has_admin_access = 0
    
    # [NEW] Cờ đánh dấu có đi qua Bastion không
    has_bastion = 0

    # --- CONTEXT: SOURCE NODE ---
    src_node = candidate_path[0]
    src_attrs = graph.nodes[src_node] if src_node in graph.nodes else {}
    src_label = str(src_attrs.get('label', str(src_node))).lower()
    is_admin_source = 1 if ("admin" in src_label or "helpdesk" in src_label) else 0

    for node in candidate_path:
        if node in graph.nodes:
            attrs = graph.nodes[node]
            role = attrs.get('role', 'unknown')
            label = str(attrs.get('label', str(node))).lower()
        else:
            role = 'unknown'
            label = str(node).lower()

        roles.append(role)

        if role == 'firewall':
            firewall_crossings += 1

        role_score += role_weights.get(role, 0)

        # [NEW] Kiểm tra Bastion Host
        if "bastion" in label:
            has_bastion = 1

        # Crown jewels / đặc quyền cao
        if "admin" in label or "sysadmin" in label or "db" in label or "sourcecode" in label:
            has_admin_access = 1
            role_score += 5

    # ==========================================================
    # 4. ENTROPY (STRUCTURAL COMPLEXITY)
    # ==========================================================
    role_counts = Counter(roles)
    total_roles = sum(role_counts.values())

    if total_roles > 0:
        role_entropy = -sum((c/total_roles) * np.log2(c/total_roles) for c in role_counts.values())
    else:
        role_entropy = 0

    # ==========================================================
    # 5. RISK MODELING (UPDATED)
    # ==========================================================
    deviation_weight = abs(total_weight - shortest_path_weight)

    # Base Risk
    risk_factor = (max_detection * (exploit_count + 1)) / (min_weight + 1)
    
    # [NEW] Cộng thêm điểm phạt nếu truy cập trực tiếp (Admin -> DB no MFA)
    risk_factor += direct_access_penalty
    
    # [NEW] Nếu có Bastion, GIẢM rủi ro xuống cực thấp (Safe path)
    if has_bastion == 1:
        risk_factor = risk_factor / 10.0  # Chia 10 để biến thành đường an toàn
        # Xóa phạt nếu lỡ cộng trước đó (vì Bastion đã lo rồi)
        if direct_access_penalty > 0:
             risk_factor -= direct_access_penalty 
             
    path_has_mfa = 0
    for u, v in zip(candidate_path[:-1], candidate_path[1:]):
        edge_data = graph.get_edge_data(u, v, default={})
        if edge_data.get('mfa', False):
            path_has_mfa = 1
            break

    # ==========================================================
    # 6. RETURN FEATURES
    # ==========================================================
    return {
        'rank': rank,

        # --- STRUCTURE ---
        'path_length': len(candidate_path),

        # --- WEIGHT (DIJKSTRA) ---
        'total_weight': total_weight,
        'avg_weight': round(avg_weight, 2),
        'min_weight': min_weight,
        'std_weight': round(std_weight, 3),
        'deviation_weight': deviation_weight,

        # --- DETECTION / NOISE ---
        'total_detection': total_detection,
        'avg_detection': round(avg_detection, 2),
        'max_detection': max_detection,

        # --- ATTACK BEHAVIOR ---
        'exploit_count': exploit_count,
        'security_controls': security_controls,
        'firewall_crossings': firewall_crossings,
        'privilege_gain': privilege_gain,

        # --- CONTEXT ---
        'role_entropy': round(role_entropy, 3),
        'role_score': role_score,
        'has_admin_access': has_admin_access,
        'is_admin_source': is_admin_source,
        'has_bastion': has_bastion,
        'has_mfa': path_has_mfa,
        # --- COMPOSITE RISK ---
        'risk_factor': round(risk_factor, 2)
    }