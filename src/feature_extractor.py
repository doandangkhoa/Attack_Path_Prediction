import numpy as np
from collections import Counter

def extract_features(candidate_path, graph, shortest_path_weight, rank=0, role_weights=None):
    """
    Feature extractor aligned with Policy Oracle:
    - Bastion, MFA, VPN awareness
    - Admin direct access detection
    - Firewall / security device context
    """

    # ==========================================================
    # 1. HANDLE INVALID PATH
    # ==========================================================
    if not candidate_path or len(candidate_path) < 2:
        return {
            'path_length': 0,
            'total_weight': 0.0, 'avg_weight': 0.0, 'min_weight': 0.0, 'std_weight': 0.0,
            'deviation_weight': 0.0,
            'total_detection': 0.0, 'avg_detection': 0.0, 'max_detection': 0.0,
            'exploit_count': 0, 'security_controls': 0,
            'privilege_gain': 0, 'role_score': 0,
            'has_admin_access': 0, 'is_admin_source': 0,
            'has_bastion': 0, 'has_mfa': 0,
            'risk_factor': 0.0
        }

    # ==========================================================
    # 2. EDGE-LEVEL ANALYSIS
    # ==========================================================
    weights = []
    detections = []
    exploit_count = 0
    privilege_gain = 0
    security_controls = 0
    direct_access_penalty = 0

    path_has_mfa = 0
    has_vpn = 0

    for u, v in zip(candidate_path[:-1], candidate_path[1:]):
        edge_data = graph.get_edge_data(u, v, default={})

        weight = edge_data.get('weight', 1000)
        detection = edge_data.get('detection', 0)
        privilege = edge_data.get('privilege', 0)
        etype = edge_data.get('type', 'normal')
        has_mfa_edge = edge_data.get('mfa', False)

        weights.append(weight)
        detections.append(detection)
        privilege_gain += privilege

        # Exploit detection
        if etype == 'exploit' or weight <= 5:
            exploit_count += 1

        # MFA
        if has_mfa_edge:
            path_has_mfa = 1

        # VPN detection via edge type or label
        if etype.lower() == "vpn" or "vpn" in str(edge_data).lower():
            has_vpn = 1

        # Security controls
        v_role = graph.nodes[v].get("role", "unknown")
        if v_role in ["firewall", "security", "gateway"]:
            security_controls += 1

        # Admin direct access to Crown Jewels without MFA
        if v_role in ['database', 'identity']:
            if etype == 'authorized' and not has_mfa_edge:
                direct_access_penalty += 5

    # Weight stats
    total_weight = sum(weights)
    avg_weight = total_weight / len(weights)
    std_weight = np.std(weights)
    min_weight = min(weights)

    # Detection stats
    total_detection = sum(detections)
    avg_detection = total_detection / len(detections)
    max_detection = max(detections)

    # ==========================================================
    # 3. NODE-LEVEL ANALYSIS
    # ==========================================================
    if role_weights is None:
        role_weights = {
            'client': 1, 'server': 5, 'database': 8, 'identity': 8,
            'firewall': -6, 'security': -8, 'gateway': -5,
            'router': 0, 'switch': 0, 'unknown': 0
        }

    roles = []
    role_score = 0
    has_admin_access = 0
    has_bastion = 0

    # Source context
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
        role_score += role_weights.get(role, 0)

        # Bastion Host detection
        if "bastion" in label:
            has_bastion = 1

        # Crown jewels / admin
        if any(x in label for x in ["admin", "sysadmin", "db", "database", "identity", "ad"]):
            has_admin_access = 1
            role_score += 4

    # Base risk
    risk_factor = (max_detection + 1) * (exploit_count + 1) / (min_weight + 1)

    # Privilege escalation influence
    if privilege_gain >= 2:
        risk_factor *= 1.3
    if privilege_gain >= 5:
        risk_factor *= 1.6

    # Admin direct access penalty
    risk_factor += direct_access_penalty

    # Bastion reduces risk (but not zero – tránh học vẹt)
    if has_bastion:
        risk_factor *= 0.3

    # VPN + MFA reduces risk
    if has_vpn and path_has_mfa:
        risk_factor *= 0.5
    elif has_vpn and not path_has_mfa:
        risk_factor *= 0.9

    # ==========================================================
    # 6. RETURN FEATURES
    # ==========================================================
    return {
        # --- STRUCTURE ---
        'path_length': len(candidate_path),

        # --- DETECTION ---
        'total_detection': total_detection,
        'avg_detection': round(avg_detection, 2),
        'max_detection': max_detection,

        # --- ATTACK BEHAVIOR ---
        'exploit_count': exploit_count,
        'security_controls': security_controls,
        'privilege_gain': privilege_gain,

        # --- CONTEXT ---
        'role_score': role_score,
        'has_admin_access': has_admin_access,
        'is_admin_source': is_admin_source,
        'has_bastion': has_bastion,
        'has_mfa': path_has_mfa,

        # --- COMPOSITE ---
        'risk_factor': round(risk_factor, 2)
    }
