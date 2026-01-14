def analyze_path(G, path):
    """
    Human-Explainable Attack Path Analysis
    - KHÔNG dựa vào ML feature
    - Tự suy luận từ topology, edge, zone, role

    Dựa trên:
    - edge["type"]       : exploit / privilege / authorized / misconfig / normal
    - edge["detection"] : độ dễ bị phát hiện (0–100)
    - edge["weight"]    : chi phí
    - edge["mfa"]       : có MFA hay không
    - node["layer"]     : Internet / DMZ / Internal / Admin / Secure...
    - node["role"]      : web / app / database / identity / bastion / user
    """

    steps = []
    phases = []
    findings = []

    # ===== METRICS (INDEPENDENT) =====
    exploit_steps = 0
    privilege_steps = 0
    misconfig_steps = 0
    authorized_steps = 0

    detection_sum = 0
    edge_count = 0
    total_cost = 0

    # ===== CONTEXT FLAGS =====
    reached_sensitive_asset = False
    crossed_trust_boundary = False
    bypassed_mfa = False

    # ===== TRUST LEVEL =====
    trust_level = {
        "Internet": 0,
        "External": 0,
        "Edge": 10,
        "DMZ": 20,
        "User_VLAN": 30,
        "Internal": 40,
        "Admin_VLAN": 60,
        "Secure": 80,
        "Secure_Admin": 100
    }

    for u, v in zip(path[:-1], path[1:]):
        edge = G[u][v]
        node_u = G.nodes[u]
        node_v = G.nodes[v]

        etype = edge.get("type", "normal").lower()
        detection = edge.get("detection", 0)
        weight = edge.get("weight", 0)
        privilege = edge.get("privilege", 0)
        has_mfa = edge.get("mfa", False)

        layer_u = node_u.get("layer", "Unknown")
        layer_v = node_v.get("layer", "Unknown")
        role_v = node_v.get("role", "unknown")
        label_v = str(node_v.get("label", v)).lower()

        trust_u = trust_level.get(layer_u, 0)
        trust_v = trust_level.get(layer_v, 0)

        # ===== METRIC ACCUMULATION =====
        detection_sum += detection
        edge_count += 1
        total_cost += weight

        step = {
            "from": u,
            "to": v,
            "type": "transit",
            "phase": "Network Movement",
            "description": "➡️ Di chuyển trong mạng."
        }

        # =====================================================
        # 1. EXPLOIT
        # =====================================================
        if etype == "exploit":
            exploit_steps += 1
            phase = "Initial Access" if trust_u <= 10 else "Lateral Movement"
            phases.append(phase)

            step["type"] = "exploit"
            step["phase"] = phase
            step["description"] = "💣 Khai thác lỗ hổng kỹ thuật để chiếm quyền truy cập."

        # =====================================================
        # 2. PRIVILEGE ESCALATION (ACCOUNT)
        # =====================================================
        elif etype == "privilege":
            privilege_steps += 1
            phases.append("Privilege Escalation")

            step["type"] = "privilege_escalation"
            step["phase"] = "Privilege Escalation"
            step["description"] = "⚡ Leo thang đặc quyền tài khoản (User ➝ Admin/Root)."

        # =====================================================
        # 3. MISCONFIG / SHADOW IT
        # =====================================================
        elif etype == "misconfig":
            misconfig_steps += 1
            phases.append("Defense Evasion")

            step["type"] = "misconfig"
            step["phase"] = "Defense Evasion"
            step["description"] = "🛠️ Lợi dụng cấu hình sai / hệ thống không được kiểm soát."

        # =====================================================
        # 4. AUTHORIZED (ABUSE OF LEGIT ACCESS)
        # =====================================================
        elif etype == "authorized":
            authorized_steps += 1
            phase = "Collection"
            if role_v in ["database", "identity"]:
                phase = "Impact"

            phases.append(phase)

            step["type"] = "authorized"
            step["phase"] = phase
            if has_mfa:
                step["description"] = "🔑 Truy cập hợp lệ có MFA."
            else:
                bypassed_mfa = True
                step["description"] = "⚠️ Truy cập hợp lệ KHÔNG có MFA (nguy cơ bị lạm dụng)."

        # =====================================================
        # 5. ZONE / TRUST ESCALATION
        # =====================================================
        elif trust_v > trust_u or privilege > 0:
            privilege_steps += 1
            crossed_trust_boundary = True
            phases.append("Privilege Escalation")

            step["type"] = "zone_elevation"
            step["phase"] = "Privilege Escalation"
            step["description"] = f"⚡ Leo thang vùng tin cậy: {layer_u} ➝ {layer_v}."

        # =====================================================
        # 6. SENSITIVE ASSET
        # =====================================================
        if role_v in ["database", "identity", "domain_controller"]:
            reached_sensitive_asset = True

        if "bastion" in label_v:
            findings.append("Đường đi thông qua Bastion host")

        steps.append(step)

    # =====================================================
    # DERIVED METRICS
    # =====================================================
    avg_detection = round(detection_sum / edge_count, 2) if edge_count else 0

    # =====================================================
    # SEVERITY HEURISTIC (RULE-BASED, NOT ML)
    # =====================================================
    severity = "LOW"

    if exploit_steps > 0 and privilege_steps > 0 and reached_sensitive_asset:
        severity = "CRITICAL"
    elif exploit_steps > 0 and privilege_steps > 0:
        severity = "HIGH"
    elif exploit_steps > 0 or misconfig_steps > 0:
        severity = "MEDIUM"

    # =====================================================
    # HUMAN SUMMARY (INDEPENDENT)
    # =====================================================
    reasons = []

    if exploit_steps > 0:
        reasons.append(f"{exploit_steps} bước khai thác lỗ hổng")
    if privilege_steps > 0:
        reasons.append(f"{privilege_steps} lần leo thang đặc quyền")
    if misconfig_steps > 0:
        reasons.append("lợi dụng cấu hình sai")
    if reached_sensitive_asset:
        reasons.append("tiếp cận tài sản nhạy cảm")
    if bypassed_mfa:
        reasons.append("bỏ qua xác thực MFA")
    if crossed_trust_boundary:
        reasons.append("vượt ranh giới vùng tin cậy")

    if reasons:
        summary = "⚠️ Chuỗi hành vi đáng ngờ: " + ", ".join(reasons) + "."
    else:
        summary = "Hoạt động mạng bình thường, không thấy dấu hiệu tấn công rõ ràng."

    return {
        "severity": severity,
        "summary": summary,
        "steps": steps,
        "phases": list(set(phases)),

        # ===== PURE EXPLAINABILITY METRICS =====
        "metrics": {
            "exploit_steps": exploit_steps,
            "privilege_steps": privilege_steps,
            "misconfig_steps": misconfig_steps,
            "authorized_steps": authorized_steps,
            "avg_detection": avg_detection,
            "total_cost": total_cost
        },

        "findings": {
            "reached_sensitive_asset": reached_sensitive_asset,
            "crossed_trust_boundary": crossed_trust_boundary,
            "bypassed_mfa": bypassed_mfa
        }
    }
