def analyze_path(G, path, ai_confidence: float):
    """
    Hybrid AI + Human Explainability
    - Severity: DO AI QUYẾT ĐỊNH (dựa trên ai_confidence)
    - Explain: suy luận từ topology, user role, authorization, trust zone

    Mở rộng:
    - Privilege escalation: dựa trên USER ROLE (vd: helpdesk ➝ admin)
    - Sensitive asset access: xét theo QUYỀN (authorized hay không)
    """

    steps = []
    phases = []
    findings = []

    # ===== METRICS (EXPLAINABILITY ONLY) =====
    exploit_steps = 0
    privilege_steps = 0
    misconfig_steps = 0
    authorized_steps = 0
    unauthorized_access = 0

    detection_sum = 0
    edge_count = 0
    total_cost = 0

    # ===== CONTEXT FLAGS =====
    reached_sensitive_asset = False
    crossed_trust_boundary = False
    bypassed_mfa = False
    user_privilege_escalation = False
    unauthorized_sensitive_access = False

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

    # ===== ROLE HIERARCHY (NGƯỜI DÙNG) =====
    role_level = {
        "guest": 0,
        "user": 10,
        "helpdesk": 30,
        "operator": 40,
        "admin": 70,
        "root": 100
    }

    # ===== SENSITIVE ASSETS =====
    sensitive_roles = ["database", "identity", "domain_controller"]

    for u, v in zip(path[:-1], path[1:]):
        edge = G[u][v]
        node_u = G.nodes[u]
        node_v = G.nodes[v]

        etype = edge.get("type", "normal").lower()
        detection = edge.get("detection", 0)
        weight = edge.get("weight", 0)
        has_mfa = edge.get("mfa", False)
        is_authorized = edge.get("authorized", True)   # NEW: có quyền hay không

        layer_u = node_u.get("layer", "Unknown")
        layer_v = node_v.get("layer", "Unknown")

        role_u = node_u.get("user_role", "user").lower()
        role_v = node_v.get("user_role", role_u).lower()  # user context

        asset_role_v = node_v.get("role", "unknown").lower()
        label_v = str(node_v.get("label", v)).lower()

        trust_u = trust_level.get(layer_u, 0)
        trust_v = trust_level.get(layer_v, 0)

        role_u_level = role_level.get(role_u, 0)
        role_v_level = role_level.get(role_v, role_u_level)

        # ===== METRIC ACCUMULATION =====
        detection_sum += detection
        edge_count += 1
        total_cost += weight

        step = {
            "from": u,
            "to": v,
            "type": "transit",
            "phase": "Network Movement",
            "description": "Di chuyển trong mạng."
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
            step["description"] = "Khai thác lỗ hổng kỹ thuật."

        # =====================================================
        # 2. USER PRIVILEGE ESCALATION (HELPDESK ➝ ADMIN)
        # =====================================================
        elif role_v_level > role_u_level:
            privilege_steps += 1
            user_privilege_escalation = True
            phases.append("Privilege Escalation")

            step["type"] = "user_privilege_escalation"
            step["phase"] = "Privilege Escalation"
            step["description"] = f"Leo thang đặc quyền người dùng: {role_u} ➝ {role_v}."

        # =====================================================
        # 3. MISCONFIG / SHADOW IT
        # =====================================================
        elif etype == "misconfig":
            exploit_steps += 1
            phases.append("Defense Evasion")

            step["type"] = "misconfig"
            step["phase"] = "Defense Evasion"
            step["description"] = "Lợi dụng cấu hình sai / hệ thống không kiểm soát."

        # =====================================================
        # 4. AUTHORIZED / UNAUTHORIZED ACCESS
        # =====================================================
        elif etype == "authorized":
            authorized_steps += 1

            # Nếu truy cập tài sản nhạy cảm
            if asset_role_v in sensitive_roles:
                reached_sensitive_asset = True

                if not is_authorized:
                    unauthorized_access += 1
                    unauthorized_sensitive_access = True
                    phases.append("Impact")

                    step["type"] = "unauthorized_access"
                    step["phase"] = "Impact"
                    step["description"] = "Truy cập tài sản nhạy cảm KHÔNG được phép."
                else:
                    phases.append("Collection")
                    step["type"] = "authorized"
                    step["phase"] = "Collection"
                    step["description"] = "Truy cập hợp lệ vào tài nguyên nhạy cảm."
            else:
                phases.append("Collection")
                step["type"] = "authorized"
                step["phase"] = "Collection"
                step["description"] = "Truy cập hợp lệ."

            if not has_mfa:
                bypassed_mfa = True

        # =====================================================
        # 5. ZONE / TRUST ESCALATION
        # =====================================================
        elif trust_v > trust_u:

            # ❌ KHÔNG tính Edge → DMZ là leo thang
            if layer_u in ["Edge", "External", "Internet"] and layer_v == "DMZ":
                step["type"] = "transit"
                step["phase"] = "Initial Access"
                step["description"] = f"Di chuyển từ vùng ngoài ({layer_u}) vào DMZ."

            else:
                privilege_steps += 1
                crossed_trust_boundary = True
                phases.append("Privilege Escalation")

                step["type"] = "zone_elevation"
                step["phase"] = "Privilege Escalation"
                step["description"] = f"Vượt ranh giới vùng tin cậy: {layer_u} ➝ {layer_v}."

        if "bastion" in label_v:
            findings.append("Đường đi thông qua Bastion host")

        steps.append(step)

    # =====================================================
    # DERIVED METRICS
    # =====================================================
    avg_detection = round(detection_sum / edge_count, 2) if edge_count else 0

    # =====================================================
    # AI-DRIVEN SEVERITY (QUYẾT ĐỊNH CUỐI CÙNG)
    # =====================================================
    if ai_confidence >= 0.9:
        severity = "CRITICAL"
    elif ai_confidence >= 0.75:
        severity = "HIGH"
    elif ai_confidence >= 0.5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # =====================================================
    # HUMAN EXPLANATION (GIẢI THÍCH CHO AI)
    # =====================================================
    reasons = []

    if exploit_steps > 0:
        reasons.append(f"{exploit_steps} bước khai thác lỗ hổng")
    if user_privilege_escalation:
        reasons.append("leo thang đặc quyền người dùng")
    if crossed_trust_boundary:
        reasons.append("vượt ranh giới vùng tin cậy")
    if unauthorized_sensitive_access:
        reasons.append("truy cập trái phép tài sản nhạy cảm")
    if bypassed_mfa:
        reasons.append("bỏ qua MFA")
    if misconfig_steps > 0:
        reasons.append("lợi dụng cấu hình sai")

    if reasons:
        summary = f"⚠️ AI đánh giá mức {severity} (confidence={ai_confidence:.2f}) do: " + ", ".join(reasons) + "."
    else:
        summary = f"Hoạt động mạng được AI đánh giá {severity} (confidence={ai_confidence:.2f})."

    return {
        "severity": severity,             # 🔑 DO AI QUYẾT ĐỊNH
        "ai_confidence": ai_confidence,
        "summary": summary,
        "steps": steps,
        "phases": list(set(phases)),

        # ===== EXPLAINABILITY METRICS =====
        "metrics": {
            "exploit_steps": exploit_steps,
            "privilege_steps": privilege_steps,
            "misconfig_steps": misconfig_steps,
            "authorized_steps": authorized_steps,
            "unauthorized_access": unauthorized_access,
            "avg_detection": avg_detection,
            "total_cost": total_cost
        },

        "findings": {
            "reached_sensitive_asset": reached_sensitive_asset,
            "unauthorized_sensitive_access": unauthorized_sensitive_access,
            "crossed_trust_boundary": crossed_trust_boundary,
            "bypassed_mfa": bypassed_mfa,
            "user_privilege_escalation": user_privilege_escalation
        }
    }
