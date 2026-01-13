import networkx as nx

def analyze_path(G, path, ai_confidence=None):
    """
    Explainable analysis for attack path:
    - Supports Bastion, MFA, VPN
    - Detects misconfiguration / chaos layer
    - Uses AI confidence as primary severity signal
    - MITRE-like phases (human-readable)
    """

    steps = []
    exploit_count = 0
    auth_count = 0
    phases = set()
    notes = []

    # === ATTACK TYPE GROUPS ===
    EXPLOIT_TYPES = ["exploit", "rce_exploit", "phishing", "sqli", "misconfig", "ad_attack"]
    PRIVILEGE_TYPES = ["privilege", "priv_esc"]
    VPN_TYPES = ["vpn"]
    
    # === ZONE TRUST MODEL ===
    zone_trust = {
        "Internet": 0, "External": 0,
        "Edge": 10, "DMZ": 15,
        "User_VLAN": 20, "Internal": 25, "Admin_VLAN": 30,
        "Secure": 40
    }

    # === FLAGS ===
    has_bastion = False
    has_mfa = False
    has_vpn = False
    has_misconfig = False
    touched_crown_jewel = False

    for u, v in zip(path[:-1], path[1:]):
        edge = G[u][v]
        node_u = G.nodes[u]
        node_v = G.nodes[v]

        etype = edge.get("type", "normal").lower()
        weight = edge.get("weight", 0)
        has_mfa_edge = edge.get("mfa", False)

        layer_u = node_u.get("layer", "Unknown")
        layer_v = node_v.get("layer", "Unknown")
        role_v = node_v.get("role", "unknown")
        label_v = str(node_v.get("label", v)).lower()

        step_info = {
            "from": u, "to": v,
            "type": etype,
            "weight": weight,
            "phase": "Transit",
            "description": ""
        }

        trust_u = zone_trust.get(layer_u, 0)
        trust_v = zone_trust.get(layer_v, 0)

        # === INFRA CONTEXT ===
        if "bastion" in label_v:
            has_bastion = True

        if has_mfa_edge:
            has_mfa = True

        if etype in VPN_TYPES:
            has_vpn = True

        if etype == "misconfig":
            has_misconfig = True

        if role_v in ['database', 'identity']:
            touched_crown_jewel = True

        # ======================================================
        # 1. EXPLOIT / INITIAL ACCESS / CHAOS
        # ======================================================
        if etype in EXPLOIT_TYPES:
            exploit_count += 1

            desc_map = {
                "rce_exploit": "Thực thi mã từ xa (RCE)",
                "sqli": "Tấn công SQL Injection",
                "phishing": "Tấn công lừa đảo (Phishing)",
                "misconfig": "Lợi dụng cấu hình sai / Shadow IT",
                "ad_attack": "Tấn công Active Directory / Identity",
                "exploit": "Khai thác lỗ hổng đã biết"
            }
            desc = desc_map.get(etype, "Khai thác lỗ hổng")

            # Phase logic
            if layer_u in ["Internet", "External"] and layer_v not in ["Internet", "External"]:
                phase = "Initial Access"
                detail = "Xâm nhập từ Internet vào hệ thống nội bộ."
            elif etype == "ad_attack":
                phase = "Credential Access"
                detail = "Tấn công hạ tầng định danh / thông tin xác thực."
            elif etype == "misconfig":
                phase = "Defense Evasion"
                detail = "Vượt kiểm soát nhờ cấu hình sai hoặc Shadow IT."
            elif trust_v > trust_u:
                phase = "Privilege Escalation"
                detail = f"Leo thang vào vùng tin cậy cao hơn ({layer_v})."
            else:
                phase = "Lateral Movement"
                detail = "Di chuyển ngang trong hệ thống."

            phases.add(phase)
            step_info["phase"] = phase
            step_info["description"] = f"🔴 {desc}: {detail}"

        # ======================================================
        # 2. PRIVILEGE ESCALATION
        # ======================================================
        elif etype in PRIVILEGE_TYPES:
            exploit_count += 1
            phase = "Privilege Escalation"
            phases.add(phase)

            step_info["phase"] = phase
            step_info["description"] = "⚡ Leo thang đặc quyền (Admin / Root)."

        # ======================================================
        # 3. AUTHORIZED ACCESS (INSIDER / CREDENTIAL ABUSE)
        # ======================================================
        elif etype == "authorized":
            auth_count += 1
            phase = "Collection / Access"

            if role_v in ['database', 'identity']:
                phase = "Impact"

            phases.add(phase)
            if has_mfa_edge:
                step_info["description"] = "🟢 Truy cập hợp lệ có MFA (xác thực đa yếu tố)."
            else:
                step_info["description"] = "🟡 Truy cập hợp lệ KHÔNG có MFA (nguy cơ lạm dụng quyền)."

            step_info["phase"] = phase

        # ======================================================
        # 4. VPN / REMOTE ACCESS
        # ======================================================
        elif etype in VPN_TYPES:
            phase = "Remote Access"
            phases.add(phase)
            step_info["phase"] = phase
            step_info["description"] = "🔐 Kết nối từ xa qua VPN."

        # ======================================================
        # 5. NORMAL NETWORK FLOW
        # ======================================================
        else:
            if role_v in ['firewall', 'security', 'gateway']:
                step_info["description"] = "🛡️ Đi qua thiết bị kiểm soát an ninh."
                step_info["phase"] = "Traffic Inspection"
            elif trust_u < trust_v:
                step_info["description"] = f"Chuyển vùng: {layer_u} ➝ {layer_v} (mức tin cậy cao hơn)."
                step_info["phase"] = "Zone Transfer"
            elif trust_u > trust_v:
                step_info["description"] = f"Luồng dữ liệu từ vùng tin cậy cao ➝ thấp ({layer_u} ➝ {layer_v})."
                step_info["phase"] = "Exfiltration"
            else:
                step_info["description"] = "Định tuyến nội bộ."
                step_info["phase"] = "Transit"

        steps.append(step_info)

    # ======================================================
    # 6. SEVERITY SCORING (AI-DRIVEN)
    # ======================================================
    severity = "LOW"
    summary_text = "Hành vi mạng thông thường."

    if ai_confidence is not None:
        if ai_confidence > 0.9:
            severity = "CRITICAL"
        elif ai_confidence > 0.7:
            severity = "HIGH"
        elif ai_confidence > 0.4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # ======================================================
    # 7. EXPLANATION LAYER
    # ======================================================
    if severity in ["CRITICAL", "HIGH"]:
        if exploit_count >= 2:
            notes.append("Chuỗi tấn công đa bước (multi-stage attack).")
        if touched_crown_jewel:
            notes.append("Đường đi chạm tới tài sản quan trọng (Database / Identity).")
        if has_misconfig:
            notes.append("Có dấu hiệu lợi dụng cấu hình sai hoặc Shadow IT.")
        if has_vpn and not has_mfa:
            notes.append("VPN được sử dụng nhưng không có MFA → nguy cơ bypass kiểm soát.")
        if auth_count > 0 and ai_confidence and ai_confidence > 0.85:
            notes.append("Hành vi sử dụng quyền hợp lệ nhưng có dấu hiệu Insider Threat.")

        summary_text = "⚠️ Phát hiện hành vi nguy hiểm: " + " ".join(notes)

    elif severity == "MEDIUM":
        summary_text = "⚠️ Hành vi bất thường cần giám sát: có dấu hiệu truy cập nhạy cảm hoặc cấu trúc đường đi không bình thường."

    else:
        if has_bastion:
            summary_text = "🛡️ Luồng truy cập đi qua Bastion Host – cơ chế bảo vệ hợp lệ."
        elif has_vpn and has_mfa:
            summary_text = "🔐 Kết nối VPN có MFA – truy cập từ xa an toàn."
        else:
            summary_text = "Hành vi mạng ở mức độ thấp, không phát hiện tấn công rõ ràng."

    return {
        "severity": severity,
        "summary": summary_text,
        "steps": steps,
        "exploit_count": exploit_count,
        "auth_count": auth_count,
        "phases": list(phases),
        "context": {
            "has_bastion": has_bastion,
            "has_mfa": has_mfa,
            "has_vpn": has_vpn,
            "has_misconfig": has_misconfig,
            "touched_crown_jewel": touched_crown_jewel,
            "ai_confidence": ai_confidence
        }
    }
