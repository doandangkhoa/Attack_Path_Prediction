import networkx as nx

def analyze_path(G, path, ai_confidence=None):
    """
    Phân tích ngữ nghĩa đường đi tấn công (Updated for Demo Graph v2).
    """
    steps = []
    exploit_count = 0
    auth_count = 0
    phases = set()
    
    # Định nghĩa các nhóm loại cạnh (Mapping từ network_builder)
    EXPLOIT_TYPES = ["exploit", "rce_exploit", "phishing", "sqli", "misconfig", "ad_attack"]
    PRIVILEGE_TYPES = ["privilege", "priv_esc"]
    
    # Độ tin cậy của vùng mạng (dùng để xác định hướng di chuyển)
    zone_trust = {
        "Internet": 0, "External": 0, 
        "Edge": 10, "DMZ": 15, 
        "User_VLAN": 20, "Internal": 25, "Admin_VLAN": 30,
        "Secure": 40
    }

    for u, v in zip(path[:-1], path[1:]):
        edge = G[u][v]
        node_u = G.nodes[u]
        node_v = G.nodes[v]
        
        etype = edge.get("type", "normal")
        weight = edge.get("weight", 0)
        
        layer_u = node_u.get("layer", "Unknown")
        layer_v = node_v.get("layer", "Unknown")
        
        step_info = {
            "from": u, "to": v,
            "type": etype,
            "weight": weight,
            "phase": "Transit",
            "description": ""
        }

        # --- LOGIC PHÂN TÍCH ---

        # 1. NHÓM TẤN CÔNG KHAI THÁC (EXPLOIT)
        if etype in EXPLOIT_TYPES:
            exploit_count += 1
            
            # Tự động sinh mô tả dựa trên loại exploit
            desc_map = {
                "rce_exploit": "Thực thi mã từ xa (RCE)",
                "sqli": "Tiêm nhiễm SQL (SQL Injection)",
                "phishing": "Tấn công lừa đảo (Phishing)",
                "misconfig": "Lợi dụng cấu hình sai (Misconfiguration)",
                "ad_attack": "Tấn công hạ tầng định danh (Active Directory)",
                "exploit": "Khai thác lỗ hổng đã biết"
            }
            desc = desc_map.get(etype, "Khai thác lỗ hổng")

            # Xác định Phase (Chiến thuật)
            trust_u = zone_trust.get(layer_u, 0)
            trust_v = zone_trust.get(layer_v, 0)

            if (layer_u in ["Internet", "External"]) and (layer_v not in ["Internet", "External"]):
                phase = "Initial Access"
                detail = "Xâm nhập từ Internet vào mạng nội bộ."
            elif etype == "ad_attack":
                 phase = "Credential Access"
                 detail = "Đánh cắp hoặc giả mạo thông tin định danh."
            elif trust_v > trust_u:
                phase = "Defense Evasion"
                detail = f"Leo thang vào vùng tin cậy cao hơn ({layer_v})."
            else:
                phase = "Lateral Movement"
                detail = "Di chuyển ngang hàng tìm kiếm mục tiêu."
            
            phases.add(phase)
            step_info["phase"] = phase
            step_info["description"] = f"🔴 {desc}: {detail}"

        # 2. NHÓM LEO THANG ĐẶC QUYỀN (PRIVILEGE)
        elif etype in PRIVILEGE_TYPES:
            exploit_count += 1 # Coi như 1 bước tấn công
            phase = "Privilege Escalation"
            phases.add(phase)
            step_info["phase"] = phase
            step_info["description"] = "⚡ Leo thang đặc quyền (Admin/Root)."

        # 3. NHÓM LẠM DỤNG QUYỀN (AUTHORIZED)
        elif etype == "authorized":
            auth_count += 1
            phase = "Collection / Exfiltration"
            # Nếu đích đến là Database hoặc AD
            if node_v.get('role') in ['database', 'identity']:
                phase = "Impact"
            
            phases.add(phase)
            step_info["phase"] = phase
            step_info["description"] = "🟢 Sử dụng quyền hợp lệ (Khả năng Insider Threat hoặc Credential Dumping)."

        # 4. HẠ TẦNG MẠNG (NORMAL)
        else:
            if node_v.get('role') in ['firewall', 'security']:
                step_info["description"] = "🛡️ Đi qua thiết bị kiểm soát an ninh."
                step_info["phase"] = "Traffic Inspection"
            elif layer_u != layer_v:
                step_info["description"] = f"Chuyển vùng: {layer_u} ➝ {layer_v}."
                step_info["phase"] = "Zone Transfer"
            else:
                step_info["description"] = "Định tuyến nội bộ."

        steps.append(step_info)

    # --- ĐÁNH GIÁ MỨC ĐỘ (SEVERITY) ---
    severity = "LOW"
    summary_text = ""

    # Logic đánh giá kết hợp AI Score
    has_critical_target = any(G.nodes[n].get('role') in ['identity', 'database'] for n in path)
    
    if exploit_count >= 2 or (exploit_count >= 1 and has_critical_target):
        severity = "CRITICAL"
        summary_text = "Phát hiện chuỗi tấn công đa bước nhắm vào tài sản quan trọng."
    elif exploit_count >= 1:
        severity = "HIGH"
        summary_text = "Phát hiện hành vi khai thác lỗ hổng bảo mật."
    elif auth_count > 0:
        # Nếu dùng quyền hợp lệ nhưng AI chấm điểm cao -> Insider Threat
        if ai_confidence and ai_confidence > 0.85:
            severity = "CRITICAL"
            summary_text = "CẢNH BÁO: Hành vi lạm dụng quyền hạn bất thường (Insider Threat)."
        else:
            severity = "MEDIUM"
            summary_text = "Truy cập hợp lệ nhưng cần giám sát."
    else:
        severity = "LOW"
        summary_text = "Hành vi định tuyến mạng thông thường."

    return {
        "severity": severity,
        "summary": summary_text, # Đã sửa lỗi biến này
        "steps": steps,
        "exploit_count": exploit_count,
        "auth_count": auth_count,
        "phases": list(phases)
    }