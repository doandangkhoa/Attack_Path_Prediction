import networkx as nx

def get_edge_attributes(link_type):
    """
    Sinh thuộc tính cho cạnh: effort (weight), detection, type.
    """
    configs = {
        # Hạ tầng mạng
        "wan":        {"weight": 100, "detection": 10,  "type": "infrastructure"},
        "fiber":      {"weight": 10,  "detection": 0,   "type": "infrastructure"},
        "lan":        {"weight": 50,  "detection": 0,   "type": "infrastructure"},
        "firewall":   {"weight": 500, "detection": 100, "type": "infrastructure"},

        # Đường tấn công (vulnerabilities)
        "rce":        {"weight": 1,   "detection": 90,  "type": "exploit"},    # Dễ nhưng ồn
        "phishing":   {"weight": 5,   "detection": 60,  "type": "exploit"},
        "sqli":       {"weight": 2,   "detection": 80,  "type": "exploit"},
        "misconfig":  {"weight": 1,   "detection": 30,  "type": "exploit"},    # Nguy hiểm: stealth
        "priv_esc":   {"weight": 3,   "detection": 70,  "type": "privilege"},  # Leo thang đặc quyền

        # Đường hợp lệ (lạm dụng quyền)
        "authorized": {"weight": 20,  "detection": 5,   "type": "authorized"},
    }
    return configs.get(link_type, configs["lan"])


def build_demo_network():
    """
    Xây dựng attack graph demo:
    - Không gắn cứng attacker
    - Source (src) và Target (dst) sẽ truyền vào lúc chạy Dijkstra / AI
    """

    G = nx.DiGraph()

    # =====================================================
    # 1. HẠ TẦNG (INFRASTRUCTURE)
    # =====================================================

    # --- External / Internet Zone ---
    G.add_node("Internet_User", label="Internet User", role="client", layer="Internet")
    G.add_node("Partner_VPN", label="Partner VPN", role="partner", layer="Internet")

    G.add_node("Gateway", label="Gateway Router", role="router", layer="Edge")
    G.add_node("Ext_FW", label="Perimeter Firewall", role="firewall", layer="Edge")
    G.add_node("WAF", label="Web Application Firewall", role="security", layer="DMZ")

    G.add_edge("Internet_User", "Gateway", **get_edge_attributes("wan"))
    G.add_edge("Partner_VPN", "Gateway", **get_edge_attributes("wan"))
    G.add_edge("Gateway", "Ext_FW", **get_edge_attributes("wan"))
    G.add_edge("Ext_FW", "WAF", **get_edge_attributes("firewall"))

    # --- DMZ ---
    G.add_node("DMZ_SW", label="DMZ Switch", role="switch", layer="DMZ")
    G.add_edge("WAF", "DMZ_SW", **get_edge_attributes("fiber"))

    G.add_node("Web_Srv", label="Public Web Server", role="server", layer="DMZ")
    G.add_node("Mail_Srv", label="Mail Server", role="server", layer="DMZ")

    G.add_edge("DMZ_SW", "Web_Srv", **get_edge_attributes("lan"))
    G.add_edge("Web_Srv", "DMZ_SW", **get_edge_attributes("lan"))
    G.add_edge("DMZ_SW", "Mail_Srv", **get_edge_attributes("lan"))
    G.add_edge("Mail_Srv", "DMZ_SW", **get_edge_attributes("lan"))

    # --- Internal Core ---
    G.add_node("Int_FW", label="Internal Firewall", role="firewall", layer="Internal")
    G.add_node("IDS", label="IDS / EDR", role="security", layer="Internal")
    G.add_node("Core_SW", label="Core Switch", role="switch", layer="Internal")

    G.add_edge("DMZ_SW", "Int_FW", **get_edge_attributes("fiber"))
    G.add_edge("Int_FW", "IDS", **get_edge_attributes("firewall"))
    G.add_edge("IDS", "Core_SW", **get_edge_attributes("fiber"))

    # --- Critical Assets (Targets) ---
    G.add_node("DB_Customer", label="Customer Database", role="database", layer="Secure")
    G.add_node("AD_Server", label="Active Directory", role="identity", layer="Secure")

    G.add_edge("Core_SW", "DB_Customer", **get_edge_attributes("fiber"))
    G.add_edge("Core_SW", "AD_Server", **get_edge_attributes("fiber"))

    # --- User Workstations ---
    G.add_node("HR_PC", label="HR User PC", role="client", layer="User_VLAN")
    G.add_node("Dev_PC", label="Developer PC", role="client", layer="User_VLAN")
    G.add_node("Admin_PC", label="SysAdmin PC", role="client", layer="Admin_VLAN")

    G.add_edge("Core_SW", "HR_PC", **get_edge_attributes("lan"))
    G.add_edge("HR_PC", "Core_SW", **get_edge_attributes("lan"))
    G.add_edge("Core_SW", "Dev_PC", **get_edge_attributes("lan"))
    G.add_edge("Dev_PC", "Core_SW", **get_edge_attributes("lan"))
    G.add_edge("Core_SW", "Admin_PC", **get_edge_attributes("lan"))
    G.add_edge("Admin_PC", "Core_SW", **get_edge_attributes("lan"))

    # =====================================================
    # 2. ĐƯỜNG TẤN CÔNG (VULNERABILITIES / ABUSE)
    # =====================================================

    # A. Internet → Web → DB (Direct Exploit, ồn ào)
    G.add_edge("Internet_User", "Web_Srv", **get_edge_attributes("rce"))
    G.add_edge("Web_Srv", "DB_Customer", **get_edge_attributes("sqli"))

    # B. Phishing → Lateral → Privilege → DB (APT)
    G.add_edge("Internet_User", "Mail_Srv", **get_edge_attributes("phishing"))
    G.add_edge("Mail_Srv", "HR_PC", **get_edge_attributes("phishing"))
    G.add_edge("HR_PC", "Admin_PC", **get_edge_attributes("priv_esc"))
    G.add_edge("Admin_PC", "DB_Customer", **get_edge_attributes("authorized"))

    # C. Supply Chain / Misconfiguration (Partner → Core)
    G.add_edge("Partner_VPN", "Core_SW", **get_edge_attributes("misconfig"))

    # D. Insider / Admin Abuse
    G.add_edge("Admin_PC", "AD_Server", **get_edge_attributes("authorized"))
    G.add_edge("AD_Server", "DB_Customer", **get_edge_attributes("priv_esc"))

    return G
