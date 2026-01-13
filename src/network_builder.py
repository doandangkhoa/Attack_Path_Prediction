import networkx as nx
import random

# ==========================================================
# EDGE ATTRIBUTE HELPER
# ==========================================================
def get_edge_attributes(link_type):
    base = {
        "exploit":   {"weight": 1,   "detection": 80, "privilege": 1},
        "auth":      {"weight": 35,  "detection": 10, "privilege": 1},
        "fiber":     {"weight": 10,  "detection": 5,  "privilege": 0},
        "lan":       {"weight": 50,  "detection": 5,  "privilege": 0},
        "wan":       {"weight": 100, "detection": 20, "privilege": 0},
        "firewall":  {"weight": 200, "detection": 95, "privilege": 0},
        "ids":       {"weight": 80,  "detection": 90, "privilege": 0},
        "waf":       {"weight": 120, "detection": 95, "privilege": 0},
        "ad_attack": {"weight": 5,   "detection": 70, "privilege": 2},
    }
    attrs = base.get(link_type, {"weight":50,"detection":20,"privilege":0})
    
    # Noise tăng hơn để ML không học vẹt
    noise_w = random.randint(-10,10)
    noise_det = random.randint(-15,15)
    
    return {
        "weight": max(1, attrs["weight"] + noise_w),
        "detection": min(100, max(0, attrs["detection"] + noise_det)),
        "privilege": attrs["privilege"]
    }

# ==========================================================
# RANDOMIZED TOPOLOGY BUILDER
# ==========================================================
def build_random_policy_oracle_graph(seed=None, config=None):
    if seed is not None:
        random.seed(seed)
    
    if config is None:
        config = {
            "num_internet": random.randint(2,4),
            "num_dmz": random.randint(2,5),
            "num_app": random.randint(2,4),
            "num_targets": random.randint(2,3),
            "num_depts": random.randint(2,3),
            "pc_per_dept": (2,4),
            "exploit_prob": 0.5
        }

    G = nx.DiGraph()

    # ---------------------
    # 1. Backbone + Security
    # ---------------------
    backbone_nodes = [
        ("r_Gateway","Gateway","router","Edge"),
        ("f_ExtFW","Ext FW","firewall","Edge"),
        ("sec_WAF","WAF","security","DMZ"),
        ("sw_DMZ","DMZ SW","switch","DMZ"),
        ("f_IntFW","Int FW","firewall","Internal"),
        ("sec_IDS","IDS","security","Internal"),
        ("sw_Core","Core SW","switch","Internal")
    ]
    for nid,lbl,role,layer in backbone_nodes:
        G.add_node(nid,label=lbl,role=role,layer=layer)

    # Backbone connections
    G.add_edge("r_Gateway","f_ExtFW",**get_edge_attributes("wan"))
    G.add_edge("f_ExtFW","sec_WAF",**get_edge_attributes("firewall"))
    G.add_edge("sec_WAF","sw_DMZ",**get_edge_attributes("waf"))
    G.add_edge("sw_DMZ","f_IntFW",**get_edge_attributes("fiber"))
    G.add_edge("f_IntFW","sec_IDS",**get_edge_attributes("firewall"))
    G.add_edge("sec_IDS","sw_Core",**get_edge_attributes("ids"))

    # ---------------------
    # 2. Internet Nodes
    # ---------------------
    internet_nodes = []
    for i in range(config["num_internet"]):
        nid = f"c_Internet_{i+1}"
        G.add_node(nid,label=f"External {i+1}",role="client",layer="External")
        G.add_edge(nid,"r_Gateway",**get_edge_attributes("wan"))
        internet_nodes.append(nid)

    # ---------------------
    # 3. DMZ Servers
    # ---------------------
    dmz_types = ["Web","Mail","VPN"]
    dmz_nodes = []
    for i in range(config["num_dmz"]):
        t = random.choice(dmz_types)
        nid = f"s_DMZ_{t}_{i}"
        G.add_node(nid,label=f"{t} Server",role="server",layer="DMZ")
        # Randomize DMZ connections
        if random.random() < 0.8:
            G.add_edge("sw_DMZ",nid,**get_edge_attributes("lan"))
        if random.random() < 0.5:
            G.add_edge(nid,"sw_DMZ",**get_edge_attributes("lan"))
        dmz_nodes.append(nid)

    # ---------------------
    # 4. Application Servers
    # ---------------------
    app_nodes = []
    for i in range(config["num_app"]):
        nid = f"s_APP_{i+1}"
        G.add_node(nid,label=f"App Server {i+1}",role="server",layer="Internal")
        # Random connection
        target_sw = random.choice(["sw_Core"] + dmz_nodes)
        G.add_edge(target_sw,nid,**get_edge_attributes("fiber"))
        G.add_edge(nid,target_sw,**get_edge_attributes("fiber"))
        app_nodes.append(nid)

    # ---------------------
    # 5. Departments (Users)
    # ---------------------
    all_depts = ["Finance","HR","Sales"]
    dept_keys = random.sample(all_depts,config["num_depts"])
    users_by_dept = {}
    for dept in dept_keys:
        sw_id = f"sw_{dept}"
        G.add_node(sw_id,label=f"{dept} SW",role="switch",layer=f"{dept}_VLAN")
        G.add_edge("sw_Core",sw_id,**get_edge_attributes("fiber"))
        G.add_edge(sw_id,"sw_Core",**get_edge_attributes("fiber"))
        users_by_dept[dept] = []
        for i in range(random.randint(*config["pc_per_dept"])):
            uid = f"c_{dept}_{i+1}"
            G.add_node(uid,label=f"{dept} User {i+1}",role="client",layer=f"{dept}_VLAN")
            G.add_edge(sw_id,uid,**get_edge_attributes("lan"))
            G.add_edge(uid,sw_id,**get_edge_attributes("lan"))
            users_by_dept[dept].append(uid)

    # ---------------------
    # 6. IT Zone + AD + Bastion
    # ---------------------
    G.add_node("sw_IT",label="IT SW",role="switch",layer="IT_VLAN")
    G.add_edge("sw_Core","sw_IT",**get_edge_attributes("fiber"))
    G.add_edge("sw_IT","sw_Core",**get_edge_attributes("fiber"))

    sysadmin = "c_SysAdmin"
    helpdesk = "c_Helpdesk"
    ad_node = "s_AD"
    bastion_node = "s_Bastion"

    for u in [sysadmin,helpdesk]:
        G.add_node(u,label=u,role="client",layer="IT_VLAN")
        G.add_edge("sw_IT",u,**get_edge_attributes("lan"))
        G.add_edge(u,"sw_IT",**get_edge_attributes("lan"))

    G.add_node(ad_node,label="Active Directory",role="identity",layer="Internal")
    G.add_node(bastion_node,label="Bastion Host",role="security",layer="Secure_Admin")
    G.add_edge("sw_IT",bastion_node,**get_edge_attributes("lan"))
    G.add_edge(bastion_node,"sw_IT",**get_edge_attributes("lan"))
    G.add_edge("sw_Core",ad_node,**get_edge_attributes("fiber"))
    G.add_edge(ad_node,"sw_Core",**get_edge_attributes("fiber"))

    # ---------------------
    # 7. Crown Jewels
    # ---------------------
    targets = ["FinanceDB","CustomerDB","SourceCode"]
    target_nodes = []
    for t in random.sample(targets,random.randint(2,len(targets))):
        nid = f"s_{t}"
        G.add_node(nid,label=t,role="server",layer="Secure")
        # Randomized connections
        conn = random.choice(app_nodes + ["sw_Core"])
        G.add_edge(conn,nid,**get_edge_attributes("fiber"))
        G.add_edge(nid,conn,**get_edge_attributes("fiber"))
        target_nodes.append(nid)

    # ---------------------
    # 8. Authorized Access Paths
    # ---------------------
    G.add_edge(sysadmin,bastion_node,**get_edge_attributes("auth"),type="authorized",mfa=True)
    for t in target_nodes:
        G.add_edge(bastion_node,t,**get_edge_attributes("auth"),type="authorized",is_secure_tunnel=True)
        if random.random() < 0.3:  # sometimes direct but risky
            G.add_edge(sysadmin,t,**get_edge_attributes("auth"),type="authorized",mfa=False)

    # Users -> Targets (department relevant)
    for dept, users in users_by_dept.items():
        for u in users:
            for t in target_nodes:
                if dept in t:  # department-specific access
                    if random.random() < 0.8:
                        G.add_edge(u,t,**get_edge_attributes("auth"),type="authorized")

    # ---------------------
    # 9. Random Exploit Paths
    # ---------------------
    all_users = [u for dept in users_by_dept.values() for u in dept]

    # DMZ -> App / App -> DB / User -> Helpdesk / Helpdesk -> AD
    for _ in range(3):
        if dmz_nodes and app_nodes and random.random() < config["exploit_prob"]:
            src = random.choice(dmz_nodes)
            dst = random.choice(app_nodes)
            G.add_edge(src,dst,**get_edge_attributes("exploit"),type="exploit")
        if app_nodes and target_nodes and random.random() < config["exploit_prob"]:
            src = random.choice(app_nodes)
            dst = random.choice(target_nodes)
            G.add_edge(src,dst,**get_edge_attributes("exploit"),type="exploit")
        if all_users and random.random() < config["exploit_prob"]:
            src = random.choice(all_users)
            G.add_edge(src,helpdesk,**get_edge_attributes("exploit"),type="exploit")
        if random.random() < config["exploit_prob"]:
            G.add_edge(helpdesk,ad_node,**get_edge_attributes("ad_attack"),type="exploit")
    
    # AD -> SysAdmin (privilege escalation)
    G.add_edge(ad_node,sysadmin,**get_edge_attributes("auth"),type="privilege")

    return G
