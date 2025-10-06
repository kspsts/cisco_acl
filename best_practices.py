# checks/best_practices.py
import re
from typing import Dict, List

def _is_telnet_enabled(vty_lines: List[str]) -> bool:
    for ln in vty_lines:
        m = re.search(r"^\s*transport input\s+(.+)$", ln)
        if m and re.search(r"\btelnet\b", m.group(1)):
            return True
    return False

def _has_access_class(vty_lines: List[str]) -> bool:
    return any(re.search(r"^\s*access-class\s+\S+\s+in\b", ln) for ln in vty_lines)

def run_checks(cfg: Dict) -> List[Dict]:
    findings = []
    hostname = cfg.get("hostname")

    # --- ACL широчайшие разрешения ---
    for acl, lines in cfg.get("acls", {}).items():
        for ln in lines:
            if re.search(r"\bpermit\s+ip\s+any\s+any\b", ln):
                findings.append({"sev":"high","type":"acl_any_any","where":f"ACL {acl}","rule":ln,
                                 "msg":"Широкое разрешение трафика (permit ip any any)."})
            if re.search(r"\bpermit\s+tcp\s+any\s+any\b", ln):
                findings.append({"sev":"high","type":"acl_tcp_any_any","where":f"ACL {acl}","rule":ln,
                                 "msg":"Широкий TCP any→any. Уточните источники/назначения/порты."})
            if re.search(r"\b(eq\s+23|eq\s+3389|range\s+1\s+1024)\b", ln):
                findings.append({"sev":"medium","type":"risky_ports","where":f"ACL {acl}","rule":ln,
                                 "msg":"Рискованные порты (Telnet/RDP/низкие диапазоны)."})
        # OK: явный deny any (лог/позиция в конце)
        if any(re.search(r"^\s*deny\s+ip\s+any\s+any", ln) for ln in lines):
            findings.append({"sev":"ok","type":"acl_explicit_deny","where":f"ACL {acl}",
                             "msg":"Явный deny ip any any (контроль падений)."})
        # Low: отсутствие логирования в deny
        if any(re.search(r"^\s*deny\s+.+\b(?!log)\s*$", ln) for ln in lines):
            findings.append({"sev":"low","type":"deny_without_log","where":f"ACL {acl}",
                             "msg":"Deny без log — рассмотрите логирование отказов."})

    # --- Интерфейсы без ACL ---
    for ifname, idef in cfg.get("interfaces", {}).items():
        if idef.get("ip") and not idef.get("acl_in") and not idef.get("acl_out"):
            findings.append({"sev":"medium","type":"iface_no_acl","where":f"interface {ifname}",
                             "msg":"IP-интерфейс без ip access-group (нет фильтрации)."})
        else:
            findings.append({"sev":"ok","type":"iface_acl_present","where":f"interface {ifname}",
                             "msg":"На интерфейсе назначен ACL (in/out)."})        

    # --- SNMP community ---
    for comm in cfg["mgmt"].get("snmp", []):
        lc = comm.lower()
        if lc in ("public","private"):
            findings.append({"sev":"high","type":"snmp_weak_comm","where":"snmp-server",
                             "msg":f"Слабое SNMP community '{comm}' — заменить, ограничить ACL."})

    # --- VTY / управление ---
    if _is_telnet_enabled(cfg["mgmt"].get("vty", [])):
        findings.append({"sev":"high","type":"telnet_enabled","where":"line vty",
                         "msg":"Включён Telnet на VTY — отключите, используйте SSH."})
    if not _has_access_class(cfg["mgmt"].get("vty", [])):
        findings.append({"sev":"medium","type":"vty_no_access_class","where":"line vty",
                         "msg":"Нет access-class на VTY — ограничьте источники управления."})
    else:
        findings.append({"sev":"ok","type":"vty_restricted","where":"line vty",
                         "msg":"VTY ограничен access-class — хорошо."})

    # --- HTTP сервер на устройстве ---
    if any(srv == "server" for srv in cfg["mgmt"].get("http", [])):
        findings.append({"sev":"medium","type":"http_server_enabled","where":"ip http server",
                         "msg":"ip http server включён — отключите либо используйте только secure-server и ACL."})
    if any(srv == "secure-server" for srv in cfg["mgmt"].get("http", [])):
        findings.append({"sev":"low","type":"https_enabled","where":"ip http secure-server",
                         "msg":"Включён HTTPS для управления — проверьте ограничение источников (ACL)."})
    if not cfg["mgmt"].get("http"):
        findings.append({"sev":"ok","type":"http_disabled","where":"ip http",
                         "msg":"HTTP/HTTPS управление отключено — ок."})

    # --- NAT ---
    for nat in cfg.get("nat", []):
        rule = nat["rule"]
        if "overload" in rule:
            findings.append({"sev":"low","type":"nat_overload","where":"ip nat","msg":"NAT overload — стандартно."})
        if re.search(r"\bstatic\b", rule) and re.search(r"\binside\s+source\b", rule):
            findings.append({"sev":"medium","type":"static_nat","where":"ip nat",
                             "msg":"Статический NAT: проверьте, нет ли проброса критичных сервисов в WAN."})

    return findings
