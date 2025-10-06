# checks/best_practices.py
import re
import ipaddress
from typing import Dict, List, Tuple

_IP_RE = re.compile(r"\b(?:(?:\d{1,3}\.){3}\d{1,3})(?:/\d{1,2})?\b")

def _is_telnet_enabled(vty_lines: List[str]) -> bool:
    for ln in vty_lines:
        m = re.search(r"^\s*transport input\s+(.+)$", ln)
        if m and re.search(r"\btelnet\b", m.group(1)):
            return True
    return False

def _has_access_class(vty_lines: List[str]) -> bool:
    return any(re.search(r"^\s*access-class\s+\S+\s+in\b", ln) for ln in vty_lines)

def _collect_if_networks(cfg: Dict) -> List[Tuple[str, str, ipaddress.IPv4Network]]:
    nets = []
    for ifn, idef in cfg.get("interfaces", {}).items():
        net = idef.get("network")
        zone = idef.get("zone") or "LAN"
        if not net: continue
        nets.append((ifn, zone, ipaddress.IPv4Network(net)))
    return nets

def _ip_tokens(s: str):
    for m in _IP_RE.finditer(s):
        tok = m.group(0)
        if "/" in tok:
            yield ipaddress.IPv4Network(tok, strict=False)
        else:
            yield ipaddress.IPv4Address(tok)

def _map_ip_to_zone(ipobj, nets) -> List[str]:
    zones = []
    for _, zone, net in nets:
        try:
            if (isinstance(ipobj, ipaddress.IPv4Address) and ipobj in net) or \
               (isinstance(ipobj, ipaddress.IPv4Network) and ipobj.subnet_of(net)):
                zones.append(zone)
        except Exception:
            continue
    return sorted(set(zones))

def _rate_pair(src: str, dst: str) -> Tuple[str, str]:
    # Возвращает (severity, note)
    if src == "INET" and dst in ("LAN","DMZ","MGMT"):
        return ("high", "Трафик с внешней сети внутрь — запрещать, кроме строго опубликованного.")
    if src == "DMZ" and dst in ("LAN","MGMT"):
        return ("medium", "DMZ не должна ходить в LAN/MGMT, кроме строго необходимых сервисов.")
    if src == "LAN" and dst == "INET":
        return ("ok", "Обычный исходящий доступ пользователей.")
    if src == "LAN" and dst in ("DMZ","PARTNER"):
        return ("low", "Разрешение допустимо по нужным портам.")
    if src == "WIFI" and dst in ("LAN","MGMT"):
        return ("high", "Гостевая/WiFi не должна ходить в LAN/MGMT.")
    if src == "PARTNER" and dst in ("LAN","MGMT"):
        return ("medium", "Партнёрская сеть должна быть жёстко ограничена.")
    if src == dst:
        return ("low", "Внутрисетевая связность — проверяйте сегментацию.")
    return ("medium", "Проверьте необходимость этого направления.")
    
def run_checks(cfg: Dict) -> List[Dict]:
    findings = []
    hostname = cfg.get("hostname")

    # --- ACL базовые ---
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
        if any(re.search(r"^\s*deny\s+ip\s+any\s+any", ln) for ln in lines):
            findings.append({"sev":"ok","type":"acl_explicit_deny","where":f"ACL {acl}",
                             "msg":"Явный deny ip any any (контроль падений)."})
        if any(re.search(r"^\s*deny\s+.+\b(?!log)\s*$", ln) for ln in lines):
            findings.append({"sev":"low","type":"deny_without_log","where":f"ACL {acl}",
                             "msg":"Deny без log — рассмотрите логирование отказов."})

    # --- Интерфейсы и ACL наличие ---
    for ifname, idef in cfg.get("interfaces", {}).items():
        if idef.get("ip") and not idef.get("acl_in") and not idef.get("acl_out"):
            findings.append({"sev":"medium","type":"iface_no_acl","where":f"interface {ifname}",
                             "msg":"IP-интерфейс без ip access-group (нет фильтрации)."})
        else:
            findings.append({"sev":"ok","type":"iface_acl_present","where":f"interface {ifname}",
                             "msg":"На интерфейсе назначен ACL (in/out)."})

    # --- SNMP / VTY / HTTP ---
    for comm in cfg["mgmt"].get("snmp", []):
        if comm.lower() in ("public","private"):
            findings.append({"sev":"high","type":"snmp_weak_comm","where":"snmp-server",
                             "msg":f"Слабое SNMP community '{comm}' — заменить, ограничить ACL."})
    if _is_telnet_enabled(cfg["mgmt"].get("vty", [])):
        findings.append({"sev":"high","type":"telnet_enabled","where":"line vty",
                         "msg":"Включён Telnet на VTY — отключите, используйте SSH."})
    if not _has_access_class(cfg["mgmt"].get("vty", [])):
        findings.append({"sev":"medium","type":"vty_no_access_class","where":"line vty",
                         "msg":"Нет access-class на VTY — ограничьте источники управления."})
    else:
        findings.append({"sev":"ok","type":"vty_restricted","where":"line vty",
                         "msg":"VTY ограничен access-class — хорошо."})
    if any(srv == "server" for srv in cfg["mgmt"].get("http", [])):
        findings.append({"sev":"medium","type":"http_server_enabled","where":"ip http server",
                         "msg":"ip http server включён — отключите либо используйте только secure-server и ACL."})
    if any(srv == "secure-server" for srv in cfg["mgmt"].get("http", [])):
        findings.append({"sev":"low","type":"https_enabled","where":"ip http secure-server",
                         "msg":"Включён HTTPS для управления — ограничьте источники (ACL)."})
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

    # === Межзоновый анализ ===
    # 1) подготовим сети интерфейсов
    nets = _collect_if_networks(cfg)
    # 2) построим направленные пары src_zone->dst_zone по ingress-ACL
    zone_pairs = {}  # (src_zone, dst_zone) -> {"permits": count, "samples":[rule]}
    for ifn, idef in cfg.get("interfaces", {}).items():
        acl_name = idef.get("acl_in")  # анализируем входящий (основное место фильтра)
        if not acl_name: continue
        lines = cfg["acls"].get(acl_name, [])
        src_zone = idef.get("zone") or "LAN"
        for ln in lines:
            if not re.search(r"\bpermit\b", ln):  # интересуют разрешения
                continue
            # соберём все IP-«назначения» в строке (упрощённо: ищем любые IP)
            ips = list(_ip_tokens(ln))
            # попробуем замэпить их к зонам
            dst_zones = set()
            for ipobj in ips:
                for z in _map_ip_to_zone(ipobj, nets):
                    dst_zones.add(z)
            for dst_zone in sorted(dst_zones):
                key = (src_zone, dst_zone)
                zone_pairs.setdefault(key, {"permits":0,"samples":[]})
                zone_pairs[key]["permits"] += 1
                if len(zone_pairs[key]["samples"]) < 3:
                    zone_pairs[key]["samples"].append(ln.strip())

    # 3) оценка пар и генерация findings
    interzone_rows = []
    for (src, dst), data in sorted(zone_pairs.items()):
        sev, note = _rate_pair(src, dst)
        interzone_rows.append({"src":src, "dst":dst, "sev":sev, "count":data["permits"], "samples":data["samples"], "note":note})
        # добавляем короткое finding
        findings.append({
            "sev": sev,
            "type": "interzone_permit",
            "where": f"{src} → {dst}",
            "msg": f"Разрешений: {data['permits']}. {note}",
            "rule": "; ".join(data["samples"])
        })

    # приложим матрицу к cfg для репортёра
    cfg["_interzone"] = interzone_rows
    return findings