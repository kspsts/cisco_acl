#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re, ipaddress, json, sys
from pathlib import Path
from html import escape
from collections import defaultdict

# ====================== PARSER ======================

_ZONE_KEYWORDS = {
    "INET":["inet","internet","wan","outside","uplink","provider"],
    "DMZ":["dmz","demilitarized","pub","edge-srv"],
    "LAN":["lan","inside","users","office"],
    "PARTNER":["partner","extnet","b2b"],
    "WIFI":["wifi","wlan","guest","hotspot"],
    "MGMT":["mgmt","oob","management","admin"],
}

_LINE_COMMENT_RE = re.compile(r"\s+(?:!|//|#).*$")


def _strip_inline_comment(line: str) -> str:
    """Удаляет хвостовые комментарии Cisco/IOS без затрагивания ключевых слов."""
    if not line:
        return line
    return _LINE_COMMENT_RE.sub("", line).rstrip()


def _is_comment_line(line: str) -> bool:
    return bool(line) and line.lstrip().startswith(("!", "#", "//"))


def _parse_object_group_member(keyword: str, value: str) -> dict:
    tokens = value.split()
    member = {
        "keyword": keyword,
        "value": value,
        "kind": keyword,
    }

    if keyword == "group-object":
        member["kind"] = "group-object"
        member["ref"] = tokens[0] if tokens else ""
        return member

    if keyword == "network-object":
        if not tokens:
            member["kind"] = "unknown"
            return member
        head = tokens[0]
        if head == "host" and len(tokens) >= 2:
            member["kind"] = "host"
            member["address"] = tokens[1]
            return member
        if head == "range" and len(tokens) >= 3:
            member["kind"] = "range"
            member["start"] = tokens[1]
            member["end"] = tokens[2]
            return member
        if head == "object-group" and len(tokens) >= 2:
            member["kind"] = "group-object"
            member["ref"] = tokens[1]
            return member
        if len(tokens) >= 2:
            member["kind"] = "network"
            member["address"] = tokens[0]
            member["mask"] = tokens[1]
            return member
        member["kind"] = "unknown"
        return member

    if keyword == "host":
        if tokens:
            member["kind"] = "host"
            member["address"] = tokens[0]
        else:
            member["kind"] = "unknown"
        return member

    if keyword == "service-object":
        member["kind"] = "service-object"
        member["parts"] = tokens
        return member

    if keyword == "port-object":
        member["kind"] = "port-object"
        member["parts"] = tokens
        return member

    member["kind"] = keyword
    return member

def _infer_zone(desc, ifname, nat_role):
    s = f"{desc or ''} {ifname or ''}".lower()
    for z, keys in _ZONE_KEYWORDS.items():
        if any(k in s for k in keys):
            return z
    if nat_role == "outside": return "INET"
    if nat_role == "inside":  return "LAN"
    return "LAN"

def _mask_to_prefix(mask):
    try: return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except: return None

def _calc_network(ip):
    if not ip or "/" not in ip: return None
    addr, mask = ip.split("/")
    p = _mask_to_prefix(mask)
    if p is None: return None
    try: return ipaddress.IPv4Network(f"{addr}/{p}", strict=False)
    except: return None

def _make_snippet(lines, idx, ctx=2):
    """Вернёт (snippet_text, start_lineno) — кусок вокруг строки idx (вкл.), с контекстом."""
    start = max(0, idx-ctx)
    end   = min(len(lines), idx+ctx+1)
    part = lines[start:end]
    return "\n".join(part), start+1  # человекочитаемая нумерация

def parse_config(text: str, zones_map: dict | None = None) -> dict:
    raw_lines = text.splitlines()
    cfg = {
        "hostname": None,
        "interfaces": {},     # name -> {...}
        "acls": {},           # name/num -> [{"text":str,"lineno":int}]
        "acl_blocks": {},     # name -> {"start":int,"end":int}
        "nat": [],
        "object_groups": {},
        "mgmt": {"vty": [], "snmp": [], "http": []},
        "security": {
            "service_password_encryption": False,
            "service_password_encryption_lineno": None,
            "enable": [],
            "user_passwords": [],
        },
        "acl_usage": defaultdict(list),
        "raw": text,
        "raw_lines": raw_lines,
    }

    m = re.search(r"^hostname\s+(\S+)", text, re.M)
    if m: cfg["hostname"] = m.group(1)

    # interface blocks with indices
    for m in re.finditer(r"(?m)^interface\s+(\S+)\s*", text):
        name = m.group(1)
        start = m.start()
        # find next block start or EOF
        rest = text[m.end():]
        next_m = re.search(r"(?m)^(interface\s+\S+|ip access-list\s+\S+|object-group\s+\S+|line\s+\S+|router\s+\S+|hostname\s+\S+|!)", rest)
        end_pos = m.end() + next_m.start() if next_m else len(text)
        body = text[m.end():end_pos]
        body_lines = []
        for raw_ln in body.splitlines():
            if _is_comment_line(raw_ln):
                continue
            cleaned = _strip_inline_comment(raw_ln.rstrip())
            if cleaned:
                body_lines.append(cleaned)
        body_clean = "\n".join(body_lines)

        desc = re.search(r"^\s*description\s+(.+)$", body_clean, re.M)
        ipm  = re.search(r"^\s*ip address\s+([\d\.]+)\s+([\d\.]+)", body_clean, re.M)
        acl_in  = re.search(r"ip access-group\s+(\S+)\s+in", body_clean)
        acl_out = re.search(r"ip access-group\s+(\S+)\s+out", body_clean)
        nat_in  = bool(re.search(r"^\s*ip nat inside\b", body_clean, re.M))
        nat_out = bool(re.search(r"^\s*ip nat outside\b", body_clean, re.M))
        nat_role = "inside" if nat_in else ("outside" if nat_out else None)
        ip = f"{ipm.group(1)}/{ipm.group(2)}" if ipm else None
        network = _calc_network(ip) if ip else None
        zone_override = (zones_map or {}).get(name) if zones_map else None
        zone = (zone_override or _infer_zone(desc.group(1).strip() if desc else "", name, nat_role))

        is_tunnel = name.lower().startswith("tunnel") or bool(re.search(r"^\s*tunnel\s+", body_clean, re.M))
        is_shutdown = bool(re.search(r"^\s*shutdown\b", body_clean, re.M))

        cfg["interfaces"][name] = {
            "description": (desc.group(1).strip() if desc else ""),
            "ip": ip,
            "network": str(network) if network else None,
            "acl_in": (acl_in.group(1) if acl_in else None),
            "acl_out": (acl_out.group(1) if acl_out else None),
            "nat_role": nat_role,
            "zone": zone,
            "is_tunnel": is_tunnel,
            "is_shutdown": is_shutdown,
        }

        if acl_in:
            cfg["acl_usage"][acl_in.group(1)].append({
                "interface": name,
                "direction": "in",
                "zone": zone,
            })
        if acl_out:
            cfg["acl_usage"][acl_out.group(1)].append({
                "interface": name,
                "direction": "out",
                "zone": zone,
            })

    # named ACLs with line numbers
    for m in re.finditer(r"^ip access-list (extended|standard)\s+(\S+)", text, re.M):
        name = m.group(2)
        start_line = text.count("\n", 0, m.start()) + 1
        # block end: next "ip access-list" or "interface" or EOF
        block_m = re.search(r"(?m)^(ip access-list\s+\S+|interface\s+\S+|hostname\s+\S+)", text[m.end():])
        end_idx = m.end()+block_m.start() if block_m else len(text)
        block = text[m.end():end_idx].splitlines()
        cfg["acl_blocks"][name] = {"start": start_line, "end": start_line + len(block)}
        for i, ln in enumerate(block, 1):
            ln = _strip_inline_comment(ln.rstrip())
            if not ln.strip() or _is_comment_line(ln):
                continue
            if re.match(r"^\s*remark\b", ln, re.I):
                continue
            cfg["acls"].setdefault(name, []).append({"text": ln.strip(), "lineno": start_line + i})

    # numbered ACLs (single lines)
    for m in re.finditer(r"^access-list\s+(\d+)\s+(.*)$", text, re.M):
        num = m.group(1)
        lineno = text.count("\n", 0, m.start()) + 1
        line = _strip_inline_comment(m.group(2).strip())
        if not line or re.match(r"^remark\b", line, re.I):
            continue
        cfg["acls"].setdefault(num, []).append({"text": line, "lineno": lineno})

    # NAT rules
    for m in re.finditer(r"^ip nat (inside|outside)\s+source\s+(.*?)$", text, re.M):
        lineno = text.count("\n", 0, m.start()) + 1
        rule = _strip_inline_comment(m.group(2).strip())
        if not rule:
            continue
        cfg["nat"].append({"dir": m.group(1), "rule": rule, "lineno": lineno})

    # object-groups (kept simple)
    for m in re.finditer(r"^object-group\s+(network|service)\s+(\S+)(.*?)(?=^object-group|^ip access-list|^interface|^line\s+|\Z)", text, re.S | re.M):
        og_type, og_name, body = m.group(1), m.group(2), m.group(3)
        start_line = text.count("\n", 0, m.start()) + 1
        members = []
        for offset, raw_ln in enumerate(body.splitlines(), 1):
            cleaned = _strip_inline_comment(raw_ln.rstrip())
            if not cleaned or _is_comment_line(cleaned):
                continue
            mm = re.match(r"^\s*(network-object|host|service-object|group-object|port-object)\s+(.+)$", cleaned)
            if not mm:
                continue
            keyword, value = mm.group(1), mm.group(2).strip()
            member = _parse_object_group_member(keyword, value)
            member.update({"lineno": start_line + offset, "raw": cleaned})
            members.append(member)
        cfg["object_groups"][og_name] = {"type": og_type, "members": members, "lineno": start_line}

    # mgmt
    vty = re.search(r"^line vty.*?(?=^line |\Z)", text, re.S | re.M)
    if vty:
        vty_block = vty.group(0)
        first_line = text.count("\n", 0, vty.start()) + 1
        vty_lines = []
        for i, ln in enumerate(vty_block.splitlines()):
            clean = _strip_inline_comment(ln.rstrip())
            if not clean or _is_comment_line(clean):
                continue
            vty_lines.append({"text": clean, "lineno": first_line + i})
        cfg["mgmt"]["vty"] = vty_lines

    cfg["mgmt"]["snmp"] = [
        {"text": _strip_inline_comment(m.group(0)).strip(),
         "lineno": text.count('\n', 0, m.start()) + 1,
         "community": m.group(1)}
        for m in re.finditer(r"^snmp-server community\s+(\S+).*?$", text, re.M)
    ]
    cfg["mgmt"]["http"] = [
        {"text": _strip_inline_comment(m.group(0)).strip(),
         "lineno": text.count('\n', 0, m.start()) + 1,
         "kind": m.group(1)}
        for m in re.finditer(r"^ip http (server|secure-server).*?$", text, re.M)
    ]
    # security / auth settings
    spe = re.search(r"(?m)^service password-encryption\b", text)
    if spe:
        cfg["security"]["service_password_encryption"] = True
        cfg["security"]["service_password_encryption_lineno"] = text.count('\n', 0, spe.start()) + 1

    for m in re.finditer(r"(?m)^enable secret\s+(.+)$", text):
        raw_line = _strip_inline_comment(m.group(0)).strip()
        tokens = raw_line.split()
        if len(tokens) < 3:
            continue
        entry = {"kind": "secret", "lineno": text.count('\n', 0, m.start()) + 1, "raw": raw_line}
        level_offset = 2
        if len(tokens) > 3 and tokens[2] == "level" and tokens[3].isdigit():
            entry["level"] = tokens[3]
            level_offset = 4
        dtype = "0"
        val_tokens = tokens[level_offset:]
        if val_tokens:
            if val_tokens[0].isdigit():
                dtype = val_tokens[0]
                val_tokens = val_tokens[1:]
        entry["type"] = dtype
        entry["value"] = " ".join(val_tokens)
        cfg["security"]["enable"].append(entry)

    for m in re.finditer(r"(?m)^enable password\s+(.+)$", text):
        raw_line = _strip_inline_comment(m.group(0)).strip()
        tokens = raw_line.split()
        if len(tokens) < 3:
            continue
        entry = {
            "kind": "password",
            "lineno": text.count('\n', 0, m.start()) + 1,
            "type": tokens[2] if tokens[2].isdigit() else "0",
            "value": " ".join(tokens[3:]) if tokens[2].isdigit() else " ".join(tokens[2:]),
            "raw": raw_line,
        }
        cfg["security"]["enable"].append(entry)

    for m in re.finditer(r"(?m)^username\s+([^\s]+)\s+.*$", text):
        raw_line = _strip_inline_comment(m.group(0)).strip()
        tokens = raw_line.split()
        if len(tokens) < 3:
            continue
        username = tokens[1]
        record = {"user": username, "lineno": text.count('\n', 0, m.start()) + 1, "raw": raw_line}
        if "secret" in tokens[2:]:
            idx = tokens.index("secret", 2)
            tp = tokens[idx + 1] if idx + 1 < len(tokens) else "0"
            val_tokens = tokens[idx + 2:]
            if not tp.isdigit():
                val_tokens = tokens[idx + 1:]
                tp = "0"
            record.update({"kind": "secret", "type": tp, "value": " ".join(val_tokens)})
        elif "password" in tokens[2:]:
            idx = tokens.index("password", 2)
            tp = tokens[idx + 1] if idx + 1 < len(tokens) else "0"
            val_tokens = tokens[idx + 2:]
            if not tp.isdigit():
                val_tokens = tokens[idx + 1:]
                tp = "0"
            record.update({"kind": "password", "type": tp, "value": " ".join(val_tokens)})
        else:
            continue
        cfg["security"]["user_passwords"].append(record)

    return cfg

# ====================== CHECKS ======================

_IP_RE = re.compile(r"\b(?:(?:\d{1,3}\.){3}\d{1,3})(?:/\d{1,2})?\b")

def _is_telnet_enabled(vty_lines):
    for item in vty_lines:
        ln = item["text"]
        m = re.search(r"^\s*transport input\s+(.+)$", ln)
        if m and re.search(r"\btelnet\b", m.group(1)):
            return True
    return False

def _has_access_class(vty_lines):
    return any(re.search(r"^\s*access-class\s+\S+\s+in\b", item["text"]) for item in vty_lines)

def _collect_if_networks(cfg):
    nets = []
    for ifn, idef in cfg.get("interfaces", {}).items():
        net = idef.get("network"); zone = idef.get("zone") or "LAN"
        if not net: continue
        nets.append((ifn, zone, ipaddress.IPv4Network(net)))
    return nets

def _ip_tokens(s, cfg):
    seen = set()

    for m in _IP_RE.finditer(s):
        tok = m.group(0)
        try:
            obj = ipaddress.IPv4Network(tok, strict=False) if "/" in tok else ipaddress.IPv4Address(tok)
        except Exception:
            continue
        if obj in seen:
            continue
        seen.add(obj)
        yield obj

    og_networks = cfg.get("_og_networks", {}) or {}
    for m in re.finditer(r"object-group\s+(\S+)", s):
        name = m.group(1)
        entries = og_networks.get(name)
        if not entries:
            continue
        for etype, payload in entries:
            if etype != "network":
                continue
            if payload in seen:
                continue
            seen.add(payload)
            yield payload

def _map_ip_to_zone(ipobj, nets):
    zones = []
    for _, zone, net in nets:
        try:
            if (isinstance(ipobj, ipaddress.IPv4Address) and ipobj in net) or \
               (isinstance(ipobj, ipaddress.IPv4Network) and ipobj.subnet_of(net)):
                zones.append(zone)
        except: pass
    return sorted(set(zones))


_SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "ok": 0}


def _find_acl_interfaces(cfg, acl_name):
    usage = cfg.get("acl_usage") or {}
    return list(usage.get(acl_name, []))


def _evaluate_any_any_risk(zone, direction):
    zone = (zone or "?").upper()
    direction = (direction or "in").lower()

    if zone == "INET":
        if direction == "in":
            return "high", "Разрешение ANY из внешней зоны внутрь."
        return "low", "Исходящий ANY в INET — стандартная политика, требуется контроль только при особых требованиях."

    if zone in ("DMZ", "PARTNER"):
        if direction == "in":
            return "high", f"ANY из зоны {zone} внутрь — риск нарушения сегментации."
        return "medium", f"ANY из {zone} наружу — убедитесь в необходимости."

    if zone in ("WIFI", "GUEST"):
        if direction == "in":
            return "high", "Гостевой/WiFi трафик не должен бесконтрольно входить в сеть."
        return "medium", "Исходящий ANY из WiFi — требуется строгое ограничение."

    if zone == "MGMT":
        return "high", "ANY на управляющем сегменте — критичный риск."

    if zone == "LAN":
        if direction == "in":
            return "medium", "ANY внутри LAN — возможны боковые перемещения."
        return "medium", "Исходящий ANY из LAN — контроль нужен на границе."

    return "medium", "Широкое правило — уточните бизнес-потребность."


def _contextual_any_any(cfg, acl_name):
    contexts = _find_acl_interfaces(cfg, acl_name)
    if not contexts:
        return "low", "ACL не назначен ни на один интерфейс."

    worst = "low"
    details = []
    for ctx in contexts:
        zone = ctx.get("zone") or "?"
        direction = ctx.get("direction") or "in"
        iface = ctx.get("interface") or "?"
        sev, desc = _evaluate_any_any_risk(zone, direction)
        if _SEVERITY_ORDER[sev] > _SEVERITY_ORDER[worst]:
            worst = sev
        details.append(f"{iface} ({direction}, {zone}): {desc}")

    return worst, "; ".join(details)

def _rate_pair(src, dst):
    if src == "INET" and dst in ("LAN","DMZ","MGMT"): return ("high","Внешняя сеть внутрь — запрещать, кроме строго опубликованного.")
    if src == "DMZ" and dst in ("LAN","MGMT"):        return ("medium","DMZ→LAN/MGMT только по строгой необходимости.")
    if src == "LAN" and dst == "INET":                return ("ok","Обычный исходящий доступ.")
    if src == "LAN" and dst in ("DMZ","PARTNER"):     return ("low","Допустимо по нужным портам.")
    if src == "WIFI" and dst in ("LAN","MGMT"):       return ("high","Гостевая/WiFi не должна ходить в LAN/MGMT.")
    if src == "PARTNER" and dst in ("LAN","MGMT"):    return ("medium","Партнёрская сеть строго ограничена.")
    if src == dst:                                    return ("low","Внутрисетевая связность — проверьте сегментацию.")
    return ("medium","Проверьте необходимость направления.")

def _finding(sev, ftype, where, msg, cfg, lineno=None, rule=None, fix=None):
    """Формирует finding с фрагментом конфига (snippet)."""
    snippet, start = None, None
    if lineno:
        # показать 2 строки контекста вокруг lineno
        lines = cfg["raw_lines"]
        snippet, start = _make_snippet(lines, lineno-1, ctx=2)
    return {
        "sev": sev, "type": ftype, "where": where, "msg": msg,
        "rule": rule, "fix": fix,
        "lineno": lineno, "snippet": snippet, "snippet_start": start
    }


def _first_lineno(text: str, pattern: str):
    m = re.search(pattern, text, re.M)
    if not m:
        return None
    return text.count('\n', 0, m.start()) + 1


_STRONG_SECRET_TYPES = {"8", "9"}
_LEGACY_SECRET_TYPES = {"5"}


def _secret_strength(dtype: str) -> str:
    dtype = (dtype or "0").strip()
    if dtype in _STRONG_SECRET_TYPES:
        return "strong"
    if dtype in _LEGACY_SECRET_TYPES:
        return "legacy"
    return "weak"


def _password_is_complex(pwd: str) -> bool:
    if not pwd or len(pwd) < 12:
        return False
    classes = 0
    if re.search(r"[a-z]", pwd):
        classes += 1
    if re.search(r"[A-Z]", pwd):
        classes += 1
    if re.search(r"\d", pwd):
        classes += 1
    if re.search(r"[^\w]", pwd):
        classes += 1
    return classes >= 3


def _analyze_object_groups(cfg):
    groups = cfg.get("object_groups", {}) or {}
    findings = []
    cycle_cache = set()
    resolved_networks = {}
    resolved_services = {}

    def _register_cycle(stack, name, lineno, raw_rule, group_type):
        cycle = tuple(stack[stack.index(name):] + [name])
        key = (group_type, cycle)
        if key in cycle_cache:
            return
        cycle_cache.add(key)
        chain = " → ".join(cycle)
        findings.append(_finding(
            "high", "object_group_cycle", f"object-group {name}",
            f"Обнаружена циклическая ссылка object-group: {chain}.", cfg,
            lineno=lineno,
            rule=raw_rule or f"object-group {group_type} {name}",
            fix="Переработать структуру object-group, исключить рекурсию."
        ))

    def resolve(name, stack):
        if name in resolved_networks:
            return ("network", resolved_networks[name])
        if name in resolved_services:
            return ("service", resolved_services[name])

        group = groups.get(name)
        if not group:
            return (None, set())

        group_type = group.get("type")
        if name in stack:
            _register_cycle(stack, name, group.get("lineno"), None, group_type)
            return (group_type, set())

        stack.append(name)

        if group_type == "network":
            container = set()
            for member in group.get("members", []):
                kind = member.get("kind")
                lineno = member.get("lineno")
                raw = member.get("raw")

                if kind == "group-object":
                    ref = member.get("ref")
                    if not ref or ref not in groups:
                        findings.append(_finding(
                            "medium", "object_group_missing", f"object-group {name}",
                            f"Ссылка на отсутствующий object-group '{ref or '?'}'.", cfg,
                            lineno=lineno, rule=raw,
                            fix="Создать недостающий object-group или удалить ссылку."
                        ))
                        continue
                    ref_type = groups[ref].get("type")
                    if ref_type != "network":
                        findings.append(_finding(
                            "medium", "object_group_type_mismatch", f"object-group {name}",
                            f"Ссылка на object-group '{ref}' другого типа ({ref_type}).", cfg,
                            lineno=lineno, rule=raw,
                            fix="Использовать внутри network-group только network-object."
                        ))
                        continue
                    if ref in stack:
                        _register_cycle(stack, ref, lineno, raw, group_type)
                        continue
                    _, resolved_set = resolve(ref, stack)
                    container.update(resolved_set)
                    continue

                if kind == "host":
                    addr = member.get("address")
                    try:
                        ip = ipaddress.IPv4Address(addr)
                        container.add(("network", ipaddress.IPv4Network(f"{ip}/32")))
                    except Exception:
                        findings.append(_finding(
                            "medium", "object_group_invalid_ip", f"object-group {name}",
                            f"Некорректный host-адрес '{addr}'.", cfg,
                            lineno=lineno, rule=raw,
                            fix="Исправить адрес или удалить запись."
                        ))
                    continue

                if kind == "network":
                    addr = member.get("address")
                    mask = member.get("mask")
                    prefix = _mask_to_prefix(mask)
                    if prefix is None:
                        findings.append(_finding(
                            "medium", "object_group_invalid_mask", f"object-group {name}",
                            f"Некорректная маска '{mask}'.", cfg,
                            lineno=lineno, rule=raw,
                            fix="Задать корректную маску или префикс."
                        ))
                        continue
                    try:
                        net = ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
                        container.add(("network", net))
                    except Exception:
                        findings.append(_finding(
                            "medium", "object_group_invalid_ip", f"object-group {name}",
                            f"Некорректная сеть '{addr} {mask}'.", cfg,
                            lineno=lineno, rule=raw,
                            fix="Проверить IP-адрес и маску."
                        ))
                    continue

                if kind == "range":
                    start, end = member.get("start"), member.get("end")
                    try:
                        ipaddress.IPv4Address(start)
                        ipaddress.IPv4Address(end)
                        container.add(("range", (start, end)))
                        findings.append(_finding(
                            "low", "object_group_range", f"object-group {name}",
                            f"Диапазон {start}-{end} не может быть точно сопоставлен зонам.", cfg,
                            lineno=lineno, rule=raw,
                            fix="Рассмотреть замену на сети/host для корректного анализа."
                        ))
                    except Exception:
                        findings.append(_finding(
                            "medium", "object_group_invalid_range", f"object-group {name}",
                            f"Некорректный диапазон '{start} {end}'.", cfg,
                            lineno=lineno, rule=raw,
                            fix="Исправить диапазон."
                        ))
                    continue

                findings.append(_finding(
                    "low", "object_group_unknown_member", f"object-group {name}",
                    f"Неизвестный тип записи '{member.get('keyword')}'.", cfg,
                    lineno=lineno, rule=raw,
                    fix="Проверить синтаксис object-group."
                ))

            stack.pop()
            resolved_networks[name] = container
            return ("network", container)

        container = set()
        for member in group.get("members", []):
            kind = member.get("kind")
            lineno = member.get("lineno")
            raw = member.get("raw")
            if kind == "group-object":
                ref = member.get("ref")
                if not ref or ref not in groups:
                    findings.append(_finding(
                        "medium", "object_group_missing", f"object-group {name}",
                        f"Ссылка на отсутствующий object-group '{ref or '?'}'.", cfg,
                        lineno=lineno, rule=raw,
                        fix="Создать недостающий object-group или удалить ссылку."
                    ))
                    continue
                ref_type = groups[ref].get("type")
                if ref_type != group_type:
                    findings.append(_finding(
                        "medium", "object_group_type_mismatch", f"object-group {name}",
                        f"Ссылка на object-group '{ref}' другого типа ({ref_type}).", cfg,
                        lineno=lineno, rule=raw,
                        fix="Привести типы object-group к одному виду."
                    ))
                    continue
                if ref in stack:
                    _register_cycle(stack, ref, lineno, raw, group_type)
                    continue
                _, resolved_set = resolve(ref, stack)
                container.update(resolved_set)
                continue
            container.add(raw)

        stack.pop()
        resolved_services[name] = container
        return ("service", container)

    for og_name in groups:
        resolve(og_name, [])

    def _format_network_entry(entry):
        etype, payload = entry
        if etype == "network":
            return str(payload)
        if etype == "range":
            start, end = payload
            return f"range {start} {end}"
        return str(payload)

    json_ready = {
        "network": {name: sorted(_format_network_entry(e) for e in values)
                     for name, values in resolved_networks.items()},
        "service": {name: sorted(values)
                     for name, values in resolved_services.items()},
    }

    return {
        "findings": findings,
        "resolved_networks": resolved_networks,
        "resolved_services": resolved_services,
        "json_ready": json_ready,
    }

def run_checks(cfg):
    findings = []

    # ---------- ACL базовые ----------
    for acl, items in cfg.get("acls", {}).items():
        # items: [{"text","lineno"}]
        has_explicit_deny = False
        deny_without_log = False
        for it in items:
            ln = it["text"]; no = it["lineno"]
            if re.search(r"\bpermit\s+ip\s+any\s+any\b", ln):
                severity, ctx_msg = _contextual_any_any(cfg, acl)
                message = "Широкое разрешение (permit ip any any)."
                if ctx_msg:
                    message += f" {ctx_msg}"
                findings.append(_finding(severity,"acl_any_any",f"ACL {acl}",
                    message,
                    cfg, lineno=no, rule=ln,
                    fix="Сузить источники/назначения, разрешать только нужные протоколы/сети; добавить явный deny/log."))
            if re.search(r"\bpermit\s+tcp\s+any\s+any\b", ln):
                severity, ctx_msg = _contextual_any_any(cfg, acl)
                if re.search(r"\bestablished\b", ln, re.I):
                    if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER["medium"]:
                        severity = "medium"
                    message = "TCP any→any с established — допускает широкий возвратный трафик."
                    fix_text = "Сузить источники/назначения либо использовать stateful-политику с контролем состояний."
                    finding_type = "acl_tcp_any_any_established"
                else:
                    message = "Широкий TCP any→any."
                    fix_text = "Уточнить src/dst и порты; рассмотреть stateful/policy-map в ZBF."
                    finding_type = "acl_tcp_any_any"
                if ctx_msg:
                    message += f" {ctx_msg}"
                findings.append(_finding(severity,finding_type,f"ACL {acl}",
                    message,
                    cfg, lineno=no, rule=ln,
                    fix=fix_text))
            if re.search(r"\b(eq\s+23|eq\s+3389|range\s+1\s+1024)\b", ln):
                findings.append(_finding("medium","risky_ports",f"ACL {acl}",
                    "Рискованные порты (Telnet/RDP/низкие диапазоны).",
                    cfg, lineno=no, rule=ln,
                    fix="Заменить Telnet на SSH; ограничить RDP по jump-host и ACL; закрыть низкие порты."))

            if re.search(r"^\s*deny\s+ip\s+any\s+any", ln):
                has_explicit_deny = True
            if re.search(r"^\s*deny\s+.+$", ln) and not re.search(r"\blog\b", ln):
                deny_without_log = True

        if has_explicit_deny:
            findings.append(_finding("ok","acl_explicit_deny",f"ACL {acl}",
                "Есть явный deny ip any any (контроль падений).", cfg))

        if deny_without_log:
            findings.append(_finding("low","deny_without_log",f"ACL {acl}",
                "Есть deny без log — рассмотрите логирование.", cfg,
                fix="Добавить 'log' к завершающим deny для аудита."))

    # ---------- Интерфейсы ----------
    for ifname, idef in cfg.get("interfaces", {}).items():
        if idef.get("is_shutdown"):
            findings.append(_finding("ok","iface_shutdown",f"interface {ifname}",
                "Интерфейс в shutdown — проверки ACL пропущены.", cfg))
            continue
        if not idef.get("ip"):
            continue
        has_acl = bool(idef.get("acl_in") or idef.get("acl_out"))
        if not has_acl:
            if idef.get("is_tunnel"):
                continue
            findings.append(_finding("medium","iface_no_acl",f"interface {ifname}",
                "IP-интерфейс без ip access-group (нет фильтрации).",
                cfg, fix="Назначить ACL in/out либо использовать Zone-Based Firewall с policy-map."))
            continue

        findings.append(_finding("ok","iface_acl_present",f"interface {ifname}",
            "На интерфейсе назначен ACL (in/out).", cfg))

    # ---------- SNMP / VTY / HTTP ----------
    for item in cfg["mgmt"].get("snmp", []):
        comm = item["community"]; no = item["lineno"]
        if comm.lower() in ("public","private"):
            findings.append(_finding("high","snmp_weak_comm","snmp-server",
                f"Слабое SNMP community '{comm}'.", cfg, lineno=no, rule=item["text"],
                fix="Заменить на длинное случайное; ограничить access-list; рассмотреть SNMPv3."))
    if _is_telnet_enabled(cfg["mgmt"].get("vty", [])):
        # найдём строку transport input telnet (первую попавшуюся)
        tr = next((i for i in cfg["mgmt"]["vty"] if re.search(r"transport input .*telnet", i["text"])), None)
        findings.append(_finding("high","telnet_enabled","line vty",
            "Включён Telnet — небезопасно.", cfg,
            lineno=(tr["lineno"] if tr else None), rule=(tr["text"] if tr else None),
            fix="В line vty: 'transport input ssh'; запретить telnet."))
    if not _has_access_class(cfg["mgmt"].get("vty", [])):
        findings.append(_finding("medium","vty_no_access_class","line vty",
            "Нет access-class для VTY — управление не ограничено по источнику.", cfg,
            fix="Создать ACL с допустимыми mgmt-сетями и применить 'access-class <ACL> in'."))
    else:
        findings.append(_finding("ok","vty_restricted","line vty",
            "VTY ограничен access-class — хорошо.", cfg))

    for item in cfg["mgmt"].get("http", []):
        if item["kind"] == "server":
            findings.append(_finding("medium","http_server_enabled","ip http server",
                "Включён нешифрованный HTTP.", cfg, lineno=item["lineno"], rule=item["text"],
                fix="Отключить 'no ip http server' или использовать только 'ip http secure-server' с ACL."))
        if item["kind"] == "secure-server":
            findings.append(_finding("low","https_enabled","ip http secure-server",
                "Включён HTTPS для управления.", cfg, lineno=item["lineno"], rule=item["text"],
                fix="Ограничить mgmt-сетями (ACL) и обновить сертификат."))

    if not cfg["mgmt"].get("http"):
        findings.append(_finding("ok","http_disabled","ip http",
            "HTTP/HTTPS управление отключено — ок.", cfg))

    # ---------- Пароли / аутентификация ----------
    sec = cfg.get("security", {})
    enable_entries = sec.get("enable", [])
    enable_secrets = [e for e in enable_entries if e.get("kind") == "secret"]
    enable_passwords = [e for e in enable_entries if e.get("kind") == "password"]

    if not enable_secrets:
        findings.append(_finding("high","enable_secret_missing","global",
            "Не задан 'enable secret' — повышенный риск компрометации привилегий.", cfg,
            fix="Выполнить 'enable secret 9 <сложный пароль>' и удалить 'enable password'."))

    strong_secret_reported = False
    for entry in enable_secrets:
        strength = _secret_strength(entry.get("type"))
        if strength == "strong":
            if not strong_secret_reported:
                findings.append(_finding("ok","enable_secret_strong","enable secret",
                    "Используется современный алгоритм (type 8/9) для enable secret.", cfg,
                    lineno=entry.get("lineno"), rule=entry.get("raw")))
                strong_secret_reported = True
        elif strength == "legacy":
            findings.append(_finding("medium","enable_secret_md5","enable secret",
                "Enable secret type 5 (MD5) считается устаревшим.", cfg,
                lineno=entry.get("lineno"), rule=entry.get("raw"),
                fix="Пересоздать enable secret c алгоритмом 9 (scrypt) или 8."))
        else:
            severity = "high"
            msg = "Enable secret хранится в открытом виде/типе слабоой защиты."
            if (entry.get("type") or "0") == "0" and not _password_is_complex(entry.get("value", "")):
                msg += " Пароль не соответствует требованиям длины/сложности."
            findings.append(_finding(severity,"enable_secret_plain","enable secret",
                f"{msg} (type {entry.get('type') or '0'}).", cfg,
                lineno=entry.get("lineno"), rule=entry.get("raw"),
                fix="Удалить строку и задать 'enable secret 9 <сложный пароль>'."))

    for entry in enable_passwords:
        dtype = entry.get("type") or "0"
        sev = "high" if dtype == "0" else "medium"
        msg = "Enable password хранится в открытом виде." if dtype == "0" else "Enable password использует слабую обратимую маскировку."
        findings.append(_finding(sev,"enable_password_present","enable password",
            msg, cfg, lineno=entry.get("lineno"), rule=entry.get("raw"),
            fix="Удалить 'enable password' и использовать только 'enable secret 9'."))

    for record in sec.get("user_passwords", []):
        dtype = (record.get("type") or "0").strip()
        kind = record.get("kind")
        where = f"username {record.get('user')}"
        raw = record.get("raw")
        lineno = record.get("lineno")
        if kind == "password":
            if dtype == "0":
                msg = "Пароль пользователя хранится в открытом виде (type 0)."
                if not _password_is_complex(record.get("value", "")):
                    msg += " Требования по длине ≥12 и разнообразию символов не выполняются."
                findings.append(_finding("high","username_plain_password", where,
                    msg, cfg, lineno=lineno, rule=raw,
                    fix="Задать 'username <user> secret 9 <сложный пароль>' и включить service password-encryption."))
            elif dtype == "7":
                findings.append(_finding("medium","username_type7_password", where,
                    "Используется type 7 — легко обратимый шифр.", cfg,
                    lineno=lineno, rule=raw,
                    fix="Переопределить учётную запись с 'secret 9'."))
            else:
                findings.append(_finding("medium","username_masked_password", where,
                    f"Используется нестандартный тип пароля {dtype}. Проверьте необходимость.", cfg,
                    lineno=lineno, rule=raw,
                    fix="Перевыпустить пароль с типом 9."))
        elif kind == "secret":
            strength = _secret_strength(dtype)
            if strength == "strong":
                findings.append(_finding("ok","username_strong_secret", where,
                    "Учетная запись использует современный алгоритм (type 8/9).", cfg,
                    lineno=lineno, rule=raw))
            elif strength == "legacy":
                findings.append(_finding("low","username_md5_secret", where,
                    "Секрет type 5 (MD5) устарел.", cfg,
                    lineno=lineno, rule=raw,
                    fix="Перевыпустить секрет type 9."))
            else:
                findings.append(_finding("high","username_weak_secret", where,
                    f"Секрет использует слабый тип {dtype}.", cfg,
                    lineno=lineno, rule=raw,
                    fix="Пересоздать с type 9 и сложным паролем."))

    if sec.get("service_password_encryption"):
        findings.append(_finding("ok","service_password_encryption_enabled","global",
            "Включено service password-encryption.", cfg,
            lineno=sec.get("service_password_encryption_lineno")))
    else:
        findings.append(_finding("medium","service_password_encryption_disabled","global",
            "Отключено service password-encryption — пароли выводятся в открытом виде.", cfg,
            fix="Выполнить 'service password-encryption' или перевести учётки на type 9."))

    # ---------- CIS базовые проверки ----------
    raw_text = cfg.get("raw", "")

    aaa_lineno = _first_lineno(raw_text, r"(?m)^aaa new-model\b")
    if aaa_lineno:
        findings.append(_finding("ok","aaa_new_model","aaa",
            "Включён aaa new-model.", cfg, lineno=aaa_lineno,
            rule=cfg["raw_lines"][aaa_lineno-1].strip()))
    else:
        findings.append(_finding("high","aaa_new_model_missing","aaa",
            "Команда 'aaa new-model' отсутствует — не выполнены требования CIS 1.1.", cfg,
            fix="Активировать AAA и настроить источники аутентификации (local/RADIUS/TACACS+)."))

    login_block = re.search(r"(?m)^login block-for\s+\d+\s+attempts\s+\d+\s+within\s+\d+", raw_text)
    if login_block:
        lb_lineno = _first_lineno(raw_text, r"(?m)^login block-for\s+\d+\s+attempts\s+\d+\s+within\s+\d+")
        findings.append(_finding("ok","login_block_for","security",
            "Настроена защита от перебора (login block-for).", cfg,
            lineno=lb_lineno, rule=cfg["raw_lines"][lb_lineno-1].strip()))
    else:
        findings.append(_finding("medium","login_block_for_missing","security",
            "Не настроен login block-for — возможен перебор паролей.", cfg,
            fix="Добавить 'login block-for <секунды> attempts <N> within <секунды>'."))

    logging_lineno = _first_lineno(raw_text, r"(?m)^logging buffered\b")
    if logging_lineno:
        findings.append(_finding("ok","logging_buffered","logging",
            "Локальное буферизированное логирование включено.", cfg,
            lineno=logging_lineno, rule=cfg["raw_lines"][logging_lineno-1].strip()))
    else:
        findings.append(_finding("medium","logging_buffered_missing","logging",
            "Не настроено logging buffered — сложнее проводить расследования.", cfg,
            fix="Добавить 'logging buffered <размер>' и пересмотреть удалённые получатели."))

    ts_lineno = _first_lineno(raw_text, r"(?m)^service timestamps log datetime")
    if ts_lineno:
        findings.append(_finding("ok","service_timestamps","logging",
            "Включены временные метки в логах (service timestamps).", cfg,
            lineno=ts_lineno, rule=cfg["raw_lines"][ts_lineno-1].strip()))
    else:
        findings.append(_finding("low","service_timestamps_missing","logging",
            "Отсутствуют service timestamps log — сложнее расследовать события.", cfg,
            fix="Добавить 'service timestamps log datetime msec localtime'."))

    seq_lineno = _first_lineno(raw_text, r"(?m)^service sequence-numbers\b")
    if seq_lineno:
        findings.append(_finding("ok","service_sequence_numbers","logging",
            "Включены sequence-numbers для логов.", cfg,
            lineno=seq_lineno, rule=cfg["raw_lines"][seq_lineno-1].strip()))
    else:
        findings.append(_finding("low","service_sequence_numbers_missing","logging",
            "Sequence-numbers для syslog не включены.", cfg,
            fix="Добавить 'service sequence-numbers' для уникальности записей."))

    ssh_v2_lineno = _first_lineno(raw_text, r"(?m)^ip ssh version 2\b")
    if ssh_v2_lineno:
        findings.append(_finding("ok","ssh_version2","ssh",
            "SSH версии 2 включён.", cfg,
            lineno=ssh_v2_lineno, rule=cfg["raw_lines"][ssh_v2_lineno-1].strip()))
    elif re.search(r"(?m)^ip ssh version 1\b", raw_text):
        findings.append(_finding("high","ssh_version1","ssh",
            "Установлена устаревшая версия SSHv1.", cfg,
            fix="Указать 'ip ssh version 2'."))
    else:
        findings.append(_finding("medium","ssh_version_unspecified","ssh",
            "Версия SSH не зафиксирована — требуется явно указать версию 2.", cfg,
            fix="Добавить 'ip ssh version 2' и ограничить алгоритмы шифрования."))

    exec_timeout_set = any("exec-timeout" in (item.get("text") or "") for item in cfg["mgmt"].get("vty", []))
    if exec_timeout_set:
        line = next((item for item in cfg["mgmt"]["vty"] if "exec-timeout" in item.get("text", "")), None)
        findings.append(_finding("ok","vty_exec_timeout","line vty",
            "Настроен тайм-аут неактивности VTY.", cfg,
            lineno=line.get("lineno") if line else None,
            rule=line.get("text") if line else None))
    else:
        findings.append(_finding("medium","vty_exec_timeout_missing","line vty",
            "Не задан exec-timeout на VTY — сессии остаются бесконечно.", cfg,
            fix="Вставить 'exec-timeout <минуты> <секунды>'."))

    for cmd in ("service tcp-keepalives-in", "service tcp-keepalives-out"):
        lineno = _first_lineno(raw_text, rf"(?m)^{cmd}\\b")
        if lineno:
            findings.append(_finding("ok",f"{cmd.replace(' ', '_')}","service", f"{cmd} включена.", cfg,
                lineno=lineno, rule=cfg["raw_lines"][lineno-1].strip()))
        else:
            findings.append(_finding("low",f"{cmd.replace(' ', '_')}_missing","service",
                f"Не настроена {cmd} — CIS рекомендует включать keepalive для выявления висячих сессий.", cfg,
                fix=f"Добавить '{cmd}'."))

    if re.search(r"(?m)^banner (motd|login)\b", raw_text):
        lineno = _first_lineno(raw_text, r"(?m)^banner (motd|login)\b")
        findings.append(_finding("ok","banner_present","banner",
            "Баннер предупреждения настроен.", cfg,
            lineno=lineno, rule=cfg["raw_lines"][lineno-1].strip()))
    else:
        findings.append(_finding("low","banner_missing","banner",
            "Отсутствует предупредительный баннер — требование CIS/NIST.", cfg,
            fix="Добавить 'banner login' с согласованным текстом."))

    # ---------- Object-groups ----------
    og_result = _analyze_object_groups(cfg)
    findings.extend(og_result["findings"])
    cfg["_object_groups_resolved"] = og_result["json_ready"]
    cfg["_og_networks"] = og_result["resolved_networks"]

    # ---------- NAT ----------
    for nat in cfg.get("nat", []):
        rule, no = nat["rule"], nat["lineno"]
        if "overload" in rule:
            findings.append(_finding("low","nat_overload","ip nat",
                "NAT overload — стандартно.", cfg, lineno=no, rule=f"ip nat {nat['dir']} source {rule}",
                fix="Убедиться, что ACL для overload ограничивает приватные сети."))
            m_acl = re.search(r"\blist\s+(\S+)", rule)
            if m_acl:
                acl_name = m_acl.group(1)
                if acl_name not in cfg.get("acls", {}):
                    findings.append(_finding("medium","nat_acl_missing","ip nat",
                        f"NAT overload использует ACL '{acl_name}', но ACL не найден.", cfg,
                        lineno=no, rule=f"ip nat {nat['dir']} source {rule}",
                        fix="Создать ACL с приватными сетями для NAT overload или исправить имя."))   
        if re.search(r"\bstatic\b", rule) and re.search(r"\binside\s+source\b", rule):
            findings.append(_finding("medium","static_nat","ip nat",
                "Static NAT — возможное экспонирование.", cfg, lineno=no, rule=f"ip nat {nat['dir']} source {rule}",
                fix="Проверить необходимость; ограничить ingress ACL; рассмотреть reverse-proxy/WAF."))

    # ---------- Межзоновые разрешения ----------
    nets = _collect_if_networks(cfg)
    zone_pairs = {}
    for ifn, idef in cfg.get("interfaces", {}).items():
        acl_name = idef.get("acl_in")
        if not acl_name: continue
        items = cfg["acls"].get(acl_name, [])
        src_zone = idef.get("zone") or "LAN"
        for it in items:
            ln, no = it["text"], it["lineno"]
            if "permit" not in ln: continue
            dst_zones = set()
            for ipobj in _ip_tokens(ln, cfg):
                for z in _map_ip_to_zone(ipobj, nets):
                    dst_zones.add(z)
            for dst_zone in sorted(dst_zones):
                key = (src_zone, dst_zone)
                zone_pairs.setdefault(key, {"permits":0,"samples":[]})
                zone_pairs[key]["permits"] += 1
                if len(zone_pairs[key]["samples"]) < 3:
                    zone_pairs[key]["samples"].append((ln, no))

    interzone_rows = []
    for (src, dst), data in sorted(zone_pairs.items()):
        sev, note = _rate_pair(src, dst)
        samples = "; ".join(s for s,_ in data["samples"])
        first_no = (data["samples"][0][1] if data["samples"] else None)
        interzone_rows.append({"src":src,"dst":dst,"sev":sev,"count":data["permits"],"samples":data["samples"],"note":note})
        findings.append(_finding(sev,"interzone_permit",f"{src} → {dst}",
            f"Разрешений: {data['permits']}. {note}", cfg,
            lineno=first_no, rule=samples,
            fix="Сузить ACL до конкретных сервисов/хостов либо запретить направление согласно сегментации."))

    cfg["_interzone"] = interzone_rows
    return findings, cfg

# ====================== HTML REPORT ======================

_PALETTE = {"high":"#ef4444","medium":"#f59e0b","low":"#3b82f6","ok":"#10b981"}

def _badge(sev): return f'<span class="badge" style="background:{_PALETTE[sev]}">{sev.upper()}</span>'

def _matrix_table(rows):
    zones = sorted({r["src"] for r in rows} | {r["dst"] for r in rows})
    cell = {(r["src"], r["dst"]): r for r in rows}
    html = ["<table class='matrix'><thead><tr><th>Src \\ Dst</th>"]
    for z in zones: html.append(f"<th>{escape(z)}</th>")
    html.append("</tr></thead><tbody>")
    for s in zones:
        html.append(f"<tr><td><b>{escape(s)}</b></td>")
        for d in zones:
            r = cell.get((s,d))
            if not r: html.append("<td class='muted'>—</td>"); continue
            sev, cnt = r["sev"], r["count"]
            title = escape(r["note"])
            html.append(f"<td class='sev-{sev}' title='{title}'>{_badge(sev)}&nbsp;{cnt}</td>")
        html.append("</tr>")
    html.append("</tbody></table>")
    return "".join(html)

def _code_block(snippet, start):
    # рендер с номерами строк и кнопкой Copy
    if not snippet: return ""
    code = []
    for i, ln in enumerate(snippet.splitlines(), start):
        code.append(f"<span class='ln'>{i:>4}</span> {escape(ln)}")
    content = "\n".join(code)
    return f"""
<div class="codewrap">
  <button class="copy" onclick="copyNextCode(this)">Copy</button>
  <pre><code>{content}</code></pre>
</div>
"""

def save_html(dev_reports, path="report.html"):
    totals = defaultdict(int)
    for r in dev_reports:
        for f in r["findings"]:
            totals[f["sev"]] += 1

    html = []
    html.append(f"""<!doctype html><meta charset="utf-8">
<title>Cisco GW Audit</title>
<style>
 body{{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:24px;line-height:1.45;background:#f8fafc}}
 h1{{margin:0 0 12px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;margin:16px 0}}
 .card{{border:1px solid #e5e7eb;border-radius:12px;padding:14px;background:#fff;box-shadow:0 1px 2px #0001}}
 .badge{{color:#fff;border-radius:999px;padding:2px 8px;font-size:12px;vertical-align:middle;margin-left:6px}}
 .chip{{display:inline-block;border:1px solid #e5e7eb;border-radius:999px;padding:4px 8px;margin:4px 4px 0 0;background:#f9fafb}}
 details{{margin:8px 0}}
 summary{{cursor:pointer;font-weight:600}}
 table{{width:100%;border-collapse:collapse;margin-top:8px}}
 th,td{{padding:6px 8px;border-bottom:1px solid #e5e7eb;font-size:14px;text-align:left;vertical-align:top}}
 .sev-high{{background:#fef2f2}}
 .sev-medium{{background:#fffbeb}}
 .sev-low{{background:#eff6ff}}
 .sev-ok{{background:#ecfdf5}}
 .muted{{color:#6b7280}}
 h3{{margin:6px 0 10px}}
 .topbar{{position:sticky;top:0;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:10px 12px;z-index:9;box-shadow:0 1px 2px #0001}}
 .controls{{display:flex;gap:12px;align-items:center;flex-wrap:wrap}}
 .controls input[type=search]{{padding:6px 10px;border:1px solid #e5e7eb;border-radius:8px;min-width:260px}}
 .matrix th, .matrix td{{text-align:center}}
 .codewrap{{position:relative}}
 .codewrap .copy{{position:absolute;right:8px;top:8px;border:1px solid #e5e7eb;background:#fff;border-radius:8px;padding:4px 8px;cursor:pointer}}
 pre{{background:#0b1020;color:#dbeafe;padding:10px;border-radius:10px;overflow:auto}}
 pre code .ln{{color:#94a3b8;margin-right:8px}}
 .toc a{{text-decoration:none}}
</style>

<div class="topbar">
  <div class="controls">
    <b>Сводка:</b>
    <span class='chip'>HIGH: {totals.get("high",0)}</span>
    <span class='chip'>MEDIUM: {totals.get("medium",0)}</span>
    <span class='chip'>LOW: {totals.get("low",0)}</span>
    <span class='chip'>OK: {totals.get("ok",0)}</span>
    <input id="q" type="search" placeholder="Поиск по сообщениям/правилам/интерфейсам…">
    <label><input type="checkbox" class="filt" value="high" checked> HIGH</label>
    <label><input type="checkbox" class="filt" value="medium" checked> MEDIUM</label>
    <label><input type="checkbox" class="filt" value="low" checked> LOW</label>
    <label><input type="checkbox" class="filt" value="ok" checked> OK</label>
  </div>
</div>

<h1>Отчёт аудита Cisco GW</h1>

<div class="card toc">
  <b>Навигация по устройствам:</b>
  <div>""" )
    # TOC
    for r in dev_reports:
        host = escape(r.get("hostname") or r.get("file"))
        html.append(f"<a href='#{host}' class='chip'>{host}</a> ")
    html.append("</div></div>")

    # По устройствам
    for r in dev_reports:
        host = escape(r.get("hostname") or r.get("file"))
        html.append(f"<div class='card' id='{host}'><h3>{host}</h3>")

        # Матрица межзоновых разрешений
        iz = r.get("_interzone", [])
        if iz:
            html.append("<b>Матрица межзоновых разрешений</b>")
            html.append(_matrix_table(iz))

        # Группировка по severity
        groups = {"high":[], "medium":[], "low":[], "ok":[]}
        for f in r["findings"]: groups[f["sev"]].append(f)
        for sev in ("high","medium","low","ok"):
            if not groups[sev]: continue
            html.append(f"<details open><summary>{sev.upper()} {_badge(sev)} — {len(groups[sev])}</summary>")
            html.append("<table class='findings'><thead><tr><th>Где</th><th>Сообщение</th><th>Рекомендация</th></tr></thead><tbody>")
            for f in groups[sev]:
                where = escape(f.get("where",""))
                msg   = escape(f.get("msg",""))
                fix   = escape(f.get("fix","")) if f.get("fix") else "—"
                rule  = escape(f.get("rule","")) if f.get("rule") else ""
                snippet = _code_block(f.get("snippet"), f.get("snippet_start"))
                row_attr = f"data-sev='{sev}' data-text='{escape((where+' '+msg+' '+rule).lower())}'"
                rule_html = f"<br><small class=\"muted\">{rule}</small>" if rule else ""
                html.append(f"<tr class='sev-{sev}' {row_attr}><td>{where}</td><td>{msg}{rule_html}{snippet}</td><td>{fix}</td></tr>")
            html.append("</tbody></table></details>")
        html.append("</div>")

    # JS: фильтр/поиск/копирование
    html.append("""
<script>
function copyNextCode(btn){
  const pre = btn.parentElement.querySelector('pre');
  const text = pre.innerText.replace(/^\\s*\\d+/mg,'').replace(/^\\s{1}/mg,'');
  navigator.clipboard.writeText(text);
  btn.innerText='Copied'; setTimeout(()=>btn.innerText='Copy',1200);
}
const q = document.getElementById('q');
const chk = document.querySelectorAll('.filt');
function applyFilters(){
  const query = (q.value||'').toLowerCase();
  const on = new Set(Array.from(chk).filter(c=>c.checked).map(c=>c.value));
  document.querySelectorAll('tr[class^="sev-"]').forEach(tr=>{
    const sev = tr.className.replace('sev-','').trim();
    const txt = tr.getAttribute('data-text')||'';
    const okSev = on.has(sev);
    const okTxt = !query || txt.includes(query);
    tr.style.display = (okSev && okTxt) ? '' : 'none';
  });
}
q.addEventListener('input', applyFilters);
chk.forEach(c=>c.addEventListener('change', applyFilters));
</script>
""")
    Path(path).write_text("".join(html), encoding="utf-8")
    return path

def _load_zones_map(path: str | None) -> dict | None:
    """Читает JSON-файл с сопоставлением интерфейс->зона. Пример: {"Gig0/0":"INET","Vlan10":"LAN"}"""
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        print(f"[!] Файл с зонами не найден: {path}", file=sys.stderr)
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            print(f"[!] Ожидается JSON-объект с интерфейсами, получили {type(data)}", file=sys.stderr)
            return None
        return {str(k): str(v).upper() for k, v in data.items()}
    except Exception as exc:
        print(f"[!] Не удалось прочитать файл зон {path}: {exc}", file=sys.stderr)
        return None

# ====================== CLI ======================

def audit_folder(folder: str, zones_map: dict | None = None):
    out = []
    for f in Path(folder).glob("*.txt"):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            print(f"[!] Ошибка чтения {f.name}: {exc}", file=sys.stderr)
            dummy_cfg = {"raw": "", "raw_lines": []}
            err = _finding(
                "high", "file_read_error", f.name,
                f"Не удалось прочитать файл: {exc}", dummy_cfg,
                fix="Проверить права доступа и целостность файла."
            )
            out.append({
                "file": f.name, "hostname": None,
                "findings": [err], "_interzone": [], "_object_groups": {}
            })
            continue

        try:
            cfg = parse_config(text, zones_map=zones_map)
            findings, cfg = run_checks(cfg)
        except Exception as exc:
            print(f"[!] Ошибка обработки {f.name}: {exc}", file=sys.stderr)
            dummy_cfg = {"raw": text, "raw_lines": text.splitlines()}
            err = _finding(
                "high", "audit_error", f.name,
                f"Ошибка обработки конфигурации: {exc}", dummy_cfg,
                fix="Проверить формат конфига или обновить парсер."
            )
            out.append({
                "file": f.name, "hostname": None,
                "findings": [err], "_interzone": [], "_object_groups": {}
            })
            continue

        out.append({
            "file": f.name, "hostname": cfg.get("hostname"),
            "findings": findings, "_interzone": cfg.get("_interzone", []),
            "_object_groups": cfg.get("_object_groups_resolved", {})
        })
    return out

if __name__ == "__main__":
    import argparse, csv
    ap = argparse.ArgumentParser(description="Cisco GW Audit (HTML+, single-file)")
    ap.add_argument("--configs", required=True, help="Папка с .txt конфигами")
    ap.add_argument("--json", default="audit_report.json")
    ap.add_argument("--html", default="report.html")
    ap.add_argument("--zones", default=None, help="JSON с маппингом интерфейс->зона (перекрывает эвристику)")
    args = ap.parse_args()

    zones_map = _load_zones_map(args.zones)
    reports = audit_folder(args.configs, zones_map=zones_map)
    Path(args.json).write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
    save_html(reports, args.html)

    with open("findings.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["hostname","severity","type","where","message","fix","lineno"])
        for r in reports:
            for fnd in r["findings"]:
                w.writerow([r["hostname"], fnd["sev"], fnd.get("type",""), fnd.get("where",""), fnd.get("msg",""), fnd.get("fix",""), fnd.get("lineno","")])
    print(f"✅ Готово: {args.html}, {args.json}, findings.csv")
