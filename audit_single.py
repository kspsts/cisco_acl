#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re, ipaddress, json
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

def parse_config(text: str) -> dict:
    raw_lines = text.splitlines()
    cfg = {
        "hostname": None,
        "interfaces": {},     # name -> {...}
        "acls": {},           # name/num -> [{"text":str,"lineno":int}]
        "acl_blocks": {},     # name -> {"start":int,"end":int}
        "nat": [],
        "object_groups": {},
        "mgmt": {"vty": [], "snmp": [], "http": []},
        "raw": text,
        "raw_lines": raw_lines,
    }

    m = re.search(r"^hostname\s+(\S+)", text, re.M)
    if m: cfg["hostname"] = m.group(1)

    # interface blocks with indices
    for m in re.finditer(r"(?m)^interface\s+(\S+)\s*"):
        name = m.group(1)
        start = m.start()
        # find next block start or EOF
        next_m = re.search(r"(?m)^interface\s+\S+", text[m.end():])
        end_pos = m.end()+next_m.start() if next_m else len(text)
        body = text[m.end():end_pos]

        desc = re.search(r"^\s*description\s+(.+)$", body, re.M)
        ipm  = re.search(r"^\s*ip address\s+([\d\.]+)\s+([\d\.]+)", body, re.M)
        acl_in  = re.search(r"ip access-group\s+(\S+)\s+in", body)
        acl_out = re.search(r"ip access-group\s+(\S+)\s+out", body)
        nat_in  = bool(re.search(r"^\s*ip nat inside\b", body, re.M))
        nat_out = bool(re.search(r"^\s*ip nat outside\b", body, re.M))
        nat_role = "inside" if nat_in else ("outside" if nat_out else None)
        ip = f"{ipm.group(1)}/{ipm.group(2)}" if ipm else None
        network = _calc_network(ip) if ip else None
        zone = _infer_zone(desc.group(1).strip() if desc else "", name, nat_role)

        cfg["interfaces"][name] = {
            "description": (desc.group(1).strip() if desc else ""),
            "ip": ip,
            "network": str(network) if network else None,
            "acl_in": (acl_in.group(1) if acl_in else None),
            "acl_out": (acl_out.group(1) if acl_out else None),
            "nat_role": nat_role,
            "zone": zone,
        }

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
            ln = ln.rstrip()
            if not ln.strip(): continue
            cfg["acls"].setdefault(name, []).append({"text": ln.strip(), "lineno": start_line + i})

    # numbered ACLs (single lines)
    for m in re.finditer(r"^access-list\s+(\d+)\s+(.*)$", text, re.M):
        num = m.group(1)
        lineno = text.count("\n", 0, m.start()) + 1
        cfg["acls"].setdefault(num, []).append({"text": m.group(2).strip(), "lineno": lineno})

    # NAT rules
    for m in re.finditer(r"^ip nat (inside|outside)\s+source\s+(.*?)$", text, re.M):
        lineno = text.count("\n", 0, m.start()) + 1
        cfg["nat"].append({"dir": m.group(1), "rule": m.group(2), "lineno": lineno})

    # object-groups (kept simple)
    for m in re.finditer(r"^object-group\s+(network|service)\s+(\S+)(.*?)(?=^object-group|^ip access-list|^interface|\Z)", text, re.S | re.M):
        og_type, og_name, body = m.group(1), m.group(2), m.group(3)
        members = []
        for n in re.finditer(r"^\s*(network-object|host|service-object)\s+(.+)$", body, re.M):
            members.append(n.group(2).strip())
        cfg["object_groups"][og_name] = {"type": og_type, "members": members}

    # mgmt
    vty = re.search(r"^line vty.*?(?=^line |\Z)", text, re.S | re.M)
    if vty:
        vty_block = vty.group(0)
        first_line = text.count("\n", 0, vty.start()) + 1
        cfg["mgmt"]["vty"] = [{"text": ln.rstrip(), "lineno": first_line + i}
                              for i, ln in enumerate(vty_block.splitlines())]
    cfg["mgmt"]["snmp"] = [{"text": m.group(0), "lineno": text.count('\n', 0, m.start()) + 1,
                             "community": m.group(1)}
                           for m in re.finditer(r"^snmp-server community\s+(\S+).*?$", text, re.M)]
    cfg["mgmt"]["http"] = [{"text": m.group(0), "lineno": text.count('\n', 0, m.start()) + 1,
                             "kind": m.group(1)}
                           for m in re.finditer(r"^ip http (server|secure-server).*?$", text, re.M)]
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

def _ip_tokens(s):
    for m in _IP_RE.finditer(s):
        tok = m.group(0)
        yield (ipaddress.IPv4Network(tok, strict=False) if "/" in tok else ipaddress.IPv4Address(tok))

def _map_ip_to_zone(ipobj, nets):
    zones = []
    for _, zone, net in nets:
        try:
            if (isinstance(ipobj, ipaddress.IPv4Address) and ipobj in net) or \
               (isinstance(ipobj, ipaddress.IPv4Network) and ipobj.subnet_of(net)):
                zones.append(zone)
        except: pass
    return sorted(set(zones))

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
                findings.append(_finding("high","acl_any_any",f"ACL {acl}",
                    "Широкое разрешение (permit ip any any).",
                    cfg, lineno=no, rule=ln,
                    fix="Сузить источники/назначения, разрешать только нужные протоколы/сети; добавить явный deny/log."))
            if re.search(r"\bpermit\s+tcp\s+any\s+any\b", ln):
                findings.append(_finding("high","acl_tcp_any_any",f"ACL {acl}",
                    "Широкий TCP any→any.",
                    cfg, lineno=no, rule=ln,
                    fix="Уточнить src/dst и порты; рассмотреть stateful/policy-map в ZBF."))
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
        if idef.get("ip") and not idef.get("acl_in") and not idef.get("acl_out"):
            findings.append(_finding("medium","iface_no_acl",f"interface {ifname}",
                "IP-интерфейс без ip access-group (нет фильтрации).",
                cfg, fix="Назначить ACL in/out либо использовать Zone-Based Firewall с policy-map."))
        else:
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

    # ---------- NAT ----------
    for nat in cfg.get("nat", []):
        rule, no = nat["rule"], nat["lineno"]
        if "overload" in rule:
            findings.append(_finding("low","nat_overload","ip nat",
                "NAT overload — стандартно.", cfg, lineno=no, rule=f"ip nat {nat['dir']} source {rule}",
                fix="Убедиться, что ACL для overload ограничивает приватные сети."))
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
            for ipobj in _ip_tokens(ln):
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
                html.append(f"<tr class='sev-{sev}' {row_attr}><td>{where}</td><td>{msg}{('<br><small class=\"muted\">'+rule+'</small>') if rule else ''}{snippet}</td><td>{fix}</td></tr>")
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

# ====================== CLI ======================

def audit_folder(folder: str):
    out = []
    for f in Path(folder).glob("*.txt"):
        text = f.read_text(encoding="utf-8", errors="ignore")
        findings, cfg = run_checks(parse_config(text))
        out.append({
            "file": f.name, "hostname": cfg.get("hostname"),
            "findings": findings, "_interzone": cfg.get("_interzone", [])
        })
    return out

if __name__ == "__main__":
    import argparse, csv
    ap = argparse.ArgumentParser(description="Cisco GW Audit (HTML+, single-file)")
    ap.add_argument("--configs", required=True, help="Папка с .txt конфигами")
    ap.add_argument("--json", default="audit_report.json")
    ap.add_argument("--html", default="report.html")
    args = ap.parse_args()

    reports = audit_folder(args.configs)
    Path(args.json).write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
    save_html(reports, args.html)

    with open("findings.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["hostname","severity","type","where","message","fix","lineno"])
        for r in reports:
            for fnd in r["findings"]:
                w.writerow([r["hostname"], fnd["sev"], fnd.get("type",""), fnd.get("where",""), fnd.get("msg",""), fnd.get("fix",""), fnd.get("lineno","")])
    print(f"✅ Готово: {args.html}, {args.json}, findings.csv")
