# parsers/cisco.py
import re
from typing import Dict

def parse_config(text: str) -> Dict:
    cfg = {
        "hostname": None,
        "interfaces": {},   # name -> {description, ip, acl_in, acl_out, nat_role}
        "acls": {},         # name/number -> [lines]
        "nat": [],          # [{dir, rule}]
        "object_groups": {},# name -> {type, members}
        "mgmt": {"vty": [], "snmp": [], "http": []},
        "raw": text
    }

    m = re.search(r"^hostname\s+(\S+)", text, re.M)
    if m: cfg["hostname"] = m.group(1)

    for m in re.finditer(r"^interface\s+(\S+)(.*?)(?=^interface\s+|\Z)", text, re.S | re.M):
        name, body = m.group(1), m.group(2)
        desc = re.search(r"^\s*description\s+(.+)$", body, re.M)
        ip = re.search(r"^\s*ip address\s+([\d\.]+)\s+([\d\.]+)", body, re.M)
        acl_in = re.search(r"ip access-group\s+(\S+)\s+in", body)
        acl_out = re.search(r"ip access-group\s+(\S+)\s+out", body)
        nat_in = bool(re.search(r"^\s*ip nat inside\b", body, re.M))
        nat_out = bool(re.search(r"^\s*ip nat outside\b", body, re.M))
        cfg["interfaces"][name] = {
            "description": (desc.group(1).strip() if desc else ""),
            "ip": (f"{ip.group(1)}/{ip.group(2)}" if ip else None),
            "acl_in": (acl_in.group(1) if acl_in else None),
            "acl_out": (acl_out.group(1) if acl_out else None),
            "nat_role": "inside" if nat_in else ("outside" if nat_out else None),
        }

    # Named ACLs
    for m in re.finditer(r"^ip access-list (extended|standard)\s+(\S+)(.*?)(?=^ip access-list|^interface|^\S|\Z)", text, re.S | re.M):
        name, body = m.group(2), m.group(3)
        lines = [ln.strip() for ln in body.strip().splitlines() if ln.strip()]
        cfg["acls"][name] = lines

    # Numbered ACLs
    for m in re.finditer(r"^access-list\s+(\d+)\s+(.*)$", text, re.M):
        num = m.group(1)
        cfg["acls"].setdefault(num, []).append(m.group(2).strip())

    # NAT
    for m in re.finditer(r"^ip nat (inside|outside)\s+source\s+(.*?)$", text, re.M):
        cfg["nat"].append({"dir": m.group(1), "rule": m.group(2)})

    # Object-groups
    for m in re.finditer(r"^object-group\s+(network|service)\s+(\S+)(.*?)(?=^object-group|^ip access-list|^interface|\Z)", text, re.S | re.M):
        og_type, og_name, body = m.group(1), m.group(2), m.group(3)
        members = []
        for n in re.finditer(r"^\s*(network-object|host|service-object)\s+(.+)$", body, re.M):
            members.append(n.group(2).strip())
        cfg["object_groups"][og_name] = {"type": og_type, "members": members}

    # Management
    vty = re.search(r"^line vty.*?(?=^line |\Z)", text, re.S | re.M)
    if vty: cfg["mgmt"]["vty"] = [ln.rstrip() for ln in vty.group(0).splitlines()]
    cfg["mgmt"]["snmp"] = re.findall(r"^snmp-server community\s+(\S+)", text, re.M)
    cfg["mgmt"]["http"] = re.findall(r"^ip http (server|secure-server)", text, re.M)

    return cfg
