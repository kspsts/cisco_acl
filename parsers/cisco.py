# parsers/cisco.py
import re
import ipaddress
from typing import Dict, Optional

_ZONE_KEYWORDS = {
    "INET":  ["inet","internet","wan","outside","uplink","provider"],
    "DMZ":   ["dmz","demilitarized","pub","edge-srv"],
    "LAN":   ["lan","inside","users","office"],
    "PARTNER":["partner","extnet","b2b"],
    "WIFI":  ["wifi","wlan","guest","hotspot"],
    "MGMT":  ["mgmt","oob","management","admin"],
}

def _infer_zone(desc: str, ifname: str, nat_role: Optional[str]) -> str:
    s = f"{desc} {ifname}".lower()
    for z, keys in _ZONE_KEYWORDS.items():
        if any(k in s for k in keys):
            return z
    if nat_role == "outside": return "INET"
    if nat_role == "inside":  return "LAN"
    return "LAN"  # безопасный дефолт

def _mask_to_prefix(mask: str) -> Optional[int]:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return None

def _calc_network(ip: str) -> Optional[ipaddress.IPv4Network]:
    if not ip or "/" not in ip: return None
    addr, mask = ip.split("/")
    prefix = _mask_to_prefix(mask)
    if prefix is None: return None
    try:
        return ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
    except Exception:
        return None

def parse_config(text: str) -> Dict:
    cfg = {
        "hostname": None,
        "interfaces": {},    # name -> {..., zone, network}
        "acls": {},          # name -> [lines]
        "nat": [],
        "object_groups": {},
        "mgmt": {"vty": [], "snmp": [], "http": []},
        "raw": text
    }

    m = re.search(r"^hostname\s+(\S+)", text, re.M)
    if m: cfg["hostname"] = m.group(1)

    # interfaces
    for m in re.finditer(r"^interface\s+(\S+)(.*?)(?=^interface\s+|\Z)", text, re.S | re.M):
        name, body = m.group(1), m.group(2)
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

    # named ACLs
    for m in re.finditer(r"^ip access-list (extended|standard)\s+(\S+)(.*?)(?=^ip access-list|^interface|^\S|\Z)", text, re.S | re.M):
        name, body = m.group(2), m.group(3)
        lines = [ln.strip() for ln in body.strip().splitlines() if ln.strip()]
        cfg["acls"][name] = lines

    # numbered ACLs
    for m in re.finditer(r"^access-list\s+(\d+)\s+(.*)$", text, re.M):
        num = m.group(1)
        cfg["acls"].setdefault(num, []).append(m.group(2).strip())

    # NAT
    for m in re.finditer(r"^ip nat (inside|outside)\s+source\s+(.*?)$", text, re.M):
        cfg["nat"].append({"dir": m.group(1), "rule": m.group(2)})

    # object-groups
    for m in re.finditer(r"^object-group\s+(network|service)\s+(\S+)(.*?)(?=^object-group|^ip access-list|^interface|\Z)", text, re.S | re.M):
        og_type, og_name, body = m.group(1), m.group(2), m.group(3)
        members = []
        for n in re.finditer(r"^\s*(network-object|host|service-object)\s+(.+)$", body, re.M):
            members.append(n.group(2).strip())
        cfg["object_groups"][og_name] = {"type": og_type, "members": members}

    # mgmt
    vty = re.search(r"^line vty.*?(?=^line |\Z)", text, re.S | re.M)
    if vty: cfg["mgmt"]["vty"] = [ln.rstrip() for ln in vty.group(0).splitlines()]
    cfg["mgmt"]["snmp"] = re.findall(r"^snmp-server community\s+(\S+)", text, re.M)
    cfg["mgmt"]["http"] = re.findall(r"^ip http (server|secure-server)", text, re.M)

    return cfg