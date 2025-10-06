# reporter/html.py
from pathlib import Path
from html import escape
from collections import defaultdict

_PALETTE = {
    "high":  "#ef4444",  # red-500
    "medium":"#f59e0b",  # amber-500
    "low":   "#3b82f6",  # blue-500
    "ok":    "#10b981",  # emerald-500
}

def _badge(sev:str) -> str:
    return f'<span class="badge" style="background:{_PALETTE[sev]}">{sev.upper()}</span>'

def render(dev_reports):
    totals = defaultdict(int)
    for r in dev_reports:
        for f in r["findings"]:
            totals[f["sev"]] += 1

    html = []
    html.append("""<!doctype html><meta charset="utf-8">
<title>Cisco GW Audit</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:24px;line-height:1.45}
 h1{margin:0 0 12px}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;margin:16px 0}
 .card{border:1px solid #e5e7eb;border-radius:12px;padding:14px;background:#fff;box-shadow:0 1px 2px #0001}
 .badge{color:#fff;border-radius:999px;padding:2px 8px;font-size:12px;vertical-align:middle;margin-left:6px}
 .chip{display:inline-block;border:1px solid #e5e7eb;border-radius:999px;padding:4px 8px;margin:4px 4px 0 0;background:#f9fafb}
 details{margin:8px 0}
 summary{cursor:pointer;font-weight:600}
 table{width:100%;border-collapse:collapse;margin-top:8px}
 th,td{padding:6px 8px;border-bottom:1px solid #e5e7eb;font-size:14px;text-align:left;vertical-align:top}
 .sev-high{background:#fef2f2}
 .sev-medium{background:#fffbeb}
 .sev-low{background:#eff6ff}
 .sev-ok{background:#ecfdf5}
 .muted{color:#6b7280}
</style>
<h1>Отчёт аудита Cisco GW</h1>
""")

    # Сводка
    html.append("<div class='card'><b>Сводка по уровням:</b><div class='grid'>")
    for sev in ("high","medium","low","ok"):
        html.append(f"<div class='chip'>{sev.upper()}: {totals.get(sev,0)}</div>")
    html.append("</div></div>")

    # По устройствам
    for r in dev_reports:
        host = escape(r.get("hostname") or r.get("file"))
        html.append(f"<div class='card'><h3>{host}</h3>")
        # Группировка по severity
        groups = {"high":[], "medium":[], "low":[], "ok":[]}
        for f in r["findings"]:
            groups[f["sev"]].append(f)

        for sev in ("high","medium","low","ok"):
            if not groups[sev]: continue
            html.append(f"<details open><summary>{sev.upper()} {_badge(sev)} — {len(groups[sev])}</summary>")
            html.append("<table><thead><tr><th>Где</th><th>Сообщение</th><th>Правило</th></tr></thead><tbody>")
            for f in groups[sev]:
                where = escape(f.get("where",""))
                msg = escape(f.get("msg",""))
                rule = escape(f.get("rule",""))
                html.append(f"<tr class='sev-{sev}'><td>{where}</td><td>{msg}</td><td><code>{rule}</code></td></tr>")
            html.append("</tbody></table></details>")
        html.append("</div>")  # card

    return "".join(html)

def save_html(dev_reports, path="report.html"):
    html = render(dev_reports)
    Path(path).write_text(html, encoding="utf-8")
    return path
