#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, cgi, io, json, html, os, sys, csv
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

from audit_single import (
    parse_config, run_checks, _load_zones_map,
    _badge, _matrix_table, _code_block, _flatten_findings
)

HTML_HEAD = """<!doctype html><meta charset="utf-8">
<title>Cisco GW Audit (web)</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:24px;line-height:1.45;background:#f8fafc}
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
 h3{margin:6px 0 10px}
 .topbar{position:sticky;top:0;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:10px 12px;z-index:9;box-shadow:0 1px 2px #0001}
 .controls{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
 .controls input[type=search]{padding:6px 10px;border:1px solid #e5e7eb;border-radius:8px;min-width:260px}
 .matrix th, .matrix td{text-align:center}
 .codewrap{position:relative}
 .codewrap .copy{position:absolute;right:8px;top:8px;border:1px solid #e5e7eb;background:#fff;border-radius:8px;padding:4px 8px;cursor:pointer}
 pre{background:#0b1020;color:#dbeafe;padding:10px;border-radius:10px;overflow:auto}
 pre code .ln{color:#94a3b8;margin-right:8px}
 .toc a{text-decoration:none}
 .upload{border:1px dashed #cbd5e1;padding:12px;border-radius:12px;background:#f8fafc}
</style>
"""

JS_FILTER = """
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
if (q) q.addEventListener('input', applyFilters);
chk.forEach(c=>c.addEventListener('change', applyFilters));
</script>
"""

def render_html(dev_reports):
    totals = {"high":0,"medium":0,"low":0,"ok":0}
    for r in dev_reports:
        for f in r.get("findings", []):
            totals[f["sev"]] = totals.get(f["sev"], 0) + 1

    parts = [HTML_HEAD]
    parts.append("""
<div class="topbar">
  <div class="controls">
    <b>Сводка:</b>
    <span class='chip'>HIGH: %d</span>
    <span class='chip'>MEDIUM: %d</span>
    <span class='chip'>LOW: %d</span>
    <span class='chip'>OK: %d</span>
    <input id="q" type="search" placeholder="Поиск по сообщениям/правилам/интерфейсам…">
    <label><input type="checkbox" class="filt" value="high" checked> HIGH</label>
    <label><input type="checkbox" class="filt" value="medium" checked> MEDIUM</label>
    <label><input type="checkbox" class="filt" value="low" checked> LOW</label>
    <label><input type="checkbox" class="filt" value="ok" checked> OK</label>
  </div>
</div>
""" % (totals.get("high",0), totals.get("medium",0), totals.get("low",0), totals.get("ok",0)))

    parts.append("""
<div class="card upload">
  <form method="post" enctype="multipart/form-data">
    <b>Загрузите конфиги (*.txt):</b><br>
    <input type="file" name="configs" multiple required>
    <button type="submit">Аудит</button>
  </form>
</div>
""")

    if not dev_reports:
        parts.append("<p class='muted'>Отчёт пока пуст. Загрузите конфиги.</p>")
    else:
        parts.append("<div class='card toc'><b>Навигация по устройствам:</b><div>")
        for r in dev_reports:
            host = (r.get("hostname") or r.get("file") or "unknown")
            parts.append(f"<a href='#{host}' class='chip'>{host}</a> ")
        parts.append("</div></div>")

        for r in dev_reports:
            host = (r.get("hostname") or r.get("file") or "unknown")
            parts.append(f"<div class='card' id='{host}'><h3>{host}</h3>")
            iz = r.get("_interzone", [])
            if iz:
                parts.append("<b>Матрица межзоновых разрешений</b>")
                parts.append(_matrix_table(iz))
            groups = {"high":[], "medium":[], "low":[], "ok":[]}
            for f in r["findings"]:
                groups[f["sev"]].append(f)
            for sev in ("high","medium","low","ok"):
                if not groups[sev]:
                    continue
                parts.append(f"<details open><summary>{sev.upper()} {_badge(sev)} — {len(groups[sev])}</summary>")
                parts.append("<table class='findings'><thead><tr><th>Где</th><th>Сообщение</th><th>Рекомендация</th></tr></thead><tbody>")
                for f in groups[sev]:
                    where = html.escape(f.get("where",""))
                    msg   = html.escape(f.get("msg",""))
                    fix   = html.escape(f.get("fix","")) if f.get("fix") else "—"
                    rule  = html.escape(f.get("rule","")) if f.get("rule") else ""
                    snippet = _code_block(f.get("snippet"), f.get("snippet_start"))
                    row_attr = f"data-sev='{sev}' data-text='{html.escape((where+' '+msg+' '+rule).lower())}'"
                    rule_html = f"<br><small class=\"muted\">{rule}</small>" if rule else ""
                    parts.append(f"<tr class='sev-{sev}' {row_attr}><td>{where}</td><td>{msg}{rule_html}{snippet}</td><td>{fix}</td></tr>")
                parts.append("</tbody></table></details>")
            parts.append("</div>")

    parts.append(JS_FILTER)
    return "".join(parts)


def handle_upload(fields, zones_map):
    reports = []
    raw_items = fields.getlist("configs")
    # FieldStorage может вернуть bytes при пустых полях — фильтруем только файлы
    items = [it for it in raw_items if hasattr(it, "file")]
    for item in items:
        filename = Path(getattr(item, "filename", "") or "config.txt").name
        data = item.file.read()
        text = data.decode("utf-8", errors="ignore")
        try:
            cfg = parse_config(text, zones_map=zones_map)
            findings, cfg = run_checks(cfg)
        except Exception as exc:
            dummy_cfg = {"raw": text, "raw_lines": text.splitlines()}
            err = {
                "sev":"high","type":"audit_error","where":filename,
                "msg":f"Ошибка обработки конфигурации: {exc}",
                "rule":None,"fix":"Проверить формат конфига или обновить парсер.",
                "lineno":None,"snippet":None,"snippet_start":None
            }
            findings = [err]
            cfg = dummy_cfg
        reports.append({
            "file": filename,
            "hostname": cfg.get("hostname"),
            "findings": findings,
            "_interzone": cfg.get("_interzone", []),
            "_object_groups": cfg.get("_object_groups_resolved", {})
        })
    return reports


def _load_to_postgres(dsn: str, table: str, rows: list[dict]) -> bool:
    try:
        import psycopg
    except Exception as exc:
        print(f"[!] psycopg не установлен, пропускаю загрузку в PG: {exc}", file=sys.stderr)
        return False

    create_sql = f"""
CREATE TABLE IF NOT EXISTS {table} (
  hostname text,
  file text,
  severity text,
  type text,
  "where" text,
  message text,
  rule text,
  fix text,
  lineno int
);
"""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["hostname","file","severity","type","where","message","rule","fix","lineno"])
    for r in rows:
        w.writerow([r.get("hostname"), r.get("file"), r.get("severity"), r.get("type"),
                    r.get("where"), r.get("message"), r.get("rule"), r.get("fix"), r.get("lineno")])
    buf.seek(0)

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(f"TRUNCATE {table}")
                cur.copy_expert(f"COPY {table} (hostname,file,severity,type,\"where\",message,rule,fix,lineno) FROM STDIN WITH CSV HEADER", buf)
            conn.commit()
        return True
    except Exception as exc:
        print(f"[!] Ошибка загрузки в PostgreSQL: {exc}", file=sys.stderr)
        return False


class UploadHandler(BaseHTTPRequestHandler):
    zones_map = None
    pg_dsn = None
    pg_table = "audit_findings"
    last_reports = []

    def _send_html(self, content):
        data = content.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        page = render_html(self.last_reports)
        self._send_html(page)

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers.get("Content-Type"),
            }
        )
        if "configs" not in form:
            self.send_error(HTTPStatus.BAD_REQUEST, "Нет файлов configs")
            return
        reports = handle_upload(form, self.zones_map)
        self.last_reports = reports
        if self.pg_dsn:
            flat = _flatten_findings(reports)
            _load_to_postgres(self.pg_dsn, self.pg_table, flat)
        page = render_html(reports)
        self._send_html(page)


def main():
    ap = argparse.ArgumentParser(description="Cisco GW Audit web UI")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--zones", default=None, help="JSON с маппингом интерфейс->зона")
    ap.add_argument("--pg-dsn", dest="pg_dsn", default=None, help="DSN PostgreSQL для загрузки (опционально, можно через env PG_DSN/DATABASE_URL)")
    ap.add_argument("--pg-dns", dest="pg_dsn", default=None, help="Опечаточный алиас для --pg-dsn")
    ap.add_argument("--pg-table", default="audit_findings", help="Имя таблицы для загрузки в PG")
    args = ap.parse_args()

    zones_map = _load_zones_map(args.zones)
    pg_dsn = args.pg_dsn or os.getenv("PG_DSN") or os.getenv("DATABASE_URL")

    handler = UploadHandler
    handler.zones_map = zones_map
    handler.pg_dsn = pg_dsn
    handler.pg_table = args.pg_table

    server = HTTPServer(("0.0.0.0", args.port), handler)
    print(f"[*] Откройте http://localhost:{args.port} и загрузите конфиги (.txt)")
    if pg_dsn:
        print(f"[*] Результаты будут грузиться в PostgreSQL ({args.pg_table})")
    server.serve_forever()


if __name__ == "__main__":
    main()
