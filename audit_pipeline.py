#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Утилита: запускает аудит папки конфигов, сохраняет HTML/JSON/CSV/NDJSON,
опционально грузит findings в PostgreSQL.
"""

import argparse, csv, io, json, os, sys
from pathlib import Path

from audit_single import audit_folder, save_html, _flatten_findings, _load_zones_map


def _test_pg_connection(dsn: str) -> bool:
    try:
        import psycopg
    except Exception as exc:
        print(f"[!] psycopg не установлен, пропускаю загрузку в PG: {exc}", file=sys.stderr)
        return False
    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception as exc:
        print(f"[!] Не удалось подключиться к PostgreSQL: {exc}", file=sys.stderr)
        return False

def _load_to_postgres(dsn: str, table: str, rows: list[dict]) -> bool:
    try:
        import psycopg
    except Exception as exc:
        print(f"[!] psycopg не установлен, пропускаю загрузку в PG: {exc}", file=sys.stderr)
        return False

    print(f"[*] Пишу в PostgreSQL {len(rows)} записей в таблицу {table}")

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

    def _copy(cur, sql, buf_obj):
        try:
            with cur.copy(sql) as cp:
                cp.write(buf_obj.getvalue())
            return
        except Exception:
            pass
        cur.copy_expert(sql, buf_obj)

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(f"TRUNCATE {table}")  # простой вариант: полная замена
                copy_sql = f"COPY {table} (hostname,file,severity,type,\"where\",message,rule,fix,lineno) FROM STDIN WITH CSV HEADER"
                _copy(cur, copy_sql, buf)
            conn.commit()
        print("[*] Загрузка в PostgreSQL завершена")
        return True
    except Exception as exc:
        print(f"[!] Ошибка загрузки в PostgreSQL: {exc}", file=sys.stderr)
        return False


def main():
    ap = argparse.ArgumentParser(description="Cisco GW Audit pipeline: файловый вывод + опционально PostgreSQL")
    ap.add_argument("--configs", required=True, help="Папка с .txt конфигами")
    ap.add_argument("--out-dir", default="out", help="Куда писать отчёты")
    ap.add_argument("--zones", default=None, help="JSON с маппингом интерфейс->зона")
    ap.add_argument("--json", default="audit_report.json", help="Имя JSON файла отчёта")
    ap.add_argument("--html", default="report.html", help="Имя HTML отчёта")
    ap.add_argument("--findings-csv", default="findings.csv", help="Имя CSV с плоскими findings")
    ap.add_argument("--findings-ndjson", default="findings.ndjson", help="Имя NDJSON с плоскими findings")
    ap.add_argument("--pg-dsn", default=None, help="DSN PostgreSQL для загрузки (опционально, иначе возьмётся PG_DSN/DATABASE_URL)")
    ap.add_argument("--pg-table", default="audit_findings", help="Имя таблицы для загрузки в PG")
    args = ap.parse_args()

    zones_map = _load_zones_map(args.zones)

    reports = audit_folder(args.configs, zones_map=zones_map)

    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / args.json
    html_path = out_dir / args.html
    csv_path = out_dir / args.findings_csv
    ndjson_path = out_dir / args.findings_ndjson

    json_path.write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
    save_html(reports, html_path)

    flat = _flatten_findings(reports)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["hostname","file","severity","type","where","message","rule","fix","lineno"])
        for row in flat:
            w.writerow([row["hostname"], row["file"], row["severity"], row["type"], row["where"], row["message"], row["rule"], row["fix"], row["lineno"]])
    with open(ndjson_path, "w", encoding="utf-8") as f:
        for row in flat:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    pg_dsn = args.pg_dsn or os.getenv("PG_DSN") or os.getenv("DATABASE_URL")
    if pg_dsn:
        if _test_pg_connection(pg_dsn):
            ok = _load_to_postgres(pg_dsn, args.pg_table, flat)
            if ok:
                print(f"✅ Загрузка в PostgreSQL ({args.pg_table}) завершена")
            else:
                print("⚠️  Загрузка в PostgreSQL пропущена или завершилась ошибкой", file=sys.stderr)
        else:
            print("⚠️  Подключение к PostgreSQL недоступно, пропускаю загрузку.", file=sys.stderr)

    print(f"✅ Готово: {html_path}, {json_path}, {csv_path}, {ndjson_path}")


if __name__ == "__main__":
    main()
