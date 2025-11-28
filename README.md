# Cisco ACL Audit

Быстрый аудит Cisco конфигов с HTML/JSON/CSV/NDJSON отчётами, веб-формой и опциональной загрузкой в PostgreSQL.

## Установка
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI (pipeline)
Аудит папки с конфигами, сохранение отчётов и загрузка в PostgreSQL:
```bash
python3 audit_pipeline.py \
  --configs ./configs \
  --out-dir ./out \
  --zones zones.json \           # опционально: интерфейс -> зона
  --pg-dsn "$PG_DSN" \           # опционально: DSN или env PG_DSN/DATABASE_URL
  --pg-table audit_findings      # имя таблицы (создаётся автоматически)
```
Результаты: `out/report.html`, `out/audit_report.json`, `out/findings.csv`, `out/findings.ndjson`.

## Веб-форма
Запуск простого веб-интерфейса для загрузки конфигов:
```bash
python3 audit_web.py --port 8000 --zones zones.json \
  --pg-dsn "$PG_DSN" --pg-table audit_findings   # опционально грузить в PG
# открыть http://localhost:8000
```
Web сохраняет отчёт в памяти для просмотра и, если задан DSN (или env PG_DSN/DATABASE_URL), загружает findings в PostgreSQL (таблица создаётся/трункетится).

## PostgreSQL (локально)
```bash
docker compose up -d postgres
export PG_DSN=postgresql://audit:audit@localhost:5432/audit
python3 audit_pipeline.py --configs ./configs --out-dir ./out --pg-dsn "$PG_DSN"
```
Таблица `audit_findings` создаётся автоматически, загрузка через COPY (по умолчанию truncate+replace).

## Структура данных
- `audit_report.json` — полный отчёт по устройствам.
- `findings.csv` / `findings.ndjson` — плоские записи: `hostname,file,severity,type,where,message,rule,fix,lineno`.
Удобно для SQL/BI: `SELECT * FROM audit_findings WHERE type='ssh_version_unspecified';`

## Зоны
Если нужны точные зоны, передайте JSON вида:
```json
{"Gig0/0":"INET","Vlan10":"LAN","Vlan99":"MGMT"}
```
Он перекроет эвристику по описанию интерфейсов.
