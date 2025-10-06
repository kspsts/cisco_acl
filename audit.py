# audit.py
import json
from pathlib import Path
from parsers.cisco import parse_config
from checks.best_practices import run_checks
from reporter.html import save_html

def audit_folder(folder: str):
    out = []
    for f in Path(folder).glob("*.txt"):
        text = f.read_text(encoding="utf-8", errors="ignore")
        cfg = parse_config(text)
        findings = run_checks(cfg)
        out.append({"file": f.name, "hostname": cfg.get("hostname"), "findings": findings})
    return out

if __name__ == "__main__":
    import argparse, csv
    ap = argparse.ArgumentParser(description="Cisco GW Audit (HTML)")
    ap.add_argument("--configs", required=True, help="Папка с .txt конфигами")
    ap.add_argument("--json", default="audit_report.json", help="Путь для JSON")
    ap.add_argument("--html", default="report.html", help="Путь для HTML")
    args = ap.parse_args()

    reports = audit_folder(args.configs)
    Path(args.json).write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")

    save_html(reports, args.html)

    # Дополнительно — короткий CSV
    with open("findings.csv","w",newline="",encoding="utf-8") as f:
        import csv
        w=csv.writer(f); w.writerow(["hostname","severity","type","where","message"])
        for r in reports:
            for fnd in r["findings"]:
                w.writerow([r["hostname"], fnd["sev"], fnd.get("type",""), fnd.get("where",""), fnd.get("msg","")])

    print(f"✅ Готово: {args.html}, {args.json}, findings.csv")
