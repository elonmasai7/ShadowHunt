import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .telemetry import RuntimeState


REPORT_DIR = Path("/data/reports")


def _simple_pdf_bytes(lines: list[str]) -> bytes:
    payload = "\\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 12 Tf 50 780 Td ({payload}) Tj ET"
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n",
        f"4 0 obj << /Length {len(stream)} >> stream\n{stream}\nendstream endobj\n",
        "5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
    ]
    header = "%PDF-1.4\n"
    offsets = []
    body = ""
    cursor = len(header.encode("utf-8"))
    for obj in objects:
        offsets.append(cursor)
        body += obj
        cursor += len(obj.encode("utf-8"))
    xref_offset = cursor
    xref = "xref\n0 6\n0000000000 65535 f \n" + "".join(f"{off:010d} 00000 n \n" for off in offsets)
    trailer = "trailer << /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref_offset) + "\n%%EOF\n"
    return (header + body + xref + trailer).encode("utf-8")


def generate_report(state: RuntimeState) -> dict[str, Any]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    snap = state.snapshot()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = REPORT_DIR / f"shadowhunt_report_{ts}.json"
    pdf_path = REPORT_DIR / f"shadowhunt_report_{ts}.pdf"

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": snap["mode"],
        "running": snap["running"],
        "totals": {
            "attack_count": snap["attack_count"],
            "alert_count": snap["alert_count"],
            "false_positives": snap["false_positives"],
            "evasion_attempts": snap["evasion_attempts"],
            "evasion_success": snap["evasion_success"],
        },
        "mitre_coverage": snap["mitre_coverage"],
        "ml_confidence_recent": snap["ml_confidence"][-20:],
        "alerts_recent": snap["alerts"][-30:],
    }
    report_bytes = json.dumps(report, indent=2).encode("utf-8")
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    report["verification"] = {
        "sha256": report_hash,
        "ledger_sim": f"block://shadowhunt/{report_hash[:24]}",
    }
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    pdf_lines = [
        "ShadowHunt Threat Simulation Report",
        f"Generated: {report['generated_at']}",
        f"Mode: {report['mode']}",
        f"Attacks: {report['totals']['attack_count']}",
        f"Alerts: {report['totals']['alert_count']}",
        f"FP: {report['totals']['false_positives']}",
        f"Evasion Success: {report['totals']['evasion_success']}/{report['totals']['evasion_attempts']}",
        f"Hash: {report_hash}",
    ]
    pdf_path.write_bytes(_simple_pdf_bytes(pdf_lines))
    return {"ok": True, "json_report": str(json_path), "pdf_report": str(pdf_path), "sha256": report_hash}
