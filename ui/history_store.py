import json
import os
import uuid
from datetime import datetime, timezone


_HISTORY_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "scan_history.json")


def load_scan_history():
    if not os.path.exists(_HISTORY_FILE):
        return []
    try:
        with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def append_scan_history(report, limit=40):
    history = load_scan_history()
    meta = report.get("scan_metadata", {})
    summary = report.get("summary", {})

    entry = {
        "history_id": f"hist-{uuid.uuid4().hex[:8]}",
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "cloud_scope": meta.get("cloud_scope", "unknown"),
        "scan_started_at": meta.get("scan_started_at", ""),
        "status": meta.get("status", "unknown"),
        "total_findings": summary.get("total_findings", 0),
        "severity_score_total": summary.get("severity_score_total", 0),
        "report": report,
    }

    history.insert(0, entry)
    history = history[:limit]

    os.makedirs(os.path.dirname(_HISTORY_FILE), exist_ok=True)
    with open(_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    return entry
