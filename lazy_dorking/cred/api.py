import asyncio
import csv
import io
import json
import sqlite3
import uuid

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse

from ..shared import normalize_domain, utc_now_iso
from ..db import DB_PATH, update_scan_status, log_scan
from ..models import CredScanRequest
from .scanner import CRED_CATEGORIES, run_cred_scan

router = APIRouter(prefix="/api/cred", tags=["Cred"])

_running_scans: dict[str, asyncio.Event] = {}
_paused_scans: dict[str, asyncio.Event] = {}
_deleted_scans: set[str] = set()
_ACTIVE_STATUSES = {"pending", "running", "paused"}


@router.post("/scans")
async def create_scan(req: CredScanRequest, bg: BackgroundTasks):
    try:
        domain = normalize_domain(req.domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    categories = list(dict.fromkeys(req.categories))
    invalid = [c for c in categories if c not in CRED_CATEGORIES]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown category: {', '.join(invalid)}")
    if not categories:
        raise HTTPException(status_code=400, detail="Select at least one category")

    scan_id = str(uuid.uuid4())
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO cred_scans (id, domain, categories, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
        (scan_id, domain, json.dumps(categories), utc_now_iso()),
    )
    con.commit()
    con.close()
    _running_scans[scan_id] = asyncio.Event()
    _paused_scans[scan_id] = asyncio.Event()
    bg.add_task(run_cred_scan, scan_id, domain, categories,
                active_bruteforce=req.active_bruteforce,
                cancel_event=_running_scans[scan_id],
                pause_event=_paused_scans[scan_id],
                deleted_scans=_deleted_scans,
                running_scans=_running_scans,
                paused_scans=_paused_scans)
    return {"scan_id": scan_id}


@router.post("/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    event = _running_scans.get(scan_id)
    if event:
        pause_event = _paused_scans.get(scan_id)
        if pause_event:
            pause_event.clear()
        event.set()
        return {"status": "cancelling"}
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT status FROM cred_scans WHERE id=?", (scan_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row[0] in _ACTIVE_STATUSES:
        update_scan_status(scan_id, "cancelled", _deleted_scans, scans_table="cred_scans")
        return {"status": "cancelled"}
    return {"status": row[0]}


@router.post("/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT status FROM cred_scans WHERE id=?", (scan_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row[0] not in _ACTIVE_STATUSES:
        return {"status": row[0]}
    pause_event = _paused_scans.get(scan_id)
    if not pause_event or scan_id not in _running_scans:
        raise HTTPException(status_code=409, detail="Scan is not active")
    pause_event.set()
    update_scan_status(scan_id, "paused", _deleted_scans, scans_table="cred_scans")
    log_scan(scan_id, "Scan paused by user.", _deleted_scans, scans_table="cred_scans", log_table="cred_scan_log")
    return {"status": "paused"}


@router.post("/scans/{scan_id}/continue")
async def continue_scan(scan_id: str):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT status FROM cred_scans WHERE id=?", (scan_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row[0] not in _ACTIVE_STATUSES:
        return {"status": row[0]}
    pause_event = _paused_scans.get(scan_id)
    if not pause_event or scan_id not in _running_scans:
        raise HTTPException(status_code=409, detail="Scan is not active")
    pause_event.clear()
    update_scan_status(scan_id, "running", _deleted_scans, scans_table="cred_scans")
    log_scan(scan_id, "Scan continued by user.", _deleted_scans, scans_table="cred_scans", log_table="cred_scan_log")
    return {"status": "running"}


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    event = _running_scans.get(scan_id)
    if event:
        pause_event = _paused_scans.get(scan_id)
        if pause_event:
            pause_event.clear()
        event.set()
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT status FROM cred_scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        con.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    if event or row[0] in {"pending", "running"}:
        _deleted_scans.add(scan_id)
    con.execute("DELETE FROM cred_results WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM cred_scan_log WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM cred_crawl_pages WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM cred_scans WHERE id=?", (scan_id,))
    con.commit()
    con.close()
    return {"status": "deleted"}


@router.get("/scans")
async def list_scans():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT id, domain, categories, status, created_at, finished_at, total_sources, total_links "
        "FROM cred_scans ORDER BY created_at DESC LIMIT 30"
    ).fetchall()
    con.close()
    return [
        {
            "id": r[0],
            "domain": r[1],
            "categories": json.loads(r[2]),
            "status": r[3],
            "created_at": r[4],
            "finished_at": r[5],
            "total_sources": r[6],
            "total_links": r[7],
        }
        for r in rows
    ]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT id, domain, categories, status, created_at, finished_at, total_sources, total_links "
        "FROM cred_scans WHERE id=?",
        (scan_id,),
    ).fetchone()
    logs = con.execute(
        "SELECT message, created_at FROM cred_scan_log WHERE scan_id=? ORDER BY id ASC",
        (scan_id,),
    ).fetchall()
    con.close()
    if not row:
        return JSONResponse(status_code=404, content={"error": "not found"})
    return {
        "id": row[0],
        "domain": row[1],
        "categories": json.loads(row[2]),
        "status": row[3],
        "created_at": row[4],
        "finished_at": row[5],
        "total_sources": row[6],
        "total_links": row[7],
        "logs": [{"message": l[0], "created_at": l[1]} for l in logs],
    }


@router.get("/scans/{scan_id}/results")
async def get_results(scan_id: str, file_type: str = "", category: str = ""):
    con = sqlite3.connect(DB_PATH)
    query = (
        "SELECT file_type, pattern_matched, source_url, target_url, anchor_text, extracted_at "
        "FROM cred_results WHERE scan_id=?"
    )
    params = [scan_id]
    filter_value = file_type or category
    if filter_value:
        query += " AND file_type=?"
        params.append(filter_value)
    rows = con.execute(query, params).fetchall()
    con.close()
    return [
        {
            "file_type": r[0],
            "category": r[0],
            "pattern_matched": r[1],
            "source_url": r[2],
            "target_url": r[3],
            "anchor_text": r[4],
            "extracted_at": r[5],
        }
        for r in rows
    ]


@router.get("/scans/{scan_id}/export")
async def export_csv(scan_id: str):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT file_type, pattern_matched, source_url, target_url, anchor_text, extracted_at "
        "FROM cred_results WHERE scan_id=?",
        (scan_id,),
    ).fetchall()
    con.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["scan_id", "file_type", "pattern_matched", "source_url", "target_url", "anchor_text", "extracted_at"])
    for r in rows:
        writer.writerow([scan_id] + list(r))
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cred_{scan_id[:8]}.csv"},
    )
