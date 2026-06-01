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
from ..models import ResultStatusUpdate, ScanRequest
from .scanner import PLATFORM_DOMAINS, run_scan

router = APIRouter(prefix="/api/blh", tags=["BLH"])
legacy_router = APIRouter(prefix="/api", tags=["BLH Legacy"])

_running_scans: dict[str, asyncio.Event] = {}
_paused_scans: dict[str, asyncio.Event] = {}
_deleted_scans: set[str] = set()
_ACTIVE_STATUSES = {"pending", "running", "paused"}
_RESULT_STATUSES = {"pending", "broken", "alive", "redirect", "blocked", "timeout", "unknown"}


def _get_running_scans():
    return _running_scans


def _get_paused_scans():
    return _paused_scans


def _get_deleted_scans():
    return _deleted_scans


@router.post("/scans")
async def create_scan(req: ScanRequest, bg: BackgroundTasks):
    try:
        domain = normalize_domain(req.domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    platforms = list(dict.fromkeys(req.platforms))
    invalid = [p for p in platforms if p not in PLATFORM_DOMAINS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown platform: {', '.join(invalid)}")
    if not platforms:
        raise HTTPException(status_code=400, detail="Select at least one platform")

    scan_id = str(uuid.uuid4())
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO scans (id, domain, platforms, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
        (scan_id, domain, json.dumps(platforms), utc_now_iso()),
    )
    con.commit()
    con.close()
    _running_scans[scan_id] = asyncio.Event()
    _paused_scans[scan_id] = asyncio.Event()
    bg.add_task(run_scan, scan_id, domain, platforms,
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
    row = con.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row[0] in _ACTIVE_STATUSES:
        update_scan_status(scan_id, "cancelled", _deleted_scans)
        return {"status": "cancelled"}
    return {"status": row[0]}


@router.post("/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row[0] not in _ACTIVE_STATUSES:
        return {"status": row[0]}
    pause_event = _paused_scans.get(scan_id)
    if not pause_event or scan_id not in _running_scans:
        raise HTTPException(status_code=409, detail="Scan is not active")
    pause_event.set()
    update_scan_status(scan_id, "paused", _deleted_scans)
    log_scan(scan_id, "Scan paused by user.", _deleted_scans)
    return {"status": "paused"}


@router.post("/scans/{scan_id}/continue")
async def continue_scan(scan_id: str):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row[0] not in _ACTIVE_STATUSES:
        return {"status": row[0]}
    pause_event = _paused_scans.get(scan_id)
    if not pause_event or scan_id not in _running_scans:
        raise HTTPException(status_code=409, detail="Scan is not active")
    pause_event.clear()
    update_scan_status(scan_id, "running", _deleted_scans)
    log_scan(scan_id, "Scan continued by user.", _deleted_scans)
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
    row = con.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        con.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    if event or row[0] in {"pending", "running"}:
        _deleted_scans.add(scan_id)
    con.execute("DELETE FROM results WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM scan_log WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM crawl_pages WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    con.commit()
    con.close()
    return {"status": "deleted"}


@router.get("/scans")
async def list_scans():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT id, domain, platforms, status, created_at, finished_at, total_sources, total_links "
        "FROM scans ORDER BY created_at DESC LIMIT 30"
    ).fetchall()
    con.close()
    return [
        {
            "id": r[0],
            "domain": r[1],
            "platforms": json.loads(r[2]),
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
        "SELECT id, domain, platforms, status, created_at, finished_at, total_sources, total_links "
        "FROM scans WHERE id=?",
        (scan_id,),
    ).fetchone()
    logs = con.execute(
        "SELECT message, created_at FROM scan_log WHERE scan_id=? ORDER BY id ASC",
        (scan_id,),
    ).fetchall()
    con.close()
    if not row:
        return JSONResponse(status_code=404, content={"error": "not found"})
    return {
        "id": row[0],
        "domain": row[1],
        "platforms": json.loads(row[2]),
        "status": row[3],
        "created_at": row[4],
        "finished_at": row[5],
        "total_sources": row[6],
        "total_links": row[7],
        "logs": [{"message": l[0], "created_at": l[1]} for l in logs],
    }


@router.get("/scans/{scan_id}/results")
async def get_results(scan_id: str, status: str = "", platform: str = ""):
    con = sqlite3.connect(DB_PATH)
    query = (
        "SELECT id, platform, source_url, target_url, anchor_text, status, http_code, final_url, error_reason, checked_at "
        "FROM results WHERE scan_id=?"
    )
    params = [scan_id]
    if status:
        query += " AND status=?"
        params.append(status)
    if platform:
        query += " AND platform=?"
        params.append(platform)
    rows = con.execute(query, params).fetchall()
    con.close()
    return [
        {
            "id": r[0],
            "platform": r[1],
            "source_url": r[2],
            "target_url": r[3],
            "anchor_text": r[4],
            "status": r[5],
            "http_code": r[6],
            "final_url": r[7],
            "error_reason": r[8],
            "checked_at": r[9],
        }
        for r in rows
    ]


@router.patch("/results/{result_id}/status")
async def update_result_status(result_id: int, req: ResultStatusUpdate):
    status = (req.status or "").strip().lower()
    if status not in _RESULT_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("UPDATE results SET status=?, status_overridden=1 WHERE id=?", (status, result_id))
    if cur.rowcount == 0:
        con.close()
        raise HTTPException(status_code=404, detail="Result not found")
    row = con.execute("SELECT id, scan_id, status FROM results WHERE id=?", (result_id,)).fetchone()
    con.commit()
    con.close()
    return {"id": row[0], "scan_id": row[1], "status": row[2]}


@router.get("/scans/{scan_id}/export")
async def export_csv(scan_id: str):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT platform, source_url, target_url, anchor_text, status, http_code, final_url, error_reason, checked_at "
        "FROM results WHERE scan_id=?",
        (scan_id,),
    ).fetchall()
    con.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_id",
            "platform",
            "source_url",
            "target_url",
            "anchor_text",
            "status",
            "http_code",
            "final_url",
            "error_reason",
            "checked_at",
        ]
    )
    for r in rows:
        writer.writerow([scan_id] + list(r))
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=blh_{scan_id[:8]}.csv"},
    )


@legacy_router.post("/scans")
async def legacy_create_scan(req: ScanRequest, bg: BackgroundTasks):
    return await create_scan(req, bg)


@legacy_router.post("/scans/{scan_id}/stop")
async def legacy_stop_scan(scan_id: str):
    return await stop_scan(scan_id)


@legacy_router.post("/scans/{scan_id}/pause")
async def legacy_pause_scan(scan_id: str):
    return await pause_scan(scan_id)


@legacy_router.post("/scans/{scan_id}/continue")
async def legacy_continue_scan(scan_id: str):
    return await continue_scan(scan_id)


@legacy_router.delete("/scans/{scan_id}")
async def legacy_delete_scan(scan_id: str):
    return await delete_scan(scan_id)


@legacy_router.get("/scans")
async def legacy_list_scans():
    return await list_scans()


@legacy_router.get("/scans/{scan_id}")
async def legacy_get_scan(scan_id: str):
    return await get_scan(scan_id)


@legacy_router.get("/scans/{scan_id}/results")
async def legacy_get_results(scan_id: str, status: str = "", platform: str = ""):
    return await get_results(scan_id, status, platform)


@legacy_router.patch("/results/{result_id}/status")
async def legacy_update_result_status(result_id: int, req: ResultStatusUpdate):
    return await update_result_status(result_id, req)


@legacy_router.get("/scans/{scan_id}/export")
async def legacy_export_csv(scan_id: str):
    return await export_csv(scan_id)
