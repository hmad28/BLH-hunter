from functools import lru_cache
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select, update

from .models import ScanConfig
from .providers import capabilities
from .store import Store, findings

router = APIRouter(prefix="/api/v2", tags=["Recon v2"])
pages_router = APIRouter()


@lru_cache
def get_store():
    store = Store()
    store.init()
    return store


@pages_router.get("/v2", include_in_schema=False)
async def workspace():
    return FileResponse(Path(__file__).with_name("workspace.html"), media_type="text/html")


@router.get("/capabilities")
def get_capabilities():
    from ..blh.scanner import PLATFORM_DOMAINS
    from ..bac.scanner import BAC_SERVICES
    from ..cred.scanner import CRED_CATEGORIES
    return {"tools_on_api_host": capabilities(), "platforms": list(PLATFORM_DOMAINS),
            "services": list(BAC_SERVICES), "categories": list(CRED_CATEGORIES),
            "note": "CLI tools and Chromium must be installed on workers. API-host availability may differ."}


@router.post("/scans", status_code=201)
def create_scan(config: ScanConfig, store=Depends(get_store)):
    return {"scan_id": store.create(config)}


@router.get("/scans")
def list_scans(store=Depends(get_store)):
    return store.list()


@router.get("/scans/{sid}")
def get_scan(sid: str, store=Depends(get_store)):
    result = store.get(sid)
    if not result:
        raise HTTPException(404, "Scan not found")
    return result


@router.post("/scans/{sid}/{action}")
def control(sid: str, action: Literal["pause", "resume", "cancel"], store=Depends(get_store)):
    try:
        return {"state": store.control(sid, action)}
    except KeyError:
        raise HTTPException(404, "Scan not found")


@router.delete("/scans/{sid}")
def delete_scan(sid: str, store=Depends(get_store)):
    try:
        return {"state": store.control(sid, "delete")}
    except KeyError:
        raise HTTPException(404, "Scan not found")


@router.get("/scans/{sid}/findings")
def results(sid: str, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), store=Depends(get_store)):
    if not store.get(sid):
        raise HTTPException(404, "Scan not found")
    return store.results(sid, limit, offset)


@router.get("/scans/{sid}/urls")
def inventory(sid: str, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), store=Depends(get_store)):
    if not store.get(sid):
        raise HTTPException(404, "Scan not found")
    return store.inventory(sid, limit, offset)


@router.get("/scans/{sid}/assets")
def assets(sid: str, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), store=Depends(get_store)):
    if not store.get(sid):
        raise HTTPException(404, "Scan not found")
    return store.assets(sid, limit, offset)


class Review(BaseModel):
    state: Literal["unreviewed", "confirmed", "false_positive", "needs_review"]


@router.patch("/findings/{fid}/review")
def review(fid: str, body: Review, store=Depends(get_store)):
    with store.tx() as con:
        if not con.scalar(select(findings.c.id).where(findings.c.id == fid)):
            raise HTTPException(404, "Finding not found")
        con.execute(update(findings).where(findings.c.id == fid).values(review=body.state))
    return {"review": body.state}
