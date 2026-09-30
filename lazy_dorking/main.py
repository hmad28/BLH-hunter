from contextlib import asynccontextmanager
import mimetypes
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .db import init_db
from .blh.api import legacy_router as blh_legacy_router
from .blh.api import router as blh_router
from .bac.api import router as bac_router
from .cred.api import router as cred_router
from .v2.api import router as v2_router, pages_router as v2_pages_router

BASE_DIR = Path(__file__).resolve().parent.parent
INDEX_PATH = BASE_DIR / "index.html"
ASSETS_PATH = BASE_DIR / "lazy_dorking" / "img"
# Windows registry associations can incorrectly label .webp as text/plain.
mimetypes.add_type("image/webp", ".webp")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Lazy Dorking", lifespan=lifespan)

app.include_router(blh_legacy_router)
app.include_router(blh_router)
app.include_router(bac_router)
app.include_router(cred_router)
app.include_router(v2_router)
app.include_router(v2_pages_router)
app.mount("/assets", StaticFiles(directory=ASSETS_PATH), name="assets")


@app.get("/api/dashboard")
async def dashboard():
    return db.get_dashboard_stats()


@app.get("/api/dashboard/{feature_id}")
async def dashboard_feature(feature_id: str):
    detail = db.get_dashboard_feature_detail(feature_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Feature not found")
    return detail


@app.get("/api/dashboard/{feature_id}/domains/{domain:path}")
async def dashboard_domain(
    feature_id: str,
    domain: str,
    q: str = "",
    result_type: str = "",
    status: str = "",
    limit: int = 100,
    offset: int = 0,
    view: str = "targets",
):
    detail = db.get_dashboard_domain_detail(feature_id, domain, q, result_type, status, limit, offset, view)
    if not detail:
        raise HTTPException(status_code=404, detail="Domain not found")
    return detail


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(INDEX_PATH)


@app.get("/index.html", include_in_schema=False)
async def index_html():
    return FileResponse(INDEX_PATH)
