"""Production v2 entrypoint, without the legacy in-process scan runner."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import mimetypes

from .api import get_store, pages_router, router
from .compat import router as classic_router


@asynccontextmanager
async def lifespan(app):
    store = get_store()
    yield
    store.engine.dispose()
    get_store.cache_clear()


app = FastAPI(title="BLH Hunter v2", lifespan=lifespan)
app.include_router(router)
app.include_router(pages_router)
app.include_router(classic_router)
mimetypes.add_type('image/webp', '.webp')
app.mount('/assets', StaticFiles(directory=Path(__file__).resolve().parents[1] / 'img'), name='assets')


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(Path(__file__).resolve().parents[2] / 'index.html')


app.add_api_route('/index.html', index, include_in_schema=False)
