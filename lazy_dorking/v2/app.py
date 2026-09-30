"""Production v2 entrypoint, without the legacy in-process scan runner."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from .api import get_store, pages_router, router


@asynccontextmanager
async def lifespan(app):
    store = get_store()
    yield
    store.engine.dispose()
    get_store.cache_clear()


app = FastAPI(title="BLH Hunter v2", lifespan=lifespan)
app.include_router(router)
app.include_router(pages_router)


@app.get("/", include_in_schema=False)
def index():
    return RedirectResponse("/v2")
