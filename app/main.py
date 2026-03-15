from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.db.session import init_db
from app.api.router import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup."""
    await init_db()
    yield


app = FastAPI(
    title="Bug Bounty Recon Platform",
    description="Elite automated recon platform for bug bounty hunters.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router, prefix="/api/v1")


@app.get("/")
async def health():
    return {"status": "ok", "version": "1.0.0"}
