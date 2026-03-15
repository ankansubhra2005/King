from fastapi import APIRouter
from app.api.endpoints import targets, scans, wordlists

router = APIRouter()
router.include_router(targets.router, prefix="/targets", tags=["Targets"])
router.include_router(scans.router, prefix="/scans", tags=["Scans"])
router.include_router(wordlists.router, prefix="/wordlists", tags=["Wordlists & Payloads"])
