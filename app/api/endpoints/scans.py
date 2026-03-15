from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from app.db.session import get_session
from app.models.models import Scan, Target, ScanStatus
from app.workers.tasks import run_scan_pipeline
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

router = APIRouter()


class ScanCreate(BaseModel):
    target_id: int
    modules: Optional[List[str]] = None  # e.g. ["subdomain", "crawler", "js", "secrets"]


@router.post("/", response_model=dict, status_code=202)
async def start_scan(data: ScanCreate, session: AsyncSession = Depends(get_session)):
    target = await session.get(Target, data.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    config = {"modules": data.modules or ["subdomain", "crawler", "js", "secrets"]}
    scan = Scan(target_id=data.target_id, config=config)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    # Dispatch to Celery
    run_scan_pipeline.delay(scan.id, target.domain, config)

    return {"scan_id": scan.uid, "status": "queued", "message": "Scan started successfully."}


@router.get("/{scan_uid}", response_model=dict)
async def get_scan_status(scan_uid: str, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Scan).where(Scan.uid == scan_uid))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.model_dump()
