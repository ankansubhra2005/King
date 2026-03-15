from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_session
from app.models.models import Target
from pydantic import BaseModel
from typing import List, Optional

router = APIRouter()


class TargetCreate(BaseModel):
    domain: str
    program_name: Optional[str] = None
    in_scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None


@router.get("/", response_model=List[dict])
async def list_targets(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Target))
    targets = result.scalars().all()
    return [t.model_dump() for t in targets]


@router.post("/", response_model=dict, status_code=201)
async def create_target(data: TargetCreate, session: AsyncSession = Depends(get_session)):
    target = Target(**data.model_dump())
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target.model_dump()


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: int, session: AsyncSession = Depends(get_session)):
    target = await session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await session.delete(target)
    await session.commit()
