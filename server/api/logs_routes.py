from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from models.log_event import LogEvent
from detection.engine import DetectionEngine

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("")
async def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    source: str | None = None,
    log_type: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(LogEvent).order_by(LogEvent.received_at.desc())
    count_query = select(func.count(LogEvent.id))

    if source:
        query = query.where(LogEvent.source == source)
        count_query = count_query.where(LogEvent.source == source)
    if log_type:
        query = query.where(LogEvent.log_type == log_type)
        count_query = count_query.where(LogEvent.log_type == log_type)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    result = await db.execute(query.offset(offset).limit(page_size))
    items = result.scalars().all()
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("/ingest")
async def ingest_log(
    log_data: dict,
    db: AsyncSession = Depends(get_db),
):
    log_event = LogEvent(
        source=log_data.get("source", "unknown"),
        log_type=log_data.get("log_type", "generic"),
        raw_content=log_data.get("raw_content", ""),
        parsed_data=log_data.get("parsed_data", {}),
        tags=log_data.get("tags", []),
        received_at=func.now(),
    )
    db.add(log_event)
    await db.commit()
    await db.refresh(log_event)

    engine = DetectionEngine()
    threats = await engine.evaluate(log_event)

    return {"log_id": log_event.id, "threats_detected": len(threats), "threats": threats}
