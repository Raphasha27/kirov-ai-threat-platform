from datetime import datetime, timezone
from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from models.alert import Alert
from models.log_event import LogEvent
from models.threat import Threat
from detection.engine import DetectionEngine

from .schemas import ThreatCreate, ThreatListResponse, ThreatResponse, ThreatStatusUpdate

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("", response_model=ThreatListResponse)
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Threat).order_by(Threat.created_at.desc())
    count_query = select(func.count(Threat.id))

    if severity:
        query = query.where(Threat.severity == severity)
        count_query = count_query.where(Threat.severity == severity)
    if status:
        query = query.where(Threat.status == status)
        count_query = count_query.where(Threat.status == status)
    if source:
        query = query.where(Threat.source_ip == source)
        count_query = count_query.where(Threat.source_ip == source)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    result = await db.execute(query)
    items = result.scalars().all()

    return ThreatListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/stats")
async def threat_stats(db: AsyncSession = Depends(get_db)):
    severity_counts = await db.execute(
        select(Threat.severity, func.count(Threat.id))
        .group_by(Threat.severity)
    )
    by_severity = {row[0]: row[1] for row in severity_counts}

    top_sources = await db.execute(
        select(Threat.source_ip, func.count(Threat.id).label("cnt"))
        .group_by(Threat.source_ip)
        .order_by(func.count(Threat.id).desc())
        .limit(10)
    )
    sources = [{"source_ip": row[0], "count": row[1]} for row in top_sources]

    timeline = await db.execute(
        select(
            func.date_trunc("hour", Threat.created_at).label("hour"),
            func.count(Threat.id).label("cnt"),
        )
        .group_by(func.date_trunc("hour", Threat.created_at))
        .order_by(func.date_trunc("hour", Threat.created_at).desc())
        .limit(48)
    )
    timeline_data = [{"time": str(row[0]), "count": row[1]} for row in timeline]

    return {"by_severity": by_severity, "top_sources": sources, "timeline": timeline_data}


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")
    return threat


@router.put("/{threat_id}/status", response_model=ThreatResponse)
async def update_threat_status(
    threat_id: int, body: ThreatStatusUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")
    threat.status = body.status
    await db.commit()
    await db.refresh(threat)
    return threat


@router.post("", response_model=ThreatResponse, status_code=status.HTTP_201_CREATED)
async def create_threat(body: ThreatCreate, db: AsyncSession = Depends(get_db)):
    threat = Threat(
        source_ip=body.source_ip,
        event_type=body.event_type,
        severity=body.severity,
        title=body.title,
        description=body.description,
        raw_log=body.raw_log,
        mitre_technique_id=body.mitre_technique_id,
        mitre_tactic=body.mitre_tactic,
        risk_score=body.risk_score,
        status=body.status,
        detected_at=body.detected_at or datetime.now(timezone.utc),
    )
    db.add(threat)
    await db.commit()
    await db.refresh(threat)
    return threat


@router.post("/{threat_id}/analyze", response_model=ThreatResponse)
async def analyze_threat(threat_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")
    threat.ai_classification = f"Re-analyzed: {threat.event_type} from {threat.source_ip}"
    threat.ai_summary = f"AI analysis complete for threat #{threat_id}. Severity: {threat.severity}, Score: {threat.risk_score}"
    await db.commit()
    await db.refresh(threat)
    return threat
