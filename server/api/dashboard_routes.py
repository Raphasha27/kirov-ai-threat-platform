from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from models.alert import Alert
from models.incident import Incident
from models.threat import Threat

from .schemas import DashboardSummary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
async def dashboard_summary(db: AsyncSession = Depends(get_db)):
    total_threats = (await db.execute(select(func.count(Threat.id)))).scalar() or 0
    active_alerts = (
        await db.execute(select(func.count(Alert.id)).where(Alert.acknowledged == False))
    ).scalar() or 0
    open_incidents = (
        await db.execute(select(func.count(Incident.id)).where(Incident.status.in_(["open", "investigating"])))
    ).scalar() or 0

    avg_score = (await db.execute(select(func.avg(Threat.risk_score)))).scalar() or 0.0

    return DashboardSummary(
        total_threats=total_threats,
        active_alerts=active_alerts,
        open_incidents=open_incidents,
        risk_score=round(float(avg_score), 2),
    )


@router.get("/recent-activity")
async def recent_activity(db: AsyncSession = Depends(get_db)):
    threats = await db.execute(
        select(Threat).order_by(Threat.created_at.desc()).limit(20)
    )
    return {
        "events": [
            {
                "type": "threat",
                "id": t.id,
                "title": t.title,
                "severity": t.severity,
                "timestamp": t.created_at.isoformat(),
            }
            for t in threats.scalars().all()
        ]
    }


@router.get("/severity-distribution")
async def severity_distribution(db: AsyncSession = Depends(get_db)):
    rows = await db.execute(
        select(Threat.severity, func.count(Threat.id))
        .group_by(Threat.severity)
    )
    return {"distribution": {r[0]: r[1] for r in rows}}


@router.get("/threat-map")
async def threat_map(db: AsyncSession = Depends(get_db)):
    rows = await db.execute(
        select(
            Threat.source_ip,
            func.count(Threat.id).label("cnt"),
            Threat.severity,
        )
        .group_by(Threat.source_ip, Threat.severity)
        .order_by(func.count(Threat.id).desc())
        .limit(50)
    )
    return {
        "points": [
            {"source_ip": r[0], "count": r[1], "severity": r[2]}
            for r in rows
        ]
    }


@router.get("/status-timeline")
async def status_timeline(db: AsyncSession = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = await db.execute(
        select(
            func.date_trunc("hour", Threat.created_at).label("hour"),
            func.count(Threat.id),
        )
        .where(Threat.created_at >= since)
        .group_by(func.date_trunc("hour", Threat.created_at))
        .order_by(func.date_trunc("hour", Threat.created_at))
    )
    return {
        "timeline": [
            {"hour": str(r[0]), "count": r[1]} for r in rows
        ]
    }
