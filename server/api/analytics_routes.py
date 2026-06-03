from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from models.alert import Alert
from models.incident import Incident
from models.threat import Threat

from .schemas import MITRECoverage, ThreatTrend

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/threat-trends")
async def threat_trends(
    period: str = Query("daily", pattern="^(daily|weekly|monthly)$"),
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)

    if period == "daily":
        trunc = func.date_trunc("day", Threat.created_at)
    elif period == "weekly":
        trunc = func.date_trunc("week", Threat.created_at)
    else:
        trunc = func.date_trunc("month", Threat.created_at)

    rows = await db.execute(
        select(
            trunc.label("period"),
            func.count(Threat.id),
            func.sum(case((Threat.severity == "critical", 1), else_=0)),
            func.sum(case((Threat.severity == "high", 1), else_=0)),
            func.sum(case((Threat.severity == "medium", 1), else_=0)),
            func.sum(case((Threat.severity == "low", 1), else_=0)),
        )
        .where(Threat.created_at >= since)
        .group_by(trunc)
        .order_by(trunc)
    )

    trends = []
    for row in rows:
        trends.append(ThreatTrend(
            date=str(row[0]),
            count=row[1],
            critical=row[2] or 0,
            high=row[3] or 0,
            medium=row[4] or 0,
            low=row[5] or 0,
        ))
    return {"trends": trends, "period": period, "days": days}


@router.get("/top-attack-vectors")
async def top_attack_vectors(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    rows = await db.execute(
        select(Threat.event_type, func.count(Threat.id).label("cnt"))
        .group_by(Threat.event_type)
        .order_by(func.count(Threat.id).desc())
        .limit(limit)
    )
    return {"vectors": [{"event_type": r[0], "count": r[1]} for r in rows]}


@router.get("/mitre-coverage")
async def mitre_coverage(db: AsyncSession = Depends(get_db)):
    rows = await db.execute(
        select(
            Threat.mitre_tactic,
            Threat.mitre_technique_id,
            func.count(Threat.id).label("cnt"),
        )
        .where(Threat.mitre_technique_id.isnot(None))
        .group_by(Threat.mitre_tactic, Threat.mitre_technique_id)
        .order_by(func.count(Threat.id).desc())
    )
    coverage = [
        MITRECoverage(tactic=r[0] or "Unknown", technique_id=r[1], technique_name=r[1], count=r[2])
        for r in rows
    ]
    return {"coverage": coverage}


@router.get("/response-time")
async def response_time(db: AsyncSession = Depends(get_db)):
    rows = await db.execute(
        select(
            Incident.severity,
            func.avg(
                func.extract("epoch", Incident.resolved_at - Incident.created_at) / 3600
            ).label("avg_hours"),
            func.count(Incident.id).label("count"),
        )
        .where(Incident.resolved_at.isnot(None))
        .group_by(Incident.severity)
    )
    mttr = [{"severity": r[0], "avg_hours": round(float(r[1] or 0), 2), "count": r[2]} for r in rows]
    return {"mttr": mttr}
