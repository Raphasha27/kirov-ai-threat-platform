from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from models.alert import Alert

from .schemas import AlertAcknowledge, AlertResponse, SilenceRule

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    acknowledged: bool | None = None,
    rule_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Alert).order_by(Alert.created_at.desc())
    count_query = select(func.count(Alert.id))

    if severity:
        query = query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)
    if acknowledged is not None:
        query = query.where(Alert.acknowledged == acknowledged)
        count_query = count_query.where(Alert.acknowledged == acknowledged)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)
        count_query = count_query.where(Alert.rule_id == rule_id)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    result = await db.execute(query.offset(offset).limit(page_size))
    items = result.scalars().all()
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/stats")
async def alert_stats(db: AsyncSession = Depends(get_db)):
    by_severity = await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )
    severity_data = {row[0]: row[1] for row in by_severity}

    by_rule = await db.execute(
        select(Alert.rule_id, func.count(Alert.id))
        .group_by(Alert.rule_id)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )
    rule_data = [{"rule_id": row[0], "count": row[1]} for row in by_rule]

    total = sum(severity_data.values()) if severity_data else 0
    unacked = await db.execute(
        select(func.count(Alert.id)).where(Alert.acknowledged == False)
    )

    return {
        "total_alerts": total,
        "unacknowledged": unacked.scalar() or 0,
        "by_severity": severity_data,
        "top_rules": rule_data,
    }


@router.put("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(alert_id: int, body: AlertAcknowledge, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.acknowledged = True
    alert.acknowledged_by = body.user_id
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)
    return alert


@router.post("/silence", status_code=status.HTTP_200_OK)
async def silence_alerts(body: SilenceRule, db: AsyncSession = Depends(get_db)):
    stmt = select(Alert)
    if body.rule_id:
        stmt = stmt.where(Alert.rule_id == body.rule_id)
    if body.source:
        stmt = stmt.where(Alert.message.ilike(f"%{body.source}%"))
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    now = datetime.now(timezone.utc)
    for alert in alerts:
        alert.acknowledged = True
        alert.acknowledged_at = now
    await db.commit()
    return {"silenced": len(alerts)}
