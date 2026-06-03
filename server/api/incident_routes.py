from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from models.incident import Incident
from models.threat import Threat

from .schemas import IncidentCreate, IncidentResponse, IncidentUpdate, TimelineEvent

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Incident).order_by(Incident.created_at.desc())
    count_query = select(func.count(Incident.id))

    if severity:
        query = query.where(Incident.severity == severity)
        count_query = count_query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
        count_query = count_query.where(Incident.status == status)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    result = await db.execute(query.offset(offset).limit(page_size))
    items = result.scalars().all()
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(body: IncidentCreate, db: AsyncSession = Depends(get_db)):
    threats = await db.execute(select(Threat).where(Threat.id.in_(body.threat_ids)))
    existing = threats.scalars().all()
    if len(existing) != len(body.threat_ids):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or more threats not found")

    incident = Incident(
        title=body.title,
        description=body.description,
        severity=body.severity,
        status="open",
        threat_ids=body.threat_ids,
        assigned_to=body.assigned_to,
        timeline=[
            {
                "action": "created",
                "description": f"Incident created with {len(body.threat_ids)} threat(s)",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident


@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(incident_id: int, body: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if body.status is not None:
        incident.status = body.status
        if body.status == "resolved":
            incident.resolved_at = datetime.now(timezone.utc)
    if body.assigned_to is not None:
        incident.assigned_to = body.assigned_to
    incident.updated_at = datetime.now(timezone.utc)

    timeline_entry = {
        "action": "updated",
        "description": "Incident updated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if body.status:
        timeline_entry["description"] = f"Status changed to {body.status}"
    if body.assigned_to:
        timeline_entry["description"] += f", assigned to user #{body.assigned_to}"
    incident.timeline = list(incident.timeline) + [timeline_entry]

    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@router.post("/{incident_id}/timeline", response_model=IncidentResponse)
async def add_timeline_event(
    incident_id: int, body: TimelineEvent, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    entry = {
        "action": body.action,
        "description": body.description,
        "user_id": body.user_id,
        "metadata": body.metadata,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    timeline = list(incident.timeline) if incident.timeline else []
    timeline.append(entry)
    incident.timeline = timeline
    incident.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(incident)
    return incident
