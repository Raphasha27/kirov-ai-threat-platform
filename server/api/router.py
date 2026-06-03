from fastapi import APIRouter

from .auth_routes import router as auth_router
from .threat_routes import router as threat_router
from .alert_routes import router as alert_router
from .incident_routes import router as incident_router
from .logs_routes import router as logs_router
from .analytics_routes import router as analytics_router
from .dashboard_routes import router as dashboard_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(threat_router)
api_router.include_router(alert_router)
api_router.include_router(incident_router)
api_router.include_router(logs_router)
api_router.include_router(analytics_router)
api_router.include_router(dashboard_router)
