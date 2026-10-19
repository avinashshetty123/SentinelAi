from fastapi import APIRouter

from app.api.v1 import dashboard, demo, events, incidents, scans, system, ws

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(system.router)
api_router.include_router(scans.router)
api_router.include_router(dashboard.router)
api_router.include_router(events.router)
api_router.include_router(incidents.router)
api_router.include_router(demo.router)
api_router.include_router(ws.router)
