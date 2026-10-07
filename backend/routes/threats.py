"""
CRYPTOSENTINEL — Threat Routes
"""

from fastapi import APIRouter
from core.threat_logger import threat_logger
from core.config import THREAT_TYPES

router = APIRouter(prefix="/api/threats", tags=["threats"])

@router.get("/list")
def list_threats(limit: int = 100):
    return {"threats": threat_logger.get_recent(limit)}

@router.get("/stats")
def stats():
    return threat_logger.stats()

@router.get("/types")
def types():
    return {"types": THREAT_TYPES}

@router.delete("/clear")
def clear():
    threat_logger.clear()
    return {"status": "cleared"}