"""Service and database health endpoints."""

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.database import check_database_connection
from app.errors import error_payload

router = APIRouter(tags=["health"])


@router.get("/health")
def get_health() -> dict:
    return {
        "status": "ok",
        "service": "intrusion-detection-api",
    }


@router.get("/health/database")
def get_database_health():
    result = check_database_connection()
    if result["status"] != "ok":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                **error_payload(
                    "database_unavailable",
                    "The database is currently unavailable.",
                ),
                **result,
            },
        )
    return result
