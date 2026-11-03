"""FastAPI application entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import PyMongoError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.auth import router as auth_router
from app.api.analyses import router as analyses_router
from app.api.alerts import router as alerts_router
from app.api.dashboard import router as dashboard_router
from app.api.health import router as health_router
from app.api.users import router as users_router
from app.config import get_settings
from app.database import close_client
from app.errors import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.users import apply_administrator_startup, ensure_user_indexes
from app.jobs import ensure_job_indexes
from app.alerts import ensure_alert_indexes
from app.ingestion.storage import cleanup_stale_uploads


@asynccontextmanager
async def lifespan(app: FastAPI):
    del app
    settings = get_settings()
    cleanup_stale_uploads(settings)
    try:
        ensure_user_indexes()
        ensure_job_indexes()
        ensure_alert_indexes()
        apply_administrator_startup(
            settings.admin_username,
            settings.admin_password,
            reset_password=settings.admin_password_reset,
        )
    except PyMongoError:
        pass
    yield
    close_client()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="AI-Powered Network Intrusion Detection API",
        version="1.0.0",
        description="College demonstration API for PCAP analysis and threat alerts.",
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.add_exception_handler(StarletteHTTPException, http_exception_handler)
    application.add_exception_handler(RequestValidationError, validation_exception_handler)
    application.add_exception_handler(Exception, unhandled_exception_handler)
    application.include_router(health_router, prefix=settings.api_prefix)
    application.include_router(auth_router, prefix=settings.api_prefix)
    application.include_router(users_router, prefix=settings.api_prefix)
    application.include_router(analyses_router, prefix=settings.api_prefix)
    application.include_router(alerts_router, prefix=settings.api_prefix)
    application.include_router(dashboard_router, prefix=settings.api_prefix)
    return application


app = create_app()
