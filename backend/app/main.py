"""FastAPI application entrypoint."""

from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor, wait
from threading import Event, Thread
import logging
import time

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
from app.database import close_client, set_required_indexes_ready
from app.errors import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.middleware import UploadBodyLimitMiddleware
from app.users import apply_administrator_startup, ensure_user_indexes
from app.jobs import claim_next_recoverable_job, ensure_job_indexes
from app.ingestion.processor import process_claimed_analysis_job, wait_for_active_heartbeats
from app.alerts import ensure_alert_indexes, relay_next_pending_alert_intent
from app.ingestion.storage import cleanup_stale_uploads
from app.task_coordinator import AnalysisTaskCoordinator
from app.analysis_results import ensure_analysis_result_indexes, cleanup_orphaned_analysis_findings
from app.token_revocation import ensure_token_revocation_indexes, cleanup_expired_token_revocations

logger = logging.getLogger(__name__)
RECOVERY_WORKER_COUNT = 2
RECOVERY_IDLE_WAIT_SECONDS = 0.5
RECOVERY_ERROR_WAIT_SECONDS = 1.0


def initialize_database(settings) -> bool:
    """Initialize required indexes and mark processing ready only on success."""
    set_required_indexes_ready(False)
    if not settings.mongodb_uri or not settings.mongodb_database:
        logger.error("Application database initialization failed (MongoDB is not configured).")
        return False
    try:
        ensure_user_indexes()
        ensure_job_indexes()
        ensure_alert_indexes()
        ensure_analysis_result_indexes()
        ensure_token_revocation_indexes()
        apply_administrator_startup(
            settings.admin_username,
            settings.admin_password,
            reset_password=settings.admin_password_reset,
        )
    except PyMongoError as exc:
        logger.error("Application database initialization failed (%s).", type(exc).__name__)
        return False
    set_required_indexes_ready(True)
    return True


def _run_recovery_worker(stop_event: Event) -> None:
    finding_cursor = None
    while not stop_event.is_set():
        try:
            cleanup_expired_token_revocations()
            scanned, _deleted, next_cursor = cleanup_orphaned_analysis_findings(after_id=finding_cursor)
            finding_cursor = next_cursor if scanned else None
            if relay_next_pending_alert_intent():
                continue
            job = claim_next_recoverable_job()
        except PyMongoError as exc:
            logger.error("Analysis job recovery could not reach MongoDB (%s); retrying.", type(exc).__name__)
            stop_event.wait(RECOVERY_ERROR_WAIT_SECONDS)
            continue
        except Exception as exc:
            logger.error("Recovery dispatcher encountered an unexpected error (%s); retrying.", type(exc).__name__)
            stop_event.wait(RECOVERY_ERROR_WAIT_SECONDS)
            continue
        if job is not None:
            try:
                process_claimed_analysis_job(job, cancel_event=stop_event)
            except Exception:
                logger.exception("Analysis job recovery worker encountered an unexpected processing error.")
            continue
        stop_event.wait(RECOVERY_IDLE_WAIT_SECONDS)


def _finish_recovery_shutdown(worker_futures, recovery_executor) -> None:
    """Close MongoDB only after workers and their lease heartbeats have exited."""
    wait(worker_futures)
    wait_for_active_heartbeats()
    recovery_executor.shutdown(wait=True, cancel_futures=True)
    close_client()


def _shutdown_recovery_workers(stop_event: Event, worker_futures, recovery_executor, grace_seconds: float) -> bool:
    """Stop workers within the grace period, deferring DB close if needed."""
    stop_event.set()
    deadline = time.monotonic() + grace_seconds
    _, pending = wait(worker_futures, timeout=grace_seconds)
    heartbeats_stopped = wait_for_active_heartbeats(max(0.0, deadline - time.monotonic()))
    if pending or not heartbeats_stopped:
        logger.warning(
            "Recovery workers exceeded the %.3f second shutdown grace period; database close is deferred.",
            grace_seconds,
        )
        recovery_executor.shutdown(wait=False, cancel_futures=True)
        Thread(
            target=_finish_recovery_shutdown,
            args=(worker_futures, recovery_executor),
            name="analysis-recovery-shutdown",
            daemon=True,
        ).start()
        return False
    recovery_executor.shutdown(wait=True, cancel_futures=True)
    close_client()
    return True


def _finish_application_shutdown(coordinator, worker_futures, recovery_executor) -> None:
    """Defer database closure until all foreground and recovery work has exited."""
    wait(worker_futures)
    coordinator.wait_until_idle()
    wait_for_active_heartbeats()
    recovery_executor.shutdown(wait=True, cancel_futures=True)
    close_client()


def _shutdown_application_work(
    coordinator: AnalysisTaskCoordinator,
    recovery_stop: Event,
    worker_futures,
    recovery_executor,
    grace_seconds: float,
) -> bool:
    """Cancel tracked work and wait no longer than the configured grace period."""
    deadline = time.monotonic() + grace_seconds
    coordinator.request_shutdown()
    recovery_stop.set()

    _, pending_workers = wait(worker_futures, timeout=max(0.0, deadline - time.monotonic()))
    foreground_stopped = coordinator.wait_until_idle(max(0.0, deadline - time.monotonic()))
    heartbeats_stopped = wait_for_active_heartbeats(max(0.0, deadline - time.monotonic()))
    if pending_workers or not foreground_stopped or not heartbeats_stopped:
        logger.warning(
            "Application work exceeded the %.3f second shutdown grace period; database close is deferred.",
            grace_seconds,
        )
        recovery_executor.shutdown(wait=False, cancel_futures=True)
        Thread(
            target=_finish_application_shutdown,
            args=(coordinator, worker_futures, recovery_executor),
            name="analysis-application-shutdown",
            daemon=True,
        ).start()
        return False
    recovery_executor.shutdown(wait=True, cancel_futures=True)
    close_client()
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    coordinator = AnalysisTaskCoordinator()
    app.state.analysis_task_coordinator = coordinator
    settings = get_settings()
    db_ready = initialize_database(settings)

    recovery_stop = Event()
    recovery_executor = ThreadPoolExecutor(
        max_workers=RECOVERY_WORKER_COUNT,
        thread_name_prefix="analysis-recovery",
    )
    recovery_workers = []
    try:
        if db_ready:
            cleanup_stale_uploads(settings)
            recovery_workers = [
                recovery_executor.submit(_run_recovery_worker, recovery_stop)
                for _ in range(RECOVERY_WORKER_COUNT)
            ]
        yield
    finally:
        _shutdown_application_work(
            coordinator,
            recovery_stop,
            recovery_workers,
            recovery_executor,
            settings.shutdown_grace_seconds,
        )


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="AI-Powered Network Intrusion Detection API",
        version="1.0.0",
        description="College demonstration API for PCAP analysis and threat alerts.",
        lifespan=lifespan,
    )
    application.add_middleware(
        UploadBodyLimitMiddleware,
        path=f"{settings.api_prefix}/analyses",
        max_body_bytes=settings.max_upload_bytes + 65_536,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
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
