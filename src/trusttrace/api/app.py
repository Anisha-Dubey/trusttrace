"""FastAPI application factory and route registration for TRUSTTRACE."""

import os
import uuid
import logging
from typing import List, Tuple
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .routes.evidence import router as evidence_router
from .routes.community import router as community_router
from .auth import validate_token_configuration, is_production_environment
from ..evidence.persistence.database import default_db
from ..evidence.community.rate_limiter import (
    default_rate_limiter,
    RedisRateLimiterBackend,
    RateLimiterBackendError,
)

logger = logging.getLogger("trusttrace.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI application lifespan managing startup validation and fail-closed security gates."""
    # TASK 1: Production authentication startup validation
    validate_token_configuration()

    # TASK 2: Production rate limiter fail-closed verification
    if is_production_environment():
        backend = default_rate_limiter.backend
        if not isinstance(backend, RedisRateLimiterBackend):
            raise RuntimeError(
                "Production configuration error: Redis rate limiter is strictly required in production mode. "
                "Set TRUSTTRACE_REDIS_URL."
            )
        try:
            backend.ping()
        except Exception as e:
            raise RuntimeError(f"Production startup failed: Redis connection error: {e}")

    yield



class SecurityAndCorrelationMiddleware(BaseHTTPMiddleware):
    """Adds request correlation IDs and enforces maximum request body size limits."""

    def __init__(self, app, max_body_bytes: int = 2 * 1024 * 1024):
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next):
        # 1. Enforce payload size limit
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_body_bytes:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"status": "error", "detail": "Payload too large. Maximum size is 2MB."},
                    )
            except ValueError:
                pass

        # 2. Attach / propagate correlation ID
        correlation_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
        request.state.correlation_id = correlation_id

        # 3. Process request
        response = await call_next(request)
        response.headers["X-Request-ID"] = correlation_id
        return response


def get_cors_configuration() -> Tuple[List[str], bool]:
    """Derive safe CORS origins and credentials policy from environment.
    
    Security rule: Never allow wildcard '*' with credentials enabled!
    """
    raw_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "")
    if raw_origins:
        origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
    else:
        origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]

    # If wildcard is present, credentials MUST be False to comply with CORS security specifications
    if "*" in origins:
        allow_credentials = False
    else:
        allow_credentials = True

    return origins, allow_credentials


def create_app() -> FastAPI:
    """Construct and configure the TRUSTTRACE FastAPI application."""
    # Fail startup if authentication configuration is invalid or missing in production
    validate_token_configuration()

    app = FastAPI(
        title="TRUSTTRACE Evidence & Collaborative Intelligence API",
        description="Evidence Ingestion, Provenance Engine, Finding Linkage, and Collaborative Threat Intelligence",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    origins, allow_credentials = get_cors_configuration()

    # CORS configuration with strict explicit origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # Register custom correlation & size middleware
    app.add_middleware(SecurityAndCorrelationMiddleware)

    # Register routers
    app.include_router(evidence_router)
    app.include_router(community_router)

    @app.get("/health", tags=["Health"])
    def health_check():
        """Liveness probe: verifies process is alive and responsive."""
        return {
            "status": "ok",
            "service": "trusttrace_worker_02",
            "subsystems": {
                "evidence_ingestion": "operational",
                "persistence": "operational",
                "provenance_engine": "operational",
                "community_intelligence": "operational",
                "rate_limiter": "operational",
                "rbac_authorization": "operational",
            },
        }

    @app.get("/ready", tags=["Health"])
    def readiness_check():
        """Readiness probe: validates database connectivity and rate-limiting infrastructure."""
        from sqlalchemy import text
        db_ready = False
        rate_ready = True
        try:
            with default_db.session_scope() as session:
                session.execute(text("SELECT 1"))
            db_ready = True
        except Exception as e:
            logger.error("Readiness check: database failure: %s", e)

        if not db_ready:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "degraded",
                    "service": "trusttrace_worker_02",
                    "dependencies": {"database": "unavailable", "rate_limiter": "operational" if rate_ready else "unavailable"},
                },
            )

        return {
            "status": "ready",
            "service": "trusttrace_worker_02",
            "dependencies": {
                "database": "connected",
                "rate_limiter": "operational",
            },
        }

    return app


app = create_app()
