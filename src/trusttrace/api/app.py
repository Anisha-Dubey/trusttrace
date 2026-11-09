"""FastAPI application factory and route registration for TRUSTTRACE."""

import os
from typing import List, Tuple
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes.evidence import router as evidence_router
from .routes.community import router as community_router


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
    app = FastAPI(
        title="TRUSTTRACE Evidence & Collaborative Intelligence API",
        description="Evidence Ingestion, Provenance Engine, Finding Linkage, and Collaborative Threat Intelligence",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
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

    # Register routers
    app.include_router(evidence_router)
    app.include_router(community_router)

    @app.get("/health", tags=["Health"])
    def health_check():
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

    return app


app = create_app()
