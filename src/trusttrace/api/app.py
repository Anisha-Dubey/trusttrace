"""FastAPI application factory and route registration for TRUSTTRACE."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes.evidence import router as evidence_router
from .routes.community import router as community_router


def create_app() -> FastAPI:
    """Construct and configure the TRUSTTRACE FastAPI application."""
    app = FastAPI(
        title="TRUSTTRACE Evidence & Collaborative Intelligence API",
        description="Evidence Ingestion, Provenance Engine, Finding Linkage, and Collaborative Threat Intelligence",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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
            },
        }

    return app


app = create_app()
