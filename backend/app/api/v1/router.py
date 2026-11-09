from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    health,
    scans,
    scan,
    tls,
    intel,
    authorized_scan,
    community,
    watchlist,
    admin,
)

api_v1_router = APIRouter(prefix="/v1")

api_v1_router.include_router(health.router, tags=["System Health & Diagnostics"])
api_v1_router.include_router(scans.router, tags=["Asynchronous Scan Jobs & Reports"])
api_v1_router.include_router(scan.router, tags=["URL & Phishing Analysis"])
api_v1_router.include_router(tls.router, tags=["TLS & Cryptographic Audits"])
api_v1_router.include_router(intel.router, tags=["Collaborative Threat Intelligence"])
api_v1_router.include_router(community.router, tags=["Community Phishing Reports"])
api_v1_router.include_router(watchlist.router, tags=["Target Domain Watchlist & Continuous Monitoring"])
api_v1_router.include_router(admin.router, tags=["Administrative Moderation & Audit Logs"])
api_v1_router.include_router(authorized_scan.router, tags=["Authorized Domain Security Testing (OWASP ZAP)"])


