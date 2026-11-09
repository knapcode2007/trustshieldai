import uuid
import logging
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, status
from backend.app.core.errors import AppError, ValidationError, ResourceNotFoundError
from backend.app.models.schemas import (
    ScanCreateRequest,
    ScanJobStateResponse,
    ScanResponse,
    ScanHistoryResponse,
    GenericActionResponse,
)
from backend.app.core.scanner import scan_engine
from backend.app.security.ssrf import SSRFSecurityException

logger = logging.getLogger("trustshield.api.scans")
router = APIRouter()

@router.post("/scans", response_model=ScanJobStateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(req: ScanCreateRequest):
    """
    Submits a destination website URL for asynchronous forensic inspection.
    Validates against SSRF, canonicalizes the URL, handles deduplication, and queues the scan.
    """
    try:
        options_dict = req.options.model_dump() if req.options else {}
        job = scan_engine.create_or_get_job(
            raw_url=req.url,
            options=options_dict,
            force_fresh=req.force_fresh
        )
        return job.to_dict()
    except SSRFSecurityException as e:
        logger.warning(f"SSRF violation blocked: {e.message} (Code: {e.code})")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": e.code,
                "message": e.message,
                "field": "url"
            }
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "MALFORMED_URL",
                "message": str(e),
                "field": "url"
            }
        )

@router.get("/scans/{scan_id}", response_model=ScanJobStateResponse)
async def get_scan_status(scan_id: str):
    """
    Retrieves the current execution state, module-level statuses, and timestamps for a scan job.
    States: queued, running, completed, partial, failed.
    """
    job = scan_engine.get_job(scan_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Scan job '{scan_id}' does not exist or has expired.",
                "scan_id": scan_id
            }
        )
    return job.to_dict()

@router.get("/reports/{scan_id}", response_model=ScanResponse)
async def get_scan_report(scan_id: str):
    """
    Retrieves the full forensic report for a completed or partial scan.
    Returns 404 if not found, or 422 if the scan has not finished executing.
    """
    job = scan_engine.get_job(scan_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "REPORT_NOT_FOUND",
                "message": f"Security report '{scan_id}' not found.",
                "scan_id": scan_id
            }
        )

    if job.state in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "SCAN_IN_PROGRESS",
                "message": "Scan is still evaluating. Poll /api/v1/scans/{id} for progress.",
                "state": job.state,
                "progress_percent": job.progress_percent
            }
        )

    if job.state == "failed":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": job.error_code or "SCAN_FAILED",
                "message": job.error_message or "Scan failed during execution.",
                "state": job.state
            }
        )

    if not job.result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "REPORT_UNAVAILABLE", "message": "Result payload missing from completed job."}
        )

    return job.result

@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=100),
    verdict: Optional[str] = Query(default=None)
):
    """Returns completed forensic reports directly for scan history lists."""
    actual_verdict = verdict if isinstance(verdict, str) else None
    actual_limit = limit if isinstance(limit, int) else 50
    return scan_engine.list_scans(limit=actual_limit, verdict=actual_verdict)

@router.delete("/scans/{scan_id}", response_model=GenericActionResponse)
async def delete_scan(scan_id: str):
    """Deletes a single scan job and its associated forensic report."""
    scan_engine.delete_job(scan_id)
    return {"success": True, "message": "Scan removed from history"}

@router.delete("/scans", response_model=GenericActionResponse)
async def clear_scans():
    """Clears all scan jobs and history records."""
    scan_engine.clear_jobs()
    return {"success": True, "message": "Scan history cleared"}

@router.get("/history", response_model=ScanHistoryResponse)
async def get_scan_history(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    verdict: Optional[str] = Query(default=None)
):
    """Returns chronological list of scans with module statuses, states, and pagination."""
    actual_verdict = verdict if isinstance(verdict, str) else None
    actual_limit = limit if isinstance(limit, int) else 50
    actual_offset = offset if isinstance(offset, int) else 0
    items = scan_engine.list_history(limit=actual_limit, offset=actual_offset, verdict=actual_verdict)
    return {
        "items": items,
        "total": len(items),
        "limit": actual_limit,
        "offset": actual_offset
    }

# Backward compatibility direct endpoint
@router.post("/scan", response_model=ScanResponse)
async def scan_direct(req: ScanCreateRequest):
    """Direct scan endpoint awaiting completion (for backward compatibility)."""
    try:
        options_dict = req.options.model_dump() if req.options else {}
        job = scan_engine.create_or_get_job(
            raw_url=req.url,
            options=options_dict,
            force_fresh=req.force_fresh
        )
        # Wait up to 8 seconds for synchronous response if needed
        import time
        start_wait = time.time()
        while job.state in ("queued", "running") and (time.time() - start_wait) < 8.0:
            time.sleep(0.1)

        if job.result:
            return job.result
        if job.state == "failed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": job.error_code, "message": job.error_message}
            )
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail={"message": "Scan is processing asynchronously", "scan_id": job.scan_id}
        )
    except SSRFSecurityException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": e.code, "message": e.message, "field": "url"}
        )
