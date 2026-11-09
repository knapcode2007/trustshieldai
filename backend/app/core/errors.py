from datetime import datetime, timezone
from typing import Any, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None

class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorDetail
    timestamp: str

class AppError(Exception):
    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Any] = None
    ):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details
        super().__init__(self.message)

class ValidationError(AppError):
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details
        )

class ResourceNotFoundError(AppError):
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(
            message=message,
            code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            details=details
        )

class UpstreamServiceError(AppError):
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(
            message=message,
            code="UPSTREAM_SERVICE_ERROR",
            status_code=status.HTTP_502_BAD_GATEWAY,
            details=details
        )

def format_error_response(code: str, message: str, details: Optional[Any] = None) -> dict:
    return {
        "success": False,
        "error": {
            "code": code,
            "message": message,
            "details": details
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    payload = format_error_response(code=exc.code, message=exc.message, details=exc.details)
    return JSONResponse(status_code=exc.status_code, content=payload)

async def http_exception_handler(request: Request, exc: Any) -> JSONResponse:
    status_code = getattr(exc, "status_code", status.HTTP_500_INTERNAL_SERVER_ERROR)
    detail = getattr(exc, "detail", str(exc))
    if isinstance(detail, dict):
        code = detail.get("code", f"HTTP_{status_code}")
        message = detail.get("message", "An HTTP error occurred.")
        details = {k: v for k, v in detail.items() if k not in ("code", "message")} or None
    else:
        code = f"HTTP_{status_code}"
        message = str(detail) if detail else "An HTTP error occurred."
        details = None
    payload = format_error_response(code=code, message=message, details=details)
    return JSONResponse(status_code=status_code, content=payload)

async def validation_exception_handler(request: Request, exc: Any) -> JSONResponse:
    errors = exc.errors() if hasattr(exc, "errors") else str(exc)
    payload = format_error_response(
        code="VALIDATION_ERROR",
        message="Request payload failed schema validation.",
        details=errors
    )
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content=payload)

async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    payload = format_error_response(
        code="UNEXPECTED_SERVER_ERROR",
        message="An unexpected system fault occurred while processing the request.",
        details=str(exc) if not isinstance(exc, SystemExit) else "System halted"
    )
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=payload)
