from fastapi import APIRouter
from backend.app.core.errors import ValidationError
from backend.app.models.schemas import TlsInspectRequest, TlsInspectResponse
from backend.app.security.tls_inspector import tls_inspector

router = APIRouter()

@router.post("/tls/inspect", response_model=TlsInspectResponse)
async def inspect_tls_certificate(req: TlsInspectRequest):
    """Executes live TLS handshake probe and cryptographic parameter audit."""
    if not req.hostname or not req.hostname.strip():
        raise ValidationError("Hostname parameter is required", details={"field": "hostname"})
    
    clean_host = req.hostname.strip().replace("https://", "").replace("http://", "").split("/")[0]
    return tls_inspector.inspect_host(hostname=clean_host, port=req.port)
