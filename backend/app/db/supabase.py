import logging
from typing import Optional, Dict, Any
from backend.app.core.config import settings

logger = logging.getLogger("trustshield.db")

class SupabaseManager:
    """Manages connection to Supabase PostgreSQL database."""
    def __init__(self):
        self._client = None
        self._configured = bool(settings.SUPABASE_URL and settings.SUPABASE_ANON_KEY and not settings.SUPABASE_URL.startswith("https://your-project"))

    def is_configured(self) -> bool:
        return self._configured

    def get_client(self):
        if not self._configured:
            return None
        if self._client is None:
            try:
                from supabase import create_client
                self._client = create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)
            except Exception as e:
                logger.warning(f"Failed to initialize Supabase client: {e}")
                self._client = None
        return self._client

    def check_health(self) -> Dict[str, Any]:
        if not self._configured:
            return {
                "status": "configured" if settings.SUPABASE_URL else "offline",
                "provider": "supabase",
                "details": "Awaiting valid Supabase credentials in environment" if not self._configured else "Ready"
            }
        try:
            client = self.get_client()
            if client:
                return {"status": "online", "provider": "supabase", "details": "Connected to Supabase cluster"}
            return {"status": "degraded", "provider": "supabase", "details": "Client initialization pending"}
        except Exception as e:
            return {"status": "degraded", "provider": "supabase", "details": str(e)}

db_manager = SupabaseManager()
