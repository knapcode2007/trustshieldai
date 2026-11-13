import os
import json
from typing import Any, List, Union
from pydantic import Field, field_validator, ValidationInfo, AliasChoices

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

def parse_cors_origins_value(v: Any, environment: str = "development") -> List[str]:
    """
    Safely parses CORS origins from comma-separated strings, JSON arrays, or native Python lists.
    Strips trailing slashes and guarantees wildcard '*' is never permitted in production.
    """
    origins: List[str] = []
    
    if v is None:
        raw_list = []
    elif isinstance(v, str):
        v_trimmed = v.strip()
        if not v_trimmed:
            raw_list = []
        elif v_trimmed.startswith("[") and v_trimmed.endswith("]"):
            try:
                parsed = json.loads(v_trimmed)
                if isinstance(parsed, list):
                    raw_list = [str(item).strip() for item in parsed if item is not None and str(item).strip()]
                else:
                    raw_list = [v_trimmed]
            except Exception:
                # If json decoding fails, fall back to comma-separated split
                raw_list = [item.strip() for item in v_trimmed.strip("[]").split(",") if item.strip()]
        else:
            raw_list = [item.strip() for item in v_trimmed.split(",") if item.strip()]
    elif isinstance(v, (list, tuple, set)):
        raw_list = [str(item).strip() for item in v if item is not None and str(item).strip()]
    else:
        raw_list = [str(v).strip()]

    # Normalize origins (strip trailing slashes, remove duplicates while preserving order)
    for origin in raw_list:
        if not origin:
            continue
        cleaned = origin.rstrip("/") if (origin != "*" and origin != "/") else origin
        if cleaned and cleaned not in origins:
            origins.append(cleaned)

    # In production, strictly remove and reject wildcard "*"
    if (environment or "development").lower() == "production":
        origins = [o for o in origins if o != "*"]

    return origins

def get_default_cors_origins(environment: str = "development") -> List[str]:
    """Provides safe defaults based on deployment environment."""
    raw_env = (environment or "development").lower()
    if raw_env == "production":
        return ["https://trustshield.vercel.app"]
    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://ais-dev-dbcl3xbf4o5l6dz2z4oeln-435192749207.asia-east1.run.app",
        "*"
    ]

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class Settings(BaseSettings):
        APP_NAME: str = "TrustShield AI Backend"
        APP_VERSION: str = "1.0.0"
        ENVIRONMENT: str = Field(default="development", alias="ENVIRONMENT")
        DEBUG: bool = True
        
        # Server Binding
        HOST: str = Field(default="127.0.0.1", alias="FASTAPI_HOST")
        PORT: int = Field(default=8000, alias="FASTAPI_PORT")
        
        # CORS: Annotated as Union[List[str], str] to prevent EnvSettingsSource from forcing JSON decoding
        CORS_ORIGINS: Union[List[str], str] = Field(
            default_factory=lambda: get_default_cors_origins(os.getenv("ENVIRONMENT", "development"))
        )

        # Supabase Persistence & Auth (supports Render backend & Vercel frontend naming conventions)
        SUPABASE_URL: str = Field(
            default="",
            validation_alias=AliasChoices("SUPABASE_URL", "VITE_SUPABASE_URL")
        )
        SUPABASE_ANON_KEY: str = Field(
            default="",
            validation_alias=AliasChoices("SUPABASE_ANON_KEY", "VITE_SUPABASE_ANON_KEY", "SUPABASE_PUBLISHABLE_KEY")
        )
        SUPABASE_SERVICE_ROLE_KEY: str = Field(
            default="",
            validation_alias=AliasChoices("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_KEY")
        )

        @property
        def is_supabase_configured(self) -> bool:
            """Determines if a valid Supabase host URL and key are provided."""
            url = (self.SUPABASE_URL or "").strip()
            key = (self.SUPABASE_SERVICE_ROLE_KEY or self.SUPABASE_ANON_KEY or "").strip()
            return bool(
                url and key
                and not url.startswith("https://your-project")
                and "placeholder" not in url
                and url.startswith("http")
            )

        @property
        def is_service_role_configured(self) -> bool:
            """Determines if an administrative service role key (or modern sb_secret_ key) is provided."""
            key = (self.SUPABASE_SERVICE_ROLE_KEY or "").strip()
            return bool(self.is_supabase_configured and key and "placeholder" not in key)

        # Threat Intelligence Feeds (Configurable)
        VIRUSTOTAL_API_KEY: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
        GOOGLE_SAFE_BROWSING_API_KEY: str = Field(default="", alias="GOOGLE_SAFE_BROWSING_API_KEY")
        URLHAUS_API_KEY: str = Field(default="", alias="URLHAUS_API_KEY")
        PHISHTANK_API_KEY: str = Field(default="", alias="PHISHTANK_API_KEY")

        # Experimental Hybrid Decision Shadow Mode (Phase 7C)
        HYBRID_SHADOW_ENABLED: bool = Field(default=False, alias="HYBRID_SHADOW_ENABLED")
        SHADOW_LOG_PATH: str = Field(default="logs/hybrid_shadow_eval.jsonl", alias="SHADOW_LOG_PATH")
        SHADOW_MAX_LOG_BYTES: int = Field(default=10 * 1024 * 1024, alias="SHADOW_MAX_LOG_BYTES")  # 10 MB
        SHADOW_BACKUP_COUNT: int = Field(default=3, alias="SHADOW_BACKUP_COUNT")
        SHADOW_RDAP_TIMEOUT: float = Field(default=1.5, alias="SHADOW_RDAP_TIMEOUT")
        SHADOW_MAX_WORKERS: int = Field(default=2, alias="SHADOW_MAX_WORKERS")
        SHADOW_QUEUE_MAXSIZE: int = Field(default=100, alias="SHADOW_QUEUE_MAXSIZE")
        RDAP_CACHE_BACKEND: str = Field(default="memory", alias="RDAP_CACHE_BACKEND")
        RDAP_SQLITE_PATH: str = Field(default="data/rdap_cache.db", alias="RDAP_SQLITE_PATH")
        RDAP_CACHE_TTL_SECONDS: int = Field(default=86400, alias="RDAP_CACHE_TTL_SECONDS")

        # Staging Protection & Rate Limiting (Phase 8B)
        STAGING_ACCESS_KEY: str = Field(default="", alias="STAGING_ACCESS_KEY")
        STAGING_RATE_LIMIT_PER_MINUTE: int = Field(default=60, alias="STAGING_RATE_LIMIT_PER_MINUTE")

        @field_validator("CORS_ORIGINS", mode="before")
        @classmethod
        def parse_cors_origins_before(cls, v: Any, info: ValidationInfo) -> List[str]:
            env = (info.data.get("ENVIRONMENT") if info.data else None) or os.getenv("ENVIRONMENT", "development")
            parsed = parse_cors_origins_value(v, environment=env)
            if not parsed and not v:
                return get_default_cors_origins(environment=env)
            return parsed

        @field_validator("CORS_ORIGINS", mode="after")
        @classmethod
        def enforce_no_wildcard_in_production(cls, v: List[str], info: ValidationInfo) -> List[str]:
            env = (info.data.get("ENVIRONMENT") if info.data else None) or os.getenv("ENVIRONMENT", "development")
            if (env or "development").lower() == "production":
                return [o for o in v if o != "*"]
            return v

        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore",
        )

except ImportError:
    from pydantic import BaseModel

    class Settings(BaseModel):
        APP_NAME: str = "TrustShield AI Backend"
        APP_VERSION: str = "1.0.0"
        ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
        DEBUG: bool = os.getenv("DEBUG", "true").lower() in ("true", "1", "yes")
        
        # Server Binding
        HOST: str = os.getenv("FASTAPI_HOST", "127.0.0.1")
        PORT: int = int(os.getenv("FASTAPI_PORT", "8000"))
        
        # CORS
        CORS_ORIGINS: List[str] = Field(
            default_factory=lambda: parse_cors_origins_value(
                os.getenv("CORS_ORIGINS") or get_default_cors_origins(os.getenv("ENVIRONMENT", "development")),
                environment=os.getenv("ENVIRONMENT", "development")
            )
        )

        # Supabase Persistence & Auth
        SUPABASE_URL: str = os.getenv("SUPABASE_URL") or os.getenv("VITE_SUPABASE_URL", "")
        SUPABASE_ANON_KEY: str = os.getenv("SUPABASE_ANON_KEY") or os.getenv("VITE_SUPABASE_ANON_KEY") or os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
        SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SECRET_KEY") or os.getenv("SUPABASE_SERVICE_KEY", "")

        @property
        def is_supabase_configured(self) -> bool:
            url = (self.SUPABASE_URL or "").strip()
            key = (self.SUPABASE_SERVICE_ROLE_KEY or self.SUPABASE_ANON_KEY or "").strip()
            return bool(
                url and key
                and not url.startswith("https://your-project")
                and "placeholder" not in url
                and url.startswith("http")
            )

        @property
        def is_service_role_configured(self) -> bool:
            key = (self.SUPABASE_SERVICE_ROLE_KEY or "").strip()
            return bool(self.is_supabase_configured and key and "placeholder" not in key)

        # Threat Intelligence Feeds (Configurable)
        VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
        GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
        URLHAUS_API_KEY: str = os.getenv("URLHAUS_API_KEY", "")
        PHISHTANK_API_KEY: str = os.getenv("PHISHTANK_API_KEY", "")

        # Experimental Hybrid Decision Shadow Mode (Phase 7C)
        HYBRID_SHADOW_ENABLED: bool = os.getenv("HYBRID_SHADOW_ENABLED", "false").lower() in ("true", "1", "yes")
        SHADOW_LOG_PATH: str = os.getenv("SHADOW_LOG_PATH", "logs/hybrid_shadow_eval.jsonl")
        SHADOW_MAX_LOG_BYTES: int = int(os.getenv("SHADOW_MAX_LOG_BYTES", str(10 * 1024 * 1024)))
        SHADOW_BACKUP_COUNT: int = int(os.getenv("SHADOW_BACKUP_COUNT", "3"))
        SHADOW_RDAP_TIMEOUT: float = float(os.getenv("SHADOW_RDAP_TIMEOUT", "1.5"))
        SHADOW_MAX_WORKERS: int = int(os.getenv("SHADOW_MAX_WORKERS", "2"))
        SHADOW_QUEUE_MAXSIZE: int = int(os.getenv("SHADOW_QUEUE_MAXSIZE", "100"))
        RDAP_CACHE_BACKEND: str = os.getenv("RDAP_CACHE_BACKEND", "memory")
        RDAP_SQLITE_PATH: str = os.getenv("RDAP_SQLITE_PATH", "data/rdap_cache.db")
        RDAP_CACHE_TTL_SECONDS: int = int(os.getenv("RDAP_CACHE_TTL_SECONDS", "86400"))
        STAGING_ACCESS_KEY: str = os.getenv("STAGING_ACCESS_KEY", "")
        STAGING_RATE_LIMIT_PER_MINUTE: int = int(os.getenv("STAGING_RATE_LIMIT_PER_MINUTE", "60"))

settings = Settings()
