import os
from typing import List
from pydantic import Field

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

def _parse_cors_origins() -> List[str]:
    raw = os.getenv("CORS_ORIGINS", "")
    if raw.strip():
        return [o.strip() for o in raw.split(",") if o.strip()]
    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://ais-dev-dbcl3xbf4o5l6dz2z4oeln-435192749207.asia-east1.run.app",
        "*"
    ]

try:
    from pydantic_settings import BaseSettings

    class Settings(BaseSettings):
        APP_NAME: str = "TrustShield AI Backend"
        APP_VERSION: str = "1.0.0"
        ENVIRONMENT: str = Field(default="development", alias="ENVIRONMENT")
        DEBUG: bool = True
        
        # Server Binding
        HOST: str = Field(default="127.0.0.1", alias="FASTAPI_HOST")
        PORT: int = Field(default=8000, alias="FASTAPI_PORT")
        
        # CORS
        CORS_ORIGINS: List[str] = Field(default_factory=_parse_cors_origins)

        # Supabase Persistence & Auth
        SUPABASE_URL: str = Field(default="", alias="VITE_SUPABASE_URL")
        SUPABASE_ANON_KEY: str = Field(default="", alias="VITE_SUPABASE_ANON_KEY")
        SUPABASE_SERVICE_ROLE_KEY: str = Field(default="", alias="SUPABASE_SERVICE_ROLE_KEY")

        # Threat Intelligence Feeds (Configurable)
        VIRUSTOTAL_API_KEY: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
        GOOGLE_SAFE_BROWSING_API_KEY: str = Field(default="", alias="GOOGLE_SAFE_BROWSING_API_KEY")

        class Config:
            env_file = ".env"
            env_file_encoding = "utf-8"
            extra = "ignore"

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
        CORS_ORIGINS: List[str] = _parse_cors_origins()

        # Supabase Persistence & Auth
        SUPABASE_URL: str = os.getenv("VITE_SUPABASE_URL", "")
        SUPABASE_ANON_KEY: str = os.getenv("VITE_SUPABASE_ANON_KEY", "")
        SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

        # Threat Intelligence Feeds (Configurable)
        VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
        GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

settings = Settings()
