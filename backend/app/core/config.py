import os
from typing import List
from pydantic import Field
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
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://ais-dev-dbcl3xbf4o5l6dz2z4oeln-435192749207.asia-east1.run.app",
        "*"
    ]

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

settings = Settings()
