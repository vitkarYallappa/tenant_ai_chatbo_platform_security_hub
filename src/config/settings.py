"""
Central configuration management for Security Hub service.
Handles environment variables, validation, and configuration sections.
"""

import os
from typing import Optional, List, Dict, Any
from pydantic import Field, validator, PostgresDsn
from pydantic_settings import BaseSettings
from pydantic.networks import AnyHttpUrl


class DatabaseSettings(BaseSettings):
    """Database configuration settings for PostgreSQL and Redis."""

    # PostgreSQL Configuration
    postgres_host: str = Field(default="localhost", env="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, env="POSTGRES_PORT")
    postgres_db: str = Field(default="security_hub", env="POSTGRES_DB")
    postgres_user: str = Field(default="postgres", env="POSTGRES_USER")
    postgres_password: str = Field(default="", env="POSTGRES_PASSWORD")
    postgres_pool_size: int = Field(default=20, env="POSTGRES_POOL_SIZE")
    postgres_max_overflow: int = Field(default=30, env="POSTGRES_MAX_OVERFLOW")
    postgres_pool_timeout: int = Field(default=30, env="POSTGRES_POOL_TIMEOUT")
    postgres_pool_recycle: int = Field(default=3600, env="POSTGRES_POOL_RECYCLE")

    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    redis_pool_size: int = Field(default=10, env="REDIS_POOL_SIZE")
    redis_timeout: int = Field(default=5, env="REDIS_TIMEOUT")

    @property
    def postgres_dsn(self) -> str:
        """Build PostgreSQL connection string."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def postgres_dsn_sync(self) -> str:
        """Build synchronous PostgreSQL connection string for migrations."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    class Config:
        env_prefix = ""
        case_sensitive = False


class SecuritySettings(BaseSettings):
    """Security-related configuration settings."""

    # JWT Configuration
    jwt_secret_key: str = Field(env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_access_token_expire_minutes: int = Field(default=30, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    jwt_refresh_token_expire_days: int = Field(default=7, env="JWT_REFRESH_TOKEN_EXPIRE_DAYS")

    # Encryption Configuration
    encryption_key: str = Field(env="ENCRYPTION_KEY")
    field_encryption_algorithm: str = Field(default="AES-256-GCM", env="FIELD_ENCRYPTION_ALGORITHM")

    # Session Configuration
    session_timeout_minutes: int = Field(default=60, env="SESSION_TIMEOUT_MINUTES")
    max_concurrent_sessions: int = Field(default=5, env="MAX_CONCURRENT_SESSIONS")
    session_refresh_threshold_minutes: int = Field(default=15, env="SESSION_REFRESH_THRESHOLD_MINUTES")

    # Password Policy
    password_min_length: int = Field(default=8, env="PASSWORD_MIN_LENGTH")
    password_require_uppercase: bool = Field(default=True, env="PASSWORD_REQUIRE_UPPERCASE")
    password_require_lowercase: bool = Field(default=True, env="PASSWORD_REQUIRE_LOWERCASE")
    password_require_numbers: bool = Field(default=True, env="PASSWORD_REQUIRE_NUMBERS")
    password_require_special: bool = Field(default=True, env="PASSWORD_REQUIRE_SPECIAL")
    password_hash_rounds: int = Field(default=12, env="PASSWORD_HASH_ROUNDS")

    # Rate Limiting
    rate_limit_requests_per_minute: int = Field(default=60, env="RATE_LIMIT_REQUESTS_PER_MINUTE")
    rate_limit_burst_size: int = Field(default=100, env="RATE_LIMIT_BURST_SIZE")

    # API Keys
    api_key_length: int = Field(default=32, env="API_KEY_LENGTH")
    api_key_prefix: str = Field(default="sh_", env="API_KEY_PREFIX")

    @validator("jwt_secret_key")
    def validate_jwt_secret(cls, v):
        if len(v) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")
        return v

    @validator("encryption_key")
    def validate_encryption_key(cls, v):
        if len(v) < 32:
            raise ValueError("Encryption key must be at least 32 characters long")
        return v

    class Config:
        env_prefix = ""
        case_sensitive = False


class ServiceSettings(BaseSettings):
    """Service identity and network configuration."""

    # Service Identity
    service_name: str = Field(default="security-hub", env="SERVICE_NAME")
    service_version: str = Field(default="1.0.0", env="SERVICE_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")

    # Network Configuration
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8005, env="PORT")

    # CORS Configuration
    cors_origins: List[str] = Field(default=["*"], env="CORS_ORIGINS")
    cors_allow_credentials: bool = Field(default=True, env="CORS_ALLOW_CREDENTIALS")
    cors_allow_methods: List[str] = Field(default=["*"], env="CORS_ALLOW_METHODS")
    cors_allow_headers: List[str] = Field(default=["*"], env="CORS_ALLOW_HEADERS")

    # Health Check Configuration
    health_check_timeout: int = Field(default=5, env="HEALTH_CHECK_TIMEOUT")
    health_check_interval: int = Field(default=30, env="HEALTH_CHECK_INTERVAL")

    # Debug and Development
    debug: bool = Field(default=False, env="DEBUG")
    reload: bool = Field(default=False, env="RELOAD")

    @validator("environment")
    def validate_environment(cls, v):
        allowed_environments = ["development", "staging", "production", "testing"]
        if v.lower() not in allowed_environments:
            raise ValueError(f"Environment must be one of: {allowed_environments}")
        return v.lower()

    @validator("cors_origins", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    class Config:
        env_prefix = ""
        case_sensitive = False


class LoggingSettings(BaseSettings):
    """Logging configuration settings."""

    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    log_max_size: int = Field(default=10485760, env="LOG_MAX_SIZE")  # 10MB
    log_backup_count: int = Field(default=5, env="LOG_BACKUP_COUNT")

    @validator("log_level")
    def validate_log_level(cls, v):
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of: {allowed_levels}")
        return v.upper()

    @validator("log_format")
    def validate_log_format(cls, v):
        allowed_formats = ["json", "text"]
        if v.lower() not in allowed_formats:
            raise ValueError(f"Log format must be one of: {allowed_formats}")
        return v.lower()

    class Config:
        env_prefix = ""
        case_sensitive = False


class Settings(BaseSettings):
    """Main application settings combining all configuration sections."""

    # Configuration sections
    database: DatabaseSettings = DatabaseSettings()
    security: SecuritySettings = SecuritySettings()
    service: ServiceSettings = ServiceSettings()
    logging: LoggingSettings = LoggingSettings()

    # Additional global settings
    testing: bool = Field(default=False, env="TESTING")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Initialize sub-settings with current environment
        self.database = DatabaseSettings()
        self.security = SecuritySettings()
        self.service = ServiceSettings()
        self.logging = LoggingSettings()

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.service.environment == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.service.environment == "development"

    @property
    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.testing or self.service.environment == "testing"

    def get_database_url(self, sync: bool = False) -> str:
        """Get database URL for async or sync connections."""
        return self.database.postgres_dsn_sync if sync else self.database.postgres_dsn

    class Config:
        env_prefix = ""
        case_sensitive = False
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()


# Convenience functions for accessing settings
def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


def get_database_settings() -> DatabaseSettings:
    """Get database settings."""
    return settings.database


def get_security_settings() -> SecuritySettings:
    """Get security settings."""
    return settings.security


def get_service_settings() -> ServiceSettings:
    """Get service settings."""
    return settings.service


def get_logging_settings() -> LoggingSettings:
    """Get logging settings."""
    return settings.logging