"""
Audit logging models for Security Hub.
Provides comprehensive audit trail for compliance, security monitoring, and forensics.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy import (
    Column, String, Text, Boolean, Integer, DateTime, BigInteger,
    ForeignKey, Index, CheckConstraint, Enum as SQLEnum
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY, INET
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property
import enum

from .base import BaseModel, TenantMixin


class AuditLogLevel(str, enum.Enum):
    """Audit log severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    DEBUG = "debug"


class AuditEventType(str, enum.Enum):
    """Types of audit events."""
    # Authentication Events
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGE = "auth.password.change"
    PASSWORD_RESET = "auth.password.reset"
    MFA_SETUP = "auth.mfa.setup"
    MFA_SUCCESS = "auth.mfa.success"
    MFA_FAILURE = "auth.mfa.failure"

    # Authorization Events
    ACCESS_GRANTED = "authz.access.granted"
    ACCESS_DENIED = "authz.access.denied"
    PERMISSION_GRANTED = "authz.permission.granted"
    PERMISSION_REVOKED = "authz.permission.revoked"
    ROLE_ASSIGNED = "authz.role.assigned"
    ROLE_REVOKED = "authz.role.revoked"

    # User Management Events
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_SUSPENDED = "user.suspended"
    USER_ACTIVATED = "user.activated"

    # Administrative Events
    ADMIN_LOGIN = "admin.login"
    ADMIN_ACTION = "admin.action"
    CONFIG_CHANGE = "admin.config.change"
    SYSTEM_MAINTENANCE = "admin.maintenance"

    # Security Events
    SECURITY_VIOLATION = "security.violation"
    SUSPICIOUS_ACTIVITY = "security.suspicious"
    BRUTE_FORCE_ATTEMPT = "security.brute_force"
    RATE_LIMIT_EXCEEDED = "security.rate_limit"

    # Data Events
    DATA_ACCESS = "data.access"
    DATA_EXPORT = "data.export"
    DATA_IMPORT = "data.import"
    DATA_DELETION = "data.deletion"

    # API Events
    API_CALL = "api.call"
    API_KEY_CREATED = "api.key.created"
    API_KEY_REVOKED = "api.key.revoked"

    # System Events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SYSTEM_ERROR = "system.error"


class AuditLog(BaseModel, TenantMixin):
    """
    Comprehensive audit log for all system activities.

    Provides detailed logging for compliance, security monitoring, and forensics.
    Designed to be immutable once created.
    """

    __tablename__ = "audit_logs"

    # Event Identification
    event_type = Column(
        SQLEnum(AuditEventType),
        nullable=False,
        comment="Type of event being logged"
    )

    event_category = Column(
        String(50),
        nullable=False,
        comment="Event category (auth, authz, user, admin, security, data, api, system)"
    )

    event_id = Column(
        String(100),
        nullable=True,
        comment="Unique event identifier for correlation"
    )

    # Event Details
    summary = Column(
        String(500),
        nullable=False,
        comment="Brief description of the event"
    )

    description = Column(
        Text,
        nullable=True,
        comment="Detailed description of the event"
    )

    # Severity and Status
    level = Column(
        SQLEnum(AuditLogLevel),
        nullable=False,
        default=AuditLogLevel.INFO,
        comment="Log level/severity"
    )

    outcome = Column(
        String(20),
        nullable=False,
        comment="Event outcome (success, failure, error, partial)"
    )

    # User and Actor Information
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("tenant_users.id"),
        nullable=True,
        comment="User who performed the action"
    )

    actor_type = Column(
        String(20),
        nullable=False,
        default="user",
        comment="Type of actor (user, system, api, service)"
    )

    actor_id = Column(
        String(255),
        nullable=True,
        comment="Identifier of the actor"
    )

    actor_name = Column(
        String(255),
        nullable=True,
        comment="Name of the actor"
    )

    # Session and Request Context
    session_id = Column(
        String(255),
        nullable=True,
        comment="Session identifier"
    )

    request_id = Column(
        String(255),
        nullable=True,
        comment="Request identifier for correlation"
    )

    correlation_id = Column(
        String(255),
        nullable=True,
        comment="Correlation ID for tracking related events"
    )

    # Network and Device Information
    ip_address = Column(
        INET,
        nullable=True,
        comment="IP address of the request"
    )

    user_agent = Column(
        String(1000),
        nullable=True,
        comment="User agent string"
    )

    device_fingerprint = Column(
        String(255),
        nullable=True,
        comment="Device fingerprint"
    )

    # Resource Information
    resource_type = Column(
        String(100),
        nullable=True,
        comment="Type of resource affected"
    )

    resource_id = Column(
        String(255),
        nullable=True,
        comment="ID of the affected resource"
    )

    resource_name = Column(
        String(500),
        nullable=True,
        comment="Name of the affected resource"
    )

    # Action and Method
    action = Column(
        String(100),
        nullable=True,
        comment="Action performed (create, read, update, delete, etc.)"
    )

    method = Column(
        String(20),
        nullable=True,
        comment="HTTP method for API calls"
    )

    endpoint = Column(
        String(500),
        nullable=True,
        comment="API endpoint accessed"
    )

    # Data and Changes
    old_values = Column(
        JSONB,
        nullable=True,
        comment="Previous values (for updates)"
    )

    new_values = Column(
        JSONB,
        nullable=True,
        comment="New values (for updates)"
    )

    additional_data = Column(
        JSONB,
        nullable=True,
        comment="Additional event data"
    )

    # Risk and Security
    risk_score = Column(
        Integer,
        nullable=True,
        comment="Risk score (0-100) for security events"
    )

    threat_indicators = Column(
        ARRAY(String),
        nullable=True,
        comment="Security threat indicators"
    )

    # Compliance and Tags
    compliance_tags = Column(
        ARRAY(String),
        nullable=True,
        comment="Compliance framework tags"
    )

    data_classification = Column(
        String(50),
        nullable=True,
        comment="Data classification level"
    )

    # Timing Information
    event_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When the event occurred"
    )

    duration_ms = Column(
        Integer,
        nullable=True,
        comment="Event duration in milliseconds"
    )

    # Source Information
    source_component = Column(
        String(100),
        nullable=True,
        comment="Component that generated the log"
    )

    source_version = Column(
        String(50),
        nullable=True,
        comment="Version of the source component"
    )

    # Retention and Processing
    retention_period_days = Column(
        Integer,
        nullable=False,
        default=2555,  # 7 years default
        comment="How long to retain this log entry"
    )

    is_sensitive = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether this log contains sensitive data"
    )

    is_exported = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether this log has been exported"
    )

    # Relationships
    user = relationship("TenantUser", backref="audit_logs")

    # Constraints
    __table_args__ = (
        CheckConstraint(
            "actor_type IN ('user', 'system', 'api', 'service', 'admin')",
            name="valid_actor_type"
        ),
        CheckConstraint(
            "outcome IN ('success', 'failure', 'error', 'partial', 'warning')",
            name="valid_outcome"
        ),
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
            name="valid_risk_score"
        ),
        CheckConstraint(
            "retention_period_days > 0",
            name="positive_retention_period"
        ),
        Index("ix_audit_logs_event_type", "event_type"),
        Index("ix_audit_logs_category", "event_category"),
        Index("ix_audit_logs_level", "level"),
        Index("ix_audit_logs_outcome", "outcome"),
        Index("ix_audit_logs_user", "user_id"),
        Index("ix_audit_logs_tenant", "tenant_id"),
        Index("ix_audit_logs_timestamp", "event_timestamp"),
        Index("ix_audit_logs_actor", "actor_type", "actor_id"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_session", "session_id"),
        Index("ix_audit_logs_request", "request_id"),
        Index("ix_audit_logs_correlation", "correlation_id"),
        Index("ix_audit_logs_ip", "ip_address"),
        Index("ix_audit_logs_risk", "risk_score"),
        Index("ix_audit_logs_compliance", "compliance_tags"),
        # Composite indexes for common queries
        Index("ix_audit_logs_tenant_type_time", "tenant_id", "event_type", "event_timestamp"),
        Index("ix_audit_logs_user_time", "user_id", "event_timestamp"),
        Index("ix_audit_logs_security", "event_category", "level", "risk_score"),
    )

    @validates("event_category")
    def validate_event_category(self, key, event_category):
        """Validate event category."""
        valid_categories = {
            "auth", "authz", "user", "admin", "security",
            "data", "api", "system", "compliance"
        }
        if event_category.lower() not in valid_categories:
            raise ValueError(f"Invalid event category: {event_category}")
        return event_category.lower()

    @validates("risk_score")
    def validate_risk_score(self, key, risk_score):
        """Validate risk score range."""
        if risk_score is not None and (risk_score < 0 or risk_score > 100):
            raise ValueError("Risk score must be between 0 and 100")
        return risk_score

    def is_high_risk(self) -> bool:
        """Check if this is a high-risk event."""
        return self.risk_score is not None and self.risk_score >= 70

    def is_security_event(self) -> bool:
        """Check if this is a security-related event."""
        return self.event_category == "security" or self.is_high_risk()

    def should_alert(self) -> bool:
        """Check if this event should trigger an alert."""
        return (
                self.level in [AuditLogLevel.ERROR, AuditLogLevel.CRITICAL] or
                self.is_high_risk() or
                self.outcome in ["failure", "error"]
        )

    def get_retention_date(self) -> datetime:
        """Get the date when this log entry should be deleted."""
        from datetime import timedelta
        return self.created_at + timedelta(days=self.retention_period_days)

    def mask_sensitive_data(self) -> Dict[str, Any]:
        """Get a masked version of the log entry for display."""
        data = self.to_dict()

        # Mask sensitive fields
        if self.is_sensitive:
            if data.get("additional_data"):
                data["additional_data"] = {"<masked>": True}
            if data.get("old_values"):
                data["old_values"] = {"<masked>": True}
            if data.get("new_values"):
                data["new_values"] = {"<masked>": True}

        # Always mask full IP for privacy
        if data.get("ip_address"):
            ip_parts = str(data["ip_address"]).split(".")
            if len(ip_parts) == 4:
                data["ip_address"] = f"{ip_parts[0]}.{ip_parts[1]}.xxx.xxx"

        return data

    @classmethod
    def create_auth_event(
            cls,
            tenant_id: uuid.UUID,
            event_type: AuditEventType,
            user_id: Optional[uuid.UUID] = None,
            outcome: str = "success",
            summary: str = "",
            ip_address: Optional[str] = None,
            user_agent: Optional[str] = None,
            session_id: Optional[str] = None,
            additional_data: Optional[Dict[str, Any]] = None
    ) -> "AuditLog":
        """Create an authentication-related audit log entry."""
        return cls(
            tenant_id=tenant_id,
            event_type=event_type,
            event_category="auth",
            user_id=user_id,
            outcome=outcome,
            summary=summary or f"Authentication event: {event_type.value}",
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            additional_data=additional_data or {},
            actor_type="user",
            actor_id=str(user_id) if user_id else None
        )

    @classmethod
    def create_security_event(
            cls,
            tenant_id: uuid.UUID,
            event_type: AuditEventType,
            summary: str,
            risk_score: int,
            user_id: Optional[uuid.UUID] = None,
            ip_address: Optional[str] = None,
            threat_indicators: Optional[List[str]] = None,
            additional_data: Optional[Dict[str, Any]] = None
    ) -> "AuditLog":
        """Create a security-related audit log entry."""
        level = AuditLogLevel.CRITICAL if risk_score >= 80 else AuditLogLevel.WARNING

        return cls(
            tenant_id=tenant_id,
            event_type=event_type,
            event_category="security",
            user_id=user_id,
            level=level,
            outcome="warning" if risk_score < 50 else "failure",
            summary=summary,
            risk_score=risk_score,
            threat_indicators=threat_indicators or [],
            ip_address=ip_address,
            additional_data=additional_data or {},
            actor_type="user" if user_id else "system",
            actor_id=str(user_id) if user_id else "system",
            is_sensitive=True
        )

    @classmethod
    def create_data_access_event(
            cls,
            tenant_id: uuid.UUID,
            user_id: uuid.UUID,
            resource_type: str,
            resource_id: str,
            action: str,
            outcome: str = "success",
            data_classification: Optional[str] = None,
            additional_data: Optional[Dict[str, Any]] = None
    ) -> "AuditLog":
        """Create a data access audit log entry."""
        return cls(
            tenant_id=tenant_id,
            event_type=AuditEventType.DATA_ACCESS,
            event_category="data",
            user_id=user_id,
            outcome=outcome,
            summary=f"Data access: {action} {resource_type}",
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            data_classification=data_classification,
            additional_data=additional_data or {},
            actor_type="user",
            actor_id=str(user_id),
            is_sensitive=data_classification in ["confidential", "restricted"]
        )


class AuditLogQuery(BaseModel, TenantMixin):
    """
    Audit log query tracking for compliance and monitoring.

    Tracks who queries audit logs and what they access.
    """

    __tablename__ = "audit_log_queries"

    # Query Details
    query_type = Column(
        String(50),
        nullable=False,
        comment="Type of query (search, export, report)"
    )

    query_description = Column(
        Text,
        nullable=True,
        comment="Description of the query purpose"
    )

    # Query Parameters
    filters = Column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Query filters applied"
    )

    date_range_start = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Start date of queried logs"
    )

    date_range_end = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="End date of queried logs"
    )

    # Results
    results_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of log entries returned"
    )

    exported_records = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of records exported"
    )

    # User and Context
    queried_by_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("tenant_users.id"),
        nullable=False,
        comment="User who performed the query"
    )

    purpose = Column(
        String(200),
        nullable=True,
        comment="Business purpose for the query"
    )

    # Query Execution
    execution_time_ms = Column(
        Integer,
        nullable=True,
        comment="Query execution time in milliseconds"
    )

    query_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When the query was executed"
    )

    # Relationships
    queried_by = relationship("TenantUser", backref="audit_queries")

    # Constraints
    __table_args__ = (
        CheckConstraint(
            "query_type IN ('search', 'export', 'report', 'investigation')",
            name="valid_query_type"
        ),
        CheckConstraint(
            "results_count >= 0",
            name="non_negative_results_count"
        ),
        Index("ix_audit_queries_user", "queried_by_user_id"),
        Index("ix_audit_queries_tenant", "tenant_id"),
        Index("ix_audit_queries_timestamp", "query_timestamp"),
        Index("ix_audit_queries_type", "query_type"),
        Index("ix_audit_queries_date_range", "date_range_start", "date_range_end"),
    )


class AuditLogExport(BaseModel, TenantMixin):
    """
    Audit log export tracking for compliance reporting.

    Tracks when audit logs are exported for compliance or legal purposes.
    """

    __tablename__ = "audit_log_exports"

    # Export Details
    export_type = Column(
        String(50),
        nullable=False,
        comment="Type of export (compliance, legal, investigation, backup)"
    )

    export_format = Column(
        String(20),
        nullable=False,
        comment="Export format (csv, json, pdf, xml)"
    )

    file_name = Column(
        String(255),
        nullable=False,
        comment="Generated file name"
    )

    file_size_bytes = Column(
        BigInteger,
        nullable=True,
        comment="Size of exported file in bytes"
    )

    # Export Criteria
    date_range_start = Column(
        DateTime(timezone=True),
        nullable=False,
        comment="Start date of exported logs"
    )

    date_range_end = Column(
        DateTime(timezone=True),
        nullable=False,
        comment="End date of exported logs"
    )

    filters_applied = Column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Filters applied to the export"
    )

    # Results
    records_exported = Column(
        Integer,
        nullable=False,
        comment="Number of records exported"
    )

    # User and Purpose
    exported_by_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("tenant_users.id"),
        nullable=False,
        comment="User who performed the export"
    )

    purpose = Column(
        String(500),
        nullable=False,
        comment="Purpose of the export"
    )

    compliance_framework = Column(
        String(100),
        nullable=True,
        comment="Compliance framework (GDPR, HIPAA, SOX, etc.)"
    )

    # Export Execution
    export_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When the export was performed"
    )

    execution_time_ms = Column(
        Integer,
        nullable=True,
        comment="Export execution time in milliseconds"
    )

    # Security and Access
    access_granted_by = Column(
        UUID(as_uuid=True),
        ForeignKey("tenant_users.id"),
        nullable=True,
        comment="User who granted access for this export"
    )

    download_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of times the export was downloaded"
    )

    last_downloaded_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the export was last downloaded"
    )

    # Relationships
    exported_by = relationship("TenantUser", foreign_keys=[exported_by_user_id], backref="audit_exports")
    approved_by = relationship("TenantUser", foreign_keys=[access_granted_by])

    # Constraints
    __table_args__ = (
        CheckConstraint(
            "export_type IN ('compliance', 'legal', 'investigation', 'backup', 'audit')",
            name="valid_export_type"
        ),
        CheckConstraint(
            "export_format IN ('csv', 'json', 'pdf', 'xml', 'xlsx')",
            name="valid_export_format"
        ),
        CheckConstraint(
            "records_exported >= 0",
            name="non_negative_records_exported"
        ),
        CheckConstraint(
            "download_count >= 0",
            name="non_negative_download_count"
        ),
        Index("ix_audit_exports_user", "exported_by_user_id"),
        Index("ix_audit_exports_tenant", "tenant_id"),
        Index("ix_audit_exports_timestamp", "export_timestamp"),
        Index("ix_audit_exports_type", "export_type"),
        Index("ix_audit_exports_compliance", "compliance_framework"),
        Index("ix_audit_exports_date_range", "date_range_start", "date_range_end"),
    )