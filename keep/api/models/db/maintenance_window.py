# builtins
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

from pydantic import BaseModel, root_validator
from sqlalchemy import DateTime, JSON

# third-parties
from sqlmodel import Column, Field, Index, SQLModel, func

from keep.api.models.alert import AlertStatus

DEFAULT_ALERT_STATUSES_TO_IGNORE = [
    AlertStatus.RESOLVED.value,
    AlertStatus.ACKNOWLEDGED.value,
]


class MaintenanceWindowRule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    tenant_id: str = Field(foreign_key="tenant.id")
    description: Optional[str] = None
    created_by: str
    cel_query: str
    start_time: datetime
    end_time: datetime
    duration_seconds: Optional[int] = None
    updated_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime(timezone=True),
            name="updated_at",
            onupdate=func.now(),
            server_default=func.now(),
        )
    )
    suppress: bool = False
    enabled: bool = True
    ignore_statuses: list = Field(sa_column=Column(JSON), default_factory=list)

    __table_args__ = (
        Index("ix_maintenance_rule_tenant_id", "tenant_id"),
        Index("ix_maintenance_rule_tenant_id_end_time", "tenant_id", "end_time"),
    )


class MaintenanceRuleCreate(BaseModel):
    """
    DTO for creating a maintenance rule.
    
    Frontend Usage:
        The frontend should send `start_time` in LOCAL time (not UTC) along with
        the `timezone` field containing the user's local timezone (e.g., "America/Santiago").
        The backend will automatically convert the local time to UTC for storage.
        
        Example request from frontend:
        {
            "name": "Nightly maintenance",
            "start_time": "2026-01-19T23:30:00",  # Local time (Chile)
            "timezone": "America/Santiago",        # User's local timezone
            "duration_seconds": 3600,
            "cel_query": "severity == 'critical'"
        }
        
        This will be stored in DB as start_time = 2026-01-20T02:30:00 UTC
        (Chile is UTC-3 in summer)
    """
    name: str
    description: Optional[str] = None
    cel_query: str
    start_time: datetime
    duration_seconds: Optional[int] = None
    suppress: bool = False
    enabled: bool = True
    ignore_statuses: list[str] = DEFAULT_ALERT_STATUSES_TO_IGNORE
    timezone: Optional[str] = None  # e.g., "America/New_York", "Europe/London"

    @root_validator(pre=False)
    def convert_start_time_to_utc(cls, values):
        """
        Convert start_time to UTC based on the provided timezone.
        If timezone is provided, interpret start_time as being in that timezone and convert to UTC.
        If start_time already has timezone info (e.g., ends with 'Z' or has offset), use it directly.
        """
        start_time = values.get("start_time")
        tz = values.get("timezone")
        
        if start_time is None:
            return values

        # If start_time already has timezone info, convert to UTC
        if start_time.tzinfo is not None:
            values["start_time"] = start_time.astimezone(timezone.utc).replace(tzinfo=None)
        elif tz:
            # If timezone is provided, interpret start_time as being in that timezone
            try:
                local_tz = ZoneInfo(tz)
                # Localize the naive datetime to the provided timezone
                localized_time = start_time.replace(tzinfo=local_tz)
                # Convert to UTC and remove tzinfo for storage
                values["start_time"] = localized_time.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                # If timezone is invalid, keep start_time as-is (assume UTC)
                pass
        # If no timezone info and no timezone provided, assume UTC (keep as-is)

        return values


class MaintenanceRuleRead(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_by: str
    cel_query: str
    start_time: datetime
    end_time: datetime
    duration_seconds: Optional[int]
    updated_at: Optional[datetime]
    suppress: bool = False
    enabled: bool = True
    ignore_statuses: list[str] = DEFAULT_ALERT_STATUSES_TO_IGNORE
