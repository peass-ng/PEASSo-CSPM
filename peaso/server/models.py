from datetime import datetime
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkspaceCreate(StrictModel):
    name: str = Field(min_length=3, max_length=80)


class WorkspaceInvite(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    role: Literal["read", "write", "admin"]


class WorkspaceRole(StrictModel):
    role: Literal["read", "write", "admin"]


class ConnectorCreate(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    provider: Literal["aws", "gcp", "azure", "k8s"]
    auth: dict = Field(default_factory=dict)
    scopes: list[str] = Field(default_factory=list)
    options: dict = Field(default_factory=dict)
    prepared_id: str | None = None
    check_token: str | None = None
    acknowledge_access_warnings: StrictBool = False


class ConnectorCheck(ConnectorCreate):
    credential_expires_at: datetime | None = None
    connector_id: str | None = None


class ConnectorPatch(StrictModel):
    prepared_id: str | None = None
    check_token: str | None = None
    acknowledge_access_warnings: StrictBool = False
    name: str | None = Field(default=None, min_length=1, max_length=200)
    auth: dict | None = None
    scopes: list[str] | None = None
    options: dict | None = None


class ScanCreate(StrictModel):
    ai_enabled: StrictBool = True
    ai_priorities_enabled: StrictBool = True
    ai_network_enabled: StrictBool = True
    ai_k8s_exposure_enabled: StrictBool = False
    connector_id: str = Field(min_length=1, max_length=100)
    categories: list[str] = Field(default_factory=list, max_length=100)
    checks: list[str] = Field(default_factory=list, max_length=10000)
    content_checks: list[str] = Field(default_factory=list, max_length=10000)
    leaks_enabled: StrictBool | None = None
    images_enabled: StrictBool | None = None
    frameworks: list[str] = Field(default_factory=list, max_length=100)


class AttackLogSource(StrictModel):
    connector_id: str = Field(min_length=1, max_length=100)
    kind: Literal["aws_event_history", "aws_cloudtrail_s3", "gcp_audit", "gke_audit", "azure_activity_log", "entra_directory_audit"]
    catalog_mode: Literal["pinned", "latest"] = "latest"
    region: str = Field(pattern=r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
    role_arn: str | None = Field(default=None, max_length=600)
    bucket: str | None = Field(default=None, min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
    prefix: str = Field(default="", max_length=1024, pattern=r"^[A-Za-z0-9!_.*'()/+=:@ -]*$")
    day: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    project_id: str | None = Field(default=None, max_length=80, pattern=r"^[a-z][a-z0-9-]{4,79}$")
    cluster_id: str | None = Field(default=None, max_length=256, pattern=r"^[A-Za-z0-9_.:/-]+$")
    subscription_id: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    tenant_id: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class AttackLogRun(AttackLogSource):
    check_token: str = Field(min_length=1, max_length=4096)


class ScheduleRule(StrictModel):
    frequency: Literal['daily', 'weekly', 'monthly']
    time: str = Field(pattern=r'^(?:[01][0-9]|2[0-3]):[0-5][0-9]$')
    weekdays: list[Annotated[int, Field(strict=True, ge=0, le=6)]] = Field(default_factory=list, max_length=7)
    day_of_month: int | None = Field(default=None, strict=True, ge=1, le=31)

    @model_validator(mode='after')
    def valid_days(self):
        if self.frequency == 'weekly':
            if not self.weekdays or len(set(self.weekdays)) != len(self.weekdays):
                raise ValueError('Select unique weekdays for a weekly rule')
        elif self.weekdays:
            raise ValueError('Weekdays only apply to weekly rules')
        if (self.frequency == 'monthly') != (self.day_of_month is not None):
            raise ValueError('Select a day of the month only for monthly rules')
        return self


def valid_schedule_timezone(value):
    if value is not None:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError('Choose a valid IANA time zone') from None
    return value


class ScheduleCreate(ScanCreate):
    interval_hours: float = Field(default=168, ge=1, le=8760)
    rules: list[ScheduleRule] | None = Field(default=None, min_length=1, max_length=20)
    timezone: str = Field(default='UTC', min_length=1, max_length=100)
    enabled: bool = True
    next_run_at: datetime | None = None

    _timezone_valid = field_validator('timezone')(valid_schedule_timezone)

    @field_validator("next_run_at")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Timezone required")
        return value


class SchedulePatch(StrictModel):
    ai_enabled: StrictBool | None = None
    ai_priorities_enabled: StrictBool | None = None
    ai_network_enabled: StrictBool | None = None
    ai_k8s_exposure_enabled: StrictBool | None = None
    connector_id: str | None = Field(default=None, min_length=1, max_length=100)
    categories: list[str] | None = Field(default=None, max_length=100)
    checks: list[str] | None = Field(default=None, max_length=10000)
    content_checks: list[str] | None = Field(default=None, max_length=10000)
    leaks_enabled: StrictBool | None = None
    images_enabled: StrictBool | None = None
    frameworks: list[str] | None = Field(default=None, max_length=100)
    interval_hours: float | None = Field(default=None, ge=1, le=8760)
    rules: list[ScheduleRule] | None = Field(default=None, min_length=1, max_length=20)
    timezone: str | None = Field(default=None, min_length=1, max_length=100)
    enabled: bool | None = None
    next_run_at: datetime | None = None

    _timezone_valid = field_validator('timezone')(valid_schedule_timezone)

    @field_validator("next_run_at")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Timezone required")
        return value


class ReachabilityQuery(StrictModel):
    source_resource_id: str = Field(min_length=1, max_length=2000)
    destination_resource_id: str = Field(min_length=1, max_length=2000)
    protocol: Literal["tcp", "udp"]
    destination_port: int = Field(ge=1, le=65535, strict=True)
    source_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    address_family: Literal["ipv4", "ipv6"] = "ipv4"


class ReachabilityBatchQuery(StrictModel):
    source_resource_id: str = Field(min_length=1, max_length=2000)
    destination_resource_ids: list[str] = Field(min_length=1, max_length=24)
    protocol: Literal["tcp", "udp"]
    destination_port: int = Field(ge=1, le=65535, strict=True)
    source_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    address_family: Literal["ipv4", "ipv6"] = "ipv4"

    @field_validator("destination_resource_ids")
    @classmethod
    def unique_destinations(cls, values):
        if any(not isinstance(value, str) or not value or len(value) > 2000 for value in values) or len(set(values)) != len(values):
            raise ValueError("Destination IDs must be unique nonempty resource IDs")
        return values


class ReachabilityMatrixQuery(StrictModel):
    endpoint_resource_ids: list[str] = Field(min_length=2, max_length=12)
    protocol: Literal["tcp", "udp"]
    destination_port: int = Field(ge=1, le=65535, strict=True)
    source_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    address_family: Literal["ipv4", "ipv6"] = "ipv4"

    @field_validator("endpoint_resource_ids")
    @classmethod
    def unique_endpoints(cls, values):
        if any(not isinstance(value, str) or not value or len(value) > 2000 for value in values) or len(set(values)) != len(values):
            raise ValueError("Endpoint IDs must be unique nonempty resource IDs")
        return values


class ReachabilityGridQuery(StrictModel):
    first_endpoint_resource_ids: list[str] = Field(min_length=1, max_length=12)
    second_endpoint_resource_ids: list[str] = Field(min_length=1, max_length=12)
    protocol: Literal["tcp", "udp"]
    destination_port: int = Field(ge=1, le=65535, strict=True)
    source_port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    address_family: Literal["ipv4", "ipv6"] = "ipv4"

    @field_validator("first_endpoint_resource_ids", "second_endpoint_resource_ids")
    @classmethod
    def unique_window(cls, values):
        if any(not isinstance(value, str) or not value or len(value) > 2000 for value in values) or len(set(values)) != len(values):
            raise ValueError("Window IDs must be unique nonempty resource IDs")
        return values
