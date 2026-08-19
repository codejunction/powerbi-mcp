"""
Pydantic models for type-safe MCP tool inputs and outputs.
"""
from typing import Annotated, List, Optional, Any, Dict
from pydantic import BaseModel, Field


# ============================================================================
# Common Models
# ============================================================================

class WorkspaceInfo(BaseModel):
    """Power BI workspace information."""
    id: str = Field(description="Workspace ID")
    name: str = Field(description="Workspace name")
    capacity_id: Optional[str] = Field(default=None, description="Capacity ID")
    default_dataset_id: Optional[str] = Field(default=None, description="Default dataset ID")


class DatasetInfo(BaseModel):
    """Power BI dataset information."""
    id: str = Field(description="Dataset ID")
    name: str = Field(description="Dataset name")
    workspace_id: str = Field(description="Workspace ID")
    configured_by: Optional[str] = Field(default=None, description="Configured by user")
    is_refreshable: bool = Field(default=False, description="Whether dataset is refreshable")
    is_on_prem_gateway_required: bool = Field(default=False, description="Whether on-prem gateway is required")


class TableInfo(BaseModel):
    """Table information in a dataset."""
    name: str = Field(description="Table name")
    rows: int = Field(description="Number of rows")
    is_hidden: bool = Field(default=False, description="Whether table is hidden")


class ColumnInfo(BaseModel):
    """Column information in a table."""
    name: str = Field(description="Column name")
    data_type: str = Field(description="Data type")
    is_hidden: bool = Field(default=False, description="Whether column is hidden")
    description: Optional[str] = Field(default=None, description="Column description")


class MeasureInfo(BaseModel):
    """Measure information in a table."""
    name: str = Field(description="Measure name")
    expression: str = Field(description="DAX expression")
    format_string: Optional[str] = Field(default=None, description="Format string")
    description: Optional[str] = Field(default=None, description="Measure description")
    is_hidden: bool = Field(default=False, description="Whether measure is hidden")


class RelationshipInfo(BaseModel):
    """Relationship information between tables."""
    from_table: str = Field(description="Source table name")
    from_column: str = Field(description="Source column name")
    to_table: str = Field(description="Target table name")
    to_column: str = Field(description="Target column name")
    is_active: bool = Field(default=True, description="Whether relationship is active")
    cross_filtering_behavior: str = Field(default="automatic", description="Cross-filtering behavior")


class ModelInfo(BaseModel):
    """Comprehensive model information."""
    dataset: DatasetInfo
    tables: List[TableInfo]
    columns: List[ColumnInfo]
    measures: List[MeasureInfo]
    relationships: List[RelationshipInfo]


# ============================================================================
# Tool Output Models
# ============================================================================

class DaxResult(BaseModel):
    """Result from DAX execution."""
    rows: List[Dict[str, Any]] = Field(description="Query result rows")
    execution_time_ms: float = Field(description="Execution time in milliseconds")
    row_count: int = Field(description="Number of rows returned")


class ValidationResult(BaseModel):
    """Result from DAX validation."""
    valid: bool = Field(description="Whether DAX is valid")
    error: Optional[str] = Field(default=None, description="Error message if invalid")
    probe: Optional[str] = Field(default=None, description="Probe query used for validation")


class SecurityStatus(BaseModel):
    """Security status information."""
    pii_detection_enabled: bool = Field(description="Whether PII detection is enabled")
    audit_logging_enabled: bool = Field(description="Whether audit logging is enabled")
    access_policies_enabled: bool = Field(description="Whether access policies are enabled")
    active_policies: List[str] = Field(description="List of active policy names")


class AuditLogEntry(BaseModel):
    """Single audit log entry."""
    timestamp: str = Field(description="Timestamp of the entry")
    tool: str = Field(description="Tool that was called")
    user: Optional[str] = Field(default=None, description="User who made the call")
    arguments: Dict[str, Any] = Field(description="Arguments passed to the tool")
    result: str = Field(description="Result of the tool call")
    pii_findings: List[str] = Field(default_factory=list, description="PII findings")


# ============================================================================
# Additional Tool Output Models
# ============================================================================

class MeasureDefinition(BaseModel):
    """Single measure definition."""
    name: str = Field(description="Measure name")
    expression: str = Field(description="DAX expression")
    format_string: Optional[str] = Field(default=None, description="Format string")
    description: Optional[str] = Field(default=None, description="Measure description")
    display_folder: Optional[str] = Field(default=None, description="Display folder")


class BpaResult(BaseModel):
    """Result from Best Practice Analyzer run."""
    violations: List[Dict[str, Any]] = Field(description="List of violations found")
    score: float = Field(description="Overall BPA score")
    recommendations: List[str] = Field(description="Recommendations for improvement")


class AiReadinessResult(BaseModel):
    """Result from AI readiness audit."""
    score: float = Field(description="AI readiness score")
    findings: List[Dict[str, Any]] = Field(description="Findings from the audit")
    recommendations: List[str] = Field(description="Recommendations for improvement")


class PreDeployCheckResult(BaseModel):
    """Result from pre-deployment gate checks."""
    passed: bool = Field(description="Whether all checks passed")
    checks: List[Dict[str, Any]] = Field(description="Individual check results")
    blocking_issues: List[str] = Field(description="Blocking issues that must be resolved")


class SecurityScanSummary(BaseModel):
    """Summary of security scan results."""
    total_findings: int = Field(description="Total number of findings")
    critical_findings: int = Field(description="Number of critical findings")
    high_findings: int = Field(description="Number of high severity findings")
    medium_findings: int = Field(description="Number of medium severity findings")
    low_findings: int = Field(description="Number of low severity findings")
    recommendations: List[str] = Field(description="Security recommendations")


class UserActivitySummary(BaseModel):
    """Summary of user activity aggregation."""
    total_events: int = Field(description="Total number of events")
    unique_users: int = Field(description="Number of unique users")
    top_users: List[Dict[str, Any]] = Field(description="Top users by activity")
    activity_trends: Dict[str, Any] = Field(description="Activity trends over time")
    security_flags: List[str] = Field(description="Potential security concerns")
