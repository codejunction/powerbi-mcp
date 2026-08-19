"""
Pydantic models for type-safe MCP tool inputs and outputs.
"""
from typing import Annotated, List, Optional, Any, Dict
from pydantic import BaseModel, Field
from enum import Enum


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
# Tool Input Models
# ============================================================================

class ListWorkspacesInput(BaseModel):
    """Input for list_workspaces tool."""
    pass


class ListDatasetsInput(BaseModel):
    """Input for list_datasets tool."""
    workspace_id: str = Field(description="ID of the workspace")


class ListTablesInput(BaseModel):
    """Input for list_tables tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class ListColumnsInput(BaseModel):
    """Input for list_columns tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")
    table_name: str = Field(description="Name of the table")


class ExecuteDaxInput(BaseModel):
    """Input for execute_dax tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")
    dax_query: str = Field(description="DAX query to execute")


class ValidateDaxInput(BaseModel):
    """Input for validate_dax tool."""
    dax: str = Field(description="DAX query or expression to validate")
    as_measure: bool = Field(default=False, description="Treat as scalar measure expression")
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class GetModelInfoInput(BaseModel):
    """Input for get_model_info tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class DescribeSemanticModelInput(BaseModel):
    """Input for describe_semantic_model tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class AnswerQueryPlanInput(BaseModel):
    """Input for answer_query_plan tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")
    question: str = Field(description="Natural language question to answer")
    execute: bool = Field(default=False, description="Whether to execute the query")
    max_rows: int = Field(default=100, ge=1, le=1000, description="Maximum rows to return")


class SecurityStatusInput(BaseModel):
    """Input for security_status tool."""
    pass


class SecurityAuditLogInput(BaseModel):
    """Input for security_audit_log tool."""
    count: int = Field(default=10, ge=1, le=100, description="Number of recent entries to show")


class RunBpaInput(BaseModel):
    """Input for run_bpa tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class AuditAiReadinessInput(BaseModel):
    """Input for audit_ai_readiness tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class AnalyzeModelStorageInput(BaseModel):
    """Input for analyze_model_storage tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class AnalyzeQueryPerformanceInput(BaseModel):
    """Input for analyze_query_performance tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")
    dax_query: str = Field(description="DAX query to analyze")


class ModelDiffInput(BaseModel):
    """Input for model_diff tool."""
    baseline_path: str = Field(description="Path to baseline JSON snapshot")
    target_path: Optional[str] = Field(default=None, description="Path to target snapshot")
    workspace_name: Optional[str] = Field(default=None, description="Workspace name (if diffing against live)")
    dataset_name: Optional[str] = Field(default=None, description="Dataset name (if diffing against live)")


class PreDeployGateInput(BaseModel):
    """Input for pre_deploy_gate tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class RefreshDoctorInput(BaseModel):
    """Input for refresh_doctor tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")
    error_code: Optional[str] = Field(default=None, description="Specific error code to diagnose")


class FindUnusedObjectsInput(BaseModel):
    """Input for find_unused_objects tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")


class ImpactAnalysisInput(BaseModel):
    """Input for impact_analysis tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")
    object_name: str = Field(description="Name of the object to analyze")
    object_type: str = Field(description="Type of object (measure, column, table)")


class RunDaxTestsInput(BaseModel):
    """Input for run_dax_tests tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")
    test_definitions: List[Dict[str, Any]] = Field(description="List of test definitions")


class ScanReferentialIntegrityInput(BaseModel):
    """Input for scan_referential_integrity tool."""
    workspace_name: str = Field(description="Name of the workspace")
    dataset_name: str = Field(description="Name of the dataset")
    max_samples: int = Field(default=5, ge=1, le=100, description="Maximum samples per violation")


class GenerateMeasureSuiteInput(BaseModel):
    """Input for generate_measure_suite tool."""
    kind: str = Field(description="Pattern preset (time_intelligence, ratios, ranking, column_stats)")
    table_name: Optional[str] = Field(default=None, description="Table to generate measures for")
    base_column: Optional[str] = Field(default=None, description="Base column for aggregations")
    base_measure: Optional[str] = Field(default=None, description="Base measure for ratios/ranking")
    target: str = Field(default="none", description="Write target (none=preview only)")
    skip_validation: bool = Field(default=False, description="Skip DAX linting")


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


class QueryPlan(BaseModel):
    """Query plan for answering a question."""
    suggested_measures: List[str] = Field(description="Suggested measures to use")
    suggested_tables: List[str] = Field(description="Suggested tables to query")
    draft_dax: str = Field(description="Draft DAX query")
    explanation: str = Field(description="Explanation of the plan")


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


class StorageAnalysis(BaseModel):
    """Result from model storage analysis."""
    total_size_mb: float = Field(description="Total model size in MB")
    table_sizes: List[Dict[str, Any]] = Field(description="Size breakdown by table")
    compression_ratio: float = Field(description="Overall compression ratio")
    recommendations: List[str] = Field(description="Storage optimization recommendations")


class QueryPerformanceAnalysis(BaseModel):
    """Result from query performance analysis."""
    execution_time_ms: float = Field(description="Query execution time")
    optimizations: List[str] = Field(description="Suggested optimizations")
    bottlenecks: List[str] = Field(description="Identified bottlenecks")


class ModelDiffResult(BaseModel):
    """Result from model diff."""
    added_objects: List[str] = Field(description="Objects added")
    removed_objects: List[str] = Field(description="Objects removed")
    changed_objects: List[Dict[str, Any]] = Field(description="Objects changed with details")


class PreDeployCheckResult(BaseModel):
    """Result from pre-deployment gate checks."""
    passed: bool = Field(description="Whether all checks passed")
    checks: List[Dict[str, Any]] = Field(description="Individual check results")
    blocking_issues: List[str] = Field(description="Blocking issues that must be resolved")


class RefreshDiagnosis(BaseModel):
    """Result from refresh doctor."""
    error_type: str = Field(description="Type of refresh error")
    root_cause: str = Field(description="Root cause analysis")
    remediation_steps: List[str] = Field(description="Steps to fix the issue")


class UnusedObjectsResult(BaseModel):
    """Result from unused objects scan."""
    unused_measures: List[str] = Field(description="Unused measures")
    unused_columns: List[str] = Field(description="Unused columns")
    unused_tables: List[str] = Field(description="Unused tables")


class ImpactAnalysisResult(BaseModel):
    """Result from impact analysis."""
    dependent_measures: List[str] = Field(description="Measures that depend on the object")
    dependent_visuals: List[str] = Field(description="Visuals that reference the object")
    downstream_impact: str = Field(description="Description of downstream impact")


class DaxTestResult(BaseModel):
    """Result from DAX tests."""
    passed: int = Field(description="Number of tests passed")
    failed: int = Field(description="Number of tests failed")
    total: int = Field(description="Total number of tests")
    failures: List[Dict[str, Any]] = Field(description="Details of failed tests")


class ReferentialIntegrityResult(BaseModel):
    """Result from referential integrity scan."""
    checked: int = Field(description="Number of relationships checked")
    violations: List[Dict[str, Any]] = Field(description="Violations found")
    status: str = Field(description="Overall integrity status")


class MeasureDefinition(BaseModel):
    """Single measure definition."""
    name: str = Field(description="Measure name")
    expression: str = Field(description="DAX expression")
    format_string: Optional[str] = Field(default=None, description="Format string")
    description: Optional[str] = Field(default=None, description="Measure description")
    display_folder: Optional[str] = Field(default=None, description="Display folder")


class MeasureSuiteResult(BaseModel):
    """Result from measure suite generation."""
    measures: List[MeasureDefinition] = Field(description="Generated measures")
    written: bool = Field(description="Whether measures were written")
    target: str = Field(description="Target used for generation")
