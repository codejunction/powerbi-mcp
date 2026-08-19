"""
Pydantic models for type-safe MCP tool inputs and outputs.

Every tool, prompt, and resource in server_fastmcp.py uses one of these models
(or a list thereof) as its return type – plain dicts are not used.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ============================================================================
# Discovery / listing
# ============================================================================

class WorkspaceInfo(BaseModel):
    """A Power BI Service workspace."""
    id: str = Field(description="Workspace GUID")
    name: str = Field(description="Display name – use in workspace_name parameters")
    type: Optional[str] = Field(default="Workspace", description="Workspace type, e.g. Workspace / PersonalGroup")
    state: Optional[str] = Field(default="Active", description="Workspace state, e.g. Active / Deleted")


class DatasetInfo(BaseModel):
    """A Power BI dataset (semantic model) in a workspace."""
    id: str = Field(description="Dataset GUID")
    name: str = Field(description="Display name – use in dataset_name parameters")
    workspace_id: str = Field(description="Parent workspace GUID")
    configured_by: Optional[str] = Field(default="Unknown", description="Owner / configuring user")
    is_refreshable: bool = Field(default=False, description="Supports scheduled refresh")
    is_on_prem_gateway_required: bool = Field(default=False, description="Needs an on-premises gateway")


class TableInfo(BaseModel):
    """A table in a semantic model (from list_tables)."""
    name: str = Field(description="Table name – use verbatim in DAX")
    rows: int = Field(description="Row count (0 when not queried)")
    is_hidden: bool = Field(default=False, description="Hidden from report authors")


class ColumnInfo(BaseModel):
    """A column in a table (from list_columns)."""
    name: str = Field(description="Column name – use as 'Table'[Column] in DAX")
    data_type: str = Field(description="Data type: Int64, String, DateTime, Decimal, Boolean …")
    is_hidden: bool = Field(default=False, description="Hidden from report authors")
    description: Optional[str] = Field(default=None, description="Semantic description")


# ============================================================================
# DAX execution & validation
# ============================================================================

class DaxResult(BaseModel):
    """Result of a DAX query executed via execute_dax."""
    rows: List[Dict[str, Any]] = Field(description="Row dicts; each key is a column name")
    execution_time_ms: float = Field(description="Wall-clock query time in milliseconds")
    row_count: int = Field(description="Rows returned (after any truncation)")
    truncated: bool = Field(default=False, description="True if result was capped at max_rows")


class ValidationResult(BaseModel):
    """Result of a DAX syntax/semantic validation via validate_dax."""
    valid: bool = Field(description="True if the DAX is syntactically and semantically correct")
    error: Optional[str] = Field(default=None, description="Engine error message when valid=false")
    probe: Optional[str] = Field(default=None, description="Exact DAX probe submitted to the engine")


# ============================================================================
# Model exploration
# ============================================================================

class TableSummary(BaseModel):
    """Compact table entry returned by get_model_info."""
    name: str = Field(description="Table name")
    columns: int = Field(description="Total column count")
    measures: int = Field(description="Total measure count")
    top_measures: List[str] = Field(description="First 10 measure names (alphabetical)")


class ModelSummaryResult(BaseModel):
    """Return type of get_model_info."""
    dataset: str = Field(description="Dataset display name")
    workspace: str = Field(description="Workspace display name")
    tables: List[TableSummary] = Field(description="Visible tables with counts")
    relationships: int = Field(description="Total relationship count")


class ColumnDetail(BaseModel):
    """Column with full metadata, used inside TableDetail."""
    name: Optional[str] = Field(default=None)
    data_type: Optional[str] = Field(default=None)
    is_hidden: bool = Field(default=False)
    description: str = Field(default="")


class MeasureDetail(BaseModel):
    """Measure with DAX expression, used inside TableDetail."""
    name: Optional[str] = Field(default=None)
    table: Optional[str] = Field(default=None)
    expression: Optional[str] = Field(default=None)
    format_string: Optional[str] = Field(default=None)
    description: str = Field(default="")
    display_folder: Optional[str] = Field(default=None)
    is_hidden: bool = Field(default=False)
    data_type: Optional[str] = Field(default=None)


class TableDetail(BaseModel):
    """Table with full column and measure lists, used inside SemanticModel."""
    name: str = Field(description="Table name")
    is_hidden: bool = Field(default=False)
    description: str = Field(default="")
    columns: List[ColumnDetail] = Field(default_factory=list)
    measures: List[MeasureDetail] = Field(default_factory=list)


class RelationshipDetail(BaseModel):
    """Relationship between two tables."""
    from_table: Optional[str] = Field(default=None)
    from_column: Optional[str] = Field(default=None)
    to_table: Optional[str] = Field(default=None)
    to_column: Optional[str] = Field(default=None)
    is_active: Optional[Any] = Field(default=None)
    cross_filter: Optional[str] = Field(default=None)
    from_cardinality: Optional[str] = Field(default=None)
    to_cardinality: Optional[str] = Field(default=None)


class SemanticModel(BaseModel):
    """Full semantic model structure (tables + relationships)."""
    dataset: str
    tables: List[TableDetail]
    relationships: List[RelationshipDetail]


class SemanticModelDescription(BaseModel):
    """Return type of describe_semantic_model."""
    model: SemanticModel
    summary: str = Field(description="Human-readable count string")
    guidance: List[str] = Field(description="Agent workflow tips")


class CandidateMeasure(BaseModel):
    """A measure that matched a natural-language question (from answer_query_plan)."""
    table: str
    measure: str
    score: int = Field(description="Keyword relevance score")
    description: Optional[str] = Field(default=None)


class QueryPlan(BaseModel):
    """The planning section of an answer_query_plan result."""
    question: str
    candidate_measures: List[CandidateMeasure]
    draft_dax: Optional[str] = Field(default=None, description="Ready-to-run DAX query")
    recommendation: str = Field(description="use_existing_measure | generate_exploratory_dax")


class QueryPlanResult(BaseModel):
    """Return type of answer_query_plan."""
    plan: QueryPlan
    rows: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Query results when execute=true; empty list otherwise",
    )


# ============================================================================
# Model quality & BPA
# ============================================================================

class BpaFinding(BaseModel):
    """A single Best Practice Analyzer finding."""
    rule_id: str
    name: str
    category: str
    severity: str = Field(description="error | warning | info")
    object: str = Field(description="Table/measure/column that violated the rule")
    detail: Optional[str] = Field(default=None)


class BpaSummary(BaseModel):
    """Summary counts from a BPA run."""
    total: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    rules_run: int


class BpaRunResult(BaseModel):
    """Return type of run_bpa."""
    summary: BpaSummary
    findings: List[BpaFinding]


class AiReadinessMetrics(BaseModel):
    """Coverage percentages from audit_ai_readiness."""
    measures_total: int
    measures_with_description_pct: float
    measures_with_format_pct: float
    visible_columns_total: int
    columns_with_description_pct: float
    tables_total: int
    tables_with_description_pct: float


class AiReadinessResult(BaseModel):
    """Return type of audit_ai_readiness."""
    score: float = Field(description="0–100 composite score")
    grade: str = Field(description="Letter grade A–F")
    metrics: AiReadinessMetrics
    recommendations: List[str]


class DaxLintFinding(BaseModel):
    """A single DAX anti-pattern finding from dax_lint."""
    rule_id: str
    severity: str = Field(description="error | warning | info")
    message: str
    suggestion: Optional[str] = Field(default=None)
    line: Optional[int] = Field(default=None)
    object: Optional[str] = Field(default=None, description="Measure name")


class DaxLintSummary(BaseModel):
    """Summary counts from a dax_lint run."""
    total: int
    by_severity: Dict[str, int]
    by_rule: Dict[str, int]
    measures_scanned: int


class DaxLintResult(BaseModel):
    """Return type of dax_lint."""
    summary: DaxLintSummary
    findings: List[DaxLintFinding]


class DaxRewrite(BaseModel):
    """A concrete before/after rewrite hint from dax_suggest_rewrite."""
    rule_id: str
    line: Optional[int] = Field(default=None)
    before: str = Field(description="Original snippet")
    after: str = Field(description="Fixed replacement snippet")
    note: Optional[str] = Field(default=None, description="Why this change is safe")
    object: Optional[str] = Field(default=None, description="Measure name when from live model")


class DaxRewriteResult(BaseModel):
    """Return type of dax_suggest_rewrite."""
    rewrites: List[DaxRewrite]
    count: int


# ============================================================================
# Storage & performance
# ============================================================================

class TableStorageInfo(BaseModel):
    """Per-table storage stats from analyze_model_storage."""
    name: str
    row_count: Optional[int] = Field(default=None, description="null if COUNTROWS failed")
    column_count: int
    measure_count: int


class ModelStorageResult(BaseModel):
    """Return type of analyze_model_storage."""
    table_count: int
    total_rows: int
    tables: List[TableStorageInfo] = Field(description="Up to 50 tables, largest first")


class QueryPerfResult(BaseModel):
    """Return type of analyze_query_performance."""
    duration_ms: float
    row_count: int
    hints: List[str] = Field(description="Heuristic optimization advice strings")


class ModelDiffResult(BaseModel):
    """Return type of model_diff."""
    has_changes: bool
    total_changes: int
    summary: str = Field(description="Human-readable one-line summary")
    markdown: str = Field(description="Full diff in Markdown")


# ============================================================================
# Governance & deployment
# ============================================================================

class ReferentialViolation(BaseModel):
    """An orphan-key violation found by scan_referential_integrity."""
    relationship: str = Field(description="'FactTable[FK] -> DimTable[PK]' notation")
    orphan_keys: Optional[int] = Field(default=None)
    samples: Optional[List[Any]] = Field(default=None, description="Example orphan key values")
    error: Optional[str] = Field(default=None, description="Set if the check query failed")


class ReferentialIntegrityResult(BaseModel):
    """Return type of scan_referential_integrity."""
    checked: int
    violations: List[ReferentialViolation]
    clean: bool


class PreDeployGateResult(BaseModel):
    """Return type of pre_deploy_gate."""
    passed: bool
    bpa_errors: int
    bpa_warnings: int
    ai_score: float
    blocking: List[str] = Field(description="'rule_id: object' strings for blocking errors")


class BpaRuleIssue(BaseModel):
    """A structural issue found in a custom BPA rules JSON."""
    index: Optional[int] = Field(default=None)
    rule_id: Optional[str] = Field(default=None)
    message: str


class BpaValidateResult(BaseModel):
    """Return type of bpa_validate_rules."""
    valid: bool
    rule_count: int
    errors: List[BpaRuleIssue]
    warnings: List[BpaRuleIssue]
    fixed_json: Optional[str] = Field(default=None, description="Corrected JSON when fix=true")


class AuditIntegrityResult(BaseModel):
    """Return type of verify_audit_integrity."""
    valid: bool
    checked: int
    message: Optional[str] = Field(default=None)
    broken_line: Optional[int] = Field(default=None, description="Line where chain breaks (if tampered)")


# ============================================================================
# Diagnostics & ops
# ============================================================================

class RefreshDiagnosis(BaseModel):
    """Root-cause classification for a refresh failure."""
    id: Optional[str] = Field(default=None)
    cause: str
    remediation: str
    matched: bool


class RefreshDoctorResult(BaseModel):
    """Return type of refresh_doctor."""
    completed: int
    failed: int
    consecutive_failures: int
    most_recent_status: Optional[str] = Field(default=None)
    most_recent_end: Optional[str] = Field(default=None)
    diagnosis: Optional[RefreshDiagnosis] = Field(default=None)
    warning: Optional[str] = Field(default=None)


class UnusedObjectsResult(BaseModel):
    """Return type of find_unused_objects."""
    unused_measures: Optional[List[str]] = Field(default=None)
    unused_columns: Optional[List[str]] = Field(default=None)
    note: Optional[str] = Field(default=None)
    error: Optional[str] = Field(default=None, description="Set when INFO.CALCDEPENDENCY is unavailable")


class DependentObject(BaseModel):
    """An object that depends on the queried measure/column (from impact_analysis)."""
    type: Optional[str] = Field(default=None)
    table: Optional[str] = Field(default=None)
    object: Optional[str] = Field(default=None)


class ImpactAnalysisResult(BaseModel):
    """Return type of impact_analysis."""
    object_name: str
    table_name: Optional[str] = Field(default=None)
    dependent_count: Optional[int] = Field(default=None)
    dependents: Optional[List[DependentObject]] = Field(default=None)
    safe_to_change: Optional[bool] = Field(default=None)
    error: Optional[str] = Field(default=None, description="Set when INFO.CALCDEPENDENCY is unavailable")


class DaxTestCaseResult(BaseModel):
    """Result of a single DAX test case."""
    name: str
    status: str = Field(description="PASS | FAIL | INFO | ERROR")
    detail: Optional[str] = Field(default=None)


class DaxTestRunResult(BaseModel):
    """Return type of run_dax_tests."""
    passed: int
    total: int
    all_passed: bool
    results: List[DaxTestCaseResult]


# ============================================================================
# Fleet / governance ops
# ============================================================================

class CrossWorkspaceLineageResult(BaseModel):
    """Return type of cross_workspace_lineage and summarize_security_scan."""
    workspaces: int
    datasets: int
    reports: int
    datasets_without_rls: List[str] = Field(description="'Workspace/Dataset' strings without RLS roles")
    datasets_without_sensitivity_label: List[str] = Field(description="'Workspace/Dataset' strings without a label")
    focus_dataset: Optional[str] = Field(default=None)
    focus_found_in: Optional[List[str]] = Field(default=None)
    downstream_reports: Optional[List[str]] = Field(default=None)


class RefreshFailure(BaseModel):
    """A dataset whose last refresh failed (from fleet_refresh_monitor)."""
    dataset: str
    end_time: Optional[str] = Field(default=None)
    cause: str


class FleetRefreshResult(BaseModel):
    """Return type of fleet_refresh_monitor."""
    checked: int
    failed_count: int
    failures: List[RefreshFailure]


class ActivityCount(BaseModel):
    """Name + count pair used in usage analytics results."""
    name: str = Field(description="Activity type, user id, or report name")
    count: int


class UsageAnalyticsResult(BaseModel):
    """Return type of usage_and_orphan_analytics and aggregate_user_activity."""
    total_events: int
    distinct_users: int
    by_activity: List[ActivityCount] = Field(description="Event counts per activity type, sorted desc")
    top_users: List[ActivityCount] = Field(description="Most active users, sorted desc")
    top_reports_by_views: List[ActivityCount] = Field(description="Most-viewed report names, sorted desc")


# ============================================================================
# Security & audit
# ============================================================================

class SecurityStatus(BaseModel):
    """Runtime security configuration of the MCP server session."""
    pii_detection_enabled: bool
    audit_logging_enabled: bool
    access_policies_enabled: bool
    active_policies: List[str] = Field(description="Table names that have at least one column policy")


class AuditEvent(BaseModel):
    """A single entry from the security audit log (flexible schema)."""
    model_config = {"extra": "allow"}

    timestamp: str = Field(description="ISO-8601 timestamp")
    session_id: Optional[str] = Field(default=None)
    event_type: Optional[str] = Field(default=None)
    severity: Optional[str] = Field(default=None)
    message: Optional[str] = Field(default=None)
    details: Optional[Dict[str, Any]] = Field(default=None)


# ============================================================================
# DAX generation
# ============================================================================

class MeasureDefinition(BaseModel):
    """A generated DAX measure (from generate_measure_suite)."""
    name: str = Field(description="Display name for the measure")
    expression: str = Field(description="DAX scalar expression (without the '[Name] =' prefix)")
    format_string: Optional[str] = Field(default=None, description="e.g. '#,##0', '0.0%'")
    description: Optional[str] = Field(default=None, description="Plain-language description for Copilot")
    display_folder: Optional[str] = Field(default=None, description="Fields pane folder")


# ============================================================================
# Legacy aliases kept for backward compatibility
# ============================================================================

MeasureInfo = MeasureDefinition          # ponytail: same shape, old name kept
RelationshipInfo = RelationshipDetail    # ponytail: same shape, old name kept
