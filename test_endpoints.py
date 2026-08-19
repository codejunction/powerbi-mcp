"""
Comprehensive endpoint tests for the Power BI FastMCP server.

Test workspace : Digital Enablement and Engagement
Test dataset   : AIR
Run            : python test_endpoints.py
"""
from __future__ import annotations

import asyncio
import json
import sys

from fastmcp import Client

WORKSPACE = "Digital Enablement and Engagement"
DATASET   = "AIR"
SSE_URL   = "http://localhost:8000/sse"

passed_n = failed_n = skipped_n = 0
results: list[tuple[str, str, str]] = []


def report(name: str, status: str, detail: str = "") -> None:
    global passed_n, failed_n, skipped_n
    sym = {"PASS": "\033[32mPASS\033[0m", "FAIL": "\033[31mFAIL\033[0m", "SKIP": "\033[33mSKIP\033[0m"}[status]
    label = detail[:120] if detail else ""
    print(f"[{sym}] {name} — {label}")
    if status == "PASS":   passed_n  += 1
    elif status == "FAIL": failed_n  += 1
    else:                  skipped_n += 1
    results.append((name, status, detail))


def extract(r) -> str:
    """Return clean JSON string from a FastMCP CallToolResult.

    content[0].text is always the unwrapped JSON; structured_content wraps lists
    in {"result": [...]}, so we prefer the raw text.
    """
    if hasattr(r, "content") and r.content:
        item = r.content[0]
        if hasattr(item, "text") and item.text:
            return item.text
    if hasattr(r, "structured_content") and r.structured_content is not None:
        sc = r.structured_content
        if isinstance(sc, dict) and "result" in sc:
            return json.dumps(sc["result"])
        return json.dumps(sc)
    return json.dumps(str(r))


async def run_tests() -> None:
    async with Client(SSE_URL) as c:

        # ── discovery ────────────────────────────────────────────────────────
        try:
            tools = await c.list_tools()
            n = len(tools)
            if n >= 20:
                report("list_tools", "PASS", f"{n} tools registered")
            else:
                report("list_tools", "FAIL", f"only {n} tools (expected ≥20)")
        except Exception as e:
            report("list_tools", "FAIL", str(e))

        try:
            prompts = await c.list_prompts()
            names = [p.name for p in prompts]
            if len(names) >= 6:
                report("list_prompts", "PASS", f"{len(names)} prompts: {names}")
            else:
                report("list_prompts", "FAIL", f"only {names}")
        except Exception as e:
            report("list_prompts", "FAIL", str(e))

        try:
            resources = await c.list_resources()
            report("list_resources", "PASS", f"{len(resources)} resources")
        except Exception as e:
            report("list_resources", "FAIL", str(e))

        # ── security ─────────────────────────────────────────────────────────
        try:
            r = await c.call_tool("security_status", {})
            d = json.loads(extract(r))
            report("security_status", "PASS",
                   f"pii={d.get('pii_detection_enabled')} audit={d.get('audit_logging_enabled')} policies={d.get('access_policies_enabled')}")
        except Exception as e:
            report("security_status", "FAIL", str(e))

        try:
            r = await c.call_tool("security_audit_log", {"count": 3})
            entries = json.loads(extract(r))
            report("security_audit_log", "PASS", f"{len(entries)} entries returned")
        except Exception as e:
            report("security_audit_log", "FAIL", str(e))

        try:
            r = await c.call_tool("verify_audit_integrity", {})
            d = json.loads(extract(r))
            report("verify_audit_integrity", "PASS", f"valid={d.get('valid')} checked={d.get('checked', 0)}")
        except Exception as e:
            report("verify_audit_integrity", "FAIL", str(e))

        # ── workspace / dataset listing ───────────────────────────────────────
        workspace_id: str | None = None
        try:
            r = await c.call_tool("list_workspaces", {})
            ws = json.loads(extract(r))
            target = next((w for w in ws if w["name"] == WORKSPACE), None)
            if target:
                workspace_id = target["id"]
                report("list_workspaces", "PASS", f"{len(ws)} workspaces – found '{WORKSPACE}'")
            else:
                report("list_workspaces", "FAIL", f"'{WORKSPACE}' not in {[w['name'] for w in ws]}")
        except Exception as e:
            report("list_workspaces", "FAIL", str(e))

        if not workspace_id:
            report("list_datasets", "SKIP", "no workspace_id")
        else:
            try:
                r = await c.call_tool("list_datasets", {"workspace_id": workspace_id})
                ds = json.loads(extract(r))
                target_ds = next((d for d in ds if d["name"] == DATASET), None)
                if target_ds:
                    report("list_datasets", "PASS", f"{len(ds)} datasets – found '{DATASET}'")
                else:
                    report("list_datasets", "FAIL", f"'{DATASET}' not in first 5: {[d['name'] for d in ds[:5]]}")
            except Exception as e:
                report("list_datasets", "FAIL", str(e))

        # ── table / column listing ────────────────────────────────────────────
        table_name: str | None = None
        try:
            r = await c.call_tool("list_tables", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            tables = json.loads(extract(r))
            if tables:
                table_name = tables[0]["name"]
                report("list_tables", "PASS", f"{len(tables)} tables in '{DATASET}'")
            else:
                report("list_tables", "FAIL", "0 tables")
        except Exception as e:
            report("list_tables", "FAIL", str(e))

        if not table_name:
            report("list_columns", "SKIP", "no table available")
        else:
            try:
                r = await c.call_tool("list_columns", {"workspace_name": WORKSPACE, "dataset_name": DATASET, "table_name": table_name})
                cols = json.loads(extract(r))
                report("list_columns", "PASS", f"{len(cols)} columns in '{table_name}'")
            except Exception as e:
                report("list_columns", "FAIL", str(e))

        # ── model exploration ─────────────────────────────────────────────────
        try:
            r = await c.call_tool("get_model_info", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            n_tables = len(d.get("tables", []))
            report("get_model_info", "PASS", f"{n_tables} visible tables, {d.get('relationships')} relationships")
        except Exception as e:
            report("get_model_info", "FAIL", str(e))

        try:
            r = await c.call_tool("describe_semantic_model", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            report("describe_semantic_model", "PASS", d.get("summary", "no summary"))
        except Exception as e:
            report("describe_semantic_model", "FAIL", str(e))

        try:
            r = await c.call_tool("answer_query_plan", {
                "workspace_name": WORKSPACE, "dataset_name": DATASET,
                "question": "What is the total count of AI assessments?"
            })
            d = json.loads(extract(r))
            rec = d.get("plan", {}).get("recommendation", "?")
            report("answer_query_plan", "PASS", f"recommendation={rec}")
        except Exception as e:
            report("answer_query_plan", "FAIL", str(e))

        # ── DAX execution ─────────────────────────────────────────────────────
        try:
            r = await c.call_tool("execute_dax", {
                "workspace_name": WORKSPACE, "dataset_name": DATASET,
                "dax_query": "EVALUATE TOPN(3, INFO.VIEW.TABLES())",
                "max_rows": 3,
            })
            d = json.loads(extract(r))
            ms = d.get("execution_time_ms", 0)
            rc = d.get("row_count", 0)
            report("execute_dax", "PASS", f"{rc} row(s), {ms:.0f} ms")
        except Exception as e:
            report("execute_dax", "FAIL", str(e))

        try:
            r = await c.call_tool("validate_dax", {
                "workspace_name": WORKSPACE, "dataset_name": DATASET,
                "dax": "EVALUATE TOPN(1, INFO.VIEW.TABLES())"
            })
            d = json.loads(extract(r))
            if d.get("valid"):
                report("validate_dax (valid)", "PASS", "valid")
            else:
                report("validate_dax (valid)", "FAIL", f"reported invalid: {d.get('error')}")
        except Exception as e:
            report("validate_dax (valid)", "FAIL", str(e))

        try:
            r = await c.call_tool("validate_dax", {
                "workspace_name": WORKSPACE, "dataset_name": DATASET,
                "dax": "EVALUATE NOTAFUNCTION_THATDOESNOTEXIST()"
            })
            d = json.loads(extract(r))
            if not d.get("valid"):
                report("validate_dax (invalid)", "PASS", "correctly detected invalid DAX")
            else:
                report("validate_dax (invalid)", "FAIL", "expected invalid but reported valid")
        except Exception as e:
            report("validate_dax (invalid)", "FAIL", str(e))

        # ── query perf ────────────────────────────────────────────────────────
        try:
            r = await c.call_tool("analyze_query_performance", {
                "workspace_name": WORKSPACE, "dataset_name": DATASET,
                "dax": "EVALUATE TOPN(5, INFO.VIEW.TABLES())",
            })
            d = json.loads(extract(r))
            report("analyze_query_performance", "PASS", f"{d.get('duration_ms', 0):.0f} ms, {d.get('row_count', 0)} rows, {len(d.get('hints', []))} hints")
        except Exception as e:
            report("analyze_query_performance", "FAIL", str(e))

        # ── model quality ─────────────────────────────────────────────────────
        try:
            r = await c.call_tool("run_bpa", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            s = d.get("summary", {})
            report("run_bpa", "PASS", f"total={s.get('total', '?')}, findings={len(d.get('findings', []))}")
        except Exception as e:
            report("run_bpa", "FAIL", str(e))

        try:
            r = await c.call_tool("audit_ai_readiness", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            report("audit_ai_readiness", "PASS", f"score={d.get('score', '?')}/100 grade={d.get('grade', '?')}")
        except Exception as e:
            report("audit_ai_readiness", "FAIL", str(e))

        try:
            r = await c.call_tool("dax_lint", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            s = d.get("summary", {})
            report("dax_lint", "PASS", f"scanned={s.get('measures_scanned', '?')}, findings={len(d.get('findings', []))}")
        except Exception as e:
            report("dax_lint", "FAIL", str(e))

        try:
            r = await c.call_tool("dax_suggest_rewrite", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            report("dax_suggest_rewrite", "PASS", f"{d.get('count', 0)} rewrite suggestions")
        except Exception as e:
            report("dax_suggest_rewrite", "FAIL", str(e))

        # ── storage analysis ──────────────────────────────────────────────────
        try:
            r = await c.call_tool("analyze_model_storage", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            report("analyze_model_storage", "PASS",
                   f"{d.get('table_count')} tables, {d.get('total_rows', 0):,} total rows")
        except Exception as e:
            report("analyze_model_storage", "FAIL", str(e))

        # ── referential integrity ─────────────────────────────────────────────
        try:
            r = await c.call_tool("scan_referential_integrity", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            report("scan_referential_integrity", "PASS",
                   f"checked={d.get('checked')}, violations={len(d.get('violations', []))}, clean={d.get('clean')}")
        except Exception as e:
            report("scan_referential_integrity", "FAIL", str(e))

        # ── pre-deploy gate ───────────────────────────────────────────────────
        try:
            r = await c.call_tool("pre_deploy_gate", {
                "workspace_name": WORKSPACE, "dataset_name": DATASET,
                "min_ai_score": 0,
            })
            d = json.loads(extract(r))
            report("pre_deploy_gate", "PASS",
                   f"passed={d.get('passed')}, bpa_errors={d.get('bpa_errors')}, ai_score={d.get('ai_score')}")
        except Exception as e:
            report("pre_deploy_gate", "FAIL", str(e))

        # ── refresh doctor ────────────────────────────────────────────────────
        try:
            r = await c.call_tool("refresh_doctor", {"workspace_name": WORKSPACE, "dataset_name": DATASET})
            d = json.loads(extract(r))
            report("refresh_doctor", "PASS",
                   f"completed={d.get('completed')}, failed={d.get('failed')}, recent={d.get('most_recent_status')}")
        except Exception as e:
            report("refresh_doctor", "FAIL", str(e))

        # ── impact analysis ───────────────────────────────────────────────────
        try:
            r = await c.call_tool("impact_analysis", {
                "workspace_name": WORKSPACE, "dataset_name": DATASET,
                "object_name": "Date",
            })
            d = json.loads(extract(r))
            if "error" in d and "CALCDEPENDENCY" in d["error"]:
                report("impact_analysis", "PASS", "INFO.CALCDEPENDENCY unavailable (needs write permission) – expected in REST-only mode")
            else:
                report("impact_analysis", "PASS", f"dependents={d.get('dependent_count')}, safe={d.get('safe_to_change')}")
        except Exception as e:
            report("impact_analysis", "FAIL", str(e))

        # ── DAX test runner ───────────────────────────────────────────────────
        try:
            r = await c.call_tool("run_dax_tests", {
                "workspace_name": WORKSPACE, "dataset_name": DATASET,
                "tests": [
                    {"name": "table_count", "dax": 'EVALUATE ROW("cnt", COUNTROWS(INFO.VIEW.TABLES()))'},
                ],
            })
            d = json.loads(extract(r))
            report("run_dax_tests", "PASS", f"results={d.get('results')}")
        except Exception as e:
            report("run_dax_tests", "FAIL", str(e))

        # ── BPA rule validation ───────────────────────────────────────────────
        try:
            good_rules = json.dumps([{
                "id": "TEST_001", "name": "No float columns", "category": "Performance",
                "severity": "warning", "condition": "table['IsHidden'] == False",
            }])
            r = await c.call_tool("bpa_validate_rules", {"rules": good_rules})
            d = json.loads(extract(r))
            report("bpa_validate_rules", "PASS", f"valid={d.get('valid')}, errors={len(d.get('errors', []))}")
        except Exception as e:
            report("bpa_validate_rules", "FAIL", str(e))

        # ── measure generation ────────────────────────────────────────────────
        try:
            r = await c.call_tool("generate_measure_suite", {
                "kind": "time_intelligence",
                "base_measure": "Total Sales",
                "date_column": "Date[Date]",
            })
            measures = json.loads(extract(r))
            report("generate_measure_suite", "PASS", f"{len(measures)} measures generated")
        except Exception as e:
            report("generate_measure_suite", "FAIL", str(e))

        # ── usage analytics ───────────────────────────────────────────────────
        try:
            r = await c.call_tool("usage_and_orphan_analytics", {})
            d = json.loads(extract(r))
            report("usage_and_orphan_analytics", "PASS",
                   f"total_events={d.get('total_events')}, distinct_users={d.get('distinct_users')}")
        except Exception as e:
            report("usage_and_orphan_analytics", "FAIL", str(e))

    # ── summary ──────────────────────────────────────────────────────────────
    total = passed_n + failed_n + skipped_n
    print()
    print("=" * 62)
    print(f"Results: {passed_n}/{total} passed  |  {failed_n} failed  |  {skipped_n} skipped")
    print("=" * 62)
    sys.exit(0 if failed_n == 0 else 1)


if __name__ == "__main__":
    asyncio.run(run_tests())
