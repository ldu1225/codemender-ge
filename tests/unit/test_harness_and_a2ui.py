# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the CodeMender 3-Stage Harness, A2UI v0.9 renderer, HITL patching, and FastAPI security."""

import subprocess
import sys
from pathlib import Path

from a2ui.parser.parser import parse_response
from fastapi.testclient import TestClient
from google.adk.a2a import _compat
from google.adk.events.event import Event
from google.genai import types as genai_types

from app.a2ui_renderer.action_handler import (
    extract_a2ui_action_from_parts,
    handle_a2ui_patch_action,
)
from app.a2ui_renderer.schema_manager import (
    CATALOG_BASIC,
    CATALOG_CODEMENDER_MATERIAL,
    CodeMenderA2uiEventConverter,
    format_a2ui_delimited_text,
    validate_a2ui_payload,
)
from app.a2ui_renderer.surface_builder import (
    build_patch_applied_surface,
    build_scan_report_surface,
    build_upload_prompt_surface,
)
from app.fast_api_app import app as fastapi_app
from app.harness.cm_runner import CodeMenderRunner
from app.ingestion.file_manager import (
    cleanup_workspace,
    get_or_create_workspace,
    ingest_bytes_into_workspace,
)


VULNERABLE_AND_SAFE_PYTHON = """import sqlite3
import subprocess

def get_user_unsafe(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchall()

def get_user_safe_parameterized(cursor, user_id):
    # Safe parameterized query that must be filtered as a False Positive in Stage 2
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

def ping_host_unsafe(host):
    return subprocess.run(f"ping {host}", shell=True, check=False)
"""


def test_3stage_harness_filters_false_positives_and_patches_true_positives(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    ws = get_or_create_workspace("sess-harness")
    try:
        ingest_bytes_into_workspace(
            ws, "db.py", VULNERABLE_AND_SAFE_PYTHON.encode("utf-8")
        )
        runner = CodeMenderRunner(model_name="gemini-3.8-flash")
        report = runner.run_pipeline(ws)

        # Stage 1 finds 3 candidates (unsafe SQL, safe parameterized SQL, unsafe subprocess)
        assert report.total_candidates_found >= 3

        # Stage 2 filters out the safe parameterized SQL query as a False Positive!
        assert report.false_positives_filtered >= 1
        fp_cwes = [fp["cwe_id"] for fp in report.filtered_candidates]
        assert "CWE-89" in fp_cwes

        # Verified findings only include True Positives (CWE-89 unsafe f-string & CWE-78 shell=True)
        verified_cwes = {v.cwe_id for v in report.findings}
        assert "CWE-89" in verified_cwes
        assert "CWE-78" in verified_cwes

        for finding in report.findings:
            assert finding.verified is True
            assert finding.is_false_positive is False
            assert finding.remediation_verified is True
            assert "--- a/db.py" in finding.unified_diff
            assert "+++ b/db.py" in finding.unified_diff
            assert finding.judge_verdict == "PASS"
    finally:
        cleanup_workspace(ws)


def test_a2ui_v09_dual_catalog_validation_and_event_converter(monkeypatch) -> None:
    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    ws = get_or_create_workspace("sess-a2ui")
    try:
        ingest_bytes_into_workspace(
            ws, "app.py", VULNERABLE_AND_SAFE_PYTHON.encode("utf-8")
        )
        runner = CodeMenderRunner(model_name="gemini-3.8-flash")
        report = runner.run_pipeline(ws)

        for catalog_mode in (CATALOG_CODEMENDER_MATERIAL, CATALOG_BASIC):
            upload_payload = build_upload_prompt_surface(catalog_mode=catalog_mode)
            validate_a2ui_payload(upload_payload, catalog_mode=catalog_mode)

            scan_payload = build_scan_report_surface(
                report, catalog_mode=catalog_mode
            )
            validate_a2ui_payload(scan_payload, catalog_mode=catalog_mode)

            applied_payload = build_patch_applied_surface(
                report,
                applied_files=[
                    {
                        "file_path": "app.py",
                        "sha256": "deadbeef1234567890",
                        "patched_content": "# patched\n",
                    }
                ],
                catalog_mode=catalog_mode,
            )
            validate_a2ui_payload(applied_payload, catalog_mode=catalog_mode)

            # Verify <a2ui-json> serialization and A2A DataPart conversion (v0.9 mimeType)
            delimited = format_a2ui_delimited_text(scan_payload)
            full_text = f"CodeMender summary text\n\n{delimited}"
            parsed = parse_response(full_text)
            assert len(parsed) == 1
            assert isinstance(parsed[0].a2ui_json, list)
            assert parsed[0].a2ui_json[0]["version"] == "v0.9"

            converter = CodeMenderA2uiEventConverter(catalog_mode=catalog_mode)
            adk_event = Event(
                author="codemender_security_agent",
                content=genai_types.Content(
                    role="model",
                    parts=[genai_types.Part.from_text(text=full_text)],
                ),
            )
            a2a_parts = converter.convert_event_to_parts(
                adk_event, catalog_mode=catalog_mode
            )
            # Should produce 1 text Part and 3 A2UI DataParts (createSurface + updateComponents + updateDataModel)
            assert len(a2a_parts) == 4
            a2ui_data_parts = [
                p
                for p in a2a_parts
                if _compat.part_metadata(p).get("mimeType") == "application/json+a2ui"
            ]
            assert len(a2ui_data_parts) == 3
    finally:
        cleanup_workspace(ws)


def test_hitl_apply_patch_action_updates_workspace_file(monkeypatch) -> None:
    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    ws = get_or_create_workspace("sess-patch")
    try:
        ingest_bytes_into_workspace(
            ws, "vuln.py", VULNERABLE_AND_SAFE_PYTHON.encode("utf-8")
        )
        runner = CodeMenderRunner(model_name="gemini-3.8-flash")
        report = runner.run_pipeline(ws)
        report_dict = report.to_dict()

        target_vid = report.findings[0].vuln_id
        action_part = genai_types.Part.from_text(
            text=f'{{"a2ui_action": {{"name": "apply_patch", "context": {{"vuln_id": "{target_vid}"}}}}}}'
        )
        extracted = extract_a2ui_action_from_parts([action_part])
        assert extracted is not None
        assert extracted["name"] == "apply_patch"
        assert extracted["context"]["vuln_id"] == target_vid

        outcome = handle_a2ui_patch_action(
            action_name=extracted["name"],
            action_context=extracted["context"],
            workspace=ws,
            pipeline_result_dict=report_dict,
            catalog_mode=CATALOG_CODEMENDER_MATERIAL,
        )
        assert len(outcome["applied_files"]) == 1
        patched_file = Path(ws.patched_dir) / "vuln.py"
        assert "WHERE id = ?" in patched_file.read_text(encoding="utf-8")
        validate_a2ui_payload(
            outcome["a2ui_messages"], catalog_mode=CATALOG_CODEMENDER_MATERIAL
        )
    finally:
        cleanup_workspace(ws)


def test_cm_cli_subcommands(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    vuln_file = tmp_path / "sample.py"
    vuln_file.write_text(VULNERABLE_AND_SAFE_PYTHON, encoding="utf-8")

    for subcmd in ("find", "verify", "fix"):
        proc = subprocess.run(
            [
                sys.executable,
                "bin/cm",
                subcmd,
                str(tmp_path),
                "--model",
                "gemini-3.8-flash",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert proc.returncode == 0
        assert "CWE-89" in proc.stdout


def test_fastapi_security_headers_and_method_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    with TestClient(fastapi_app) as client:
        resp = client.get("/a2a/app/.well-known/agent-card.json")
        assert resp.status_code == 200
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")

        card = resp.json()
        assert "application/json+a2ui" in card.get("defaultOutputModes", [])
        extensions = card.get("capabilities", {}).get("extensions", [])
        assert any(
            ext.get("uri") == "https://a2ui.org/a2a-extension/a2ui/v0.9"
            for ext in extensions
        )

        # Disallowed HTTP verb (e.g., DELETE) must return 405
        del_resp = client.delete("/a2a/app/.well-known/agent-card.json")
        assert del_resp.status_code == 405

        # Test v0.3 A2A JSON-RPC message/send ("안녕" + a2uiClientCapabilities DataPart) as sent by Gemini Enterprise Web UI
        rpc_resp = client.post(
            "/a2a/app",
            json={
                "jsonrpc": "2.0",
                "id": "ge-test-1",
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": "msg-hello-1",
                        "role": "user",
                        "parts": [
                            {"kind": "text", "text": "안녕"},
                            {
                                "kind": "data",
                                "data": {
                                    "a2uiClientCapabilities": {
                                        "supportedCatalogIds": [
                                            "https://a2ui.org/specification/v0_9/basic_catalog.json"
                                        ]
                                    }
                                },
                            },
                        ],
                    }
                },
            },
        )
        assert rpc_resp.status_code == 200
        rpc_data = rpc_resp.json()
        task_res = rpc_data["result"]
        assert task_res["status"]["state"] == "completed"
        # Ensure status.message is omitted on terminal event so GE Web UI does not render duplicate bubbles
        assert task_res["status"].get("message") is None
        artifact_parts = task_res["artifacts"][0]["parts"]
        assert len(artifact_parts) == 1
        assert artifact_parts[0]["kind"] == "text"
        assert "CodeMender Security Agent" in artifact_parts[0]["text"]
        assert "Extension ''" not in artifact_parts[0]["text"]


def test_agent_e2e_upload_scan_and_hitl_patch_flow(monkeypatch) -> None:
    from google.adk.artifacts import InMemoryArtifactService
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService

    from app.agent import app as adk_app

    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    session_service = InMemorySessionService()
    artifact_service = InMemoryArtifactService()
    session = session_service.create_session_sync(
        user_id="ge_user", app_name=adk_app.name
    )
    runner = Runner(
        app=adk_app,
        session_service=session_service,
        artifact_service=artifact_service,
    )

    # 1. Greeting without attachment -> clean Markdown onboarding guide
    msg1 = genai_types.Content(
        role="user",
        parts=[genai_types.Part.from_text(text="안녕! 코드 취약점 진단해줘")],
    )
    events1 = list(
        runner.run(user_id="ge_user", session_id=session.id, new_message=msg1)
    )
    assert events1
    text1 = events1[-1].content.parts[0].text
    assert "CodeMender Security Agent" in text1
    assert "<a2ui-json>" not in text1

    # 2. Direct file upload (inline_data) -> 3-Stage Harness scan + clean Markdown report (NO unsolicited cost clutter)
    msg2 = genai_types.Content(
        role="user",
        parts=[
            genai_types.Part.from_text(text="이 파일 보안 진단해줘"),
            genai_types.Part(
                inline_data=genai_types.Blob(
                    data=VULNERABLE_AND_SAFE_PYTHON.encode("utf-8"),
                    mime_type="text/x-python",
                    display_name="payment_service.py",
                )
            ),
        ],
    )
    events2 = list(
        runner.run(user_id="ge_user", session_id=session.id, new_message=msg2)
    )
    assert events2
    text2 = events2[-1].content.parts[0].text
    assert "CM-CWE-89-001" in text2
    assert "CM-CWE-78-002" in text2
    assert "이번 실행 비용 (USD / KRW)" not in text2
    assert "CodeMender 단계별 비용 및 토큰 추적" not in text2

    # 3. HITL patch action ("패치 적용") -> applies patch & saves modified artifact (silently records Stage 4 cost)
    msg3 = genai_types.Content(
        role="user",
        parts=[
            genai_types.Part.from_text(
                text="CM-CWE-89-001 패치 적용"
            )
        ],
    )
    events3 = list(
        runner.run(user_id="ge_user", session_id=session.id, new_message=msg3)
    )
    assert events3
    text3 = events3[-1].content.parts[0].text
    assert "PATCH APPLIED" in text3 or "보안 패치 적용 완료" in text3
    assert "payment_service.py" in text3
    assert "이번 실행 비용 (USD / KRW)" not in text3
    import asyncio

    saved_keys = asyncio.run(
        artifact_service.list_artifact_keys(
            app_name=adk_app.name, user_id="ge_user", session_id=session.id
        )
    )
    assert "patched_payment_service.py" in saved_keys

    # 4. On-Demand Cost Query ("몇월 며칠까지 얼마 비용 청구됐어? 각 세션이랑 트랜잭션마다 비용이 얼마나 나왔는지 알려줘")
    msg4 = genai_types.Content(
        role="user",
        parts=[
            genai_types.Part.from_text(
                text="몇월 며칠까지 얼마 비용 청구됐어? 각 세션이랑 트랜잭션마다 비용이 얼마나 나왔는지 알려줘"
            )
        ],
    )
    events4 = list(
        runner.run(user_id="ge_user", session_id=session.id, new_message=msg4)
    )
    assert events4
    text4 = events4[-1].content.parts[0].text
    assert "총 누적 청구(발생) 예상 금액" in text4
    assert "각 세션(Session)별 비용 정산 내역" in text4
    assert "각 트랜잭션(Transaction / 개별 작업 실행)별 상세 비용 내역" in text4
    assert "USD" in text4 and "KRW" in text4


def test_full_cm_command_suite_in_agent_session(monkeypatch) -> None:
    """Verifies all 12 CodeMender (`cm` v0.12.0) commands + on-demand-only cost tracking in an interactive session."""
    from google.adk.artifacts import InMemoryArtifactService
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService

    from app.agent import app as adk_app

    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    session_service = InMemorySessionService()
    artifact_service = InMemoryArtifactService()
    session = session_service.create_session_sync(
        user_id="ge_power_user", app_name=adk_app.name
    )
    runner = Runner(
        app=adk_app,
        session_service=session_service,
        artifact_service=artifact_service,
    )

    def _chat(prompt_text: str) -> str:
        msg = genai_types.Content(
            role="user",
            parts=[genai_types.Part.from_text(text=prompt_text)],
        )
        evs = list(
            runner.run(
                user_id="ge_power_user", session_id=session.id, new_message=msg
            )
        )
        assert evs
        return evs[-1].content.parts[0].text

    # 1. cm init --verify (no unsolicited cost footer)
    out_init = _chat("cm init --verify")
    assert "config.yaml" in out_init
    assert "cm init" in out_init
    assert "CodeMender 실행 비용 추적" not in out_init

    # 2. cm find (no unsolicited cost line)
    out_find = _chat("cm find")
    assert "CM-CWE-89-001" in out_find
    assert "DISMISSED (FP)" in out_find
    assert "파이프라인 실행 비용" not in out_find

    # 3. cm verify 1 (no unsolicited cost footer)
    out_verify = _chat("cm verify 1")
    assert "VERIFIED (98%)" in out_verify
    assert ".exploit/verify_" in out_verify
    assert "CodeMender 실행 비용 추적" not in out_verify

    # 4. cm triage (before fix -> BLOCKED, no unsolicited cost footer)
    out_triage_before = _chat("cm triage")
    assert "BLOCKED" in out_triage_before
    assert "CodeMender 실행 비용 추적" not in out_triage_before

    # 5. cm fix 1 -c "SQL 파라미터 바인딩 감사 주석 추가" (no unsolicited cost table)
    out_fix_ctx = _chat('cm fix 1 -c "SQL 파라미터 바인딩 감사 주석 추가"')
    assert "PATCH APPLIED" in out_fix_ctx
    assert "SQL 파라미터 바인딩 감사 주석 추가" in out_fix_ctx
    assert "이번 실행 비용 (USD / KRW)" not in out_fix_ctx

    # 6. cm vcs status & cm vcs diff & cm vcs stage
    out_vcs_status = _chat("cm vcs status")
    assert "MODIFIED" in out_vcs_status

    out_vcs_diff = _chat("cm vcs diff")
    assert "--- a/sample_payment_service.py" in out_vcs_diff

    out_vcs_stage = _chat("cm vcs stage")
    assert "Pull Request" in out_vcs_stage

    # 7. cm build
    out_build = _chat("cm build")
    assert "BUILD SUCCEEDED" in out_build
    assert "py_compile" in out_build

    # 8. cm report -f json & cm report -f html
    out_rep_json = _chat("cm report -f json")
    assert '"FindingID": 1' in out_rep_json
    assert '"Status": "FIXED"' in out_rep_json
    assert '"cost_telemetry"' in out_rep_json

    out_rep_html = _chat("cm report -f html")
    assert "codemender-report.html" in out_rep_html

    # 9. On-demand cost queries: cm stats / cm cost / cm logs / 비용 조회, cm sessions, cm artifacts
    out_stats = _chat("cm stats")
    assert "토큰" in out_stats
    assert "현재 세션 누적" in out_stats
    assert "각 세션(Session)별 비용 정산 내역" in out_stats
    assert "각 트랜잭션(Transaction / 개별 작업 실행)별 상세 비용 내역" in out_stats
    assert "Cloud Logging" in out_stats

    out_cost_nl = _chat("비용 조회")
    assert "텔레메트리 대시보드" in out_cost_nl
    assert "총 누적 청구(발생) 예상 금액" in out_cost_nl
    assert "CODEMENDER_COST_TELEMETRY" in out_cost_nl
    assert "USD" in out_cost_nl and "KRW" in out_cost_nl

    out_logs = _chat("cm logs")
    assert "run.googleapis.com/stdout" in out_logs
    assert "run.googleapis.com/requests" in out_logs

    out_sessions = _chat("cm sessions")
    assert "cm init --verify" in out_sessions
    assert "비용 (USD / KRW)" in out_sessions

    out_artifacts = _chat("cm artifacts")
    assert "patched_sample_payment_service.py" in out_artifacts
    assert "codemender_cost_ledger.json" in out_artifacts

    # 10. cm models & cm switch-model
    out_switch = _chat("cm switch-model gemini-3.8-flash-cyber")
    assert "gemini-3.8-flash-cyber" in out_switch
    assert "ACTIVE" in out_switch
    assert "단가 (Input / Output / Think per 1M)" in out_switch

    # 11. cm fix --revert & cm vcs reset
    out_revert = _chat("cm fix --revert 1")
    assert "롤백(원복) 완료" in out_revert

    out_reset = _chat("cm vcs reset")
    assert "CLEAN" in out_reset

    # 12. cm help
    out_help = _chat("cm help")
    assert "13가지 핵심 기능" in out_help
    assert "cm github" in out_help

    # 13. cm github status (without token configured -> unauthenticated guidance)
    out_gh_status = _chat("cm github status")
    assert "GitHub 연동 상태" in out_gh_status or "GitHub" in out_gh_status



def test_codemender_cost_tracker_and_a2ui_cost_surface(monkeypatch) -> None:
    """Verifies per-stage cost calculation, Cloud Logging emission, session/ledger accumulation, and A2UI v0.9 cost surface validation."""
    from app.a2ui_renderer import (
        build_cost_report_surface,
        validate_a2ui_payload,
    )
    from app.harness import (
        CodeMenderRunner,
        get_session_and_ledger_cost_report,
        record_patch_application_cost,
        record_session_cost,
    )
    from app.ingestion import get_or_create_workspace, ingest_bytes_into_workspace

    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    ws = get_or_create_workspace("cost_test_sess", "cost_user")
    ingest_bytes_into_workspace(
        ws, "service.py", VULNERABLE_AND_SAFE_PYTHON.encode("utf-8")
    )

    state: dict[str, object] = {}
    runner = CodeMenderRunner()
    res = runner.run_pipeline(ws)
    assert res.cost_summary is not None
    assert res.cost_summary.total_tokens > 0
    assert res.cost_summary.total_cost_usd > 0.0
    assert res.cost_summary.total_cost_krw > 0.0
    assert len(res.cost_summary.stages) == 3

    updated_cost = record_session_cost(state, res.cost_summary)
    assert updated_cost.session_total_runs == 1

    # Simulate applying a HITL patch and recording Stage 4 cost
    patched_cost = record_patch_application_cost(
        existing_cost_dict=updated_cost.to_dict(),
        applied_files=[
            {
                "vuln_id": "CM-CWE-89-001",
                "file_path": "service.py",
                "patched_content": VULNERABLE_AND_SAFE_PYTHON,
            }
        ],
        state=state,
    )
    assert patched_cost is not None
    assert len(patched_cost.stages) == 4
    assert patched_cost.session_total_runs == 2
    assert patched_cost.total_cost_usd > res.cost_summary.total_cost_usd

    report_dict = get_session_and_ledger_cost_report(state)
    assert report_dict["session"]["session_total_runs"] == 2
    assert report_dict["ledger"]["total_runs"] >= 2
    assert "cloud_logging" in report_dict
    assert "CODEMENDER_COST_TELEMETRY" in report_dict["cloud_logging"]["log_explorer_filter"]

    for mode in ("codemender_material", "basic"):
        cost_msgs = build_cost_report_surface(report_dict, catalog_mode=mode)
        assert len(cost_msgs) == 3
        for msg in cost_msgs:
            validate_a2ui_payload(msg, catalog_mode=mode)


def test_github_pr_routing_and_vcs_stage_auto_apply(monkeypatch) -> None:
    """Verifies that '깃허브 PR 생성' / 'pr 생성' routes to `github pr` (not hijacked by `vcs stage`)
    and that `cm vcs stage` automatically applies pending verified patches so modified_entries > 0."""
    from app.harness.cm_commands import parse_cm_chat_command
    from app.harness.patch_applier import apply_patch_to_workspace
    from app.ingestion import get_or_create_workspace, ingest_bytes_into_workspace

    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")

    for phrase in ("깃허브 PR 생성", "pr 생성", "풀리퀘스트 만들어줘", "깃허브에 올려줘"):
        parsed = parse_cm_chat_command(phrase)
        assert parsed is not None
        assert parsed["subcommand"] == "github"
        assert parsed["positional"][0] == "pr"

    # Verify fuzzy indentation-tolerant & line-range patch application
    ws = get_or_create_workspace("fuzzy_patch_sess", "fuzzy_user")
    indented_code = (
        "def evaluate_program(code_str):\n"
        "    namespace = {}\n"
        "    exec(code_str, namespace)\n"
        "    return namespace\n"
    )
    ingest_bytes_into_workspace(
        ws,
        ".agents_skills_alpha_evolve_experiment_design_examples_circle_packing_evaluator.py",
        indented_code.encode("utf-8"),
    )
    # LLM returned before_snippet without leading 4-space indentation
    res = apply_patch_to_workspace(
        ws,
        vuln_id="CM-CWE-94-001",
        file_path=".agents_skills_alpha_evolve_experiment_design_examples_circle_packing_evaluator.py",
        before_snippet="exec(code_str, namespace)",
        after_snippet='exec(code_str, {"__builtins__": {}}, namespace)',
        start_line=3,
        end_line=3,
    )
    assert res.applied is True
    assert '    exec(code_str, {"__builtins__": {}}, namespace)' in res.patched_content


def test_multi_user_session_isolation_and_snapshot_rehydration(monkeypatch) -> None:
    """Verifies that User A's personal GitHub OAuth token and workspace snapshot in Session A
    are strictly isolated from User B in Session B, while rehydrating seamlessly across instances for Session A."""
    from app.agent import _load_session_snapshot, _save_session_snapshot
    from app.harness.github_integration import (
        _load_persisted_github_state,
        _save_persisted_github_state,
    )
    from app.ingestion import get_or_create_workspace, ingest_bytes_into_workspace

    monkeypatch.setenv("CM_DISABLE_LLM_NETWORK", "true")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_PAT", raising=False)

    session_a = "ge_chat_room_user_a_001"
    session_b = "ge_chat_room_user_b_002"

    # 1. User A authenticates their personal GitHub account in Session A
    _save_persisted_github_state(
        {"access_token": "gho_secret_personal_token_user_a", "token_type": "bearer"},
        session_id=session_a,
    )

    state_a: dict[str, object] = {"_cm_session_id": session_a}
    state_b: dict[str, object] = {"_cm_session_id": session_b}

    # User A resolves their token in Session A
    loaded_a = _load_persisted_github_state(state=state_a)
    assert loaded_a.get("access_token") == "gho_secret_personal_token_user_a"

    # User B in Session B MUST NOT receive User A's personal token
    assert _load_persisted_github_state(state=state_b) == {}
    assert _load_persisted_github_state(session_id=session_b) == {}

    # 2. User A scans a repository in Session A and saves session snapshot
    ws_a = get_or_create_workspace(session_a, "user_a")
    ingest_bytes_into_workspace(ws_a, "private_repo_code.py", b"x = eval(user_input)\n")
    state_a["cm_workspace"] = ws_a.to_dict()
    state_a["cm_github_repo_context"] = {"owner": "user_a", "repo": "secret-private-repo"}
    _save_session_snapshot(session_a, state_a)

    # 3. Simulate Cloud Run autoscaling to a new container instance for Session A vs Session B
    new_instance_state_a: dict[str, object] = {"_cm_session_id": session_a}
    new_instance_state_b: dict[str, object] = {"_cm_session_id": session_b}

    _load_session_snapshot(session_a, new_instance_state_a)
    assert "cm_workspace" in new_instance_state_a
    file_names_a = [
        f["relative_path"] for f in new_instance_state_a["cm_workspace"]["files"]  # type: ignore[index]
    ]
    assert "private_repo_code.py" in file_names_a
    assert new_instance_state_a["cm_github_repo_context"]["repo"] == "secret-private-repo"  # type: ignore[index]

    # User B on a new instance has no snapshot from User A
    _load_session_snapshot(session_b, new_instance_state_b)
    assert "cm_workspace" not in new_instance_state_b


