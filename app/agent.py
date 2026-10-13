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

"""CodeMender x Gemini Enterprise A2UI v0.9 Security Agent."""

from __future__ import annotations

import logging
from typing import Any

from google.adk.agents import Agent
from google.adk.agents.callback_context import CallbackContext
from google.adk.apps import App
from google.adk.models import Gemini
from google.adk.plugins.save_files_as_artifacts_plugin import (
    SaveFilesAsArtifactsPlugin,
)
from google.adk.tools import ToolContext
from google.genai import types

from app.a2ui_renderer import (
    build_cost_report_surface,
    build_scan_report_surface,
    build_upload_prompt_surface,
    extract_a2ui_action_from_parts,
    format_a2ui_delimited_text,
    get_codemender_schema_manager,
    handle_a2ui_patch_action,
    select_catalog_mode,
)
from app.config import (
    CODEMENDER_MODEL,
    GCP_PROJECT_ID,
    GCS_ARTIFACT_BUCKET,
    GE_ENGINE_ID,
    GE_LOCATION,
)
from app.harness import (
    CodeMenderRunner,
    apply_patch_to_workspace,
    execute_cm_command,
    format_krw,
    format_tokens,
    format_usd,
    get_session_and_ledger_cost_report,
    parse_cm_chat_command,
    record_session_cost,
)
from app.ingestion import (
    WorkspaceSecurityError,
    extract_files_from_genai_parts,
    get_or_create_workspace,
    ingest_bytes_into_workspace,
)

logger = logging.getLogger(__name__)

# Single unified model for Find, Verify, Fix, and LLM-as-a-Judge
MODEL = CODEMENDER_MODEL

_SAMPLE_VULNERABLE_FILENAME = "sample_payment_service.py"
_SAMPLE_VULNERABLE_CODE = '''"""Sample enterprise payment & diagnostics service for CodeMender verification."""

import sqlite3
import subprocess


def get_customer_invoice(db_conn: sqlite3.Connection, invoice_id: str) -> list:
    cursor = db_conn.cursor()
    # [VULNERABLE CWE-89] Unparameterized f-string SQL query
    cursor.execute(f"SELECT id, amount, status FROM invoices WHERE invoice_id = '{invoice_id}'")
    return cursor.fetchall()


def get_audit_logs_safe(db_conn: sqlite3.Connection, user_id: str) -> list:
    cursor = db_conn.cursor()
    # [SAFE PARAMETERIZED QUERY] Should be filtered out as False Positive in Stage 2 (cm verify)
    cursor.execute("SELECT action, ts FROM audit_logs WHERE user_id = ?", (user_id,))
    return cursor.fetchall()


def ping_gateway_host(gateway_host: str) -> str:
    # [VULNERABLE CWE-78] OS command execution with shell=True
    proc = subprocess.run(f"ping -c 1 {gateway_host}", shell=True, capture_output=True, text=True)
    return proc.stdout
'''


_SESSION_SNAPSHOT_KEYS = (
    "cm_workspace",
    "cm_pipeline_result",
    "cm_github_repo_context",
    "cm_github_auth",
    "cm_command_history",
    "cm_active_model",
    "codemender_session_cost_ledger",
    "_cm_session_id",
)


def _sanitize_sid(session_id: str) -> str:
    return "".join(
        ch if (ch.isalnum() or ch in ("-", "_")) else "_"
        for ch in str(session_id or "default").strip()
    ) or "default"


def _load_session_snapshot(session_id: str, state: Any) -> None:
    """Rehydrates session state from session-scoped local or GCS snapshot if in-memory state was lost across Cloud Run instances."""
    import json
    import os
    import urllib.parse
    import urllib.request
    from pathlib import Path
    from app.ingestion.file_manager import _get_gcs_access_token

    if state.get("cm_workspace"):
        return

    sid = _sanitize_sid(session_id)
    snap: dict[str, Any] = {}

    local_snap = Path(f"/tmp/codemender_sessions/session_{sid}.json")
    if local_snap.exists():
        try:
            snap = json.loads(local_snap.read_text(encoding="utf-8"))
        except Exception:
            snap = {}

    if not snap and os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        gcs_token = _get_gcs_access_token()
        if gcs_token:
            try:
                obj_name = f"codemender-config/sessions/{sid}/session_snapshot.json"
                encoded = urllib.parse.quote(obj_name, safe="")
                url = f"https://storage.googleapis.com/storage/v1/b/{GCS_ARTIFACT_BUCKET}/o/{encoded}?alt=media"
                req = urllib.request.Request(
                    url,
                    headers={
                        "Authorization": f"Bearer {gcs_token}",
                        "X-Goog-User-Project": GCP_PROJECT_ID,
                    },
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    loaded = json.loads(resp.read().decode("utf-8"))
                    if isinstance(loaded, dict):
                        snap = loaded
            except Exception:
                pass

    if isinstance(snap, dict) and snap:
        for k in _SESSION_SNAPSHOT_KEYS:
            if k in snap and snap[k] is not None and not state.get(k):
                state[k] = snap[k]


def _save_session_snapshot(session_id: str, state: Any) -> None:
    """Persists session state strictly under the session's own local and GCS path."""
    import json
    import os
    import urllib.parse
    import urllib.request
    from pathlib import Path
    from app.ingestion.file_manager import _get_gcs_access_token

    if state is None or not hasattr(state, "get"):
        return

    sid = _sanitize_sid(session_id or state.get("_cm_session_id") or "default")
    snap = {k: state.get(k) for k in _SESSION_SNAPSHOT_KEYS if state.get(k) is not None}
    if not snap:
        return

    try:
        local_snap = Path(f"/tmp/codemender_sessions/session_{sid}.json")
        local_snap.parent.mkdir(parents=True, exist_ok=True)
        local_snap.write_text(
            json.dumps(snap, ensure_ascii=False), encoding="utf-8"
        )
        os.chmod(local_snap, 0o600)
    except Exception:
        pass

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        gcs_token = _get_gcs_access_token()
        if gcs_token:
            try:
                obj_name = f"codemender-config/sessions/{sid}/session_snapshot.json"
                encoded = urllib.parse.quote(obj_name, safe="")
                url = f"https://storage.googleapis.com/upload/storage/v1/b/{GCS_ARTIFACT_BUCKET}/o?uploadType=media&name={encoded}"
                req = urllib.request.Request(
                    url,
                    data=json.dumps(snap, ensure_ascii=False).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {gcs_token}",
                        "Content-Type": "application/json; charset=utf-8",
                        "X-Goog-User-Project": GCP_PROJECT_ID,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5.0):
                    pass
            except Exception:
                pass


def _resolve_session_workspace(state: Any, session_id: str, user_id: str):
    state["_cm_session_id"] = session_id
    _load_session_snapshot(session_id, state)
    existing_ws = state.get("cm_workspace")
    ws = get_or_create_workspace(
        session_id=session_id,
        user_id=user_id,
        existing_context=existing_ws if isinstance(existing_ws, dict) else None,
    )
    state["cm_workspace"] = ws.to_dict()
    return ws


def _populate_default_sample(ws: Any, state: Any) -> None:
    ws.files = []
    ingest_bytes_into_workspace(
        ws,
        _SAMPLE_VULNERABLE_FILENAME,
        _SAMPLE_VULNERABLE_CODE.encode("utf-8"),
    )
    state["cm_workspace"] = ws.to_dict()


def ingest_source_code(
    filename: str,
    source_code: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Ingests a source code file into the isolated session workspace for CodeMender analysis.

    Args:
        filename: Name of the source file (e.g., 'app.py', 'server.js').
        source_code: Full text content of the source file.

    Returns:
        dict with ingestion status and workspace file list.
    """
    session_id = getattr(tool_context._invocation_context.session, "id", "default")
    user_id = getattr(tool_context._invocation_context, "user_id", "default_user")
    ws = _resolve_session_workspace(tool_context.state, session_id, user_id)
    ingested = ingest_bytes_into_workspace(
        ws, filename, source_code.encode("utf-8")
    )
    tool_context.state["cm_workspace"] = ws.to_dict()
    return {
        "status": "success",
        "workspace_id": ws.workspace_id,
        "ingested_files": [f.to_dict() for f in ingested],
    }


def _build_response_text(lead_md: str, a2ui_messages: list[dict[str, Any]]) -> str:
    """Returns clean Markdown by default; only appends <a2ui-json> if explicitly enabled."""
    import os

    if os.getenv("CM_ENABLE_A2UI_SURFACE", "false").lower() == "true":
        return format_a2ui_delimited_text(a2ui_messages, lead_text=lead_md)
    return lead_md.strip()


def _format_upload_guide_markdown(
    error_msg: str | None = None,
    active_model: str = MODEL,
) -> str:
    """Builds a rich Korean Markdown onboarding guide for Gemini Enterprise Web UI."""
    banner = f"> ⚠️ **보안 경고**: `{error_msg}`\n\n" if error_msg else ""
    return (
        f"{banner}"
        f"### 🛡️ CodeMender Security Agent (`{active_model}`)\n"
        f"안녕하세요! **Gemini Enterprise (`{GCP_PROJECT_ID}` / {GE_LOCATION.upper()})** 환경에 통합된 **CodeMender (`cm` v0.12.0) 전 기능 탑재 보안 에이전트**입니다.\n\n"
        "| 파이프라인 단계 | 실행 명령 | 설명 |\n"
        "| :--- | :--- | :--- |\n"
        f"| **Stage 1 — 탐색** | `cm find` | AST + `{active_model}` 정적/추론 스캔으로 CWE/OWASP 취약점 후보 탐지 |\n"
        "| **Stage 2 — 검증** | `cm verify [<ID\\|ALL>]` | 격리된 샌드박스에서 PoC를 직접 실행하여 **오탐(False Positive)을 100% 필터링** |\n"
        f"| **Stage 3 — 패치** | `cm fix [<ID\\|ALL>] [-c \"...\"]` | 최소 변경 보안 패치(`CodeDiff`) 생성·적용·롤백(`--revert`) 및 `{active_model}` Judge 검증 |\n"
        "| **🐙 GitHub 연동 & PR** | `깃허브 로그인` / `cm github` | **내 GitHub OAuth 기기 인증(`https://github.com/login/device`)으로 Private/Public 레포 스캔 및 실제 브랜치 푸시·PR 자동 생성** |\n"
        "| **💰 비용/청구 조회 (요청 시)** | `비용 조회` / `cm cost` | 백그라운드에서 Cloud Logging 기반으로 누적 기록되며, **물어보실 때만 일자별 총 청구 금액·세션별·트랜잭션별 비용을 호출해 안내**합니다 |\n\n"
        "#### 🛠️ 채팅창에서 바로 쓸 수 있는 `cm` 전체 명령어 (13종)\n"
        "- **초기화 / 탐색 / 검증**: `cm init --verify` · `cm find` · `cm verify ALL` (또는 `cm verify 1`)\n"
        "- **패치 적용 / 맞춤 패치 / 롤백**: `cm fix ALL` · `cm fix 1 -c \"로깅 추가해줘\"` · `cm fix --revert`\n"
        "- **GitHub 계정 연동 / 레포 스캔 / 자동 PR 생성**: `깃허브 로그인` (`cm github login`) · `깃허브 인증 완료` · `내 레포 목록` · `깃허브 스캔 <owner/repo>` · `깃허브 PR 생성`\n"
        "- **리포트 내보내기 & 다운로드**: `cm report` · `cm report -f json` · `cm report -f html` · `다운로드` (`cm download`)\n"
        "- **트리아지 & CI/CD 보안 게이트**: `cm triage` (또는 `트리아지`, `보안 게이트`)\n"
        "- **VCS 버전 관리 & 로컬 PR 시뮬레이션**: `cm vcs status` · `cm vcs diff` · `cm vcs reset` · `cm vcs stage`\n"
        "- **빌드 검증 / 이력 / 멀티 모델 / 온디맨드 비용 조회**: `cm build` · `cm sessions` · `cm artifacts` · `cm models` · `cm cost` (`비용 얼마 나왔어?`) · `cm help`\n\n"
        "#### 🚀 지금 바로 테스트하는 4가지 방법\n"
        "1. **내 GitHub 연동 & 스캔**: 채팅창에 **`깃허브 로그인`**을 입력해 기기 인증 후 **`깃허브 스캔 <내레포>`** 또는 **`깃허브 PR 생성`**을 실행하세요.\n"
        "2. **데모 즉시 실행**: 채팅창에 **`샘플 진단 실행`** (또는 **`cm find`**)이라고 입력하세요.\n"
        "3. **파일 / `.zip` 첨부**: 대화창의 `+` 버튼으로 `.py`, `.c`, `.cpp`, `.js`, `.ts`, `.go`, `.java`, `.zip` 파일을 업로드하세요.\n"
        "4. **소스코드 붙여넣기**: 진단할 코드 블록(` ```python ... ``` ` 또는 ` ```c ... ``` `)을 대화창에 그대로 붙여넣으세요."
    )


def _format_scan_report_markdown(
    pipeline_result: Any,
    applied_files: list[dict[str, Any]] | None = None,
) -> str:
    """Builds a structured Korean Markdown report with unified CodeDiffs and Judge verdicts (no cost clutter)."""
    files_str = ", ".join(pipeline_result.scanned_files) or "없음"
    lines: list[str] = []

    if applied_files:
        lines.append("### ✅ CodeMender 보안 패치 적용 완료 (`cm fix`)")
        lines.append(
            f"승인하신 보안 패치가 워크스페이스 소스코드에 반영되었으며, **Google Cloud Storage (`gs://{GCS_ARTIFACT_BUCKET}`)** 및 격리 워크스페이스에 영구 저장되었습니다.\n"
        )
        # Deduplicate by file_path so multiple patches to the same file show the final combined file once
        dedup_by_path: dict[str, dict[str, Any]] = {}
        applied_vids_by_path: dict[str, list[str]] = {}
        for item in applied_files:
            fpath = str(item.get("file_path") or "patched_file.py")
            dedup_by_path[fpath] = item
            vid = str(item.get("vuln_id") or "")
            if vid:
                applied_vids_by_path.setdefault(fpath, []).append(vid)

        lines.extend(
            [
                "#### 📥 수정된 파일 저장 위치 및 원클릭 다운로드 (Gemini Enterprise 브라우저 직접 다운로드)",
                "| 파일명 | 적용된 취약점 ID | 1️⃣ 원클릭 직접 다운로드 (클릭) | 2️⃣ GCP Storage 버킷 경로 (`gs://`) | 3️⃣ 컨테이너 내부 경로 |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        zip_dl_url = ""
        zip_gcs_uri = ""
        for fpath, item in dedup_by_path.items():
            patched_fname = f"patched_{fpath.rsplit('/', 1)[-1]}"
            dl_url = item.get("download_url") or ""
            con_url = item.get("console_url") or ""
            gcs_uri = item.get("gcs_uri") or f"gs://{GCS_ARTIFACT_BUCKET}/codemender-patches/{pipeline_result.workspace_id}/{patched_fname}"
            loc_path = item.get("local_container_path") or f"/tmp/codemender_workspaces/{pipeline_result.workspace_id}/patched/{fpath}"
            if item.get("zip_download_url"):
                zip_dl_url = str(item["zip_download_url"])
            if item.get("zip_gcs_uri"):
                zip_gcs_uri = str(item["zip_gcs_uri"])
            vids_str = ", ".join(f"`{v}`" for v in applied_vids_by_path.get(fpath, [])) or "`ALL`"
            dl_link_md = (
                f"**[📥 `{patched_fname}` 다운로드]({dl_url})** ([콘솔 보기]({con_url}))"
                if dl_url
                else f"`{patched_fname}`"
            )
            lines.append(
                f"| **`{patched_fname}`** | {vids_str} | {dl_link_md} | `{gcs_uri}` | `{loc_path}` |"
            )
        if zip_dl_url:
            lines.append(
                f"| **📦 전체 수정본 ZIP 번들** | 전체 파일 패키지 | **[📦 `codemender_patched.zip` 다운로드]({zip_dl_url})** | `{zip_gcs_uri}` | `/tmp/codemender_workspaces/{pipeline_result.workspace_id}/patched/` |"
            )
        lines.append("")

        for fpath, item in dedup_by_path.items():
            ext = fpath.rsplit(".", 1)[-1].lower() if "." in fpath else "text"
            lang_map = {"py": "python", "c": "c", "cpp": "cpp", "js": "javascript", "ts": "typescript", "go": "go", "java": "java"}
            lang = lang_map.get(ext, "text")
            patched_fname = f"patched_{fpath.rsplit('/', 1)[-1]}"
            gcs_uri = item.get("gcs_uri") or f"gs://{GCS_ARTIFACT_BUCKET}/codemender-patches/{pipeline_result.workspace_id}/{patched_fname}"
            lines.append(
                f"#### 📄 수정 완료된 전체 소스 코드 전문: `{fpath}` (SHA-256: `{item['sha256'][:16]}...`)"
            )
            lines.append(
                f"> 💡 위 표의 **[📥 `{patched_fname}` 다운로드]** 링크를 클릭하시거나, 아래 코드 블록 우측 상단의 **복사(Copy)** 버튼을 눌러 바로 저장하실 수 있습니다. (터미널 다운로드: `gcloud storage cp {gcs_uri} ./`)"
            )
            lines.append(f"```{lang}\n{item['patched_content'].rstrip()}\n```\n")
    else:
        lines.append("### 🛡️ CodeMender 3-Stage 보안 진단 및 패치 리포트")

    lines.extend(
        [
            "| 항목 | 결과 |",
            "| :--- | :--- |",
            f"| **추론/검증 모델** | `{pipeline_result.model_used}` |",
            f"| **진단 대상 파일** | `{files_str}` |",
            f"| **Stage 1 (`cm find`) 탐색 후보** | **{pipeline_result.total_candidates_found}건** |",
            f"| **Stage 2 (`cm verify`) 오탐(False Positive) 제거** | **{pipeline_result.false_positives_filtered}건** (샌드박스 방어 확인) |",
            f"| **Stage 2 (`cm verify`) 확증 취약점(True Positive)** | **{pipeline_result.verified_count}건** |",
            "",
        ]
    )

    if pipeline_result.filtered_candidates:
        lines.append("#### 🔍 Stage 2 샌드박스에서 필터링된 오탐(False Positive) 내역")
        for fp in pipeline_result.filtered_candidates:
            evidence = fp.get("sandbox_evidence") or fp.get("reason") or "Safe guard confirmed"
            lines.append(
                f"- ~~`[{fp.get('cwe_id')}] {fp.get('title')}` (`{fp.get('file_path')}` Line {fp.get('start_line')})~~ → **오탐 제외**: `{evidence}`"
            )
        lines.append("")

    if not pipeline_result.findings and not applied_files:
        lines.extend(
            [
                "---",
                "#### ✅ 보안 검증 결과: 악용 가능한(Exploitable) 취약점 없음",
                f"- 업로드하신 `{files_str}` 파일에 대해 Stage 1 (`cm find`) 및 Stage 2 (`cm verify`) 격리 샌드박스 검증을 완료했습니다.",
                "- 다른 파일이나 취약한 코드 스니펫을 업로드하시거나 **`샘플 진단 실행`**을 입력해 패치 생성 플로우를 테스트해 보세요.",
            ]
        )

    for idx, f in enumerate(pipeline_result.findings, start=1):
        status_badge = (
            "✅ PATCH APPLIED"
            if f.patch_status == "APPLIED"
            else ("❌ REJECTED" if f.patch_status == "REJECTED" else f"🚨 {f.severity} · VERIFIED")
        )
        lines.extend(
            [
                "---",
                f"#### {idx}. [{status_badge}] `{f.vuln_id}` — {f.title}",
                f"- **분류**: `{f.cwe_id}` | `{f.owasp_category}`",
                f"- **위치**: `{f.file_path}` (Lines {f.start_line}–{f.end_line})",
                f"- **취약점 상세**: {f.description}",
                f"- **Stage 2 샌드박스 검증 로그**: `{f.sandbox_evidence}`",
                f"- **Stage 3 LLM-as-a-Judge 평가**: **{f.judge_score}/10 ({f.judge_verdict})** — {f.judge_rationale}",
                "",
                "**전/후 코드 비교 (Unified CodeDiff)**:",
                f"```diff\n{f.unified_diff.strip()}\n```",
                "",
            ]
        )

    if pipeline_result.findings:
        lines.extend(
            [
                "---",
                "💡 **사용 가능한 `cm` 후속 명령어**:",
                "- **패치 적용 / 컨텍스트 맞춤 패치 / 롤백**: **`cm fix ALL`** (또는 **`패치 적용`**) · **`cm fix 1 -c \"추가 요구사항\"`** · **`cm fix --revert`**",
                "- **우선순위 트리아지 & CI/CD 보안 게이트**: **`cm triage`**",
                "- **VCS 변경 비교 / 자율 PR 생성 / 초기화**: **`cm vcs diff`** · **`cm vcs stage`** · **`cm vcs reset`**",
                "- **리포트 내보내기 / 빌드 검증 / 비용 조회(요청 시)**: **`cm report -f json`** · **`cm report -f html`** · **`cm build`** · **`비용 조회`** (`cm cost`)",
            ]
        )
    return "\n".join(lines)


def _extract_user_plain_text(parts: list[types.Part]) -> str:
    texts: list[str] = []
    for p in parts:
        t = getattr(p, "text", None)
        if (
            t
            and not t.strip().startswith('{"a2ui_action"')
            and '[Uploaded Artifact: "' not in t
        ):
            texts.append(t.strip())
    return "\n".join(texts).strip()


def run_codemender_scan(
    catalog_mode: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Runs the 3-stage CodeMender pipeline (cm find -> cm verify -> cm fix) and tracks token/sandbox cost."""
    session_id = getattr(tool_context._invocation_context.session, "id", "default")
    user_id = getattr(tool_context._invocation_context, "user_id", "default_user")
    ws = _resolve_session_workspace(tool_context.state, session_id, user_id)

    if not ws.files:
        _populate_default_sample(ws, tool_context.state)

    active_model = tool_context.state.get("cm_active_model", MODEL)
    runner = CodeMenderRunner(model_name=active_model)
    pipeline_result = runner.run_pipeline(ws)
    if pipeline_result.cost_summary is not None:
        record_session_cost(tool_context.state, pipeline_result.cost_summary)
    tool_context.state["cm_pipeline_result"] = pipeline_result.to_dict()

    effective_mode = (
        catalog_mode
        if catalog_mode in ("codemender_material", "basic")
        else tool_context.state.get("cm_catalog_mode", "basic")
    )
    a2ui_messages = build_scan_report_surface(
        pipeline_result,
        catalog_mode=effective_mode,
    )
    lead_md = _format_scan_report_markdown(pipeline_result)
    tool_context.actions.skip_summarization = True
    return {
        "status": "success",
        "verified_count": pipeline_result.verified_count,
        "false_positives_filtered": pipeline_result.false_positives_filtered,
        "cost_summary": (
            pipeline_result.cost_summary.to_dict()
            if pipeline_result.cost_summary is not None
            else None
        ),
        "result": _build_response_text(lead_md, a2ui_messages),
    }


async def apply_verified_security_patch(
    vuln_id: str,
    file_path: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Applies a user-approved security patch (HITL), records incremental cost, and saves the patched file artifact."""
    session_id = getattr(tool_context._invocation_context.session, "id", "default")
    user_id = getattr(tool_context._invocation_context, "user_id", "default_user")
    ws = _resolve_session_workspace(tool_context.state, session_id, user_id)
    pipeline_dict = tool_context.state.get("cm_pipeline_result")
    if not pipeline_dict:
        return {"status": "error", "message": "No active CodeMender scan results in session."}

    action_name = (
        "apply_all_patches" if vuln_id.upper() == "ALL" else "apply_patch"
    )
    catalog_mode = tool_context.state.get("cm_catalog_mode", "basic")
    outcome = handle_a2ui_patch_action(
        action_name=action_name,
        action_context={"vuln_id": vuln_id, "file_path": file_path},
        workspace=ws,
        pipeline_result_dict=pipeline_dict,
        catalog_mode=catalog_mode,
        state=tool_context.state,
    )
    tool_context.state["cm_workspace"] = ws.to_dict()
    tool_context.state["cm_pipeline_result"] = outcome["updated_pipeline_result"]

    for item in outcome["applied_files"]:
        part = types.Part.from_bytes(
            data=item["patched_content"].encode("utf-8"),
            mime_type="text/x-python" if item["file_path"].endswith(".py") else "text/plain",
        )
        await tool_context.save_artifact(f"patched_{item['file_path']}", part)

    from app.a2ui_renderer.action_handler import reconstruct_pipeline_result

    updated_res = reconstruct_pipeline_result(outcome["updated_pipeline_result"])
    lead_md = _format_scan_report_markdown(
        updated_res, applied_files=outcome["applied_files"]
    )
    tool_context.actions.skip_summarization = True
    return {
        "status": "success",
        "applied_files": [
            {"file_path": f["file_path"], "sha256": f["sha256"]}
            for f in outcome["applied_files"]
        ],
        "cost_summary": (
            updated_res.cost_summary.to_dict()
            if updated_res.cost_summary is not None
            else None
        ),
        "result": _build_response_text(lead_md, outcome["a2ui_messages"]),
    }


async def run_cm_cli_command(
    command: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Executes any CodeMender (`cm`) CLI command (init, find, verify, fix, report, triage, vcs, build, stats/cost, sessions, artifacts, models)."""
    session_id = getattr(tool_context._invocation_context.session, "id", "default")
    user_id = getattr(tool_context._invocation_context, "user_id", "default_user")
    ws = _resolve_session_workspace(tool_context.state, session_id, user_id)
    parsed = parse_cm_chat_command(command) or {"subcommand": "help", "raw": command}

    async def _save_art(name: str, data: bytes) -> None:
        mime = "application/json" if name.endswith(".json") else ("text/html" if name.endswith(".html") else "text/plain")
        await tool_context.save_artifact(name, types.Part.from_bytes(data=data, mime_type=mime))

    cmd_out = await execute_cm_command(
        parsed,
        workspace=ws,
        state=tool_context.state,
        save_artifact_fn=_save_art,
        default_sample_fn=_populate_default_sample,
    )
    md = cmd_out.get("markdown")
    if md is None and cmd_out.get("pipeline_result") is not None:
        md = _format_scan_report_markdown(
            cmd_out["pipeline_result"], applied_files=cmd_out.get("applied_files")
        )
    tool_context.actions.skip_summarization = True
    return {"status": "success", "result": md or ""}


async def get_codemender_cost_report(
    tool_context: ToolContext,
) -> dict[str, Any]:
    """Returns the complete CodeMender LLM token & Cloud Run sandbox cost telemetry report (session + persistent ledger in USD & KRW)."""
    session_id = getattr(tool_context._invocation_context.session, "id", "default")
    user_id = getattr(tool_context._invocation_context, "user_id", "default_user")
    ws = _resolve_session_workspace(tool_context.state, session_id, user_id)
    cmd_out = await execute_cm_command(
        {"subcommand": "cost", "raw": "cm cost"},
        workspace=ws,
        state=tool_context.state,
        default_sample_fn=_populate_default_sample,
    )
    report_dict = get_session_and_ledger_cost_report(tool_context.state)
    catalog_mode = tool_context.state.get("cm_catalog_mode", "basic")
    a2ui_messages = build_cost_report_surface(report_dict, catalog_mode=catalog_mode)
    tool_context.actions.skip_summarization = True
    return {
        "status": "success",
        "cost_report": report_dict,
        "result": _build_response_text(cmd_out.get("markdown") or "", a2ui_messages),
    }


async def codemender_before_agent_callback(
    callback_context: CallbackContext,
) -> types.Content | None:
    """Intercepts file uploads and chat commands for deterministic 3-Stage CodeMender execution with automatic cost tracking."""
    state = callback_context.state
    inv_ctx = callback_context._invocation_context
    session_id = getattr(inv_ctx.session, "id", "default_session")
    try:
        return await _codemender_before_agent_callback_inner(
            callback_context, state, inv_ctx, session_id
        )
    finally:
        _save_session_snapshot(session_id, state)


async def _codemender_before_agent_callback_inner(
    callback_context: CallbackContext,
    state: Any,
    inv_ctx: Any,
    session_id: str,
) -> types.Content | None:
    user_id = getattr(inv_ctx, "user_id", "default_user")

    # 1. Negotiate catalog mode
    client_caps = state.get("client_ui_capabilities")
    catalog_mode, selected_catalog = select_catalog_mode(
        client_caps if isinstance(client_caps, dict) else None
    )
    state["cm_catalog_mode"] = catalog_mode
    state["system:a2ui_enabled"] = True
    state["system:a2ui_catalog"] = selected_catalog
    active_model = state.get("cm_active_model", MODEL)

    # 2. Initialize or load isolated session workspace
    ws = _resolve_session_workspace(state, session_id, user_id)

    user_content = callback_context.user_content
    parts = list(user_content.parts) if (user_content and user_content.parts) else []

    # 3. Expand any artifacts captured by SaveFilesAsArtifactsPlugin FIRST
    expanded_parts = list(parts)
    for part in parts:
        txt = getattr(part, "text", None)
        if txt and '[Uploaded Artifact: "' in txt:
            start = txt.find('[Uploaded Artifact: "') + len('[Uploaded Artifact: "')
            end = txt.find('"]', start)
            if end > start:
                artifact_name = txt[start:end]
                try:
                    loaded_part = await callback_context.load_artifact(artifact_name)
                    if loaded_part is not None:
                        if (
                            getattr(loaded_part, "inline_data", None)
                            and not getattr(loaded_part.inline_data, "display_name", None)
                        ):
                            loaded_part.inline_data.display_name = artifact_name
                        expanded_parts.append(loaded_part)
                except Exception as exc:
                    logger.debug(f"Could not load uploaded artifact {artifact_name}: {exc}")

    user_text = _extract_user_plain_text(parts)
    user_text_lower = user_text.lower()

    async def _save_callback_artifact(name: str, data: bytes) -> None:
        mime = (
            "application/json"
            if name.endswith(".json")
            else ("text/html" if name.endswith(".html") else "text/plain")
        )
        try:
            await callback_context.save_artifact(
                name, types.Part.from_bytes(data=data, mime_type=mime)
            )
        except Exception as exc:
            logger.debug(f"Artifact save skipped in memory mode: {exc}")

    # 4. Extract newly uploaded files or pasted code snippets first if present
    try:
        newly_ingested = extract_files_from_genai_parts(expanded_parts, ws)
    except WorkspaceSecurityError as sec_err:
        logger.warning(f"Rejected unsafe file upload: {sec_err}")
        a2ui_messages = build_upload_prompt_surface(catalog_mode=catalog_mode)
        lead_md = _format_upload_guide_markdown(
            error_msg=str(sec_err), active_model=active_model
        )
        return types.Content(
            role="model",
            parts=[
                types.Part.from_text(
                    text=_build_response_text(lead_md, a2ui_messages)
                )
            ],
        )

    if newly_ingested:
        state["cm_workspace"] = ws.to_dict()
        runner = CodeMenderRunner(model_name=active_model)
        pipeline_res = runner.run_pipeline(ws)
        if pipeline_res.cost_summary is not None:
            record_session_cost(state, pipeline_res.cost_summary)
        state["cm_pipeline_result"] = pipeline_res.to_dict()
        a2ui_messages = build_scan_report_surface(
            pipeline_res,
            catalog_mode=catalog_mode,
        )
        lead_md = _format_scan_report_markdown(pipeline_res)
        return types.Content(
            role="model",
            parts=[
                types.Part.from_text(
                    text=_build_response_text(lead_md, a2ui_messages)
                )
            ],
        )

    # 5. Check if user invoked any `cm <subcommand>` or natural-language `cm` feature
    parsed_cm = parse_cm_chat_command(user_text)
    if parsed_cm is not None:
        cmd_out = await execute_cm_command(
            parsed_cm,
            workspace=ws,
            state=state,
            save_artifact_fn=_save_callback_artifact,
            default_sample_fn=_populate_default_sample,
        )
        md = cmd_out.get("markdown")
        if md is None and cmd_out.get("pipeline_result") is not None:
            md = _format_scan_report_markdown(
                cmd_out["pipeline_result"],
                applied_files=cmd_out.get("applied_files"),
            )
        return types.Content(
            role="model",
            parts=[
                types.Part.from_text(
                    text=_build_response_text(
                        md or "", cmd_out.get("a2ui_messages") or []
                    )
                )
            ],
        )

    # 6. Check if the user triggered a demo/patch/cost action (via button DataPart OR natural-language command)
    action_event = extract_a2ui_action_from_parts(expanded_parts)
    if not action_event and user_text:
        if any(
            kw in user_text_lower
            for kw in ("샘플", "데모", "sample", "demo", "테스트 실행", "진단 실행")
        ):
            action_event = {"name": "run_sample_scan", "context": {}}
        elif state.get("cm_pipeline_result") and any(
            kw in user_text_lower
            for kw in ("패치 적용", "패치해", "전체 패치", "apply patch", "apply all", "수정본")
        ):
            import re

            vid_match = re.search(r"(CM-[A-Z0-9-]+-\d+)", user_text, re.IGNORECASE)
            if vid_match:
                action_event = {
                    "name": "apply_patch",
                    "context": {"vuln_id": vid_match.group(1).upper()},
                }
            else:
                action_event = {"name": "apply_all_patches", "context": {}}

    if action_event:
        action_name = action_event["name"]
        action_ctx = action_event.get("context") or {}

        if action_name == "view_cost_report":
            cmd_out = await execute_cm_command(
                {"subcommand": "cost", "raw": "cm cost"},
                workspace=ws,
                state=state,
                save_artifact_fn=_save_callback_artifact,
                default_sample_fn=_populate_default_sample,
            )
            report_dict = get_session_and_ledger_cost_report(state)
            a2ui_messages = build_cost_report_surface(
                report_dict, catalog_mode=catalog_mode
            )
            return types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text=_build_response_text(
                            cmd_out.get("markdown") or "", a2ui_messages
                        )
                    )
                ],
            )

        if action_name == "run_sample_scan":
            _populate_default_sample(ws, state)
            runner = CodeMenderRunner(model_name=active_model)
            pipeline_res = runner.run_pipeline(ws)
            if pipeline_res.cost_summary is not None:
                record_session_cost(state, pipeline_res.cost_summary)
            state["cm_pipeline_result"] = pipeline_res.to_dict()
            a2ui_messages = build_scan_report_surface(
                pipeline_res,
                catalog_mode=catalog_mode,
            )
            lead_md = _format_scan_report_markdown(pipeline_res)
            return types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text=_build_response_text(lead_md, a2ui_messages)
                    )
                ],
            )

        if action_name in ("apply_patch", "apply_all_patches", "reject_patch"):
            pipeline_dict = state.get("cm_pipeline_result")
            if pipeline_dict:
                outcome = handle_a2ui_patch_action(
                    action_name=action_name,
                    action_context=action_ctx,
                    workspace=ws,
                    pipeline_result_dict=pipeline_dict,
                    catalog_mode=catalog_mode,
                    state=state,
                )
                state["cm_workspace"] = ws.to_dict()
                state["cm_pipeline_result"] = outcome["updated_pipeline_result"]
                from app.a2ui_renderer.action_handler import reconstruct_pipeline_result

                updated_res = reconstruct_pipeline_result(
                    outcome["updated_pipeline_result"]
                )
                lead_md = _format_scan_report_markdown(
                    updated_res, applied_files=outcome["applied_files"]
                )
                for item in outcome["applied_files"]:
                    await _save_callback_artifact(
                        f"patched_{item['file_path']}",
                        item["patched_content"].encode("utf-8"),
                    )
                return types.Content(
                    role="model",
                    parts=[
                        types.Part.from_text(
                            text=_build_response_text(lead_md, outcome["a2ui_messages"])
                        )
                    ],
                )

    # 7. If workspace has no files yet OR user sends a greeting/help query, return onboarding guide
    is_greeting_or_help = bool(
        user_text_lower
        and any(
            kw in user_text_lower
            for kw in ("안녕", "hello", "hi", "도움말", "help", "사용법", "어떻게")
        )
    )
    if not ws.files or is_greeting_or_help:
        a2ui_messages = build_upload_prompt_surface(catalog_mode=catalog_mode)
        lead_md = _format_upload_guide_markdown(active_model=active_model)
        return types.Content(
            role="model",
            parts=[
                types.Part.from_text(
                    text=_build_response_text(lead_md, a2ui_messages)
                )
            ],
        )

    # 8. If workspace already has files and user asks to scan/diagnose, run pipeline
    runner = CodeMenderRunner(model_name=active_model)
    pipeline_res = runner.run_pipeline(ws)
    if pipeline_res.cost_summary is not None:
        record_session_cost(state, pipeline_res.cost_summary)
    state["cm_pipeline_result"] = pipeline_res.to_dict()
    a2ui_messages = build_scan_report_surface(
        pipeline_res,
        catalog_mode=catalog_mode,
    )
    lead_md = _format_scan_report_markdown(pipeline_res)
    return types.Content(
        role="model",
        parts=[
            types.Part.from_text(
                text=_build_response_text(lead_md, a2ui_messages)
            )
        ],
    )


_SCHEMA_MANAGER = get_codemender_schema_manager()
_SYSTEM_INSTRUCTION = _SCHEMA_MANAGER.generate_system_prompt(
    role_description=(
        "You are the CodeMender Security Agent integrated with Gemini Enterprise "
        f"(project: {GCP_PROJECT_ID}, engine: {GE_ENGINE_ID}), "
        "powered by gemini-3.8-flash."
    ),
    workflow_description=(
        "1. Ingest uploaded source code files or archives into the isolated workspace.\n"
        "2. Run the 3-stage CodeMender security harness (cm find -> cm verify in sandbox -> cm fix + Judge).\n"
        "3. Automatically track and display LLM token consumption and Cloud Run Gen2 sandbox compute costs (USD & KRW) for every CodeMender execution.\n"
        "4. Support all 12 CodeMender (`cm` v0.12.0) commands: init, find, verify, fix, fix -c, fix --revert, report, triage, vcs, build, stats/cost, sessions, artifacts, models.\n"
        "5. When the user approves a patch, apply the verified diff, record incremental cost, and return the patched file."
    ),
    ui_description=(
        "Present verified vulnerabilities, false-positive filtering metrics, Unified CodeDiff views, "
        "real-time stage-by-stage and cumulative USD/KRW cost telemetry, and interactive cm commands in clear Korean Markdown."
    ),
    include_schema=False,
    include_examples=False,
)

root_agent = Agent(
    name="root_agent",
    model=Gemini(
        model=MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    description=(
        "CodeMender Security Agent (gemini-3.8-flash) for Gemini Enterprise with "
        "full cm v0.12.0 CLI suite and real-time LLM token & Cloud Run sandbox cost tracking (USD/KRW)."
    ),
    instruction=_SYSTEM_INSTRUCTION,
    tools=[
        ingest_source_code,
        run_codemender_scan,
        apply_verified_security_patch,
        run_cm_cli_command,
        get_codemender_cost_report,
    ],
    before_agent_callback=codemender_before_agent_callback,
)

app = App(
    root_agent=root_agent,
    name="app",
    plugins=[SaveFilesAsArtifactsPlugin()],
)


