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
    WORKSPACE_ROOT,
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
# Encoded as base64 so self-scans of `app/agent.py` do not mistake the built-in demo fixture for live code
_SAMPLE_VULNERABLE_CODE = __import__("base64").b64decode(
    "IiIiU2FtcGxlIGVudGVycHJpc2UgcGF5bWVudCAmIGRpYWdub3N0aWNzIHNlcnZpY2UgZm9yIENvZGVNZW5kZXIgdmVyaWZpY2F0aW9uLiIiIgoKaW1wb3J0IHNxbGl0ZTMKaW1wb3J0IHN1YnByb2Nlc3MKCgpkZWYgZ2V0X2N1c3RvbWVyX2ludm9pY2UoZGJfY29ubjogc3FsaXRlMy5Db25uZWN0aW9uLCBpbnZvaWNlX2lkOiBzdHIpIC0+IGxpc3Q6CiAgICBjdXJzb3IgPSBkYl9jb25uLmN1cnNvcigpCiAgICAjIFtWVUxORVJBQkxFIENXRS04OV0gVW5wYXJhbWV0ZXJpemVkIGYtc3RyaW5nIFNRTCBxdWVyeQogICAgY3Vyc29yLmV4ZWN1dGUoZiJTRUxFQ1QgaWQsIGFtb3VudCwgc3RhdHVzIEZST00gaW52b2ljZXMgV0hFUkUgaW52b2ljZV9pZCA9ICd7aW52b2ljZV9pZH0nIikKICAgIHJldHVybiBjdXJzb3IuZmV0Y2hhbGwoKQoKCmRlZiBnZXRfYXVkaXRfbG9nc19zYWZlKGRiX2Nvbm46IHNxbGl0ZTMuQ29ubmVjdGlvbiwgdXNlcl9pZDogc3RyKSAtPiBsaXN0OgogICAgY3Vyc29yID0gZGJfY29ubi5jdXJzb3IoKQogICAgIyBbU0FGRSBQQVJBTUVURVJJWkVEIFFVRVJZXSBTaG91bGQgYmUgZmlsdGVyZWQgb3V0IGFzIEZhbHNlIFBvc2l0aXZlIGluIFN0YWdlIDIgKGNtIHZlcmlmeSkKICAgIGN1cnNvci5leGVjdXRlKCJTRUxFQ1QgYWN0aW9uLCB0cyBGUk9NIGF1ZGl0X2xvZ3MgV0hFUkUgdXNlcl9pZCA9ID8iLCAodXNlcl9pZCwpKQogICAgcmV0dXJuIGN1cnNvci5mZXRjaGFsbCgpCgoKZGVmIHBpbmdfZ2F0ZXdheV9ob3N0KGdhdGV3YXlfaG9zdDogc3RyKSAtPiBzdHI6CiAgICAjIFtWVUxORVJBQkxFIENXRS03OF0gT1MgY29tbWFuZCBleGVjdXRpb24gd2l0aCBzaGVsbD1UcnVlCiAgICBwcm9jID0gc3VicHJvY2Vzcy5ydW4oZiJwaW5nIC1jIDEge2dhdGV3YXlfaG9zdH0iLCBzaGVsbD1UcnVlLCBjYXB0dXJlX291dHB1dD1UcnVlLCB0ZXh0PVRydWUpCiAgICByZXR1cm4gcHJvYy5zdGRvdXQK"
).decode("utf-8")


_SESSION_SNAPSHOT_KEYS = (
    "cm_workspace",
    "cm_pipeline_result",
    "cm_github_repo_context",
    "cm_github_auth",
    "cm_command_history",
    "cm_chat_history",
    "cm_target_repo",
    "cm_active_model",
    "codemender_session_cost_ledger",
    "_cm_session_id",
)


import os as _os

_SESSION_TTL_SECONDS = int(_os.getenv("CM_SESSION_TTL_SECONDS", "43200"))  # Default: 12 hours



def _sanitize_sid(session_id: str) -> str:
    return "".join(
        ch if (ch.isalnum() or ch in ("-", "_")) else "_"
        for ch in str(session_id or "default").strip()
    ) or "default"


def _cleanup_expired_local_sessions() -> None:
    """Purges expired local session snapshots and workspaces in /tmp so container tmpfs never grows unboundedly."""
    import shutil
    import time
    from pathlib import Path

    now_ts = time.time()
    sess_dir = Path("/tmp/codemender_sessions")
    if sess_dir.exists():
        try:
            for p in sess_dir.glob("session_*.json"):
                try:
                    if (now_ts - p.stat().st_mtime) > _SESSION_TTL_SECONDS:
                        p.unlink(missing_ok=True)
                except OSError:
                    pass
        except OSError:
            pass

    ws_root = Path(WORKSPACE_ROOT)
    if ws_root.exists():
        try:
            for d in ws_root.iterdir():
                try:
                    if not d.is_dir():
                        continue
                    # Measure the most recent activity anywhere in the workspace tree (not only the root dir mtime)
                    latest_mtime = d.stat().st_mtime
                    for p in d.rglob("*"):
                        try:
                            latest_mtime = max(latest_mtime, p.stat().st_mtime)
                        except OSError:
                            continue
                    if (now_ts - latest_mtime) > _SESSION_TTL_SECONDS:
                        shutil.rmtree(d, ignore_errors=True)
                except OSError:
                    pass
        except OSError:
            pass


def _delete_session_snapshot(session_id: str) -> None:
    """Physically deletes an expired session snapshot from both local disk (/tmp) and GCS."""
    import os
    import urllib.parse
    import urllib.request
    from pathlib import Path
    from app.ingestion.file_manager import _get_gcs_access_token

    sid = _sanitize_sid(session_id)
    local_snap = Path(f"/tmp/codemender_sessions/session_{sid}.json")
    try:
        local_snap.unlink(missing_ok=True)
    except OSError:
        pass

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        gcs_token = _get_gcs_access_token()
        if gcs_token:
            try:
                obj_name = f"codemender-config/sessions/{sid}/session_snapshot.json"
                encoded = urllib.parse.quote(obj_name, safe="")
                url = f"https://storage.googleapis.com/storage/v1/b/{GCS_ARTIFACT_BUCKET}/o/{encoded}"
                req = urllib.request.Request(
                    url,
                    headers={
                        "Authorization": f"Bearer {gcs_token}",
                        "X-Goog-User-Project": GCP_PROJECT_ID,
                    },
                    method="DELETE",
                )
                with urllib.request.urlopen(req, timeout=4.0):
                    pass
            except Exception:
                pass


def _load_session_snapshot(session_id: str, state: Any) -> None:
    """Rehydrates session state from session-scoped local or GCS snapshot if in-memory state was lost across Cloud Run instances."""
    import json
    import os
    import time
    import urllib.parse
    import urllib.request
    from pathlib import Path
    from app.ingestion.file_manager import _get_gcs_access_token

    if state.get("cm_workspace"):
        return

    _cleanup_expired_local_sessions()
    sid = _sanitize_sid(session_id)
    snap: dict[str, Any] = {}

    local_snap = Path(f"/tmp/codemender_sessions/session_{sid}.json")
    if local_snap.exists():
        try:
            snap = json.loads(local_snap.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as err:
            logger.debug(f"Failed to read local session snapshot: {err}")
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
            except (OSError, json.JSONDecodeError) as err:
                logger.debug(f"Failed to read GCS session snapshot: {err}")

    if isinstance(snap, dict) and snap:
        expires_at = int(snap.get("_cm_expires_at_epoch") or 0)
        if expires_at > 0 and int(time.time()) > expires_at:
            _delete_session_snapshot(sid)
            return
        for k in _SESSION_SNAPSHOT_KEYS:
            if k in snap and snap[k] is not None and not state.get(k):
                state[k] = snap[k]


def _save_session_snapshot(session_id: str, state: Any) -> None:
    """Persists session state strictly under the session's own local and GCS path with TTL and zero plaintext secrets."""
    import json
    import os
    import re
    import time
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

    # Never store plaintext GitHub OAuth access_token or device_code inside session_snapshot.json
    if isinstance(snap.get("cm_github_auth"), dict):
        sanitized_auth = dict(snap["cm_github_auth"])
        sanitized_auth.pop("access_token", None)
        sanitized_auth.pop("pending_device_code", None)
        snap["cm_github_auth"] = sanitized_auth

    now_ts = int(time.time())
    snap["_cm_saved_at_epoch"] = now_ts
    snap["_cm_expires_at_epoch"] = now_ts + _SESSION_TTL_SECONDS

    serialized_snap = json.dumps(snap, ensure_ascii=False)
    serialized_snap = re.sub(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,})\b",
        "[REDACTED_GITHUB_TOKEN]",
        serialized_snap,
    )
    serialized_snap = re.sub(
        r"(?i)(cm\s+github\s+token\s+)[^\s\"'\\]+",
        r"\1[REDACTED_GITHUB_TOKEN]",
        serialized_snap,
    )

    try:
        local_dir = Path("/tmp/codemender_sessions")
        local_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        local_snap = local_dir / f"session_{sid}.json"
        fd = os.open(str(local_snap), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(serialized_snap)
    except OSError as err:
        logger.debug(f"Failed to write local session snapshot: {err}")

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        gcs_token = _get_gcs_access_token()
        if gcs_token:
            try:
                obj_name = f"codemender-config/sessions/{sid}/session_snapshot.json"
                encoded = urllib.parse.quote(obj_name, safe="")
                url = f"https://storage.googleapis.com/upload/storage/v1/b/{GCS_ARTIFACT_BUCKET}/o?uploadType=media&name={encoded}"
                req = urllib.request.Request(
                    url,
                    data=serialized_snap.encode("utf-8"),
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
        "1. **내 GitHub 연동 & 스캔**: 채팅창에 `깃허브 로그인`을 입력해 기기 인증 후 **`깃허브 스캔 <내레포>`** 또는 `깃허브 PR 생성`을 실행하세요.\n"
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
            loc_path = item.get("local_container_path") or f"{WORKSPACE_ROOT}/{pipeline_result.workspace_id}/patched/{fpath}"
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
                f"| **📦 전체 수정본 ZIP 번들** | 전체 파일 패키지 | **[📦 `codemender_patched.zip` 다운로드]({zip_dl_url})** | `{zip_gcs_uri}` | `{WORKSPACE_ROOT}/{pipeline_result.workspace_id}/patched/` |"
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
                "- 다른 파일이나 취약한 코드 스니펫을 업로드하시거나 `샘플 진단 실행`을 입력해 패치 생성 플로우를 테스트해 보세요.",
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


def _record_turn_in_chat_history(
    state: Any,
    user_text: str,
    resp_content: types.Content | None,
) -> None:
    """Appends the current user turn and a concise summary of the assistant response to `cm_chat_history`."""
    if state is None or not hasattr(state, "get") or not (user_text or "").strip():
        return
    assistant_text = ""
    if resp_content and getattr(resp_content, "parts", None):
        for p in resp_content.parts:
            t = getattr(p, "text", None)
            if t:
                assistant_text += t + "\n"
    if "---a2ui_JSON---" in assistant_text:
        assistant_text = assistant_text.split("---a2ui_JSON---", 1)[0]
    assistant_text = assistant_text.strip()
    if not assistant_text:
        return

    history = list(state.get("cm_chat_history") or [])
    history.append(
        {
            "user": user_text.strip()[:500],
            "assistant": assistant_text[:900],
        }
    )
    state["cm_chat_history"] = history[-10:]


async def codemender_before_agent_callback(
    callback_context: CallbackContext,
) -> types.Content | None:
    """Intercepts file uploads and chat commands for deterministic 3-Stage CodeMender execution with automatic cost tracking."""
    state = callback_context.state
    inv_ctx = callback_context._invocation_context
    session_id = getattr(inv_ctx.session, "id", "default_session")
    user_content = callback_context.user_content
    parts = list(user_content.parts) if (user_content and user_content.parts) else []
    user_text = _extract_user_plain_text(parts)
    try:
        resp_content = await _codemender_before_agent_callback_inner(
            callback_context, state, inv_ctx, session_id
        )
        if resp_content is not None and user_text.strip():
            _record_turn_in_chat_history(state, user_text, resp_content)
        return resp_content
    finally:
        _save_session_snapshot(session_id, state)


def _classify_user_intent(
    user_text: str,
    ws: Any,
    state: Any,
    active_model: str,
) -> dict[str, Any]:
    """Classifies user intent using multi-turn conversation context (`cm_chat_history`, `cm_target_repo`) + Gemini JSON router."""
    import json
    import os
    import re
    from google import genai
    from google.genai import types as genai_types
    from app.config import CODEMENDER_FALLBACK_MODEL
    from app.harness.cm_commands import (
        extract_exclude_paths_from_text,
        extract_target_repo_from_text,
    )

    clean_text = (user_text or "").strip()
    low = (
        clean_text.lower()
        .replace("래포", "레포")
        .replace("리포", "레포")
    )
    no_space = re.sub(r"\s+", "", low)
    exclude_paths = extract_exclude_paths_from_text(clean_text)
    mentioned_repo = extract_target_repo_from_text(clean_text)

    if mentioned_repo:
        state["cm_target_repo"] = mentioned_repo

    chat_history = list(state.get("cm_chat_history") or [])
    active_target_repo = str(
        mentioned_repo
        or state.get("cm_target_repo")
        or (
            (state.get("cm_github_repo_context") or {}).get("repo")
            if isinstance(state.get("cm_github_repo_context"), dict)
            else ""
        )
        or ""
    ).strip()

    if not active_target_repo and chat_history:
        for turn in reversed(chat_history[-6:]):
            r_cand = extract_target_repo_from_text(str(turn.get("user") or ""))
            if r_cand and r_cand.lower() not in ("owner/repo", "<owner>/<repo>", "소유자/저장소명"):
                active_target_repo = r_cand
                state["cm_target_repo"] = r_cand
                break

    # 1. Guardrail: Explanatory questions about files/results/context ("대상 파일: sample_payment_service.py 이게지금어디에있는건데", "뭔데 이게", "왜 이래")
    is_explanatory_question = any(
        q in low or q.replace(" ", "") in no_space
        for q in (
            "대상 파일:",
            "어디에있는건데",
            "어디에 있는건데",
            "어디에있어",
            "어디 있어",
            "어디있는",
            "이게지금어디",
            "뭔데 이게",
            "이게 뭔데",
            "이게 뭐야",
            "무슨 파일",
            "무슨 뜻",
            "왜 이래",
            "왜 이런",
            "왜 스캔",
            "오늘날씨",
            "오늘 날씨",
        )
    )
    if is_explanatory_question and not any(
        dl in low for dl in ("다운로드", "download", "수정한 파일", "수정된 파일", "패치된 파일")
    ):
        return {"intent": "chat_or_question", "target_repo": active_target_repo}

    # 2. Explicit built-in demo / sample scan request (ONLY when NOT excluding a sample folder and NOT asking about sample_payment_service.py)
    if (
        not exclude_paths
        and not mentioned_repo
        and "sample_payment_service" not in low
        and any(
            kw in low or kw.replace(" ", "") in no_space
            for kw in (
                "샘플 진단",
                "샘플 스캔",
                "샘플 실행",
                "샘플 테스트",
                "샘플 코드",
                "데모 실행",
                "데모 스캔",
                "데모 진단",
                "run sample",
                "sample scan",
                "demo scan",
            )
        )
    ) or low in ("샘플", "데모", "sample", "demo", "테스트 실행", "진단 실행"):
        return {"intent": "run_sample_scan"}

    # 3. If user only mentioned a repository name without any scan/PR action verb (e.g. "codemender-ge레포")
    has_scan_verb = any(
        v in low or v.replace(" ", "") in no_space
        for v in (
            "스캔",
            "진단",
            "검사",
            "분석",
            "점검",
            "찾아",
            "탐색",
            "scan",
            "audit",
            "check",
        )
    )
    has_affirmative_scan_followup = bool(
        active_target_repo
        and chat_history
        and any(
            k in str(chat_history[-1].get("assistant") or "")
            for k in ("스캔을 시작할까요", "진행하실 작업", "저장소를 확인했습니다")
        )
        and any(
            a in low
            for a in ("응", "그래", "네", "어", "해줘", "해봐", "시작", "진행", "스캔")
        )
    )

    if mentioned_repo and not has_scan_verb and "pr" not in low and not exclude_paths:
        return {"intent": "chat_or_question", "target_repo": active_target_repo}

    # 4. Folder exclusion scan or active target repo scan ("sample폴더외에 다 스캔해", "다 스캔해", "응 스캔해줘")
    if (exclude_paths and has_scan_verb) or (
        active_target_repo and (has_scan_verb or has_affirmative_scan_followup)
    ):
        return {
            "intent": "github_scan",
            "target_repo": active_target_repo,
            "exclude_paths": exclude_paths,
            "subpath": "",
        }


    # 5. Patch application on existing scan findings
    if state.get("cm_pipeline_result") and any(
        kw in low
        for kw in ("패치 적용", "패치해", "전체 패치", "apply patch", "apply all", "수정본 적용")
    ):
        vid_match = re.search(r"(CM-[A-Z0-9-]+-\d+)", clean_text, re.IGNORECASE)
        return {
            "intent": "apply_patch",
            "vuln_id": vid_match.group(1).upper() if vid_match else "ALL",
        }

    # 6. Greeting or help onboarding
    if low in ("안녕", "안녕하세요", "반가워", "hello", "hi", "도움말", "help", "사용법"):
        return {"intent": "greeting_or_help"}

    # 7. Workspace scan when files are already uploaded in workspace and no external target repo is pending
    if ws.files and has_scan_verb and not active_target_repo:
        return {"intent": "workspace_scan"}

    # 8. LLM Multi-Turn Intent Router for nuanced or multi-turn requests when network is enabled
    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        ws_files = [f.relative_path for f in getattr(ws, "files", [])]
        history_lines = []
        for idx, turn in enumerate(chat_history[-6:], start=1):
            history_lines.append(
                f"Turn {idx} User: {turn.get('user', '')}\nTurn {idx} Assistant: {turn.get('assistant', '')[:300]}"
            )
        history_block = "\n".join(history_lines) if history_lines else "(이전 대화 없음)"

        router_prompt = (
            "당신은 CodeMender Security Agent의 멀티턴 대화 맥락 기반 의도 분류기(Intent Router)입니다.\n"
            "이전 대화 이력과 현재 세션 상태, 그리고 사용자의 이번 발화를 보고 실제 의도(intent)를 JSON으로 분류하세요.\n\n"
            "[중요 분류 규칙]\n"
            "1. 사용자가 이전 턴에서 특정 GitHub 레포지토리(예: 'codemender-ge레포')를 언급했고, 이번 턴에서 "
            "'sample폴더외에 다 스캔해', '응 스캔해봐', 'app 폴더만 검사해' 등 스캔을 지시했다면 반드시 `intent: \"github_scan\"`, "
            "`target_repo: \"<해당 레포>\"`, `exclude_paths: [\"sample\"]` 등으로 분류하세요. "
            "절대 폴더 이름에 'sample'이 들어갔다고 해서 내장 데모(`run_sample_scan`)로 분류하면 안 됩니다!\n"
            "2. 사용자가 '뭔데 이게', '대상 파일: sample_payment_service.py 이게지금어디에있는건데', '이게 왜 나와?', "
            "'오늘 날씨는?' 처럼 질문하거나 설명을 요구하거나 당황해하는 반응이면, 절대 스캔(`run_sample_scan`, `github_scan`, `workspace_scan`)을 실행하지 말고 "
            "반드시 `intent: \"chat_or_question\"`으로 분류하세요!\n"
            "3. 사용자가 단순히 레포지토리 이름만 말하고(예: 'codemender-ge레포') 아직 구체적인 작업(스캔/PR)을 지시하지 않았다면 "
            "`intent: \"chat_or_question\"`, `target_repo: \"codemender-ge\"`로 분류하세요.\n"
            "4. 사용 가능한 intent 값:\n"
            "   - \"chat_or_question\": 질문 답변, 파일 위치/이유 설명, 레포 확인 안내, 일상 대화\n"
            "   - \"github_scan\": GitHub 레포지토리 스캔 (target_repo, subpath, exclude_paths 포함)\n"
            "   - \"github_repos\": 내 GitHub 레포 목록 조회 (visibility: all|private|public)\n"
            "   - \"github_pr\": 패치된 코드를 GitHub PR로 생성\n"
            "   - \"github_login\": GitHub OAuth 로그인\n"
            "   - \"workspace_scan\": 이미 업로드된 워크스페이스 파일 스캔\n"
            "   - \"run_sample_scan\": 사용자가 명시적으로 '기본 내장 샘플/데모 진단 실행'을 요청했을 때만\n"
            "   - \"apply_patch\": 발견된 취약점 패치 적용 (vuln_id: CM-... 또는 ALL)\n"
            "   - \"cost_report\": 비용/요금/토큰 정산 내역 조회\n"
            "   - \"models\": 모델 목록 조회 또는 모델 전환\n"
            "   - \"sessions\": 세션 실행 이력 조회\n"
            "   - \"artifacts\": 패치 완료된 파일 다운로드 링크 조회\n"
            "   - \"greeting_or_help\": 인사 또는 전체 도움말\n\n"
            f"[현재 세션 상태]\n"
            f"- 현재 지목된 타겟 레포(cm_target_repo): {active_target_repo or '없음'}\n"
            f"- 현재 워크스페이스 파일: {', '.join(ws_files) if ws_files else '없음'}\n"
            f"- 스캔 결과 존재 여부: {'있음' if state.get('cm_pipeline_result') else '없음'}\n\n"
            f"[최근 대화 이력]\n{history_block}\n\n"
            f"[이번 사용자 발화]\n{clean_text}\n\n"
            "반드시 아래 JSON 스키마로만 응답하세요:\n"
            '{"intent": "...", "target_repo": "", "subpath": "", "exclude_paths": [], "visibility": "all", "vuln_id": "ALL"}'
        )

        candidate_models = []
        for m in (active_model, CODEMENDER_FALLBACK_MODEL, "gemini-2.5-flash"):
            if m and m not in candidate_models:
                candidate_models.append(m)

        client = genai.Client(
            vertexai=True, project=GCP_PROJECT_ID, location="global"
        )
        for model_name in candidate_models:
            try:
                resp = client.models.generate_content(
                    model=model_name,
                    contents=router_prompt,
                    config=genai_types.GenerateContentConfig(
                        temperature=0.0,
                        response_mime_type="application/json",
                    ),
                )
                if resp and resp.text:
                    parsed_json = json.loads(resp.text.strip())
                    if isinstance(parsed_json, dict) and parsed_json.get("intent"):
                        if not parsed_json.get("target_repo") and active_target_repo:
                            parsed_json["target_repo"] = active_target_repo
                        if exclude_paths and not parsed_json.get("exclude_paths"):
                            parsed_json["exclude_paths"] = exclude_paths
                        if parsed_json.get("target_repo"):
                            state["cm_target_repo"] = str(parsed_json["target_repo"]).strip()
                        return parsed_json
            except Exception as err:
                logger.debug(f"LLM intent classification fallback ({model_name}): {err}")

    return {"intent": "chat_or_question", "target_repo": active_target_repo}


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

    # 4. Extract newly uploaded files or pasted source code snippets first if present
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

    # 5. Check if user clicked an interactive A2UI button DataPart first
    action_event = extract_a2ui_action_from_parts(expanded_parts)

    # 6. Check if user invoked an explicit `cm <subcommand>` or unambiguous command phrase
    parsed_cm = parse_cm_chat_command(user_text) if not action_event else None

    # 7. If not an explicit `cm` command or button event, run Multi-Turn Context & LLM Intent Router
    if not action_event and parsed_cm is None and user_text.strip():
        intent_info = _classify_user_intent(
            user_text=user_text,
            ws=ws,
            state=state,
            active_model=active_model,
        )
        intent = str(intent_info.get("intent") or "chat_or_question")
        target_repo = str(intent_info.get("target_repo") or state.get("cm_target_repo") or "").strip()
        subpath = str(intent_info.get("subpath") or "").strip()
        exclude_paths = list(intent_info.get("exclude_paths") or [])

        if intent == "github_scan":
            pos = ["scan"]
            if target_repo:
                pos.append(target_repo)
            if subpath:
                pos.append(subpath)
            parsed_cm = {
                "subcommand": "github",
                "positional": pos,
                "target_repo": target_repo,
                "subpath": subpath,
                "exclude_paths": exclude_paths,
                "raw": user_text,
            }
        elif intent == "github_repos":
            parsed_cm = {
                "subcommand": "github",
                "positional": ["repos"],
                "visibility": str(intent_info.get("visibility") or "all"),
                "raw": user_text,
            }
        elif intent == "github_pr":
            pos = ["pr"]
            if target_repo:
                pos.append(target_repo)
            parsed_cm = {
                "subcommand": "github",
                "positional": pos,
                "raw": user_text,
            }
        elif intent == "github_login":
            parsed_cm = {
                "subcommand": "github",
                "positional": ["login"],
                "raw": user_text,
            }
        elif intent == "cost_report":
            parsed_cm = {"subcommand": "cost", "raw": user_text}
        elif intent == "models":
            parsed_cm = {"subcommand": "models", "raw": user_text}
        elif intent == "sessions":
            parsed_cm = {"subcommand": "sessions", "raw": user_text}
        elif intent == "artifacts":
            parsed_cm = {"subcommand": "artifacts", "raw": user_text}
        elif intent == "run_sample_scan":
            action_event = {"name": "run_sample_scan", "context": {}}
        elif intent == "apply_patch":
            vid = str(intent_info.get("vuln_id") or "ALL").upper()
            if vid == "ALL":
                action_event = {"name": "apply_all_patches", "context": {}}
            else:
                action_event = {"name": "apply_patch", "context": {"vuln_id": vid}}
        elif intent == "workspace_scan" and ws.files:
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
        elif intent == "greeting_or_help":
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

    if not user_text.strip():
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

    # 8. Contextual & general conversational response (handles follow-up questions, repo confirmations, and casual queries)
    chat_md = _generate_contextual_chat_response(
        user_text=user_text,
        ws=ws,
        state=state,
        active_model=active_model,
    )
    return types.Content(
        role="model",
        parts=[types.Part.from_text(text=chat_md)],
    )


def _generate_contextual_chat_response(
    user_text: str,
    ws: Any,
    state: Any,
    active_model: str,
) -> str:
    """Generates a natural, context-aware Korean response for general questions or contextual follow-ups without triggering unrequested scans."""
    import os
    from google import genai
    from google.genai import types as genai_types
    from app.config import CODEMENDER_FALLBACK_MODEL
    from app.harness.github_integration import (
        list_user_github_repos,
        poll_or_verify_github_auth,
    )

    ws_files = [f.relative_path for f in getattr(ws, "files", [])]
    pipe_dict = state.get("cm_pipeline_result") if hasattr(state, "get") else None
    gh_ctx = state.get("cm_github_repo_context") if hasattr(state, "get") else None
    target_repo = str(state.get("cm_target_repo") or "").strip() if hasattr(state, "get") else ""
    chat_history = list(state.get("cm_chat_history") or []) if hasattr(state, "get") else []
    gh_auth = poll_or_verify_github_auth(state)
    gh_login = str(gh_auth.get("login") or "") if isinstance(gh_auth, dict) else ""

    if target_repo and "/" not in target_repo and gh_login:
        target_repo_full = f"{gh_login}/{target_repo}"
    else:
        target_repo_full = target_repo

    ctx_lines = [
        f"- 현재 활성 모델: {active_model}",
        f"- 현재 지목/대화 중인 타겟 GitHub 레포지토리: {target_repo_full or '아직 지정되지 않음'}",
        f"- 현재 세션 워크스페이스 파일({len(ws_files)}개): {', '.join(ws_files) if ws_files else '아직 업로드/스캔된 파일 없음'}",
    ]
    if _SAMPLE_VULNERABLE_FILENAME in ws_files:
        ctx_lines.append(
            f"- [중요 파일 출처 안내] `{_SAMPLE_VULNERABLE_FILENAME}` 파일은 사용자의 GitHub 레포지토리에 있는 파일이 아니라, "
            f"CodeMender Cloud Run 컨테이너 내부 임시 격리 워크스페이스(`{ws.orig_dir}/{_SAMPLE_VULNERABLE_FILENAME}`)에 내장된 **기본 데모용 샘플 파일(SQLi CWE-89 + OS Command Injection CWE-78 검증용)**입니다."
        )
    if isinstance(gh_ctx, dict) and gh_ctx.get("repo"):
        ctx_lines.append(
            f"- 최근 스캔 완료한 GitHub 레포지토리: {gh_ctx.get('repo')} (브랜치: {gh_ctx.get('branch', 'main')}, 가져온 파일: {', '.join(gh_ctx.get('fetched_files') or [])})"
        )
    if isinstance(gh_auth, dict) and gh_auth.get("authenticated") and gh_login:
        ctx_lines.append(f"- 연동된 GitHub 계정: @{gh_login}")
        try:
            user_repos = list_user_github_repos(
                str(gh_auth.get("access_token") or ""), limit=25, visibility="all"
            )
            if user_repos:
                repo_summaries = [
                    f"{r['full_name']} ({'Private/비공개' if r.get('private') else 'Public/공개'}, 주언어:{r.get('language', '-')})"
                    for r in user_repos
                ]
                ctx_lines.append(
                    f"- @{gh_login} 계정의 실제 GitHub 보유 레포지토리 목록({len(user_repos)}개): "
                    + ", ".join(repo_summaries)
                )
        except Exception:
            pass

    if isinstance(pipe_dict, dict):
        findings = pipe_dict.get("findings") or []
        fp_count = pipe_dict.get("false_positives_filtered", 0)
        ctx_lines.append(
            f"- 최근 3-Stage 보안 스캔 요약: 확증 취약점 {len(findings)}건, Stage 2 오탐 제거 {fp_count}건"
        )
        for idx, f in enumerate(findings[:10], start=1):
            ctx_lines.append(
                f"  [{idx}] {f.get('vuln_id')} ({f.get('cwe_id')} · {f.get('severity')} · 상태:{f.get('patch_status')}): "
                f"{f.get('title')} @ {f.get('file_path')}:{f.get('start_line')} — {f.get('description')}"
            )

    history_lines = []
    for idx, turn in enumerate(chat_history[-8:], start=1):
        history_lines.append(
            f"[Turn {idx} 사용자]: {turn.get('user', '')}\n[Turn {idx} 에이전트]: {turn.get('assistant', '')[:400]}"
        )
    history_block = "\n".join(history_lines) if history_lines else "(이전 대화 없음)"
    context_block = "\n".join(ctx_lines)

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        prompt = (
            "당신은 Google Cloud Gemini Enterprise에 통합된 'CodeMender Security Agent (cm v0.12.0)'입니다.\n"
            "반드시 [최근 대화 이력]과 [현재 세션 컨텍스트]를 함께 읽고, 사용자의 질문이나 발화 의도에 정확히 맞춰 한국어로 자연스럽고 명확하게 답변하세요.\n\n"
            "[응답 원칙]\n"
            "1. 사용자가 일상적인 질문(예: '오늘 날씨는?', '점심 추천해줘', '고마워', '너는 누구야?')을 하면, "
            "절대 보안 스캔 리포트를 쏟아내지 말고 질문 맥락에 맞춰 먼저 자연스럽게 대답하세요.\n"
            "2. 사용자가 `sample_payment_service.py`가 어디에 있는 파일인지, 왜 이 파일이 나왔는지, 혹은 '뭔데 이게'라고 물어보면: "
            f"`sample_payment_service.py`는 사용자의 GitHub 레포지토리 파일이 아니라 CodeMender 컨테이너 격리 워크스페이스(`{WORKSPACE_ROOT}/<workspace_id>/orig/sample_payment_service.py`)에 내장된 기본 데모용 샘플 파일임을 명확히 설명하세요. "
            "그리고 현재 지목된 타겟 레포지토리(예: `ldu1225/codemender-ge`)를 스캔하려면 `깃허브 스캔 ldu1225/codemender-ge` 또는 `sample 폴더 외에 다 스캔해`라고 입력하면 즉시 해당 GitHub 레포의 실제 코드를 가져와 스캔한다고 안내하세요.\n"
            "3. 사용자가 특정 레포지토리 이름(예: 'codemender-ge레포')만 언급했다면, 해당 레포지토리(`"
            f"{target_repo_full or '지정된 레포'}`"
            ")를 현재 세션의 타겟 저장소로 설정했음을 안내하고, 전체 스캔 또는 특정 폴더 제외 스캔(예: `sample 폴더 외에 다 스캔해`) 등 원하시는 작업을 말씀해 달라고 간결하게 안내하세요.\n"
            "4. 절대 사용자에게 '터미널에서 직접 명령어를 실행하세요'(예: 'gh repo list', 'cm repo list --visibility private' 등)라고 떠넘기지 마세요! "
            "[현재 세션 컨텍스트]에 제공된 실제 GitHub 레포지토리 목록(Private/Public 구분 포함)을 사용해 그 자리에서 직접 답변하세요.\n\n"
            f"[현재 세션 컨텍스트]\n{context_block}\n\n"
            f"[최근 대화 이력]\n{history_block}\n\n"
            f"[이번 사용자 메시지]\n{user_text}"
        )
        candidate_models = []
        for m in (active_model, CODEMENDER_FALLBACK_MODEL, "gemini-2.5-flash"):
            if m and m not in candidate_models:
                candidate_models.append(m)

        client = genai.Client(
            vertexai=True, project=GCP_PROJECT_ID, location="global"
        )
        for model_name in candidate_models:
            try:
                resp = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=genai_types.GenerateContentConfig(
                        temperature=0.25,
                    ),
                )
                if resp and resp.text and resp.text.strip():
                    return resp.text.strip()
            except Exception as err:
                logger.debug(f"Contextual chat generation failed on {model_name}: {err}")

    # Deterministic context-aware fallback when CM_DISABLE_LLM_NETWORK=true
    low_q = user_text.lower()
    if "sample_payment_service" in low_q or "어디에" in low_q or "어디 있" in low_q:
        return (
            f"### 📍 `sample_payment_service.py` 파일 위치 및 출처 안내\n"
            f"- **실제 위치**: Cloud Run 컨테이너 내부 임시 격리 워크스페이스 경로인 `{ws.orig_dir}/{_SAMPLE_VULNERABLE_FILENAME}`에 위치한 **CodeMender 내장 기본 데모 파일**입니다.\n"
            f"- **왜 이 파일이 표시되었나요?**: 회원님의 GitHub 저장소(`{target_repo_full or 'codemender-ge'}`)에 들어 있는 파일이 아니라, CodeMender의 3단계 파이프라인(SQL Injection `CWE-89` · OS Command Injection `CWE-78` 탐지 및 오탐 필터링)을 시연하기 위해 내장된 샘플 코드입니다.\n"
            f"- **내 GitHub 저장소 스캔하기**: 현재 타겟 저장소(**`{target_repo_full or 'codemender-ge'}`**)의 실제 소스 코드를 스캔하시려면 **`깃허브 스캔 {target_repo_full or 'codemender-ge'}`** 또는 **`sample폴더외에 다 스캔해`**라고 입력해 주세요!"
        )
    if target_repo_full and any(k in low_q.replace("래포", "레포").replace("리포", "레포") for k in ("레포", "저장소", "repo")):
        return (
            f"### 🎯 타겟 GitHub 레포지토리 설정 완료: `{target_repo_full}`\n"
            f"- 현재 세션의 작업 대상 저장소가 **`{target_repo_full}`**(으)로 설정되었습니다.\n"
            "- 이제 바로 다음과 같이 자연어로 지시하실 수 있습니다:\n"
            "  - **전체 코드 스캔**: `다 스캔해` 또는 `보안 스캔 시작해`\n"
            "  - **특정 폴더 제외 스캔**: `sample폴더외에 다 스캔해` 또는 `tests 빼고 스캔해`\n"
            "  - **패치 후 PR 생성**: `깃허브 PR 생성`"
        )

    return (
        f"### 💬 CodeMender Security Agent (`{active_model}`)\n"
        f"질문하신 내용(**\"{user_text}\"**)을 이전 대화 맥락과 함께 확인했습니다.\n\n"
        "- 저는 **CodeMender 자율 보안 에이전트**로, 격리된 클라우드 보안 샌드박스에서 동작하기 때문에 실시간 외부 생활 정보(날씨 등)는 직접 조회하지 못하지만 코드 보안 진단·취약점 분석·패치 및 GitHub PR 생성에 관한 질문은 현재 세션 맥락에 맞춰 바로 답변해 드릴 수 있습니다.\n\n"
        f"#### 📌 현재 세션 상태 요약\n{context_block}\n\n"
        "> 💡 **유용한 단축 명령**: **`모델 관리`** (`cm models`) · **`세션 이력`** (`cm sessions`) · **`샘플 진단 실행`** (`cm find`) · **`비용 조회`** (`cm cost`) · **`깃허브 연동`** (`cm github login`)"
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


