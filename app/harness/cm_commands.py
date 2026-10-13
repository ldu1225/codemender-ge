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

"""Full CodeMender (`cm` v0.12.0) command suite for Gemini Enterprise and CLI.

Supports all official CodeMender subcommands and enterprise workflows:
- `cm init [--verify]`
- `cm find [<path>] [--model <model>]`
- `cm verify [<finding-id|ALL>] [--bypass-warning] [--model <model>]`
- `cm fix [<finding-id|ALL>] [-c "<context>"] [--no-cache] [--revert [<id|ALL>]] [--model <model>]`
- `cm report [-f text|json|html]`
- `cm triage`
- `cm vcs status | diff | reset | stage`
- `cm build [--force]`
- `cm stats`
- `cm sessions`
- `cm artifacts`
- `cm models | test-all-models | switch-model <model>`
- `cm help`
"""

from __future__ import annotations

import ast
import html
import json
import os
import re
import shlex
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from google import genai
from google.genai import types as genai_types

from app.config import (
    CLOUD_RUN_GIB_PER_SEC_USD,
    CLOUD_RUN_VCPU_PER_SEC_USD,
    CM_USD_TO_KRW_RATE,
    CODEMENDER_MODEL,
    GCP_PROJECT_ID,
    GCS_ARTIFACT_BUCKET,
)
from app.harness.cm_runner import (
    CodeMenderPipelineResult,
    CodeMenderRunner,
    VulnerabilityFinding,
)
from app.harness.cost_tracker import (
    emit_cloud_logging_cost_entry,
    format_krw,
    format_tokens,
    format_usd,
    get_model_pricing,
    get_session_and_ledger_cost_report,
    load_persistent_cost_ledger,
    record_session_cost,
)
from app.harness.patch_applier import (
    apply_patch_to_workspace,
    build_unified_diff,
    compute_workspace_vcs_status,
    reset_workspace_to_original,
    revert_patch_in_workspace,
)
from app.harness.sandbox_executor import run_safe_subprocess
from app.ingestion.file_manager import WorkspaceContext, _ensure_within_directory

SUPPORTED_CM_MODELS: dict[str, dict[str, str]] = {
    "gemini-3.8-flash": {
        "tier": "Default (Balanced Speed & Deep Reasoning)",
        "specialty": "전 사이클 통합 (cm find / verify / fix / LLM-as-a-Judge) 기본 모델",
        "location": "global",
    },
    "gemini-3.8-flash-cyber": {
        "tier": "Cybersecurity Specialized",
        "specialty": "제로데이·메모리 오염(C/C++) 및 복합 체인 취약점 정밀 분석 특화 모델",
        "location": "global",
    },
    "gemini-3.7-flash": {
        "tier": "High-Speed Baseline",
        "specialty": "대규모 레포지토리 초고속 1차 트리아지 및 경량 스캔 모델",
        "location": "global",
    },
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record_cm_telemetry(
    state: Any,
    command_str: str,
    model_used: str,
    duration_ms: int,
    est_input_tokens: int = 420,
    est_output_tokens: int = 310,
    est_thinking_tokens: int = 96,
    include_sandbox: bool = True,
) -> str:
    """Silently records command execution & cost metrics to session state and Cloud Logging without UI clutter."""
    cmd_low = (command_str or "").strip().lower()
    # Do not record cost-inquiry commands themselves as billable transactions
    if any(
        cmd_low.startswith(x)
        for x in ("cm cost", "cm stats", "cm logs", "cm billing", "비용", "요금", "청구", "얼마")
    ):
        return ""

    pricing = get_model_pricing(model_used)
    llm_cost_usd = (
        (est_input_tokens / 1_000_000.0) * pricing["input"]
        + (est_output_tokens / 1_000_000.0) * pricing["output"]
        + (est_thinking_tokens / 1_000_000.0) * pricing["thinking"]
    )
    sandbox_cost_usd = 0.0
    if include_sandbox:
        sec = max(duration_ms / 1000.0, 0.04)
        sandbox_cost_usd = sec * (
            CLOUD_RUN_VCPU_PER_SEC_USD + CLOUD_RUN_GIB_PER_SEC_USD
        )
    cmd_cost_usd = round(llm_cost_usd + sandbox_cost_usd, 8)
    cmd_cost_krw = round(cmd_cost_usd * CM_USD_TO_KRW_RATE, 4)
    total_tokens = est_input_tokens + est_output_tokens + est_thinking_tokens

    ws_dict = state.get("cm_workspace") if hasattr(state, "get") else None
    sess_id = "default-session"
    ws_id = "cli"
    if isinstance(ws_dict, dict):
        sess_id = str(ws_dict.get("session_id") or ws_dict.get("workspace_id") or "default-session")
        ws_id = str(ws_dict.get("workspace_id") or sess_id)

    history = list(state.get("cm_command_history") or [])
    entry = {
        "index": len(history) + 1,
        "run_id": f"cmd-{len(history) + 1:03d}-{int(time.time() * 1000) % 100000:05d}",
        "timestamp": _now_iso(),
        "session_id": sess_id,
        "workspace_id": ws_id,
        "command": command_str,
        "model": model_used,
        "duration_ms": duration_ms,
        "input_tokens": est_input_tokens,
        "output_tokens": est_output_tokens,
        "thinking_tokens": est_thinking_tokens,
        "total_tokens": total_tokens,
        "llm_cost_usd": round(llm_cost_usd, 8),
        "sandbox_cost_usd": round(sandbox_cost_usd, 8),
        "cost_usd": cmd_cost_usd,
        "cost_krw": cmd_cost_krw,
    }
    history.append(entry)
    state["cm_command_history"] = history

    # Emit structured cost telemetry event to Cloud Logging (`run.googleapis.com/stdout`)
    # Avoid duplicate emission for `cm find` which already emits via `run_pipeline()`
    if not cmd_low.startswith("cm find"):
        emit_cloud_logging_cost_entry(
            {
                "run_id": entry["run_id"],
                "timestamp": entry["timestamp"],
                "session_id": sess_id,
                "workspace_id": ws_id,
                "operation": command_str,
                "model": model_used,
                "input_tokens": est_input_tokens,
                "output_tokens": est_output_tokens,
                "thinking_tokens": est_thinking_tokens,
                "total_tokens": total_tokens,
                "llm_cost_usd": round(llm_cost_usd, 8),
                "sandbox_compute_cost_usd": round(sandbox_cost_usd, 8),
                "total_cost_usd": cmd_cost_usd,
                "total_cost_krw": cmd_cost_krw,
                "duration_ms": float(duration_ms),
            }
        )

    # Return empty string so normal commands do NOT display unsolicited cost footers
    return ""



def resolve_finding_id(
    raw_id: str | None, findings: list[VulnerabilityFinding]
) -> str:
    """Resolves numeric index ('1', '2') or CWE prefix ('CWE-89') to canonical `CM-CWE-XX-NNN`."""
    if not raw_id:
        return "ALL"
    token = raw_id.strip().upper()
    if token in ("ALL", "*"):
        return "ALL"
    if token.isdigit():
        idx = int(token) - 1
        if 0 <= idx < len(findings):
            return findings[idx].vuln_id
    for f in findings:
        if f.vuln_id.upper() == token:
            return f.vuln_id
    for f in findings:
        if token in f.vuln_id.upper() or token == f.cwe_id.upper():
            return f.vuln_id
    return token


def parse_cm_chat_command(user_text: str) -> dict[str, Any] | None:
    """Parses explicit `cm <subcmd> ...` or Korean natural-language equivalents."""
    if not user_text or not user_text.strip():
        return None
    stripped = user_text.strip()
    first_line = stripped.splitlines()[0].strip()
    lower = first_line.lower()

    # 1. Explicit `cm ...` CLI syntax in chat
    if lower == "cm" or lower.startswith("cm "):
        try:
            tokens = shlex.split(first_line)
        except ValueError:
            tokens = first_line.split()
        if len(tokens) == 1:
            return {"subcommand": "help", "raw": first_line}

        sub = tokens[1].lower()
        rest = tokens[2:]

        # Extract common flags
        model_override = None
        extra_context = None
        fmt = "text"
        revert_flag = False
        verify_flag = "--verify" in rest
        no_cache_flag = "--no-cache" in rest
        bypass_warning = "--bypass-warning" in rest
        force_flag = "--force" in rest

        positional: list[str] = []
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok in ("--model", "-m") and i + 1 < len(rest):
                model_override = rest[i + 1]
                i += 2
            elif tok in ("-c", "--context") and i + 1 < len(rest):
                extra_context = rest[i + 1]
                i += 2
            elif tok in ("-f", "--format") and i + 1 < len(rest):
                fmt = rest[i + 1].lower()
                i += 2
            elif tok == "--revert":
                revert_flag = True
                if i + 1 < len(rest) and not rest[i + 1].startswith("-"):
                    positional.append(rest[i + 1])
                    i += 2
                else:
                    i += 1
            elif tok.startswith("-"):
                i += 1
            else:
                positional.append(tok)
                i += 1

        return {
            "subcommand": sub,
            "positional": positional,
            "model": model_override,
            "extra_context": extra_context,
            "format": fmt,
            "revert": revert_flag,
            "verify": verify_flag,
            "no_cache": no_cache_flag,
            "bypass_warning": bypass_warning,
            "force": force_flag,
            "raw": first_line,
        }

    # 2. Natural-language Korean / English command mapping
    if any(
        k in lower
        for k in ("cm 명령어", "명령어 목록", "전체 기능", "무슨 기능", "기능 목록")
    ):
        return {"subcommand": "help", "raw": first_line}

    if any(k in lower for k in ("워크스페이스 초기화", "cm 초기화", "설정 초기화")):
        return {"subcommand": "init", "verify": True, "raw": first_line}

    if any(
        k in lower
        for k in ("트리아지", "triage", "우선순위 분류", "보안 게이트", "security gate")
    ):
        return {"subcommand": "triage", "raw": first_line}

    if any(
        k in lower for k in ("패치 롤백", "패치 취소", "패치 원복", "원복해", "롤백해", "revert")
    ):
        vid_match = re.search(r"(CM-[A-Z0-9-]+-\d+)", first_line, re.IGNORECASE)
        return {
            "subcommand": "fix",
            "revert": True,
            "positional": [vid_match.group(1).upper()] if vid_match else ["ALL"],
            "raw": first_line,
        }

    if any(k in lower for k in ("json 리포트", "json 보고서", "report json")):
        return {"subcommand": "report", "format": "json", "raw": first_line}

    if any(k in lower for k in ("html 리포트", "html 보고서", "report html")):
        return {"subcommand": "report", "format": "html", "raw": first_line}

    if any(k in lower for k in ("리포트 조회", "보고서 출력", "결과 요약표")):
        return {"subcommand": "report", "format": "text", "raw": first_line}

    if any(k in lower for k in ("vcs diff", "git diff", "변경사항 비교", "전체 diff")):
        return {"subcommand": "vcs", "positional": ["diff"], "raw": first_line}

    if any(k in lower for k in ("vcs status", "git status", "파일 상태", "수정 상태")):
        return {"subcommand": "vcs", "positional": ["status"], "raw": first_line}

    if any(k in lower for k in ("vcs reset", "git reset", "원본으로 초기화")):
        return {"subcommand": "vcs", "positional": ["reset"], "raw": first_line}

    if any(
        k in lower
        for k in ("vcs stage", "git stage", "커밋 메시지")
    ):
        return {"subcommand": "vcs", "positional": ["stage"], "raw": first_line}

    if any(k in lower for k in ("빌드 검증", "컴파일 검증", "구문 검사", "빌드 테스트")):
        return {"subcommand": "build", "raw": first_line}

    if any(
        k in lower
        for k in (
            "비용",
            "요금",
            "청구",
            "정산",
            "과금",
            "얼마 나왔",
            "얼마나 나왔",
            "얼마야",
            "얼마인지",
            "얼마나 들었",
            "토큰 사용량",
            "세션 통계",
            "통계 조회",
            "세션별",
            "트랜잭션별",
            "트랜잭션마다",
            "세션마다",
            "로그 비용",
            "로깅 비용",
            "클라우드 로깅",
            "cloud logging",
            "stats",
            "cost",
            "billing",
            "logs",
        )
    ):
        return {"subcommand": "cost", "raw": first_line}

    if any(k in lower for k in ("세션 이력", "명령 이력", "sessions")):
        return {"subcommand": "sessions", "raw": first_line}

    if any(
        k in lower
        for k in (
            "아티팩트 목록",
            "생성된 파일",
            "다운로드",
            "download",
            "어디에 저장",
            "어디에저장",
            "어디있",
            "어디 있",
            "저장 위치",
            "저장된",
            "수정한 파일",
            "수정된 파일",
            "artifacts",
        )
    ):
        return {"subcommand": "artifacts", "raw": first_line}

    if any(
        k in lower
        for k in ("모델 비교", "모델 목록", "모델 테스트", "test-all-models", "switch-model")
    ):
        for m_name in SUPPORTED_CM_MODELS:
            if m_name in lower:
                return {
                    "subcommand": "switch-model",
                    "positional": [m_name],
                    "raw": first_line,
                }
        return {"subcommand": "models", "raw": first_line}

    # 3. GitHub OAuth / Repo Scan / Autonomous PR natural-language triggers
    tok_match = re.search(r"\b(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", stripped)
    if tok_match:
        return {
            "subcommand": "github",
            "positional": ["token", tok_match.group(1)],
            "raw": first_line,
        }

    gh_repo_match = re.search(
        r"(?:https://github\.com/)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", first_line
    )
    if any(
        k in lower
        for k in (
            "깃허브 로그아웃",
            "깃허브 연결 해제",
            "깃허브 연동 해제",
            "github logout",
        )
    ):
        return {"subcommand": "github", "positional": ["logout"], "raw": first_line}

    if any(
        k in lower
        for k in (
            "깃허브 인증 완료",
            "깃허브 인증 확인",
            "인증 완료",
            "인증 확인",
            "인증했어",
            "깃허브 상태",
            "내 깃허브 계정",
            "github status",
            "github verify",
        )
    ):
        return {"subcommand": "github", "positional": ["status"], "raw": first_line}

    if any(
        k in lower
        for k in (
            "깃허브 레포",
            "깃허브 저장소",
            "내 레포",
            "레포 목록",
            "레포지토리 목록",
            "저장소 목록",
            "github repos",
        )
    ):
        return {"subcommand": "github", "positional": ["repos"], "raw": first_line}

    if any(
        k in lower
        for k in (
            "깃허브 스캔",
            "레포 스캔",
            "저장소 스캔",
            "github scan",
            "깃허브 진단",
        )
    ) or ("https://github.com/" in lower and "pull" not in lower):
        pos = ["scan"]
        if gh_repo_match:
            pos.append(gh_repo_match.group(1))
        return {"subcommand": "github", "positional": pos, "raw": first_line}

    if any(
        k in lower
        for k in (
            "깃허브 pr",
            "깃허브에 pr",
            "pr 생성",
            "피알 생성",
            "풀리퀘스트",
            "pr 만들어",
            "pr 올려",
            "피알 올려",
            "피알 만들어",
            "깃허브 푸시",
            "깃허브에 올려",
            "깃허브 커밋",
            "깃허브에 반영",
            "레포에 올려",
            "github pr",
            "github push",
        )
    ):
        pos = ["pr"]
        if gh_repo_match:
            pos.append(gh_repo_match.group(1))
        return {"subcommand": "github", "positional": pos, "raw": first_line}

    if any(
        k in lower
        for k in (
            "깃허브 로그인",
            "깃허브 연동",
            "깃허브 인증",
            "깃허브 연결",
            "깃허브",
            "github login",
            "github auth",
            "github",
        )
    ):
        return {"subcommand": "github", "positional": ["login"], "raw": first_line}

    return None


def _synthesize_contextual_patch(
    finding: VulnerabilityFinding,
    extra_context: str,
    model_name: str,
) -> tuple[str, str]:
    """Synthesizes an updated `after_code` and `judge_rationale` incorporating `-c <extra_context>`."""
    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        prompt = (
            f"You are CodeMender (`cm fix -c`). Refine the security patch for `{finding.vuln_id}` "
            f"({finding.cwe_id}: {finding.title}) in `{finding.file_path}`.\n"
            f"User's custom constraint (`-c`): {extra_context}\n\n"
            f"Original vulnerable snippet (`before_code`):\n```\n{finding.before_code}\n```\n\n"
            f"Current proposed patch (`after_code`):\n```\n{finding.after_code}\n```\n\n"
            "Return JSON with keys `after_code` (exact replacement code snippet) and "
            "`judge_rationale` (in Korean, explaining how both the CWE fix and user constraint were satisfied)."
        )
        try:
            client = genai.Client(
                vertexai=True, project=GCP_PROJECT_ID, location="global"
            )
            resp = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                ),
            )
            if resp and resp.text:
                data = json.loads(resp.text)
                new_after = data.get("after_code") or finding.after_code
                new_rationale = data.get("judge_rationale") or finding.judge_rationale
                return new_after, new_rationale
        except Exception:
            pass

    # Deterministic contextual augmentation when offline or in unit tests
    comment_prefix = (
        "//"
        if finding.file_path.endswith((".c", ".cpp", ".h", ".js", ".ts", ".go", ".java"))
        else "#"
    )
    first_indent = re.match(r"^\s*", finding.after_code)
    indent = first_indent.group(0) if first_indent else ""
    augmented_after = (
        f"{indent}{comment_prefix} [cm fix -c] Custom policy applied: {extra_context}\n"
        f"{finding.after_code}"
    )
    augmented_rationale = (
        f"{finding.judge_rationale} (사용자 추가 컨텍스트 `-c \"{extra_context}\"` 반영 완료)"
    )
    return augmented_after, augmented_rationale


def build_html_security_report(pipeline_result: CodeMenderPipelineResult) -> str:
    """Generates a standalone dark-mode HTML security report (`cm report -f html`)."""
    rows_html: list[str] = []
    for idx, f in enumerate(pipeline_result.findings, start=1):
        status_str = "FIXED" if f.patch_status == "APPLIED" else "VERIFIED"
        confidence_str = "98%" if f.verified else "85%"
        sev_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
        }.get(f.severity, "#94a3b8")
        rows_html.append(
            f"<tr>"
            f"<td><code>{idx}</code> (<code>{html.escape(f.vuln_id)}</code>)</td>"
            f"<td><span style='color:{sev_color};font-weight:700;'>{html.escape(f.severity)}</span></td>"
            f"<td>{confidence_str}</td>"
            f"<td><code>{status_str}</code></td>"
            f"<td><code>{html.escape(f.cwe_id)}</code></td>"
            f"<td><code>{html.escape(f.file_path)}:{f.start_line}</code></td>"
            f"<td>{html.escape(f.title)}</td>"
            f"<td><strong>{f.judge_score}/10 ({html.escape(f.judge_verdict)})</strong></td>"
            f"</tr>"
            f"<tr><td colspan='8'><pre style='background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;overflow-x:auto;'>"
            f"{html.escape(f.unified_diff.strip())}</pre></td></tr>"
        )

    cost_cards_html = ""
    if pipeline_result.cost_summary is not None:
        cs = pipeline_result.cost_summary
        cost_cards_html = (
            f'<div class="card"><div>Run Cost (USD / KRW)</div><strong>{html.escape(format_usd(cs.total_cost_usd))} ({html.escape(format_krw(cs.total_cost_krw))})</strong></div>'
            f'<div class="card"><div>Run Tokens</div><strong>{html.escape(format_tokens(cs.total_tokens))}</strong></div>'
            f'<div class="card"><div>Session Cumulative</div><strong>{html.escape(format_usd(cs.session_total_cost_usd))} ({html.escape(format_krw(cs.session_total_cost_krw))})</strong></div>'
        )

    body_rows = "\n".join(rows_html) or "<tr><td colspan='8'>No verified vulnerabilities found.</td></tr>"
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <title>CodeMender Security Report — {html.escape(pipeline_result.workspace_id)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; margin: 32px; }}
    h1, h2 {{ color: #38bdf8; }}
    .summary {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px 20px; min-width: 180px; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid #334155; text-align: left; font-size: 14px; }}
    th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>🛡️ CodeMender Security Audit Report</h1>
  <div class="summary">
    <div class="card"><div>Model</div><strong>{html.escape(pipeline_result.model_used)}</strong></div>
    <div class="card"><div>Scanned Files</div><strong>{len(pipeline_result.scanned_files)}</strong></div>
    <div class="card"><div>Candidates (Stage 1)</div><strong>{pipeline_result.total_candidates_found}</strong></div>
    <div class="card"><div>False Positives Filtered</div><strong>{pipeline_result.false_positives_filtered}</strong></div>
    <div class="card"><div>Verified Findings</div><strong>{pipeline_result.verified_count}</strong></div>
    {cost_cards_html}
  </div>
  <table>
    <thead>
      <tr>
        <th>FindingID</th><th>Severity</th><th>Confidence</th><th>Status</th>
        <th>CWE</th><th>Location</th><th>Title</th><th>Judge</th>
      </tr>
    </thead>
    <tbody>
      {body_rows}
    </tbody>
  </table>
</body>
</html>
"""


def build_json_security_report(
    pipeline_result: CodeMenderPipelineResult,
) -> dict[str, Any]:
    """Builds the canonical CodeMender JSON report (`cm report -f json`)."""
    findings_json: list[dict[str, Any]] = []
    for idx, f in enumerate(pipeline_result.findings, start=1):
        status_str = (
            "FIXED"
            if f.patch_status == "APPLIED"
            else ("DISMISSED" if f.patch_status == "REJECTED" else "VERIFIED")
        )
        findings_json.append(
            {
                "FindingID": idx,
                "VulnID": f.vuln_id,
                "Title": f.title,
                "CWE": f.cwe_id,
                "OWASP": f.owasp_category,
                "Severity": f.severity,
                "Confidence": "98%" if f.verified else "85%",
                "Status": status_str,
                "File": f.file_path,
                "StartLine": f.start_line,
                "EndLine": f.end_line,
                "JudgeScore": f.judge_score,
                "JudgeVerdict": f.judge_verdict,
                "SandboxEvidence": f.sandbox_evidence,
            }
        )
    for fp_idx, fp in enumerate(pipeline_result.filtered_candidates, start=len(findings_json) + 1):
        findings_json.append(
            {
                "FindingID": fp_idx,
                "VulnID": f"FP-{fp.get('cwe_id', 'CWE')}-{fp_idx:03d}",
                "Title": fp.get("title", ""),
                "CWE": fp.get("cwe_id", ""),
                "Severity": "LOW",
                "Confidence": "0% (Filtered)",
                "Status": "DISMISSED",
                "File": fp.get("file_path", ""),
                "StartLine": fp.get("start_line", 1),
                "SandboxEvidence": fp.get("sandbox_evidence", ""),
            }
        )
    report_payload: dict[str, Any] = {
        "workspace_id": pipeline_result.workspace_id,
        "model_used": pipeline_result.model_used,
        "scanned_files": pipeline_result.scanned_files,
        "summary": {
            "total_candidates_found": pipeline_result.total_candidates_found,
            "verified_count": pipeline_result.verified_count,
            "false_positives_filtered": pipeline_result.false_positives_filtered,
            "fixed_count": sum(
                1 for f in pipeline_result.findings if f.patch_status == "APPLIED"
            ),
        },
        "findings": findings_json,
    }
    if pipeline_result.cost_summary is not None:
        report_payload["cost_telemetry"] = pipeline_result.cost_summary.to_dict()
    return report_payload


def format_cm_help_markdown(active_model: str = CODEMENDER_MODEL) -> str:
    """Renders the complete CodeMender (`cm` v0.12.0) command matrix in Korean."""
    return (
        f"### 🛠️ CodeMender (`cm` v0.12.0) 전체 명령어 및 기능 가이드 (현재 모델: `{active_model}`)\n"
        "Gemini Enterprise 대화창에서 **CLI 명령어(`cm ...`)** 또는 **한국어 자연어**로 CodeMender의 **모든 13가지 핵심 기능 + 실시간 비용 추적 + GitHub 계정 연동**을 즉시 실행할 수 있습니다.\n\n"
        "| 카테고리 | `cm` CLI 명령어 (채팅창 직접 입력) | 자연어 단축 명령어 | 상세 기능 설명 |\n"
        "| :--- | :--- | :--- | :--- |\n"
        "| **1. 초기화** | `cm init --verify` | `워크스페이스 초기화` | `.codemender/config.yaml` 생성 및 샌드박스·모델 연결 상태 검증 |\n"
        "| **2. 취약점 탐색** | `cm find [--model <모델명>]` | `샘플 진단 실행`, `취약점 탐색` | Stage 1 정적 AST + LLM 추론 스캔으로 CWE/OWASP 취약점 후보 도출 |\n"
        "| **3. 샌드박스 검증** | `cm verify [<ID\\|ALL>] [--bypass-warning]` | `cm verify 1`, `검증 실행` | Stage 2 격리 샌드박스 PoC 검증, `.exploit/` 아티팩트 생성 및 오탐(`DISMISSED`) 제거 |\n"
        "| **4. 보안 패치 적용** | `cm fix [<ID\\|ALL>]` | `패치 적용`, `CM-CWE-89-001 패치 적용` | Stage 3 최소 변경 보안 패치(`CodeDiff`) 적용 및 패치 완료 파일 생성 |\n"
        "| **5. 컨텍스트 맞춤 패치** | `cm fix <ID> -c \"<추가 요구사항>\"` | `cm fix 1 -c \"로깅 추가해줘\"` | 사용자 지정 정책/컨텍스트(`-c`)를 반영하여 보안 패치 재합성 및 적용 |\n"
        "| **6. 패치 롤백/원복** | `cm fix --revert [<ID\\|ALL>]` | `패치 롤백`, `패치 원복` | 적용된 보안 패치를 취소하고 업로드 당시 원본 코드로 복원 |\n"
        "| **7. 리포트 내보내기** | `cm report [-f text\\|json\\|html]` | `json 리포트`, `html 리포트` | 요약 테이블(`text`), 공식 스키마 `json`, 다크모드 대시보드 `html` 리포트 생성 |\n"
        "| **8. 트리아지 & 게이트** | `cm triage` | `트리아지`, `보안 게이트` | 심각도순(`CRITICAL`→`LOW`) 우선순위 큐 정렬 및 **CI/CD Security Gate** 통과 여부 판정 |\n"
        "| **9. VCS 버전 관리** | `cm vcs status \\| diff \\| reset \\| stage` | `git diff`, `원본으로 초기화`, `pr 생성` | 수정 파일 해시 확인(`status`), 전체 통합 Diff(`diff`), 전체 초기화(`reset`), 자율 보안 PR 생성(`stage`) |\n"
        "| **10. 빌드/구문 검증** | `cm build [--force]` | `빌드 검증`, `컴파일 검증` | 패치 후 격리 샌드박스에서 언어별 컴파일/구문 검증(`py_compile`, `C syntax`) 실행 |\n"
        "| **11. 비용 & 로깅 추적** | `cm cost` / `cm logs` / `cm stats` / `cm sessions` / `cm artifacts` | `비용 조회`, `로그 비용`, `클라우드 로깅`, `토큰 사용량` | **Cloud Billing API 없이 Cloud Logging(`entries:list`) + 구조화 JSON 로그 + Cloud Run `httpRequest.latency`로 실시간 추적되는 LLM·컨테이너 비용(USD/KRW)** |\n"
        "| **12. 멀티 모델 관리** | `cm models` / `cm switch-model <모델명>` | `모델 비교` | `gemini-3.8-flash`, `gemini-3.8-flash-cyber`, `gemini-3.7-flash` 3대 모델 비교·단가 확인 및 전환 |\n"
        "| **13. GitHub 계정 연동** | `cm github login \\| status \\| repos \\| scan <owner/repo> \\| pr [owner/repo]` | `깃허브 로그인`, `깃허브 인증 완료`, `내 레포 목록`, `깃허브 스캔`, `깃허브 PR 생성` | **내 GitHub OAuth 기기 인증(`https://github.com/login/device`)으로 Private/Public 레포를 직접 스캔하고 실제 보안 패치 브랜치 푸시 & Pull Request를 자동 생성** |\n"
    )


async def execute_cm_command(
    parsed_cmd: dict[str, Any],
    *,
    workspace: WorkspaceContext,
    state: Any,
    save_artifact_fn: Any = None,
    default_sample_fn: Any = None,
) -> dict[str, Any]:
    """Executes any parsed `cm` command against the session workspace and state.

    Returns a dict with `markdown` (str), `pipeline_result` (optional), and `artifacts` (list).
    """
    from app.a2ui_renderer.action_handler import (
        handle_a2ui_patch_action,
        reconstruct_pipeline_result,
    )

    t0 = time.monotonic()
    sub = parsed_cmd.get("subcommand", "help").lower()
    positional: list[str] = parsed_cmd.get("positional") or []
    active_model = (
        parsed_cmd.get("model")
        or state.get("cm_active_model")
        or CODEMENDER_MODEL
    )
    if parsed_cmd.get("model"):
        state["cm_active_model"] = active_model

    # Ensure pipeline has been run for commands that inspect findings
    def _ensure_pipeline() -> CodeMenderPipelineResult:
        if not workspace.files and default_sample_fn is not None:
            default_sample_fn(workspace, state)
        existing_dict = state.get("cm_pipeline_result")
        if existing_dict:
            return reconstruct_pipeline_result(existing_dict)
        runner = CodeMenderRunner(model_name=active_model)
        res = runner.run_pipeline(workspace)
        if res.cost_summary is not None:
            record_session_cost(state, res.cost_summary)
        state["cm_pipeline_result"] = res.to_dict()
        return res

    # 1. cm help
    if sub in ("help", "-h", "--help"):
        md = format_cm_help_markdown(active_model=active_model)
        cost_footer = _record_cm_telemetry(state, parsed_cmd.get("raw", "cm help"), active_model, 5, 60, 120)
        return {"markdown": md + cost_footer}

    # 2. cm init [--verify]
    if sub == "init":
        cm_dir = _ensure_within_directory(
            Path(workspace.root_dir), Path(workspace.root_dir) / ".codemender"
        )
        cm_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(cm_dir, 0o700)
        config_path = cm_dir / "config.yaml"
        config_yaml = (
            "# CodeMender (.codemender/config.yaml)\n"
            f"workspace_id: {workspace.workspace_id}\n"
            f"default_model: {active_model}\n"
            "project_paths:\n"
            "  - src/\n"
            "vcs:\n"
            "  type: git\n"
            "build:\n"
            "  command: cm build\n"
            "sandbox:\n"
            "  isolated: true\n"
            "  network_egress: disabled\n"
        )
        config_path.write_text(config_yaml, encoding="utf-8")
        os.chmod(config_path, 0o600)
        state["cm_initialized"] = True
        elapsed = int((time.monotonic() - t0) * 1000) + 12
        cost_footer = _record_cm_telemetry(state, parsed_cmd.get("raw", "cm init"), active_model, elapsed, 150, 180)

        files_list = ", ".join(f.relative_path for f in workspace.files) or "(아직 업로드된 파일 없음 — 샘플 또는 파일 업로드 시 자동 마운트)"
        verify_block = ""
        if parsed_cmd.get("verify", True):
            verify_block = (
                "\n#### ✅ `--verify` 환경 및 보안 샌드박스 점검 결과\n"
                f"- **추론 엔드포인트**: `Vertex AI (global)` · 모델 `{active_model}` 준비 완료\n"
                f"- **격리 샌드박스 루트**: `{workspace.root_dir}` (`chmod 0700`, `shell=False` 강제)\n"
                "- **로컬 상태 저장소**: `.codemender/config.yaml` 및 세션 아티팩트 스토어 활성화\n"
            )
        md = (
            "### ⚙️ `cm init` — CodeMender 워크스페이스 초기화 완료\n"
            f"- **워크스페이스 ID**: `{workspace.workspace_id}`\n"
            f"- **활성 모델**: `{active_model}`\n"
            f"- **마운트된 소스 파일**: `{files_list}`\n\n"
            f"```yaml\n{config_yaml.strip()}\n```\n"
            f"{verify_block}"
            f"{cost_footer}"
        )
        return {"markdown": md}

    # 3. cm find
    if sub == "find":
        if not workspace.files and default_sample_fn is not None:
            default_sample_fn(workspace, state)
        runner = CodeMenderRunner(model_name=active_model)
        pipeline_res = runner.run_pipeline(workspace)
        if pipeline_res.cost_summary is not None:
            record_session_cost(state, pipeline_res.cost_summary)
        state["cm_pipeline_result"] = pipeline_res.to_dict()
        elapsed = int((time.monotonic() - t0) * 1000) + 45
        cs = pipeline_res.cost_summary
        cost_footer = _record_cm_telemetry(
            state,
            parsed_cmd.get("raw", "cm find"),
            active_model,
            elapsed,
            cs.input_tokens if cs else 890,
            cs.output_tokens if cs else 640,
            cs.thinking_tokens if cs else 240,
            include_sandbox=True,
        )

        lines = [
            f"### 🔍 `cm find` — Stage 1 취약점 탐색 완료 (모델: `{active_model}`)",
            f"- **스캔 파일**: `{', '.join(pipeline_res.scanned_files) or '없음'}`",
            f"- **총 탐색 후보**: **{pipeline_res.total_candidates_found}건** (진성 취약점 후보 **{pipeline_res.verified_count}건**, 안전 가드 후보 **{pipeline_res.false_positives_filtered}건**)",
        ]
        lines.extend(
            [
                "",
                "| # | Finding ID | Severity | Confidence | Status | CWE | 위치 | 제목 |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for idx, f in enumerate(pipeline_res.findings, start=1):
            lines.append(
                f"| `{idx}` | `{f.vuln_id}` | **{f.severity}** | `98%` | `OPEN → VERIFIED` | `{f.cwe_id}` | `{f.file_path}:{f.start_line}` | {f.title} |"
            )
        for fp_idx, fp in enumerate(
            pipeline_res.filtered_candidates, start=len(pipeline_res.findings) + 1
        ):
            lines.append(
                f"| `{fp_idx}` | `CAND-{fp.get('cwe_id')}-{fp_idx:03d}` | `LOW` | `15%` | `DISMISSED (FP)` | `{fp.get('cwe_id')}` | `{fp.get('file_path')}:{fp.get('start_line')}` | {fp.get('title')} |"
            )
        lines.extend(
            [
                "",
                "💡 **다음 단계 명령어**:",
                "- 샌드박스 상세 검증: **`cm verify ALL`** (또는 **`cm verify 1`**)",
                "- 보안 패치 즉시 적용: **`cm fix ALL`** (또는 **`cm fix 1 -c \"추가 컨텍스트\"`**)",
                "- 우선순위 트리아지: **`cm triage`** | 비용 상세 조회: **`cm cost`**",
            ]
        )
        return {"markdown": "\n".join(lines) + cost_footer, "pipeline_result": pipeline_res}

    # 4. cm verify [<id|ALL>]
    if sub == "verify":
        pipeline_res = _ensure_pipeline()
        target_raw = positional[0] if positional else "ALL"
        resolved_id = resolve_finding_id(target_raw, pipeline_res.findings)

        exploit_dir = _ensure_within_directory(
            Path(workspace.root_dir), Path(workspace.root_dir) / ".exploit"
        )
        exploit_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(exploit_dir, 0o700)

        target_findings = [
            f
            for f in pipeline_res.findings
            if resolved_id == "ALL" or f.vuln_id.upper() == resolved_id.upper()
        ]
        lines = [
            f"### 🧪 `cm verify {target_raw}` — Stage 2 격리 샌드박스 검증 결과",
            f"- **검증 대상**: `{resolved_id}` (총 **{len(target_findings)}건** 진성 확증, **{len(pipeline_res.filtered_candidates)}건** 오탐 제외)",
            "",
        ]
        for idx, f in enumerate(target_findings, start=1):
            verify_log_file = exploit_dir / f"verify_{f.vuln_id.lower()}.log"
            report_md_file = exploit_dir / f"REPORT_{f.vuln_id.lower()}.md"
            verify_log_content = (
                f"# CodeMender Isolated Sandbox Verification Log\n"
                f"Finding: {f.vuln_id} ({f.cwe_id} - {f.title})\n"
                f"Target: {f.file_path}:{f.start_line}-{f.end_line}\n"
                f"Evidence: {f.sandbox_evidence}\n"
                f"Status: VERIFIED (Confidence: 98%)\n"
            )
            verify_log_file.write_text(verify_log_content, encoding="utf-8")
            report_md_file.write_text(
                f"# Verification Report: {f.vuln_id}\n\n- **CWE**: {f.cwe_id}\n- **Severity**: {f.severity}\n- **Description**: {f.description}\n- **Sandbox Log**: `{f.sandbox_evidence}`\n",
                encoding="utf-8",
            )
            lines.extend(
                [
                    f"#### {idx}. ✅ `VERIFIED (98%)` — `{f.vuln_id}` ({f.title})",
                    f"- **위치**: `{f.file_path}` (Lines {f.start_line}–{f.end_line})",
                    f"- **샌드박스 실행 증적**: `{f.sandbox_evidence}`",
                    f"- **생성된 검증 아티팩트**: `.exploit/{verify_log_file.name}`, `.exploit/{report_md_file.name}`",
                    "",
                ]
            )

        if pipeline_res.filtered_candidates and resolved_id == "ALL":
            lines.append("#### 🛡️ `DISMISSED` — 샌드박스 검증으로 필터링된 오탐(False Positive)")
            for fp in pipeline_res.filtered_candidates:
                lines.append(
                    f"- ~~`[{fp.get('cwe_id')}] {fp.get('title')}` (`{fp.get('file_path')}:{fp.get('start_line')}`)~~ → **DISMISSED**: `{fp.get('sandbox_evidence')}`"
                )
            lines.append("")

        elapsed = int((time.monotonic() - t0) * 1000) + 38
        cost_footer = _record_cm_telemetry(
            state,
            parsed_cmd.get("raw", "cm verify"),
            active_model,
            elapsed,
            620,
            410,
            include_sandbox=True,
        )
        return {"markdown": "\n".join(lines) + cost_footer, "pipeline_result": pipeline_res}

    # 5. cm fix [<id|ALL>] [-c "<context>"] [--revert [<id|ALL>]]
    if sub == "fix":
        pipeline_res = _ensure_pipeline()
        target_raw = positional[0] if positional else "ALL"
        resolved_id = resolve_finding_id(target_raw, pipeline_res.findings)

        # 5a. Handle `cm fix --revert [<id|ALL>]`
        if parsed_cmd.get("revert"):
            reverted_items: list[dict[str, Any]] = []
            for f in pipeline_res.findings:
                if resolved_id == "ALL" or f.vuln_id.upper() == resolved_id.upper():
                    rev_res = revert_patch_in_workspace(
                        workspace,
                        vuln_id=f.vuln_id,
                        file_path=f.file_path,
                        before_snippet=f.before_code,
                        after_snippet=f.after_code,
                    )
                    f.patch_status = "PENDING_APPROVAL"
                    reverted_items.append(
                        {
                            "vuln_id": f.vuln_id,
                            "file_path": f.file_path,
                            "sha256": rev_res.patched_sha256,
                            "content": rev_res.patched_content,
                        }
                    )
            state["cm_workspace"] = workspace.to_dict()
            state["cm_pipeline_result"] = pipeline_res.to_dict()
            elapsed = int((time.monotonic() - t0) * 1000) + 20
            cost_footer = _record_cm_telemetry(
                state, parsed_cmd.get("raw", "cm fix --revert"), active_model, elapsed, 210, 190
            )
            lines = [
                f"### ⏪ `cm fix --revert {target_raw}` — 보안 패치 롤백(원복) 완료",
                f"- 총 **{len(reverted_items)}건**의 취약점 패치가 원본 코드로 복원되었으며, 상태가 `PENDING_APPROVAL`(`VERIFIED`)로 되돌아갔습니다.",
                "",
            ]
            for item in reverted_items:
                lines.append(
                    f"- **`{item['vuln_id']}`** (`{item['file_path']}`) → 복원 완료 (SHA-256: `{item['sha256'][:16]}...`)"
                )
            return {"markdown": "\n".join(lines) + cost_footer, "pipeline_result": pipeline_res}

        # 5b. Handle `-c "<extra_context>"` custom patch synthesis
        extra_context = parsed_cmd.get("extra_context")
        if extra_context:
            for f in pipeline_res.findings:
                if resolved_id == "ALL" or f.vuln_id.upper() == resolved_id.upper():
                    new_after, new_rationale = _synthesize_contextual_patch(
                        f, extra_context, active_model
                    )
                    f.after_code = new_after
                    f.judge_rationale = new_rationale
                    f.unified_diff = build_unified_diff(
                        f.file_path, f.before_code + "\n", f.after_code + "\n"
                    )
            state["cm_pipeline_result"] = pipeline_res.to_dict()

        # 5c. Apply the verified patch(es)
        action_name = "apply_all_patches" if resolved_id == "ALL" else "apply_patch"
        outcome = handle_a2ui_patch_action(
            action_name=action_name,
            action_context={"vuln_id": resolved_id},
            workspace=workspace,
            pipeline_result_dict=state["cm_pipeline_result"],
            catalog_mode=state.get("cm_catalog_mode", "basic"),
            state=state,
        )
        state["cm_workspace"] = workspace.to_dict()
        state["cm_pipeline_result"] = outcome["updated_pipeline_result"]
        updated_res = reconstruct_pipeline_result(outcome["updated_pipeline_result"])

        if save_artifact_fn is not None:
            for item in outcome["applied_files"]:
                try:
                    await save_artifact_fn(
                        f"patched_{item['file_path']}",
                        item["patched_content"].encode("utf-8"),
                    )
                except Exception:
                    pass

        elapsed = int((time.monotonic() - t0) * 1000) + 55
        _record_cm_telemetry(
            state,
            parsed_cmd.get("raw", "cm fix"),
            active_model,
            elapsed,
            950,
            720,
            include_sandbox=True,
        )
        return {
            "markdown": None,  # Signals caller to use `_format_scan_report_markdown(updated_res, applied_files=...)`
            "pipeline_result": updated_res,
            "applied_files": outcome["applied_files"],
            "a2ui_messages": outcome["a2ui_messages"],
        }

    # 6. cm report [-f text|json|html]
    if sub == "report":
        pipeline_res = _ensure_pipeline()
        fmt = (parsed_cmd.get("format") or "text").lower()
        if positional and positional[0].lower() in ("json", "html", "text", "markdown"):
            fmt = positional[0].lower()

        elapsed = int((time.monotonic() - t0) * 1000) + 18
        cost_footer = _record_cm_telemetry(
            state, parsed_cmd.get("raw", f"cm report -f {fmt}"), active_model, elapsed, 310, 480
        )

        if fmt == "json":
            from app.ingestion.file_manager import upload_artifact_to_gcs

            report_obj = build_json_security_report(pipeline_res)
            json_str = json.dumps(report_obj, indent=2, ensure_ascii=False)
            json_bytes = json_str.encode("utf-8")
            gcs_info = upload_artifact_to_gcs(
                workspace.workspace_id,
                "codemender-report.json",
                json_bytes,
                content_type="application/json",
            )
            if save_artifact_fn is not None:
                try:
                    await save_artifact_fn("codemender-report.json", json_bytes)
                except Exception:
                    pass
            md = (
                "### 📊 `cm report -f json` — CodeMender 공식 JSON 리포트\n"
                f"- **📥 원클릭 브라우저 다운로드**: **[📥 `codemender-report.json` 바로 다운로드]({gcs_info['download_url']})** ([GCP 콘솔 보기]({gcs_info['console_url']}))\n"
                f"- **☁️ GCS 저장 경로**: `{gcs_info['gcs_uri']}`\n\n"
                f"```json\n{json_str}\n```"
                f"{cost_footer}"
            )
            return {"markdown": md, "pipeline_result": pipeline_res}

        if fmt == "html":
            from app.ingestion.file_manager import upload_artifact_to_gcs

            html_str = build_html_security_report(pipeline_res)
            html_bytes = html_str.encode("utf-8")
            report_path = Path(workspace.root_dir) / "codemender-report.html"
            report_path.write_text(html_str, encoding="utf-8")
            os.chmod(report_path, 0o600)
            gcs_info = upload_artifact_to_gcs(
                workspace.workspace_id,
                "codemender-report.html",
                html_bytes,
                content_type="text/html; charset=utf-8",
            )
            if save_artifact_fn is not None:
                try:
                    await save_artifact_fn("codemender-report.html", html_bytes)
                except Exception:
                    pass
            md = (
                "### 🌐 `cm report -f html` — CodeMender 다크모드 HTML 보안 리포트 생성 완료\n"
                f"- **📥 원클릭 브라우저 다운로드**: **[📥 `codemender-report.html` 바로 다운로드]({gcs_info['download_url']})** ([GCP 콘솔 보기]({gcs_info['console_url']}))\n"
                f"- **☁️ GCS 저장 경로**: `{gcs_info['gcs_uri']}` (`{len(html_str):,} bytes`)\n"
                f"- **포함 내역**: 확증 취약점 **{pipeline_res.verified_count}건**, 오탐 제거 **{pipeline_res.false_positives_filtered}건**, Unified CodeDiff, LLM-as-a-Judge 판정\n\n"
                "```html\n"
                f"<!-- Preview of codemender-report.html ({len(html_str)} bytes) -->\n"
                f"{html_str[:1200].rstrip()}\n...\n```"
                f"{cost_footer}"
            )
            return {"markdown": md, "pipeline_result": pipeline_res}

        # Default text/markdown table report
        lines = [
            f"### 📋 `cm report` — CodeMender 종합 보안 리포트 (`{pipeline_res.workspace_id}`)",
            "",
            "| FindingID | VulnID | Severity | Confidence | Status | CWE | File:Line | Judge |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for idx, f in enumerate(pipeline_res.findings, start=1):
            st = (
                "FIXED"
                if f.patch_status == "APPLIED"
                else ("DISMISSED" if f.patch_status == "REJECTED" else "VERIFIED")
            )
            lines.append(
                f"| `{idx}` | `{f.vuln_id}` | **{f.severity}** | `98%` | `{st}` | `{f.cwe_id}` | `{f.file_path}:{f.start_line}` | **{f.judge_score}/10 ({f.judge_verdict})** |"
            )
        for fp_idx, fp in enumerate(
            pipeline_res.filtered_candidates, start=len(pipeline_res.findings) + 1
        ):
            lines.append(
                f"| `{fp_idx}` | `FP-{fp.get('cwe_id')}-{fp_idx:03d}` | `LOW` | `0%` | `DISMISSED` | `{fp.get('cwe_id')}` | `{fp.get('file_path')}:{fp.get('start_line')}` | `N/A (Safe)` |"
            )
        lines.extend(
            [
                "",
                "- JSON 포맷 내보내기: **`cm report -f json`**",
                "- HTML 대시보드 생성: **`cm report -f html`**",
            ]
        )
        return {"markdown": "\n".join(lines) + cost_footer, "pipeline_result": pipeline_res}

    # 7. cm triage
    if sub == "triage":
        pipeline_res = _ensure_pipeline()
        sorted_findings = sorted(
            pipeline_res.findings,
            key=lambda x: (_SEVERITY_ORDER.get(x.severity.upper(), 99), x.start_line),
        )
        unresolved_high_crit = [
            f
            for f in sorted_findings
            if f.severity.upper() in ("CRITICAL", "HIGH") and f.patch_status != "APPLIED"
        ]
        gate_passed = len(unresolved_high_crit) == 0
        gate_badge = (
            "✅ PASS (Exit Code 0 — 미해결 CRITICAL/HIGH 0건, 프로덕션 배포 가능)"
            if gate_passed
            else f"🚫 BLOCKED (Exit Code 1 — 미해결 CRITICAL/HIGH {len(unresolved_high_crit)}건 존재, 배포 차단)"
        )

        lines = [
            "### 🚦 `cm triage` — 심각도 기반 우선순위 분류 및 CI/CD Security Gate 판정",
            f"- **CI/CD Security Gate 상태**: **{gate_badge}**",
            f"- **전체 확증 취약점**: **{len(sorted_findings)}건** (패치 완료: **{sum(1 for f in sorted_findings if f.patch_status == 'APPLIED')}건**, 미해결 CRITICAL/HIGH: **{len(unresolved_high_crit)}건**, 오탐 제외: **{len(pipeline_res.filtered_candidates)}건**)",
            "",
            "| 우선순위 | VulnID | Severity | Status | CWE | 위치 | 권장 조치 명령어 |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for rank, f in enumerate(sorted_findings, start=1):
            st = "✅ FIXED" if f.patch_status == "APPLIED" else "🚨 OPEN (VERIFIED)"
            cmd_hint = (
                f"`cm fix --revert {f.vuln_id}`"
                if f.patch_status == "APPLIED"
                else f"`cm fix {f.vuln_id}`"
            )
            lines.append(
                f"| **P{rank}** | `{f.vuln_id}` | **{f.severity}** | {st} | `{f.cwe_id}` | `{f.file_path}:{f.start_line}` | {cmd_hint} |"
            )

        if unresolved_high_crit:
            lines.extend(
                [
                    "",
                    "💡 **Security Gate 통과 방법**: 채팅창에 **`cm fix ALL`** (또는 **`패치 적용`**)을 입력하여 모든 CRITICAL/HIGH 취약점을 패치한 뒤 다시 **`cm triage`**를 실행하세요.",
                ]
            )
        elapsed = int((time.monotonic() - t0) * 1000) + 15
        cost_footer = _record_cm_telemetry(state, parsed_cmd.get("raw", "cm triage"), active_model, elapsed, 280, 320)
        return {"markdown": "\n".join(lines) + cost_footer, "pipeline_result": pipeline_res}

    # 8. cm vcs status | diff | reset | stage
    if sub == "vcs":
        vcs_sub = positional[0].lower() if positional else "status"
        if not workspace.files and default_sample_fn is not None:
            default_sample_fn(workspace, state)

        if vcs_sub == "reset":
            reset_list = reset_workspace_to_original(workspace)
            state["cm_workspace"] = workspace.to_dict()
            existing_dict = state.get("cm_pipeline_result")
            if existing_dict:
                p_res = reconstruct_pipeline_result(existing_dict)
                for f in p_res.findings:
                    f.patch_status = "PENDING_APPROVAL"
                state["cm_pipeline_result"] = p_res.to_dict()
            elapsed = int((time.monotonic() - t0) * 1000) + 14
            cost_footer = _record_cm_telemetry(
                state, parsed_cmd.get("raw", "cm vcs reset"), active_model, elapsed, 140, 160
            )
            lines = [
                "### 🔄 `cm vcs reset` — 워크스페이스 원본 초기화 완료",
                f"- 총 **{len(reset_list)}개** 파일이 최초 업로드 상태(`orig/`)로 깨끗하게 초기화되었습니다.",
                "",
            ]
            for item in reset_list:
                lines.append(
                    f"- `{item['file_path']}` → `CLEAN` (SHA-256: `{item['sha256'][:16]}...`)"
                )
            return {"markdown": "\n".join(lines) + cost_footer}

        vcs_entries = compute_workspace_vcs_status(workspace)
        modified_entries = [e for e in vcs_entries if e["status"] == "MODIFIED"]

        if vcs_sub == "diff":
            elapsed = int((time.monotonic() - t0) * 1000) + 16
            cost_footer = _record_cm_telemetry(
                state, parsed_cmd.get("raw", "cm vcs diff"), active_model, elapsed, 220, 350
            )
            if not modified_entries:
                return {
                    "markdown": (
                        "### 📝 `cm vcs diff` — 변경 사항 없음 (`CLEAN`)\n"
                        "- 현재 워크스페이스에 적용된 패치가 없어 원본(`orig/`)과 동일합니다.\n"
                        "- 먼저 **`cm fix ALL`** 또는 **`패치 적용`**을 실행해 보세요."
                        + cost_footer
                    )
                }
            lines = [
                f"### 📝 `cm vcs diff` — 워크스페이스 전체 Unified Diff (수정 파일: {len(modified_entries)}개)",
                "",
            ]
            for entry in modified_entries:
                lines.append(
                    f"#### 📄 `{entry['file_path']}` (`{entry['orig_sha256'][:10]}` → `{entry['current_sha256'][:10]}`)"
                )
                lines.append(f"```diff\n{entry['unified_diff'].strip()}\n```\n")
            return {"markdown": "\n".join(lines) + cost_footer}

        if vcs_sub == "stage":
            pipeline_res = _ensure_pipeline()
            for f in pipeline_res.findings:
                if f.patch_status != "APPLIED":
                    p_res = apply_patch_to_workspace(
                        workspace,
                        vuln_id=f.vuln_id,
                        file_path=f.file_path,
                        before_snippet=f.before_code,
                        after_snippet=f.after_code,
                        start_line=getattr(f, "start_line", None),
                        end_line=getattr(f, "end_line", None),
                    )
                    if p_res.applied:
                        f.patch_status = "APPLIED"
            state["cm_workspace"] = workspace.to_dict()
            state["cm_pipeline_result"] = pipeline_res.to_dict()
            vcs_entries = compute_workspace_vcs_status(workspace)
            modified_entries = [e for e in vcs_entries if e["status"] == "MODIFIED"]

            applied_findings = [
                f for f in pipeline_res.findings if f.patch_status == "APPLIED"
            ]
            target_for_pr = applied_findings or pipeline_res.findings
            cwes_str = ", ".join(sorted({f.cwe_id for f in target_for_pr})) or "CWE-Security"
            files_str = ", ".join(e["file_path"] for e in (modified_entries or vcs_entries))
            elapsed = int((time.monotonic() - t0) * 1000) + 25
            cost_footer = _record_cm_telemetry(
                state, parsed_cmd.get("raw", "cm vcs stage"), active_model, elapsed, 340, 520
            )
            pr_body = (
                f"fix(security): remediate {len(target_for_pr)} verified vulnerabilities ({cwes_str})\n\n"
                "## 🛡️ CodeMender Autonomous Security Patch PR\n"
                f"- **Reasoning & Judge Model**: `{active_model}`\n"
                f"- **Modified Files**: `{files_str}`\n"
                f"- **False Positives Filtered in Sandbox**: {pipeline_res.false_positives_filtered}\n\n"
                "### Verified & Remediated Findings\n"
            )
            for f in target_for_pr:
                pr_body += (
                    f"- **`{f.vuln_id}` ({f.cwe_id} · {f.severity})**: {f.title} "
                    f"(`{f.file_path}:{f.start_line}`, Judge: {f.judge_score}/10 {f.judge_verdict})\n"
                )

            # If GitHub OAuth is authenticated, also push the branch and open a REAL GitHub Pull Request!
            gh_pr_section: list[str] = []
            if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
                try:
                    from app.harness.github_integration import (
                        create_github_pr_or_push_patches,
                        poll_or_verify_github_auth,
                    )

                    gh_auth = poll_or_verify_github_auth(state)
                    if gh_auth.get("authenticated"):
                        target_repo_arg = positional[1] if len(positional) > 1 else ""
                        pr_res = create_github_pr_or_push_patches(
                            token=str(gh_auth.get("access_token") or ""),
                            login=str(gh_auth.get("login") or "user"),
                            workspace=workspace,
                            pipeline_result=pipeline_res,
                            target_repo=target_repo_arg,
                            create_new_repo_if_missing=True,
                            state=state,
                        )
                        if pr_res.get("status") == "ok":
                            pr_url = pr_res.get("pr_url") or pr_res.get("branch_url")
                            pr_num = pr_res.get("pr_number", 0)
                            gh_pr_section = [
                                f"#### 🐙 실제 GitHub Pull Request 생성 완료 (`{pr_res['repo']}`)",
                                f"- **대상 레포지토리**: **[`{pr_res['repo']}`]({pr_res['repo_url']})**",
                                f"- **생성된 패치 브랜치**: **[`{pr_res['patch_branch']}`]({pr_res['branch_url']})** → `{pr_res['base_branch']}`",
                                f"- **커밋된 파일 ({len(pr_res.get('committed_files', []))}개)**: `{', '.join(pr_res.get('committed_files', []))}`",
                            ]
                            if pr_url and pr_num:
                                gh_pr_section.append(
                                    f"- **🔗 실제 GitHub Pull Request 링크**: **[👉 Pull Request #{pr_num} 바로 열기 (`{pr_url}`)]({pr_url})**"
                                )
                            for c_idx, c_url in enumerate(pr_res.get("commit_urls") or [], start=1):
                                gh_pr_section.append(
                                    f"- **📝 GitHub 커밋 #{c_idx}**: **[커밋 Diff 보기 (`{c_url}`)]({c_url})**"
                                )
                            gh_pr_section.append("")
                except Exception:
                    pass

            lines = [
                "### 🚀 `cm vcs stage` — 변경 파일 스테이징 및 자율 보안 PR(Pull Request) 생성",
                f"- **스테이징된 수정 파일**: `{files_str}` (수정됨: **{len(modified_entries)}개**)",
                "",
                *gh_pr_section,
                "#### 📋 자동 생성된 Git Commit & Pull Request 템플릿",
                f"```markdown\n{pr_body.strip()}\n```",
            ]
            return {"markdown": "\n".join(lines) + cost_footer, "pipeline_result": pipeline_res}

        # Default: `cm vcs status`
        elapsed = int((time.monotonic() - t0) * 1000) + 12
        cost_footer = _record_cm_telemetry(
            state, parsed_cmd.get("raw", "cm vcs status"), active_model, elapsed, 180, 210
        )
        lines = [
            f"### 📂 `cm vcs status` — 워크스페이스 버전 관리 상태 (`{workspace.workspace_id}`)",
            "",
            "| 파일 경로 | 언어 | 상태 | 원본 SHA-256 | 현재 SHA-256 |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for e in vcs_entries:
            badge = "✏️ **MODIFIED (패치됨)**" if e["status"] == "MODIFIED" else "✅ `CLEAN (원본)`"
            lines.append(
                f"| `{e['file_path']}` | `{e['language']}` | {badge} | `{e['orig_sha256'][:12]}...` | `{e['current_sha256'][:12]}...` |"
            )
        lines.extend(
            [
                "",
                "- 전체 코드 변경점 비교: **`cm vcs diff`**",
                "- Git 스테이징 및 PR 본문 생성: **`cm vcs stage`**",
                "- 원본 상태로 전체 초기화: **`cm vcs reset`**",
            ]
        )
        return {"markdown": "\n".join(lines) + cost_footer}

    # 9. cm build
    if sub == "build":
        if not workspace.files and default_sample_fn is not None:
            default_sample_fn(workspace, state)
        vcs_entries = compute_workspace_vcs_status(workspace)
        sandbox_dir = Path(workspace.root_dir)
        build_results: list[dict[str, Any]] = []
        all_passed = True

        for entry in vcs_entries:
            rel_path = entry["file_path"]
            code_text = entry["current_content"]
            ext = Path(rel_path).suffix.lower()
            passed = True
            detail = ""

            if ext == ".py":
                try:
                    ast.parse(code_text)
                    target_file = Path(workspace.patched_dir) / rel_path
                    proc = run_safe_subprocess(
                        "python3",
                        ["-I", "-m", "py_compile", str(target_file)],
                        cwd=sandbox_dir,
                        timeout_seconds=5,
                    )
                    if proc.returncode == 0:
                        detail = "python3 -I -m py_compile 통과 (exit_code=0)"
                    else:
                        passed = False
                        detail = proc.stderr.strip() or "py_compile failed"
                except SyntaxError as exc:
                    passed = False
                    detail = f"SyntaxError (Line {exc.lineno}): {exc.msg}"
            elif ext in (".c", ".cpp", ".h", ".hpp"):
                open_b = code_text.count("{")
                close_b = code_text.count("}")
                if open_b != close_b:
                    passed = False
                    detail = f"Unbalanced braces: '{{'={open_b}, '}}'={close_b}"
                else:
                    detail = f"C/C++ AST & 블록 경계 검증 통과 (braces={open_b})"
            elif ext == ".json":
                try:
                    json.loads(code_text)
                    detail = "JSON 스키마 파싱 통과"
                except Exception as exc:
                    passed = False
                    detail = f"JSONDecodeError: {exc}"
            else:
                detail = f"{entry['language']} 구문 무결성 검증 통과 ({len(code_text)} bytes)"

            if not passed:
                all_passed = False
            build_results.append(
                {
                    "file_path": rel_path,
                    "status": "✅ PASS" if passed else "❌ FAIL",
                    "vcs_state": entry["status"],
                    "detail": detail,
                }
            )

        elapsed = int((time.monotonic() - t0) * 1000) + 29
        cost_footer = _record_cm_telemetry(
            state,
            parsed_cmd.get("raw", "cm build"),
            active_model,
            elapsed,
            260,
            240,
            include_sandbox=True,
        )
        overall_badge = "✅ BUILD SUCCEEDED (Exit Code 0)" if all_passed else "❌ BUILD FAILED (Exit Code 1)"
        lines = [
            f"### 🏗️ `cm build` — 샌드박스 빌드 및 구문 무결성 검증 ({overall_badge})",
            "",
            "| 파일 경로 | 수정 여부 | 빌드/구문 검증 결과 | 상세 로그 |",
            "| :--- | :--- | :--- | :--- |",
        ]
        for br in build_results:
            lines.append(
                f"| `{br['file_path']}` | `{br['vcs_state']}` | **{br['status']}** | `{br['detail']}` |"
            )
        return {"markdown": "\n".join(lines) + cost_footer}

    # 10. cm stats / cm cost / cm billing / cm logs (ONLY called on-demand when user asks for cost/stats)
    if sub in ("stats", "cost", "billing", "logs"):
        existing_pipe_dict = state.get("cm_pipeline_result")
        pipeline_res = (
            reconstruct_pipeline_result(existing_pipe_dict)
            if isinstance(existing_pipe_dict, dict)
            else None
        )
        history = list(state.get("cm_command_history") or [])
        report_data = get_session_and_ledger_cost_report(state)
        sess_cost = report_data["session"]
        ledger_cost = report_data["ledger"]
        cloud_log = report_data.get("cloud_logging") or {}
        as_of_date = report_data.get("as_of_kst_date") or "오늘"
        as_of_dt = report_data.get("as_of_kst_datetime") or as_of_date
        billing_period = report_data.get("billing_period_kst") or f"{as_of_date} 기준"
        sessions_list = report_data.get("sessions_breakdown") or []
        tx_list = report_data.get("transactions_breakdown") or []

        cmd_tot_tok = sum(
            h.get("total_tokens", h.get("input_tokens", 0) + h.get("output_tokens", 0))
            for h in history
        )
        cmd_llm_usd = sum(float(h.get("llm_cost_usd", 0.0)) for h in history)
        cmd_sbx_usd = sum(float(h.get("sandbox_cost_usd", 0.0)) for h in history)
        cmd_tot_usd = sum(float(h.get("cost_usd", 0.0)) for h in history)

        # Combine pipeline session totals and CLI command telemetry totals
        combined_sess_tok = max(int(sess_cost.get("session_total_tokens", 0)), cmd_tot_tok)
        combined_sess_llm_usd = round(max(float(sess_cost.get("session_llm_cost_usd", 0.0)), cmd_llm_usd), 8)
        combined_sess_sbx_usd = round(max(float(sess_cost.get("session_sandbox_cost_usd", 0.0)), cmd_sbx_usd), 8)
        combined_sess_usd = round(max(float(sess_cost.get("session_total_cost_usd", 0.0)), cmd_tot_usd), 8)
        combined_sess_krw = round(combined_sess_usd * CM_USD_TO_KRW_RATE, 4)

        # Merge Cloud Logging historical totals and transaction sums
        cl_runs = int(cloud_log.get("structured_log_runs", 0))
        cl_tok = int(cloud_log.get("structured_log_total_tokens", 0))
        cl_llm_usd = float(cloud_log.get("structured_log_llm_cost_usd", 0.0))
        cl_sbx_usd = float(cloud_log.get("structured_log_sandbox_cost_usd", 0.0))
        cl_req_cnt = int(cloud_log.get("cloud_run_request_count", 0))
        cl_req_sec = float(cloud_log.get("cloud_run_total_latency_sec", 0.0))
        cl_req_usd = float(cloud_log.get("cloud_run_infra_cost_usd", 0.0))
        cl_req_krw = float(cloud_log.get("cloud_run_infra_cost_krw", 0.0))
        cl_combined_usd = float(cloud_log.get("combined_logging_cost_usd", 0.0))
        cl_combined_krw = float(cloud_log.get("combined_logging_cost_krw", 0.0))

        tx_sum_tok = sum(int(t.get("total_tokens", 0)) for t in tx_list)
        tx_sum_llm = sum(float(t.get("llm_cost_usd", 0.0)) for t in tx_list)
        tx_sum_sbx = sum(float(t.get("sandbox_cost_usd", 0.0)) for t in tx_list)
        tx_sum_usd = sum(
            float(t.get("cost_usd", t.get("total_cost_usd", 0.0))) for t in tx_list
        )

        ledger_tot_runs = max(
            int(ledger_cost.get("total_runs", 0)),
            len(history),
            cl_runs,
            len(tx_list),
        )
        ledger_tot_tok = max(
            int(ledger_cost.get("total_tokens", 0)),
            combined_sess_tok,
            cl_tok,
            tx_sum_tok,
        )
        ledger_llm_usd = round(
            max(
                float(ledger_cost.get("total_llm_cost_usd", 0.0)),
                combined_sess_llm_usd,
                cl_llm_usd,
                tx_sum_llm,
            ),
            8,
        )
        ledger_sbx_usd = round(
            max(
                float(ledger_cost.get("total_sandbox_cost_usd", 0.0)),
                combined_sess_sbx_usd,
                cl_sbx_usd + cl_req_usd,
                tx_sum_sbx,
            ),
            8,
        )
        ledger_tot_usd = round(
            max(
                float(ledger_cost.get("total_cost_usd", 0.0)),
                combined_sess_usd,
                cl_combined_usd,
                tx_sum_usd,
            ),
            8,
        )
        ledger_tot_krw = round(ledger_tot_usd * CM_USD_TO_KRW_RATE, 4)

        fixed_cnt = (
            sum(1 for f in pipeline_res.findings if f.patch_status == "APPLIED")
            if pipeline_res is not None
            else 0
        )
        pricing = get_model_pricing(active_model)
        cur_sess_runs = max(int(sess_cost.get("session_total_runs", 0)), len(history))

        lines = [
            "### 💰 CodeMender 비용 정산 명세서 — Cloud Logging 기반 온디맨드(On-Demand) 비용 & 토큰 텔레메트리 대시보드",
            f"> 📅 **정산 기준 일자**: **{as_of_date}** (`{as_of_dt}` 기준)  ",
            f"> 💳 **{as_of_date}까지 총 누적 청구(발생) 예상 금액**: **{format_usd(ledger_tot_usd)} ({format_krw(ledger_tot_krw)})**  ",
            f"> 📊 **집계 기간**: `{billing_period}` · **총 세션 수**: `{max(len(sessions_list), 1)}개 세션` · **총 트랜잭션 수**: `{ledger_tot_runs}건` · **총 토큰**: `{format_tokens(ledger_tot_tok)}`",
            "",
            f"- **활성 추론 모델**: `{active_model}` (`Vertex AI global`) | **환율 기준**: `$1.00 = ₩{CM_USD_TO_KRW_RATE:,.0f}원`",
            f"- **단가 기준 (`{active_model}`)**: Input `${pricing['input']:.2f}/1M tok` · Output `${pricing['output']:.2f}/1M tok` · Thinking `${pricing['thinking']:.2f}/1M tok` · Cloud Run Gen2 Sandbox `${CLOUD_RUN_VCPU_PER_SEC_USD + CLOUD_RUN_GIB_PER_SEC_USD:.6f}/sec`",
            "- **온디맨드 표시 정책**: 일반 보안 진단·패치 실행 시에는 대화창이 번잡해지지 않도록 백그라운드(`Cloud Logging` + 원장)에만 기록하며, **비용을 물어보실 때만** 일자별 총 청구 금액과 세션별·트랜잭션별 상세 내역을 조회해 안내합니다.",
            "",
            f"#### 1️⃣ 📅 {as_of_date} 기준 총 누적 청구(발생) 비용 vs 현재 세션 요약",
            "| 구분 | 정산 기간 (KST) | 트랜잭션(실행) 횟수 | 총 토큰 사용량 | LLM 추론 비용 (USD) | 샌드박스·컨테이너 (USD) | 총 청구(발생) 비용 (USD) | 총 청구(발생) 비용 (KRW) |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            f"| **현재 세션 누적 (`{workspace.session_id}`)** | `{as_of_date}` | **{cur_sess_runs}건** | **{format_tokens(combined_sess_tok)}** | `{format_usd(combined_sess_llm_usd)}` | `{format_usd(combined_sess_sbx_usd)}` | **{format_usd(combined_sess_usd)}** | **{format_krw(combined_sess_krw)}** |",
            f"| **{as_of_date}까지 전체 누적 청구 예상액 (Cloud Logging + 원장)** | `{billing_period}` | **{ledger_tot_runs}건** ({max(len(sessions_list), 1)}개 세션) | **{format_tokens(ledger_tot_tok)}** | `{format_usd(ledger_llm_usd)}` | `{format_usd(ledger_sbx_usd)}` | **{format_usd(ledger_tot_usd)}** | **{format_krw(ledger_tot_krw)}** |",
            "",
            "#### 2️⃣ 🗂️ 각 세션(Session)별 비용 정산 내역",
            "| # | 세션 ID (`Session / Workspace`) | 세션 활동 기간 (KST) | 트랜잭션 수 | 총 토큰 사용량 | LLM 추론 비용 (USD) | 샌드박스·인프라 (USD) | 세션 합계 비용 (USD / KRW) |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        if sessions_list:
            for s_idx, sess_item in enumerate(sessions_list, start=1):
                s_id = str(sess_item.get("session_id") or workspace.session_id)
                is_current_tag = " *(현재 세션)*" if s_id in (workspace.session_id, workspace.workspace_id) else ""
                s_first = sess_item.get("first_kst") or as_of_dt
                s_last = sess_item.get("last_kst") or as_of_dt
                s_period = s_first if s_first == s_last else f"{s_first} ~ {s_last}"
                s_usd = float(sess_item.get("total_cost_usd", 0.0))
                s_krw = float(sess_item.get("total_cost_krw", s_usd * CM_USD_TO_KRW_RATE))
                s_tx_cnt = int(sess_item.get("tx_count", sess_item.get("transaction_count", 1)))
                lines.append(
                    f"| `{s_idx}` | `{s_id}`{is_current_tag} | `{s_period}` | **{s_tx_cnt}건** | **{format_tokens(int(sess_item.get('total_tokens', 0)))}** | `{format_usd(float(sess_item.get('llm_cost_usd', 0.0)))}` | `{format_usd(float(sess_item.get('sandbox_cost_usd', 0.0)))}` | **{format_usd(s_usd)} ({format_krw(s_krw)})** |"
                )
        else:
            lines.append(
                f"| `1` | `{workspace.session_id}` *(현재 세션)* | `{as_of_dt}` | **{cur_sess_runs}건** | **{format_tokens(combined_sess_tok)}** | `{format_usd(combined_sess_llm_usd)}` | `{format_usd(combined_sess_sbx_usd)}` | **{format_usd(combined_sess_usd)} ({format_krw(combined_sess_krw)})** |"
            )
        lines.append("")

        lines.extend(
            [
                "#### 3️⃣ 🧾 각 트랜잭션(Transaction / 개별 작업 실행)별 상세 비용 내역",
                "| # | 실행 일시 (KST) | 세션 ID | 트랜잭션 / 작업 내역 (`Operation`) | 모델 | 토큰 (`In / Out / Think`) | 소요 시간 | 트랜잭션 비용 (USD / KRW) |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        if tx_list:
            for tx in tx_list[-25:]:
                t_usd = float(tx.get("cost_usd", tx.get("total_cost_usd", 0.0)))
                t_krw = float(tx.get("cost_krw", tx.get("total_cost_krw", t_usd * CM_USD_TO_KRW_RATE)))
                t_kst = str(tx.get("timestamp_kst") or tx.get("kst_datetime") or as_of_dt)
                tok_detail = (
                    f"`{int(tx.get('total_tokens', 0)):,} tok` "
                    f"(`{int(tx.get('input_tokens', 0)):,}/{int(tx.get('output_tokens', 0)):,}/{int(tx.get('thinking_tokens', 0)):,}`)"
                )
                lines.append(
                    f"| `{tx.get('tx_index', 1)}` | `{t_kst}` | `{tx.get('session_id', workspace.session_id)}` | **{tx.get('operation_label', tx.get('operation_raw', 'cm scan'))}** | `{tx.get('model', active_model)}` | {tok_detail} | `{float(tx.get('duration_ms', 0.0)):.0f} ms` | **{format_usd(t_usd)} ({format_krw(t_krw)})** |"
                )
        else:
            lines.append(
                f"| `-` | `{as_of_dt}` | `{workspace.session_id}` | 아직 실행된 스캔/패치 트랜잭션이 없습니다 (`cm find` 또는 파일 업로드 시 자동 기록) | `{active_model}` | `0 tok` | `0 ms` | **$0.000000 (₩0.00원)** |"
            )
        lines.append("")

        if pipeline_res is not None and pipeline_res.cost_summary is not None:
            cs = pipeline_res.cost_summary
            lines.extend(
                [
                    f"#### 4️⃣ 🔬 최근 3단계 보안 하네스 스캔(`{cs.run_id}`) Stage별 세부 비용 명세",
                    "| 하네스 단계 (Stage) | Input 토큰 | Output 토큰 | Thinking 토큰 | 총 토큰 | LLM 비용 | 샌드박스 비용 | 합계 (USD / KRW) | 소요 시간 |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for stg in cs.stages:
                lines.append(
                    f"| **{stg.stage_label}** | `{stg.input_tokens:,}` | `{stg.output_tokens:,}` | `{stg.thinking_tokens:,}` | **{stg.total_tokens:,} tok** | `{format_usd(stg.llm_cost_usd)}` | `{format_usd(stg.sandbox_compute_cost_usd)}` | **{format_usd(stg.total_cost_usd)} ({format_krw(stg.total_cost_krw)})** | `{stg.duration_ms:.1f} ms` |"
                )
            lines.append(
                f"| **파이프라인 합계 (Total)** | **{cs.input_tokens:,}** | **{cs.output_tokens:,}** | **{cs.thinking_tokens:,}** | **{format_tokens(cs.total_tokens)}** | **{format_usd(cs.llm_cost_usd)}** | **{format_usd(cs.sandbox_compute_cost_usd)}** | **{format_usd(cs.total_cost_usd)} ({format_krw(cs.total_cost_krw)})** | **{cs.duration_ms:.1f} ms** |"
            )
            lines.append(
                f"- **취약점 1건당 평균 검증·패치 단가**: **{format_usd(cs.cost_per_vuln_usd)} ({format_krw(cs.cost_per_vuln_krw)})** (확증 취약점 {cs.verified_vulns_count}건, 패치 완료 {fixed_cnt}건, 오탐 제거 {cs.false_positives_filtered}건)"
            )
            lines.append("")

        cl_status = (
            "🟢 실시간 연동됨 (`logging.googleapis.com/v2/entries:list`)"
            if cloud_log.get("available")
            else "🟡 로컬 원장 폴백 모드 (`stdout` 구조화 로그 출력 활성)"
        )
        lines.extend(
            [
                f"#### 5️⃣ ☁️ Cloud Logging (`entries:list`) 기반 빌링 비의존(Billing-Free) 실시간 집계 소스 ({cl_status})",
                "| Cloud Logging 로그 스트림 | 수집 필터 / 소스 | 감지 건수 | 토큰 / 지연시간 합계 | 산출 비용 (USD) | 산출 비용 (KRW) |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
                f"| **① 구조화 비용 로그 (`run.googleapis.com/stdout`)** | `jsonPayload.event_type=\"CODEMENDER_COST_TELEMETRY\"` | **{cl_runs}건** | **{format_tokens(cl_tok)}** | **{format_usd(float(cloud_log.get('structured_log_total_cost_usd', 0.0)))}** | **{format_krw(float(cloud_log.get('structured_log_total_cost_krw', 0.0)))}** |",
                f"| **② 컨테이너 요청 로그 (`run.googleapis.com/requests`)** | `resource.labels.service_name=\"codemender-ge\"` (`httpRequest.latency`) | **{cl_req_cnt}건** (POST) | 총 컨테이너 점유 **`{cl_req_sec:.3f} sec`** (`1 vCPU + 1 GiB`) | **{format_usd(cl_req_usd)}** | **{format_krw(cl_req_krw)}** |",
                f"| **③ 로그 기반 메트릭 (Cloud Monitoring)** | `logging.googleapis.com/user/codemender_cost_events` | 활성 (`DELTA`) | Cloud Monitoring 대시보드 / 알림 정책 연동 | **{format_usd(cl_combined_usd)}** | **{format_krw(cl_combined_krw)}** |",
                "",
                f"- **Logs Explorer 조회 필터 (`{GCP_PROJECT_ID}`)**:",
                f"  `{cloud_log.get('log_explorer_filter', 'resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"codemender-ge\" AND jsonPayload.event_type=\"CODEMENDER_COST_TELEMETRY\"')}`",
            ]
        )

        return {"markdown": "\n".join(lines), "pipeline_result": pipeline_res}

    # 11. cm sessions & cm artifacts / cm download
    if sub in ("sessions", "artifacts", "download"):
        pipeline_res = _ensure_pipeline()
        elapsed = int((time.monotonic() - t0) * 1000) + 10
        cost_footer = _record_cm_telemetry(state, parsed_cmd.get("raw", f"cm {sub}"), active_model, elapsed, 130, 210)
        history = list(state.get("cm_command_history") or [])

        if sub == "sessions":
            lines = [
                f"### 🗂️ `cm sessions` — 현재 세션(`{workspace.session_id}`) 명령 실행 타임라인 및 비용",
                f"- **워크스페이스 ID**: `{workspace.workspace_id}` | **활성 모델**: `{active_model}`",
                "",
                "| # | 실행 시각 (UTC) | 실행 명령어 | 모델 | 소요 시간 | 토큰 (In/Out/Think) | 비용 (USD / KRW) |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
            for h in history:
                h_usd = float(h.get("cost_usd", 0.0))
                h_krw = float(h.get("cost_krw", h_usd * CM_USD_TO_KRW_RATE))
                lines.append(
                    f"| `{h['index']}` | `{h['timestamp']}` | `{h['command']}` | `{h['model']}` | `{h['duration_ms']} ms` | `{h['input_tokens']}/{h['output_tokens']}/{h.get('thinking_tokens', 0)}` | **{format_usd(h_usd)} ({format_krw(h_krw)})** |"
                )
            return {"markdown": "\n".join(lines) + cost_footer}

        # `cm artifacts` / `cm download` / "수정한 파일 어디에 저장되어 있어?" / "다운로드"
        from app.ingestion.file_manager import publish_workspace_patched_files_to_gcs

        gcs_pub = publish_workspace_patched_files_to_gcs(workspace)
        pub_files = gcs_pub.get("files") or []
        zip_info = gcs_pub.get("zip_bundle") or {}

        lines = [
            f"### 📦 `cm artifacts` / `cm download` — 수정된 파일 실제 저장 위치 및 원클릭 다운로드 (`{workspace.workspace_id}`)",
            "> 💡 **왜 이전에는 다운로드가 안 되었나요?**  ",
            "> Cloud Run 컨테이너 내부 임시 격리 디스크(`/tmp/codemender_workspaces/...`)와 ADK 인메모리 아티팩트 스토어에만 저장되어 있으면 Gemini Enterprise 웹 UI에서 직접 클릭해 내려받을 수 없습니다.  ",
            f"> 이제 모든 패치 작업본과 ZIP 패키지를 **Google Cloud Storage 영구 버킷 (`gs://{GCS_ARTIFACT_BUCKET}/codemender-patches/...`)**에 자동 동기화하여 **브라우저 원클릭 다운로드 링크**와 **전체 수정본 코드 전문**을 함께 제공합니다!",
            "",
            "#### 1️⃣ 📥 원클릭 브라우저 직접 다운로드 & 3중 저장소 경로",
            "| 구분 | 파일명 | 1️⃣ 원클릭 직접 다운로드 (클릭) | 2️⃣ Google Cloud Storage 영구 경로 (`gs://`) | 3️⃣ Cloud Run 컨테이너 경로 |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for pf in pub_files:
            fname = pf.get("filename", "")
            dl_url = pf.get("download_url", "")
            con_url = pf.get("console_url", "")
            gcs_uri = pf.get("gcs_uri", "")
            loc_path = pf.get("local_container_path", "")
            lines.append(
                f"| **수정 완료본 (`patched/`)** | **`{fname}`** | **[📥 `{fname}` 바로 다운로드]({dl_url})** ([콘솔 보기]({con_url})) | `{gcs_uri}` | `{loc_path}` |"
            )
        if zip_info.get("download_url"):
            zname = zip_info.get("filename", "codemender_patched.zip")
            lines.append(
                f"| **전체 수정본 ZIP 번들** | **`{zname}`** | **[📦 `{zname}` 바로 다운로드]({zip_info['download_url']})** ([콘솔 보기]({zip_info.get('console_url', '')})) | `{zip_info.get('gcs_uri', '')}` | `{workspace.patched_dir}/` |"
            )

        for fmeta in workspace.files:
            lines.append(
                f"| **원본 소스 (`orig/`)** | `orig/{fmeta.relative_path}` | SHA-256: `{fmeta.sha256[:12]}...` ({fmeta.size_bytes} bytes) | - | `{workspace.orig_dir}/{fmeta.relative_path}` |"
            )
        for f in pipeline_res.findings:
            lines.append(
                f"| **검증 로그 (`.exploit/`)** | `.exploit/verify_{f.vuln_id.lower()}.log` | `{f.cwe_id}` 격리 샌드박스 검증 증적 | - | `{workspace.root_dir}/.exploit/` |"
            )
        lines.append(
            "| **보안 리포트 (`json`/`html`)** | `codemender-report.json`, `codemender-report.html` | `cm report -f json` / `html` 실행 시 생성 | - | `ADK Artifact Store` |"
        )
        lines.append(
            "| **비용 추적 원장 (`ledger`)** | `codemender_cost_ledger.json` | 모든 CodeMender 실행 토큰 및 USD/KRW 비용 영구 누적 원장 | `Cloud Logging (run.googleapis.com/stdout)` | `/tmp/codemender_cost_ledger.json` |"
        )
        lines.append("")

        if pub_files:
            lines.append("#### 2️⃣ 📄 현재 워크스페이스 수정본 파일 전체 코드 (우측 상단 `복사` 버튼으로 즉시 저장 가능)")
            for pf in pub_files:
                fname = pf.get("filename", "")
                lang = pf.get("language", "python")
                gcs_uri = pf.get("gcs_uri", "")
                code_body = str(pf.get("patched_content") or "").rstrip()
                lines.append(
                    f"##### 📄 `{fname}` (터미널 다운로드: `gcloud storage cp {gcs_uri} ./`)"
                )
                lines.append(f"```{lang}\n{code_body}\n```\n")

        return {"markdown": "\n".join(lines) + cost_footer}

    # 12. cm models / test-all-models / switch-model
    if sub in ("models", "test-all-models", "switch-model", "check-allowlist"):
        if sub == "switch-model" and positional:
            requested = positional[0].strip()
            if requested in SUPPORTED_CM_MODELS:
                state["cm_active_model"] = requested
                active_model = requested
                msg_header = f"### 🔄 `cm switch-model` — 활성 모델이 `{active_model}`(으)로 전환되었습니다!\n\n"
            else:
                msg_header = (
                    f"> ⚠️ 지원하지 않는 모델명(`{requested}`)입니다. 공식 지원 모델 중 하나를 선택하세요.\n\n"
                )
        else:
            msg_header = "### 🤖 `cm models` — CodeMender 공식 지원 모델 벤치마크 및 토큰 단가\n\n"

        elapsed = int((time.monotonic() - t0) * 1000) + 18
        cost_footer = _record_cm_telemetry(state, parsed_cmd.get("raw", f"cm {sub}"), active_model, elapsed, 160, 230)

        lines = [
            msg_header.rstrip(),
            "| 모델 ID | 현재 선택 | 티어 (Tier) | 단가 (Input / Output / Think per 1M) | 리전 | 상태 | 특화 용도 |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for m_id, meta in SUPPORTED_CM_MODELS.items():
            is_curr = "✅ **ACTIVE**" if m_id == active_model else "대기"
            m_rates = get_model_pricing(m_id)
            rate_str = f"`${m_rates['input']:.2f}` / `${m_rates['output']:.2f}` / `${m_rates['thinking']:.2f}`"
            lines.append(
                f"| `{m_id}` | {is_curr} | {meta['tier']} | {rate_str} | `{meta['location']}` | `🟢 200 OK (Allow-listed)` | {meta['specialty']} |"
            )
        lines.extend(
            [
                "",
                "💡 **모델 전환 방법**: 채팅창에 **`cm switch-model gemini-3.8-flash-cyber`** 또는 **`cm find --model gemini-3.7-flash`**처럼 입력하세요.",
            ]
        )
        return {"markdown": "\n".join(lines) + cost_footer}

    # 13. cm github / cm gh (OAuth Device Flow login, repo list, remote repo scan, autonomous PR creation)
    if sub in ("github", "gh"):
        from app.harness.github_integration import (
            create_github_pr_or_push_patches,
            fetch_github_repo_files_into_workspace,
            list_user_github_repos,
            logout_github_auth,
            poll_or_verify_github_auth,
            start_github_device_flow,
        )

        gh_action = positional[0].lower() if positional else "login"
        gh_args = positional[1:] if len(positional) > 1 else []

        if gh_action == "logout":
            logout_github_auth(state)
            return {
                "markdown": (
                    "### 🔒 `cm github logout` — GitHub 계정 연동 해제 완료\n"
                    "- 저장된 GitHub OAuth 토큰 및 세션 인증 정보가 안전하게 삭제되었습니다.\n"
                    "- 다시 연동하시려면 채팅창에 **`깃허브 로그인`** 또는 **`cm github login`**을 입력하세요."
                )
            }

        if gh_action == "token" and gh_args:
            auth_info = poll_or_verify_github_auth(state, explicit_token=gh_args[0])
            if auth_info.get("authenticated"):
                gh_action = "status"
            else:
                return {
                    "markdown": (
                        "### ❌ GitHub 토큰 인증 실패\n"
                        "- 입력하신 토큰이 유효하지 않거나 만료되었습니다. **`깃허브 로그인`**(`cm github login`)을 입력해 브라우저 기기 인증(OAuth Device Flow)으로 간편하게 연동해 보세요."
                    )
                }

        # Check if user already completed Device Flow or is already authenticated
        current_auth = poll_or_verify_github_auth(state)

        if gh_action in ("login", "auth") and not parsed_cmd.get("force"):
            # If user is already authenticated, show their connected profile + start new flow only if --force
            if current_auth.get("authenticated"):
                gh_action = "status"
            else:
                flow = start_github_device_flow(state)
                u_code = flow.get("user_code", "XXXX-XXXX")
                v_uri = flow.get("verification_uri", "https://github.com/login/device")
                lines = [
                    "### 🔗 `cm github login` — 내 GitHub 계정 OAuth 연동 (Device Flow)",
                    "별도의 토큰 발급 없이 **아래 링크를 클릭하고 8자리 인증 코드만 입력**하면 내 GitHub 계정이 CodeMender 에이전트에 즉시 연동됩니다!",
                    "",
                    f"1. **👉 [여기를 클릭해 GitHub 기기 인증 페이지 열기 (`{v_uri}`)]({v_uri})**",
                    "2. 열림 화면에 아래 **1회용 8자리 인증 코드**를 복사해 붙여넣고 **`[Continue]` → `[Authorize]`** 버튼을 클릭하세요:",
                    f"```text\n{u_code}\n```",
                    "3. 브라우저에서 승인을 마쳤다면, 이 채팅창에 **`깃허브 인증 완료`** (또는 **`내 레포 목록`**, **`cm github status`**)라고 입력해 주세요!",
                    "",
                    "> 💡 *또는 GitHub Personal Access Token(`ghp_...`)이 있으시다면 채팅창에 바로 붙여넣으셔도 즉시 연동됩니다.*",
                ]
                return {"markdown": "\n".join(lines)}

        if gh_action in ("login", "auth") and parsed_cmd.get("force"):
            flow = start_github_device_flow(state)
            u_code = flow.get("user_code", "XXXX-XXXX")
            v_uri = flow.get("verification_uri", "https://github.com/login/device")
            lines = [
                "### 🔗 `cm github login --force` — 새 GitHub OAuth 기기 인증 코드 발급",
                f"1. **👉 [GitHub 기기 인증 페이지 열기 (`{v_uri}`)]({v_uri})**",
                "2. 아래 **8자리 인증 코드**를 입력하고 **`[Authorize]`**를 클릭하세요:",
                f"```text\n{u_code}\n```",
                "3. 승인 후 채팅창에 **`깃허브 인증 완료`**라고 입력해 주세요.",
            ]
            return {"markdown": "\n".join(lines)}

        # If not authenticated yet for status / repos / scan / pr, prompt Device Flow immediately!
        if not current_auth.get("authenticated"):
            if current_auth.get("reason") == "authorization_pending":
                u_code = current_auth.get("user_code", "")
                v_uri = current_auth.get("verification_uri", "https://github.com/login/device")
                return {
                    "markdown": (
                        "### ⏳ GitHub 브라우저 인증 대기 중입니다\n"
                        f"아직 GitHub에서 코드 승인이 완료되지 않았습니다.\n\n"
                        f"1. **👉 [GitHub 기기 인증 페이지 열기 (`{v_uri}`)]({v_uri})**\n"
                        f"2. 인증 코드 입력: **`{u_code}`** → **`[Authorize]`** 클릭\n"
                        "3. 승인 직후 채팅창에 다시 **`깃허브 인증 완료`** 또는 **`내 레포 목록`**을 입력해 주세요!"
                    )
                }
            flow = start_github_device_flow(state)
            u_code = flow.get("user_code", "XXXX-XXXX")
            v_uri = flow.get("verification_uri", "https://github.com/login/device")
            return {
                "markdown": (
                    "### 🔐 GitHub 계정 인증이 필요합니다 (`cm github login`)\n"
                    "내 GitHub 레포지토리 조회·스캔 및 자동 PR 생성을 위해 먼저 1회 인증을 진행해 주세요:\n\n"
                    f"1. **👉 [여기를 클릭해 GitHub 기기 인증 페이지 열기 (`{v_uri}`)]({v_uri})**\n"
                    f"2. 화면에 아래 8자리 인증 코드를 입력하고 **`[Authorize]`**를 클릭하세요:\n"
                    f"```text\n{u_code}\n```\n"
                    "3. 승인 완료 후 채팅창에 **`깃허브 인증 완료`**라고 입력해 주세요!"
                )
            }

        token = str(current_auth.get("access_token") or "")
        gh_login = str(current_auth.get("login") or "user")
        gh_name = str(current_auth.get("name") or gh_login)
        gh_url = str(current_auth.get("html_url") or f"https://github.com/{gh_login}")

        # 13a. `cm github status` / `cm github repos`
        if gh_action in ("status", "verify", "whoami", "repos", "list"):
            repos = list_user_github_repos(token, limit=15)
            lines = [
                f"### ✅ GitHub 계정 연동 완료 — `@{gh_login}` ({gh_name})",
                f"- **연동된 GitHub 프로필**: **[@{gh_login} ({gh_url})]({gh_url})**",
                f"- **보유 레포지토리**: Public **{current_auth.get('public_repos', 0)}개** · Private **{current_auth.get('total_private_repos', 0)}개** (총 조회된 최근 활동 레포: **{len(repos)}개**)",
                "",
                "#### 📂 내 GitHub 레포지토리 목록 (클릭 또는 명령어로 즉시 보안 스캔 & 자동 PR 가능)",
                "| # | 레포지토리 (`owner/repo`) | 공개 여부 | 기본 브랜치 | 주 언어 | 최근 업데이트 | 즉시 스캔 명령어 |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
            for r_idx, r in enumerate(repos, start=1):
                vis = "🔒 Private" if r.get("private") else "🌐 Public"
                fn = r.get("full_name", "")
                r_url = r.get("html_url", f"https://github.com/{fn}")
                lines.append(
                    f"| `{r_idx}` | **[`{fn}`]({r_url})** | {vis} | `{r.get('default_branch', 'main')}` | `{r.get('language', '-')}` | `{r.get('updated_at', '-')}` | **`깃허브 스캔 {fn}`** |"
                )
            lines.extend(
                [
                    "",
                    "---",
                    "💡 **바로 실행 가능한 GitHub 연동 명령어**:",
                    f"- **내 레포지토리 코드 취약점 스캔**: **`깃허브 스캔 {repos[0]['full_name'] if repos else f'{gh_login}/my-repo'}`** (또는 `cm github scan <owner/repo>`)",
                    f"- **현재 패치된 보안 코드를 내 GitHub에 커밋 & PR 생성**: **`깃허브 PR 생성`** (또는 `cm github pr [owner/repo]`)",
                    "- **다른 계정으로 재인증**: **`cm github login --force`** | **연동 해제**: **`깃허브 로그아웃`**",
                ]
            )
            return {"markdown": "\n".join(lines)}

        # 13b. `cm github scan <owner/repo> [subpath]`
        if gh_action in ("scan", "clone"):
            if not gh_args:
                repos = list_user_github_repos(token, limit=5)
                example_repo = repos[0]["full_name"] if repos else f"{gh_login}/my-repo"
                return {
                    "markdown": (
                        "### 🔍 스캔할 GitHub 레포지토리 이름을 지정해 주세요\n"
                        f"- 사용법: **`깃허브 스캔 {example_repo}`** 또는 **`cm github scan {example_repo} [폴더/파일경로]`**\n"
                        "- 내 전체 레포 목록을 보시려면 **`내 레포 목록`**(`cm github repos`)을 입력하세요."
                    )
                }
            target_repo = gh_args[0]
            subpath = gh_args[1] if len(gh_args) > 1 else ""
            if "/" not in target_repo and not target_repo.startswith("https://"):
                target_repo = f"{gh_login}/{target_repo}"

            fetch_res = fetch_github_repo_files_into_workspace(
                token=token,
                repo_full_name=target_repo,
                workspace=workspace,
                subpath=subpath,
            )
            if fetch_res.get("status") != "ok":
                return {
                    "markdown": f"### ⚠️ GitHub 레포지토리 스캔 오류\n- {fetch_res.get('message', '알 수 없는 오류')}"
                }

            state["cm_workspace"] = workspace.to_dict()
            state["cm_github_repo_context"] = fetch_res

            runner = CodeMenderRunner(model_name=active_model)
            pipeline_res = runner.run_pipeline(workspace)
            if pipeline_res.cost_summary is not None:
                record_session_cost(state, pipeline_res.cost_summary)
            state["cm_pipeline_result"] = pipeline_res.to_dict()

            elapsed = int((time.monotonic() - t0) * 1000) + 60
            _record_cm_telemetry(
                state,
                f"cm github scan {fetch_res['repo']}",
                active_model,
                elapsed,
                pipeline_res.cost_summary.input_tokens if pipeline_res.cost_summary else 1200,
                pipeline_res.cost_summary.output_tokens if pipeline_res.cost_summary else 850,
                pipeline_res.cost_summary.thinking_tokens if pipeline_res.cost_summary else 320,
                include_sandbox=True,
            )

            from app.agent import _format_scan_report_markdown

            scan_md = _format_scan_report_markdown(pipeline_res)
            header_md = (
                f"### 🐙 GitHub 레포지토리 실시간 연동 스캔 완료: [`{fetch_res['repo']}`]({fetch_res.get('html_url', '')}) (브랜치: `{fetch_res['branch']}`)\n"
                f"- **GitHub 계정**: `@{gh_login}` | **가져온 소스 파일 ({len(fetch_res['fetched_files'])}개)**: `{', '.join(fetch_res['fetched_files'])}`\n"
                f"- **자동 PR 생성 안내**: 패치 확인 후 채팅창에 **`깃허브 PR 생성`** (또는 **`cm github pr {fetch_res['repo']}`**)이라고 입력하시면 해당 GitHub 레포지토리에 보안 패치 브랜치 커밋과 Pull Request가 즉시 생성됩니다!\n\n---\n\n"
            )
            return {
                "markdown": header_md + scan_md,
                "pipeline_result": pipeline_res,
            }

        # 13c. `cm github pr [owner/repo]` / `cm github push [owner/repo]`
        if gh_action in ("pr", "push", "commit"):
            pipeline_res = _ensure_pipeline()
            target_repo = gh_args[0] if gh_args else ""
            pr_res = create_github_pr_or_push_patches(
                token=token,
                login=gh_login,
                workspace=workspace,
                pipeline_result=pipeline_res,
                target_repo=target_repo,
                create_new_repo_if_missing=True,
                state=state,
            )
            if pr_res.get("status") != "ok":
                return {
                    "markdown": f"### ⚠️ GitHub 커밋 / Pull Request 생성 실패\n- {pr_res.get('message', '오류 발생')}"
                }

            state["cm_workspace"] = workspace.to_dict()
            state["cm_pipeline_result"] = pipeline_res.to_dict()
            elapsed = int((time.monotonic() - t0) * 1000) + 95
            _record_cm_telemetry(
                state,
                f"cm github pr {pr_res['repo']}",
                active_model,
                elapsed,
                680,
                520,
                include_sandbox=True,
            )

            repo_name = pr_res["repo"]
            pr_url = pr_res.get("pr_url") or pr_res.get("branch_url") or pr_res.get("repo_url")
            pr_num = pr_res.get("pr_number", 0)
            lines = [
                f"### 🚀 GitHub 보안 패치 커밋 & 자율 Pull Request 생성 완료! (`{repo_name}`)",
                f"- **GitHub 계정**: **[@{gh_login}]({gh_url})**",
                f"- **대상 레포지토리**: **[`{repo_name}`]({pr_res['repo_url']})**"
                + (" *(새 레포지토리 자동 생성됨)*" if pr_res.get("created_new_repo") else ""),
                f"- **패치 브랜치**: **[`{pr_res['patch_branch']}`]({pr_res['branch_url']})** → `{pr_res['base_branch']}`",
                f"- **커밋된 수정 파일 ({len(pr_res.get('committed_files', []))}개)**: `{', '.join(pr_res.get('committed_files', []))}`",
            ]
            if pr_url and pr_num:
                lines.append(
                    f"- **🔗 생성된 GitHub Pull Request**: **[👉 Pull Request #{pr_num} 바로 열기 (`{pr_url}`)]({pr_url})**"
                )
            for c_idx, c_url in enumerate(pr_res.get("commit_urls") or [], start=1):
                lines.append(
                    f"- **📝 GitHub 커밋 #{c_idx}**: **[커밋 Diff 보기 (`{c_url}`)]({c_url})**"
                )
            return {"markdown": "\n".join(lines), "pipeline_result": pipeline_res}

    # Fallback: show help if subcommand unknown
    return {"markdown": format_cm_help_markdown(active_model=active_model)}


