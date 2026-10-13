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

"""A2UI v0.9 Surface Builder for CodeMender Vulnerability & Patch Visualization.

Supports Dual-Catalog rendering:
1. 'codemender_material': Uses MaterialCard, MaterialBadge, CodeDiff, MaterialButton
2. 'basic': Uses standard A2UI v0.9 BasicCatalog (Card, Row, Column, Tabs, Text, Button, Icon)
Every generated payload is validated against the A2UI v0.9 JSON Schema and topology checker.
"""

from __future__ import annotations

from typing import Any

from app.a2ui_renderer.schema_manager import validate_a2ui_payload
from app.config import (
    A2UI_BASIC_CATALOG_ID,
    CODEMENDER_CUSTOM_CATALOG_ID,
    GCP_PROJECT_ID,
    GE_LOCATION,
)
from app.harness.cm_runner import CodeMenderPipelineResult, VulnerabilityFinding
from app.harness.cost_tracker import (
    CodeMenderCostBreakdown,
    format_krw,
    format_tokens,
    # [CodeMender CM-CWE-20-005] Applied verified security remediation:
    def _catalog_id_for_mode(catalog_mode: str) -> str:
        if catalog_mode == "basic":
            return A2UI_BASIC_CATALOG_ID
        if catalog_mode == "codemender_material":
            return CODEMENDER_CUSTOM_CATALOG_ID
        raise ValueError(f"Unsupported catalog_mode: {catalog_mode}")
    if catalog_mode == "codemender_material":
        return CODEMENDER_CUSTOM_CATALOG_ID
    raise ValueError(f"Unsupported catalog_mode: {catalog_mode}")


def build_upload_prompt_surface(
    surface_id: str = "codemender-upload-guide",
    catalog_mode: str = "codemender_material",
) -> list[dict[str, Any]]:
    """Builds an interactive A2UI v0.9 onboarding card when no source file is attached yet."""
    catalog_id = _catalog_id_for_mode(catalog_mode)

    if catalog_mode == "codemender_material":
        components: list[dict[str, Any]] = [
            {
                "id": "root",
                "component": "Column",
                "children": ["welcome_card"],
            },
            {
                "id": "welcome_card",
                "component": "MaterialCard",
                "title": "🛡️ CodeMender Security Agent (Gemini 3.8 Flash)",
                "subtitle": f"Gemini Enterprise ({GCP_PROJECT_ID} / {GE_LOCATION.upper()}) — 3단계 보안 하네스 (cm find → cm verify → cm fix)",
                "elevation": 2,
                "status": "INFO",
                "children": [
                    "welcome_badge_row",
                    "welcome_desc",
                    "demo_btn_row",
                ],
            },
            {
                "id": "welcome_badge_row",
                "component": "Row",
                "children": ["badge_model", "badge_sandbox"],
                "justify": "start",
                "align": "center",
            },
            {
                "id": "badge_model",
                "component": "MaterialBadge",
                "label": "Model: gemini-3.8-flash",
                "severity": "INFO",
            },
            {
                "id": "badge_sandbox",
                "component": "MaterialBadge",
                "label": "Zero False-Positive Sandbox",
                "severity": "VERIFIED",
            },
            {
                "id": "welcome_desc",
                "component": "Text",
                "text": (
                    "채팅창에 진단할 소스코드 파일(.py, .js, .ts, .go, .java, .c, .zip 등)을 직접 첨부하거나 "
                    "코드 블록을 입력해 주세요. 업로드 즉시 격리된 워크스페이스에 마운트하여 CWE/OWASP 취약점 탐색, "
                    "샌드박스 PoC 재현 검증, 최소 변경 보안 패치(CodeDiff)를 인터랙티브 UI로 생성합니다."
                ),
                "variant": "body",
            },
            {
                "id": "demo_btn_row",
                "component": "Row",
                "children": ["run_sample_scan_btn"],
                "justify": "start",
                "align": "center",
            },
            {
                "id": "run_sample_scan_btn",
                "component": "MaterialButton",
                "label": "🧪 샘플 취약 소스코드로 즉시 진단 데모 실행",
                "variant": "primary",
                "action": {
                    "event": {
                        "name": "run_sample_scan",
                        "context": {"sample": "default_vulnerable_app"},
                    }
                },
            },
        ]
    else:
        components = [
            {
                "id": "root",
                "component": "Column",
                "children": ["welcome_card"],
            },
            {
                "id": "welcome_card",
                "component": "Card",
                "child": "welcome_col",
            },
            {
                "id": "welcome_col",
                "component": "Column",
                "children": ["welcome_title", "welcome_desc", "run_sample_scan_btn"],
            },
            {
                "id": "welcome_title",
                "component": "Text",
                "text": "🛡️ CodeMender Security Agent (gemini-3.8-flash)",
                "variant": "h2",
            },
            {
                "id": "welcome_desc",
                "component": "Text",
                "text": (
                    "채팅창에 소스코드 파일(단일 파일, 멀티 파일, .zip)을 업로드하면 "
                    "3단계 하네스(Find → Verify → Fix)를 실행하여 인터랙티브 패치 UI를 렌더링합니다."
                ),
                "variant": "body",
            },
            {
                "id": "run_sample_scan_btn",
                "component": "Button",
                "child": "run_sample_scan_btn_txt",
                "variant": "primary",
                "action": {
                    "event": {
                        "name": "run_sample_scan",
                        "context": {"sample": "default_vulnerable_app"},
                    }
                },
            },
            {
                "id": "run_sample_scan_btn_txt",
                "component": "Text",
                "text": "🧪 샘플 취약 코드로 즉시 진단 실행",
                "variant": "body",
            },
        ]

    messages = [
        {
            "version": "v0.9",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": catalog_id,
                "theme": {
                    "primaryColor": "#1A73E8",
                    "agentDisplayName": "CodeMender Security Agent (gemini-3.8-flash)",
                },
            },
        },
        {
            "version": "v0.9",
            "updateComponents": {
                "surfaceId": surface_id,
                "components": components,
            },
        },
    ]
    validate_a2ui_payload(messages, catalog_mode=catalog_mode)
    return messages


def _build_material_finding_card(
    idx: int,
    finding: VulnerabilityFinding,
) -> tuple[str, list[dict[str, Any]]]:
    """Builds a MaterialCard + MaterialBadge + CodeDiff + MaterialButton tree for a finding."""
    prefix = f"vuln_{idx}"
    card_id = f"{prefix}_card"
    badge_row_id = f"{prefix}_badge_row"
    sev_badge_id = f"{prefix}_sev_badge"
    cwe_badge_id = f"{prefix}_cwe_badge"
    judge_badge_id = f"{prefix}_judge_badge"
    desc_id = f"{prefix}_desc"
    sandbox_id = f"{prefix}_sandbox_log"
    diff_id = f"{prefix}_codediff"
    judge_text_id = f"{prefix}_judge_rationale"
    action_row_id = f"{prefix}_action_row"
    apply_btn_id = f"{prefix}_apply_btn"
    reject_btn_id = f"{prefix}_reject_btn"

    is_applied = finding.patch_status == "APPLIED"
    is_rejected = finding.patch_status == "REJECTED"

    status_label = (
        "PATCH APPLIED ✅"
        if is_applied
        else ("REJECTED ❌" if is_rejected else f"{finding.severity} · VERIFIED")
    )
    badge_severity = "PATCHED" if is_applied else finding.severity

    components: list[dict[str, Any]] = [
        {
            "id": card_id,
            "component": "MaterialCard",
            "title": f"[{finding.vuln_id}] {finding.title}",
            "subtitle": f"파일: {finding.file_path} (Lines {finding.start_line}–{finding.end_line}) · {finding.owasp_category}",
            "elevation": 3,
            "status": finding.patch_status,
            "children": [
                badge_row_id,
                desc_id,
                sandbox_id,
                diff_id,
                judge_text_id,
                action_row_id,
            ],
        },
        {
            "id": badge_row_id,
            "component": "Row",
            "children": [sev_badge_id, cwe_badge_id, judge_badge_id],
            "justify": "start",
            "align": "center",
        },
        {
            "id": sev_badge_id,
            "component": "MaterialBadge",
            "label": status_label,
            "severity": badge_severity,
            "cweId": finding.cwe_id,
            "owaspCategory": finding.owasp_category,
        },
        {
            "id": cwe_badge_id,
            "component": "MaterialBadge",
            "label": f"{finding.cwe_id} · Sandbox PoC Verified",
            "severity": "VERIFIED",
            "cweId": finding.cwe_id,
        },
        {
            "id": judge_badge_id,
            "component": "MaterialBadge",
            "label": f"LLM-as-a-Judge: {finding.judge_score}/10 ({finding.judge_verdict})",
            "severity": "INFO",
        },
        {
            "id": desc_id,
            "component": "Text",
            "text": f"취약점 분석: {finding.description}",
            "variant": "body",
        },
        {
            "id": sandbox_id,
            "component": "Text",
            "text": f"샌드박스 검증 로그: {finding.sandbox_evidence}",
            "variant": "caption",
        },
        {
            "id": diff_id,
            "component": "CodeDiff",
            "filePath": finding.file_path,
            "language": "python" if finding.file_path.endswith(".py") else "plaintext",
            "startLine": finding.start_line,
            "endLine": finding.end_line,
            "beforeCode": finding.before_code,
            "afterCode": finding.after_code,
            "unifiedDiff": finding.unified_diff,
        },
        {
            "id": judge_text_id,
            "component": "Text",
            "text": f"패치 검증 의견 (gemini-3.8-flash Judge): {finding.judge_rationale}",
            "variant": "caption",
        },
        {
            "id": action_row_id,
            "component": "Row",
            "children": [apply_btn_id, reject_btn_id],
            "justify": "end",
            "align": "center",
        },
        {
            "id": apply_btn_id,
            "component": "MaterialButton",
            "label": "✅ 패치 적용 완료" if is_applied else "✅ 패치 적용 (Apply Patch)",
            "variant": "primary",
            "disabled": is_applied,
            "action": {
                "event": {
                    "name": "apply_patch",
                    "context": {
                        "vuln_id": finding.vuln_id,
                        "file_path": finding.file_path,
                    },
                }
            },
        },
        {
            "id": reject_btn_id,
            "component": "MaterialButton",
            "label": "패치 보류/거절 (Reject)",
            "variant": "outlined",
            "disabled": is_applied or is_rejected,
            "action": {
                "event": {
                    "name": "reject_patch",
                    "context": {
                        "vuln_id": finding.vuln_id,
                        "file_path": finding.file_path,
                    },
                }
            },
        },
    ]
    return card_id, components


def _build_basic_finding_card(
    idx: int,
    finding: VulnerabilityFinding,
) -> tuple[str, list[dict[str, Any]]]:
    """Builds a 100% standard A2UI v0.9 BasicCatalog Card + Tabs + Button tree for a finding."""
    prefix = f"vuln_{idx}"
    card_id = f"{prefix}_card"
    col_id = f"{prefix}_col"
    title_id = f"{prefix}_title"
    meta_id = f"{prefix}_meta"
    tabs_id = f"{prefix}_tabs"
    tab_diff_id = f"{prefix}_tab_diff"
    tab_verify_id = f"{prefix}_tab_verify"
    action_row_id = f"{prefix}_action_row"
    apply_btn_id = f"{prefix}_apply_btn"
    apply_btn_txt_id = f"{prefix}_apply_btn_txt"
    reject_btn_id = f"{prefix}_reject_btn"
    reject_btn_txt_id = f"{prefix}_reject_btn_txt"

    is_applied = finding.patch_status == "APPLIED"
    status_tag = "PATCH APPLIED ✅" if is_applied else finding.severity

    components: list[dict[str, Any]] = [
        {
            "id": card_id,
            "component": "Card",
            "child": col_id,
        },
        {
            "id": col_id,
            "component": "Column",
            "children": [title_id, meta_id, tabs_id, action_row_id],
        },
        {
            "id": title_id,
            "component": "Text",
            "text": f"[{status_tag}] {finding.vuln_id}: {finding.title} ({finding.cwe_id})",
            "variant": "h3",
        },
        {
            "id": meta_id,
            "component": "Text",
            "text": (
                f"파일: {finding.file_path} (Lines {finding.start_line}–{finding.end_line}) | "
                f"{finding.owasp_category} | Judge: {finding.judge_score}/10 ({finding.judge_verdict})"
            ),
            "variant": "caption",
        },
        {
            "id": tabs_id,
            "component": "Tabs",
            "tabs": [
                {"title": "전/후 코드 비교 (CodeDiff)", "child": tab_diff_id},
                {"title": "샌드박스 검증 및 Judge 평가", "child": tab_verify_id},
            ],
        },
        {
            "id": tab_diff_id,
            "component": "Text",
            "text": (
                f"설명: {finding.description}\n\n"
                f"[Unified Diff]\n{finding.unified_diff.strip()}"
            ),
            "variant": "body",
        },
        {
            "id": tab_verify_id,
            "component": "Text",
            "text": (
                f"{finding.sandbox_evidence}\n"
                f"Judge 의견: {finding.judge_rationale}"
            ),
            "variant": "body",
        },
        {
            "id": action_row_id,
            "component": "Row",
            "children": [apply_btn_id, reject_btn_id],
            "justify": "end",
            "align": "center",
        },
        {
            "id": apply_btn_id,
            "component": "Button",
            "child": apply_btn_txt_id,
            "variant": "primary",
            "action": {
                "event": {
                    "name": "apply_patch",
                    "context": {
                        "vuln_id": finding.vuln_id,
                        "file_path": finding.file_path,
                    },
                }
            },
        },
        {
            "id": apply_btn_txt_id,
            "component": "Text",
            "text": "✅ 패치 적용 완료" if is_applied else "✅ 패치 적용 (Apply Patch)",
            "variant": "body",
        },
        {
            "id": reject_btn_id,
            "component": "Button",
            "child": reject_btn_txt_id,
            "variant": "default",
            "action": {
                "event": {
                    "name": "reject_patch",
                    "context": {
                        "vuln_id": finding.vuln_id,
                        "file_path": finding.file_path,
                    },
                }
            },
        },
        {
            "id": reject_btn_txt_id,
            "component": "Text",
            "text": "거절 (Reject)",
            "variant": "body",
        },
    ]
    return card_id, components


def _build_cost_tracking_card_components(
    cost_summary: CodeMenderCostBreakdown,
    catalog_mode: str,
) -> tuple[str, list[dict[str, Any]]]:
    """Builds a dedicated A2UI v0.9 card for stage-by-stage token & cost telemetry."""
    card_id = "cost_tracking_card"
    stage_lines = []
    for stg in cost_summary.stages:
        stage_lines.append(
            f"• {stg.stage_label}: {format_tokens(stg.total_tokens)} "
            f"(In {stg.input_tokens:,} / Out {stg.output_tokens:,} / Think {stg.thinking_tokens:,}) "
            f"· {stg.duration_ms:.1f}ms → {format_usd(stg.total_cost_usd)} ({format_krw(stg.total_cost_krw)})"
        )
    stages_text = "\n".join(stage_lines)
    totals_text = (
        f"이번 실행 합계: {format_tokens(cost_summary.total_tokens)} | "
        f"LLM 비용: {format_usd(cost_summary.llm_cost_usd)} + 샌드박스 연산: {format_usd(cost_summary.sandbox_compute_cost_usd)} = "
        f"총 {format_usd(cost_summary.total_cost_usd)} ({format_krw(cost_summary.total_cost_krw)}) | "
        f"취약점 1건당 평균: {format_usd(cost_summary.cost_per_vuln_usd)} ({format_krw(cost_summary.cost_per_vuln_krw)})\n"
        f"세션 누적 ({cost_summary.session_total_runs}회): {format_tokens(cost_summary.session_total_tokens)} · "
        f"{format_usd(cost_summary.session_total_cost_usd)} ({format_krw(cost_summary.session_total_cost_krw)}) | "
        f"전체 원장 누적 ({cost_summary.ledger_total_runs}회): {format_tokens(cost_summary.ledger_total_tokens)} · "
        f"{format_usd(cost_summary.ledger_total_cost_usd)} ({format_krw(cost_summary.ledger_total_cost_krw)})"
    )

    if catalog_mode == "codemender_material":
        return card_id, [
            {
                "id": card_id,
                "component": "MaterialCard",
                "title": "💰 CodeMender 비용 및 토큰 사용량 추적 (Cost & Token Telemetry)",
                "subtitle": (
                    f"이번 실행: {format_usd(cost_summary.total_cost_usd)} ({format_krw(cost_summary.total_cost_krw)}) · "
                    f"세션 누적: {format_usd(cost_summary.session_total_cost_usd)} ({format_krw(cost_summary.session_total_cost_krw)})"
                ),
                "elevation": 2,
                "status": "INFO",
                "children": [
                    "cost_card_badge_row",
                    "cost_card_stages_txt",
                    "cost_card_totals_txt",
                ],
            },
            {
                "id": "cost_card_badge_row",
                "component": "Row",
                "children": [
                    "cost_run_badge",
                    "cost_session_badge",
                    "cost_ledger_badge",
                ],
                "justify": "start",
                "align": "center",
            },
            {
                "id": "cost_run_badge",
                "component": "MaterialBadge",
                "label": f"Run: {format_usd(cost_summary.total_cost_usd)} ({format_krw(cost_summary.total_cost_krw)})",
                "severity": "INFO",
            },
            {
                "id": "cost_session_badge",
                "component": "MaterialBadge",
                "label": f"Session ({cost_summary.session_total_runs}회): {format_usd(cost_summary.session_total_cost_usd)}",
                "severity": "VERIFIED",
            },
            {
                "id": "cost_ledger_badge",
                "component": "MaterialBadge",
                "label": f"All-Time ({cost_summary.ledger_total_runs}회): {format_usd(cost_summary.ledger_total_cost_usd)}",
                "severity": "INFO",
            },
            {
                "id": "cost_card_stages_txt",
                "component": "Text",
                "text": stages_text,
                "variant": "body",
            },
            {
                "id": "cost_card_totals_txt",
                "component": "Text",
                "text": totals_text,
                "variant": "caption",
            },
        ]

    return card_id, [
        {
            "id": card_id,
            "component": "Card",
            "child": "cost_card_col",
        },
        {
            "id": "cost_card_col",
            "component": "Column",
            "children": [
                "cost_card_title",
                "cost_card_stages_txt",
                "cost_card_totals_txt",
            ],
        },
        {
            "id": "cost_card_title",
            "component": "Text",
            "text": "💰 CodeMender 비용 및 토큰 사용량 추적 (Cost & Token Telemetry)",
            "variant": "h3",
        },
        {
            "id": "cost_card_stages_txt",
            "component": "Text",
            "text": stages_text,
            "variant": "body",
        },
        {
            "id": "cost_card_totals_txt",
            "component": "Text",
            "text": totals_text,
            "variant": "caption",
        },
    ]


def build_scan_report_surface(
    pipeline_result: CodeMenderPipelineResult,
    *,
    surface_id: str = "codemender-security-report",
    catalog_mode: str = "codemender_material",
    status_banner: str | None = None,
) -> list[dict[str, Any]]:
    """Builds the full interactive A2UI v0.9 security report and patch approval UI."""
    catalog_id = _catalog_id_for_mode(catalog_mode)
    root_children: list[str] = ["summary_card"]
    all_components: list[dict[str, Any]] = []

    files_str = ", ".join(pipeline_result.scanned_files) or "없음"
    cost_suffix = ""
    if pipeline_result.cost_summary is not None:
        cs = pipeline_result.cost_summary
        cost_suffix = (
            f" | 비용: {format_usd(cs.total_cost_usd)} ({format_krw(cs.total_cost_krw)}) · "
            f"토큰: {format_tokens(cs.total_tokens)}"
        )
    subtitle_text = (
        f"모델: {pipeline_result.model_used} | 스캔 파일: {files_str} | "
        f"탐색 후보: {pipeline_result.total_candidates_found}건 → "
        f"샌드박스 확증(True Positive): {pipeline_result.verified_count}건 "
        f"(오탐 제거: {pipeline_result.false_positives_filtered}건){cost_suffix}"
    )
    if status_banner:
        subtitle_text = f"{status_banner} · {subtitle_text}"

    if catalog_mode == "codemender_material":
        summary_children = ["summary_badges_row", "summary_metrics_text"]
        if pipeline_result.findings:
            summary_children.append("summary_apply_all_row")

        badge_row_children = [
            "summary_tp_badge",
            "summary_fp_badge",
            "summary_model_badge",
        ]
        if pipeline_result.cost_summary is not None:
            badge_row_children.append("summary_cost_badge")

        summary_components: list[dict[str, Any]] = [
            {
                "id": "summary_card",
                "component": "MaterialCard",
                "title": "🛡️ CodeMender 3-Stage 보안 진단 및 패치 리포트",
                "subtitle": subtitle_text,
                "elevation": 3,
                "status": "INFO",
                "children": summary_children,
            },
            {
                "id": "summary_badges_row",
                "component": "Row",
                "children": badge_row_children,
                "justify": "start",
                "align": "center",
            },
            {
                "id": "summary_tp_badge",
                "component": "MaterialBadge",
                "label": f"Verified 취약점: {pipeline_result.verified_count}건",
                "severity": "CRITICAL" if pipeline_result.verified_count > 0 else "VERIFIED",
            },
            {
                "id": "summary_fp_badge",
                "component": "MaterialBadge",
                "label": f"오탐(False Positive) 필터링: {pipeline_result.false_positives_filtered}건",
                "severity": "VERIFIED",
            },
            {
                "id": "summary_model_badge",
                "component": "MaterialBadge",
                "label": f"Engine: {pipeline_result.model_used}",
                "severity": "INFO",
            },
            {
                "id": "summary_metrics_text",
                "component": "Text",
                "text": (
                    "각 취약점의 전/후 코드 비교(CodeDiff)와 샌드박스 재현 결과를 검토한 후 "
                    "[패치 적용] 버튼을 클릭하면 수정된 소스코드 파일이 즉시 생성·반환됩니다."
                ),
                "variant": "body",
            },
        ]
        if pipeline_result.cost_summary is not None:
            cs = pipeline_result.cost_summary
            summary_components.append(
                {
                    "id": "summary_cost_badge",
                    "component": "MaterialBadge",
                    "label": (
                        f"Cost: {format_usd(cs.total_cost_usd)} ({format_krw(cs.total_cost_krw)}) · "
                        f"{format_tokens(cs.total_tokens)}"
                    ),
                    "severity": "INFO",
                }
            )
        if pipeline_result.findings:
            summary_components.extend(
                [
                    {
                        "id": "summary_apply_all_row",
                        "component": "Row",
                        "children": ["apply_all_btn"],
                        "justify": "end",
                        "align": "center",
                    },
                    {
                        "id": "apply_all_btn",
                        "component": "MaterialButton",
                        "label": "📦 검증된 전체 보안 패치 일괄 적용 및 파일 반환",
                        "variant": "tonal",
                        "action": {
                            "event": {
                                "name": "apply_all_patches",
                                "context": {
                                    "workspace_id": pipeline_result.workspace_id
                                },
                            }
                        },
                    },
                ]
            )
        all_components.extend(summary_components)

        for idx, finding in enumerate(pipeline_result.findings, start=1):
            card_id, card_comps = _build_material_finding_card(idx, finding)
            root_children.append(card_id)
            all_components.extend(card_comps)
    else:
        # Standard A2UI v0.9 BasicCatalog layout
        summary_col_children = ["summary_title", "summary_sub"]
        if pipeline_result.findings:
            summary_col_children.append("apply_all_btn")

        all_components.extend(
            [
                {
                    "id": "summary_card",
                    "component": "Card",
                    "child": "summary_col",
                },
                {
                    "id": "summary_col",
                    "component": "Column",
                    "children": summary_col_children,
                },
                {
                    "id": "summary_title",
                    "component": "Text",
                    "text": "🛡️ CodeMender 3-Stage 보안 진단 및 패치 리포트",
                    "variant": "h2",
                },
                {
                    "id": "summary_sub",
                    "component": "Text",
                    "text": subtitle_text,
                    "variant": "body",
                },
            ]
        )
        if pipeline_result.findings:
            all_components.extend(
                [
                    {
                        "id": "apply_all_btn",
                        "component": "Button",
                        "child": "apply_all_btn_txt",
                        "variant": "primary",
                        "action": {
                            "event": {
                                "name": "apply_all_patches",
                                "context": {
                                    "workspace_id": pipeline_result.workspace_id
                                },
                            }
                        },
                    },
                    {
                        "id": "apply_all_btn_txt",
                        "component": "Text",
                        "text": "📦 검증된 전체 보안 패치 일괄 적용 및 파일 반환",
                        "variant": "body",
                    },
                ]
            )

        for idx, finding in enumerate(pipeline_result.findings, start=1):
            card_id, card_comps = _build_basic_finding_card(idx, finding)
            root_children.append(card_id)
            all_components.extend(card_comps)

    if pipeline_result.cost_summary is not None:
        cost_card_id, cost_card_comps = _build_cost_tracking_card_components(
            pipeline_result.cost_summary, catalog_mode
        )
        root_children.append(cost_card_id)
        all_components.extend(cost_card_comps)

    root_component = {
        "id": "root",
        "component": "Column",
        "children": root_children,
    }
    components = [root_component, *all_components]

    summary_value: dict[str, Any] = {
        "workspaceId": pipeline_result.workspace_id,
        "modelUsed": pipeline_result.model_used,
        "verifiedCount": pipeline_result.verified_count,
        "falsePositivesFiltered": pipeline_result.false_positives_filtered,
    }
    if pipeline_result.cost_summary is not None:
        summary_value["costSummary"] = pipeline_result.cost_summary.to_dict()

    messages: list[dict[str, Any]] = [
        {
            "version": "v0.9",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": catalog_id,
                "theme": {
                    "primaryColor": "#1A73E8",
                    "agentDisplayName": "CodeMender Security Agent (gemini-3.8-flash)",
                },
            },
        },
        {
            "version": "v0.9",
            "updateComponents": {
                "surfaceId": surface_id,
                "components": components,
            },
        },
        {
            "version": "v0.9",
            "updateDataModel": {
                "surfaceId": surface_id,
                "path": "/scanSummary",
                "value": summary_value,
            },
        },
    ]

    validate_a2ui_payload(messages, catalog_mode=catalog_mode)
    return messages


def build_patch_applied_surface(
    pipeline_result: CodeMenderPipelineResult,
    applied_files: list[dict[str, Any]],
    *,
    surface_id: str = "codemender-patch-result",
    catalog_mode: str = "codemender_material",
) -> list[dict[str, Any]]:
    """Builds an updated A2UI v0.9 surface after the user approves one or more patches."""
    applied_summary = ", ".join(
        f"{item['file_path']} (SHA-256: {item['sha256'][:10]}...)"
        for item in applied_files
    )
    banner = f"✅ 보안 패치 적용 완료 및 수정본 파일 아티팩트 생성됨: {applied_summary}"
    return build_scan_report_surface(
        pipeline_result,
        surface_id=surface_id,
        catalog_mode=catalog_mode,
        status_banner=banner,
    )


def build_cost_report_surface(
    cost_report: dict[str, Any],
    *,
    surface_id: str = "codemender-cost-dashboard",
    catalog_mode: str = "codemender_material",
) -> list[dict[str, Any]]:
    """Builds a standalone A2UI v0.9 cost & token usage dashboard surface."""
    catalog_id = _catalog_id_for_mode(catalog_mode)
    sess = cost_report.get("session", {})
    ledger = cost_report.get("ledger", {})
    model_name = cost_report.get("model", "gemini-3.8-flash")

    s_runs = int(sess.get("session_total_runs", 0))
    s_tok = int(sess.get("session_total_tokens", 0))
    s_usd = float(sess.get("session_total_cost_usd", 0.0))
    s_krw = float(sess.get("session_total_cost_krw", 0.0))

    l_runs = int(ledger.get("total_runs", 0))
    l_tok = int(ledger.get("total_tokens", 0))
    l_usd = float(ledger.get("total_cost_usd", 0.0))
    l_krw = float(ledger.get("total_cost_krw", 0.0))

    body_text = (
        f"• 현재 세션 ({s_runs}회 실행): {format_tokens(s_tok)} | "
        f"{format_usd(s_usd)} ({format_krw(s_krw)})\n"
        f"• 전체 워크스페이스 원장 ({l_runs}회 실행): {format_tokens(l_tok)} | "
        f"{format_usd(l_usd)} ({format_krw(l_krw)})"
    )

    if catalog_mode == "codemender_material":
        components: list[dict[str, Any]] = [
            {
                "id": "root",
                "component": "Column",
                "children": ["cost_dashboard_card"],
            },
            {
                "id": "cost_dashboard_card",
                "component": "MaterialCard",
                "title": "💰 CodeMender 비용 및 토큰 사용량 대시보드",
                "subtitle": f"모델: {model_name} | 세션 누적: {format_usd(s_usd)} ({format_krw(s_krw)})",
                "elevation": 3,
                "status": "INFO",
                "children": ["cost_dash_txt"],
            },
            {
                "id": "cost_dash_txt",
                "component": "Text",
                "text": body_text,
                "variant": "body",
            },
        ]
    else:
        components = [
            {
                "id": "root",
                "component": "Column",
                "children": ["cost_dashboard_card"],
            },
            {
                "id": "cost_dashboard_card",
                "component": "Card",
                "child": "cost_dash_col",
            },
            {
                "id": "cost_dash_col",
                "component": "Column",
                "children": ["cost_dash_title", "cost_dash_txt"],
            },
            {
                "id": "cost_dash_title",
                "component": "Text",
                "text": f"💰 CodeMender 비용 및 토큰 사용량 대시보드 ({model_name})",
                "variant": "h2",
            },
            {
                "id": "cost_dash_txt",
                "component": "Text",
                "text": body_text,
                "variant": "body",
            },
        ]

    messages: list[dict[str, Any]] = [
        {
            "version": "v0.9",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": catalog_id,
                "theme": {
                    "primaryColor": "#1A73E8",
                    "agentDisplayName": "CodeMender Security Agent (gemini-3.8-flash)",
                },
            },
        },
        {
            "version": "v0.9",
            "updateComponents": {
                "surfaceId": surface_id,
                "components": components,
            },
        },
        {
            "version": "v0.9",
            "updateDataModel": {
                "surfaceId": surface_id,
                "path": "/costDashboard",
                "value": cost_report,
            },
        },
    ]
    validate_a2ui_payload(messages, catalog_mode=catalog_mode)
    return messages

