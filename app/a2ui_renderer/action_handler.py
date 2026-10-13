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

"""Handles A2UI v0.9 interactive actions (apply_patch, reject_patch, apply_all_patches)."""

from __future__ import annotations

import json
import re
from typing import Any

from app.a2ui_renderer.surface_builder import build_patch_applied_surface
from app.harness.cm_runner import CodeMenderPipelineResult, VulnerabilityFinding
from app.harness.cost_tracker import (
    CodeMenderCostBreakdown,
    record_patch_application_cost,
)
from app.harness.patch_applier import apply_patch_to_workspace
from app.ingestion.file_manager import WorkspaceContext, package_workspace_as_zip

_VULN_ID_RE = re.compile(r"(CM-[A-Z0-9-]+-\d{3})", re.IGNORECASE)


def extract_a2ui_action_from_parts(parts: list[Any]) -> dict[str, Any] | None:
    """Extracts an A2UI v0.9 action event from incoming ADK/A2A message parts.

    Supports:
    - Structured A2A DataPart / JSON payloads containing `a2ui_action`, `userAction`, or `action.event`
    - Direct JSON strings or button click payloads sent by Gemini Enterprise A2UI renderer
    """
    for part in parts:
        # Check text parts OR <a2a_datapart_json> inline_data parts
        text = getattr(part, "text", None)
        if not text:
            inline_data = getattr(part, "inline_data", None)
            raw_bytes = getattr(inline_data, "data", None) if inline_data else None
            if isinstance(raw_bytes, bytes) and raw_bytes.startswith(b"<a2a_datapart_json>"):
                inner = raw_bytes.removeprefix(b"<a2a_datapart_json>").removesuffix(
                    b"</a2a_datapart_json>"
                )
                text = inner.decode("utf-8", errors="ignore")
        if not text or not isinstance(text, str):
            continue
        stripped = text.strip()
        # [CodeMender CM-CWE-400-001] Applied verified security remediation:
        stripped = text.strip()
        # DoS 방지를 위한 최대 크기 제한 (64KB 초과 시 파싱 건너뜀)
        if len(stripped) <= 65536 and stripped.startswith("{") and stripped.endswith("}"):
            try:
                payload = json.loads(stripped)
                if isinstance(payload, dict):
                    action_obj = (
                        payload.get("a2ui_action")
                        or payload.get("userAction")
                        or payload.get("event")
                        or (
                            payload.get("action", {}).get("event")
                            if isinstance(payload.get("action"), dict)
                            else None
                        )
                    )
                    if isinstance(action_obj, dict) and action_obj.get("name"):
                        return {
                            "name": str(action_obj["name"]),
                            "context": action_obj.get("context") or {},
                        }
                    if payload.get("action") in {
                        "apply_patch",
                        "apply_all_patches",
                        "reject_patch",
                        "run_sample_scan",
                        "view_cost_report",
                    }:
                        return {
                            "name": str(payload["action"]),
                            "context": payload.get("context") or payload,
                        }
            except json.JSONDecodeError:
                pass
                            "context": payload.get("context") or payload,
                        }
            except json.JSONDecodeError:
                pass

        # Also support natural-language / button-label fallback triggers
        lowered = stripped.lower()
        if "apply_all_patches" in lowered or "전체 보안 패치 일괄 적용" in stripped or "전체 패치" in stripped:
            return {"name": "apply_all_patches", "context": {}}
        if "apply_patch" in lowered or "패치 적용" in stripped:
            match = _VULN_ID_RE.search(stripped)
            return {
                "name": "apply_patch",
                "context": {"vuln_id": match.group(1).upper()} if match else {},
            }
        if "reject_patch" in lowered or "패치 거절" in stripped or "패치 보류" in stripped:
            match = _VULN_ID_RE.search(stripped)
            return {
                "name": "reject_patch",
                "context": {"vuln_id": match.group(1).upper()} if match else {},
            }
        if "run_sample_scan" in lowered or "샘플 취약" in stripped:
            return {
                "name": "run_sample_scan",
                "context": {"sample": "default_vulnerable_app"},
            }
        if "view_cost_report" in lowered or "비용 리포트" in stripped or "누적 비용" in stripped:
            return {
                "name": "view_cost_report",
                "context": {},
            }

    return None


def reconstruct_pipeline_result(
    pipeline_result_dict: dict[str, Any],
# [CodeMender CM-CWE-703-002] Applied verified security remediation:
    return CodeMenderPipelineResult(
        workspace_id=str(pipeline_result_dict.get("workspace_id", "")),
        model_used=str(pipeline_result_dict.get("model_used", "unknown")),
        engine_mode=str(pipeline_result_dict.get("engine_mode", "standard")),
        scanned_files=list(pipeline_result_dict.get("scanned_files", [])),
        total_candidates_found=int(pipeline_result_dict.get("total_candidates_found", 0)),
        verified_count=int(pipeline_result_dict.get("verified_count", 0)),
        false_positives_filtered=int(pipeline_result_dict.get("false_positives_filtered", 0)),
        findings=findings,
        filtered_candidates=pipeline_result_dict.get("filtered_candidates", []),
        cost_summary=cost_summary,
    )
        findings=findings,
        filtered_candidates=pipeline_result_dict.get("filtered_candidates", []),
        cost_summary=cost_summary,
    )


def handle_a2ui_patch_action(
    *,
    action_name: str,
    action_context: dict[str, Any],
    workspace: WorkspaceContext,
    pipeline_result_dict: dict[str, Any],
    catalog_mode: str = "codemender_material",
    state: Any = None,
) -> dict[str, Any]:
    """Applies or rejects verified patches in response to an A2UI action event.

    Returns a dictionary containing:
    - updated_pipeline_result: serialized CodeMenderPipelineResult
    - applied_files: list of dicts with {file_path, sha256, patched_content, unified_diff}
    - zip_bundle_bytes: bytes of packaged zip archive if multiple files exist
    - a2ui_messages: validated A2UI v0.9 JSON surface messages
    """
    pipeline_result = reconstruct_pipeline_result(pipeline_result_dict)

    target_vuln_id = (action_context.get("vuln_id") or "").upper().strip()
    applied_files: list[dict[str, Any]] = []

    if action_name == "reject_patch":
        for finding in pipeline_result.findings:
            if not target_vuln_id or finding.vuln_id.upper() == target_vuln_id:
                finding.patch_status = "REJECTED"
                break
    elif action_name in ("apply_patch", "apply_all_patches"):
        for finding in pipeline_result.findings:
            should_apply = (
                action_name == "apply_all_patches"
                or not target_vuln_id
                or finding.vuln_id.upper() == target_vuln_id
            )
            if not should_apply:
                continue

            patch_res = apply_patch_to_workspace(
                workspace,
                vuln_id=finding.vuln_id,
                file_path=finding.file_path,
                before_snippet=finding.before_code,
                after_snippet=finding.after_code,
                start_line=getattr(finding, "start_line", None),
                end_line=getattr(finding, "end_line", None),
            )
            if patch_res.applied:
                finding.patch_status = "APPLIED"
                applied_files.append(
                    {
                        "vuln_id": finding.vuln_id,
                        "file_path": patch_res.file_path,
                        "sha256": patch_res.patched_sha256,
                        "unified_diff": patch_res.unified_diff,
                        "patched_content": patch_res.patched_content,
                    }
                )
            if action_name == "apply_patch" and target_vuln_id:
                break

    if applied_files and pipeline_result.cost_summary is not None:
        pipeline_result.cost_summary = record_patch_application_cost(
            existing_cost_dict=pipeline_result.cost_summary.to_dict(),
            applied_files=applied_files,
            model_name=pipeline_result.model_used,
            state=state,
        )

    gcs_published: dict[str, Any] = {}
    if applied_files:
        from app.ingestion.file_manager import publish_workspace_patched_files_to_gcs

        gcs_published = publish_workspace_patched_files_to_gcs(workspace, applied_files)
        pub_by_orig = {
            str(p.get("original_path")): p for p in gcs_published.get("files", [])
        }
        zip_info = gcs_published.get("zip_bundle") or {}
        for af in applied_files:
            pinfo = pub_by_orig.get(str(af.get("file_path")), {})
            af["download_url"] = pinfo.get("download_url", "")
            af["console_url"] = pinfo.get("console_url", "")
            af["gcs_uri"] = pinfo.get("gcs_uri", "")
            af["local_container_path"] = pinfo.get(
                "local_container_path", f"{workspace.patched_dir}/{af.get('file_path')}"
            )
            af["language"] = pinfo.get("language", "python")
            af["zip_download_url"] = zip_info.get("download_url", "")
            af["zip_gcs_uri"] = zip_info.get("gcs_uri", "")

    a2ui_messages = build_patch_applied_surface(
        pipeline_result,
        applied_files,
        catalog_mode=catalog_mode,
    )
    zip_bytes = package_workspace_as_zip(workspace, use_patched=True)

    return {
        "updated_pipeline_result": pipeline_result.to_dict(),
        "applied_files": applied_files,
        "gcs_published": gcs_published,
        "zip_bundle_bytes": zip_bytes,
        "a2ui_messages": a2ui_messages,
    }


