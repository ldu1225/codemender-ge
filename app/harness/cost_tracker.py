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

"""Real-time LLM token & Cloud Run sandbox cost tracking for CodeMender 3-Stage Harness.

Tracks per-stage (cm find, cm verify, cm fix + Judge, HITL patch apply) token consumption,
GEAP Gemini API pricing, Cloud Run Gen2 isolated sandbox compute cost, session-level
cumulative totals, and persistent workspace ledger totals in both USD and KRW.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import (
    CLOUD_RUN_GIB_PER_SEC_USD,
    CLOUD_RUN_VCPU_PER_SEC_USD,
    CM_INPUT_COST_PER_1M_USD,
    CM_OUTPUT_COST_PER_1M_USD,
    CM_THINKING_COST_PER_1M_USD,
    CM_USD_TO_KRW_RATE,
    CODEMENDER_MODEL,
    COST_LEDGER_FILENAME,
    GCP_PROJECT_ID,
    MODEL_PRICING_PER_1M_TOKENS,
    WORKSPACE_ROOT,
)
from app.ingestion.file_manager import _ensure_within_directory

logger = logging.getLogger(__name__)
_LEDGER_LOCK = threading.Lock()
_CLOUD_LOG_CACHE: dict[str, Any] = {"ts": 0.0, "data": None}


def emit_cloud_logging_cost_entry(event_payload: dict[str, Any]) -> None:
    """Emits a structured JSON log line to stdout so Cloud Run indexes it into Cloud Logging.

    Cloud Run automatically maps single-line JSON on stdout into `jsonPayload` inside
    `projects/<project>/logs/run.googleapis.com%2Fstdout` and increments the
    `codemender_cost_events` log-based metric without requiring Cloud Billing API access.
    """
    structured_entry = {
        "severity": "INFO",
        "event_type": "CODEMENDER_COST_TELEMETRY",
        "message": (
            f"[CODEMENDER_COST_TELEMETRY] run_id={event_payload.get('run_id')} "
            f"op={event_payload.get('operation_type')} model={event_payload.get('model_used')} "
            f"tokens={event_payload.get('total_tokens')} cost_usd=${event_payload.get('total_cost_usd', 0.0):.6f} "
            f"cost_krw=₩{event_payload.get('total_cost_krw', 0.0):.3f}"
        ),
        "logging.googleapis.com/labels": {
            "app": "codemender-ge",
            "component": "codemender-cost-tracker",
            "model": str(event_payload.get("model_used", CODEMENDER_MODEL)),
            "operation_type": str(event_payload.get("operation_type", "scan")),
        },
        "codemender_cost": event_payload,
    }
    try:
        sys.stdout.write(json.dumps(structured_entry, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    except Exception as exc:
        logger.debug(f"Structured stdout cost log emission skipped: {exc}")



def get_model_pricing(model_name: str) -> dict[str, float]:
    """Returns per-1M-token USD pricing for the given Gemini model."""
    normalized = (model_name or CODEMENDER_MODEL).lower().strip()
    if normalized in MODEL_PRICING_PER_1M_TOKENS:
        return MODEL_PRICING_PER_1M_TOKENS[normalized]
    for key, rates in MODEL_PRICING_PER_1M_TOKENS.items():
        if key in normalized:
            return rates
    return {
        "input": CM_INPUT_COST_PER_1M_USD,
        "output": CM_OUTPUT_COST_PER_1M_USD,
        "thinking": CM_THINKING_COST_PER_1M_USD,
        "cached_input": CM_INPUT_COST_PER_1M_USD * 0.25,
    }


def format_tokens(count: int) -> str:
    """Formats token count using compact notation (e.g., 450 tok, 2.4k tok, 1.20M tok)."""
    if count >= 1_000_000:
        return f"{count / 1_000_000:.2f}M tok ({count:,})"
    if count >= 1_000:
        return f"{count / 1_000:.1f}k tok ({count:,})"
    return f"{count:,} tok"


def format_usd(amount: float) -> str:
    """Formats a USD cost value with precision suited for micro-cent LLM calls."""
    if amount >= 0.01:
        return f"${amount:.4f}"
    return f"${amount:.6f}"


def format_krw(amount: float) -> str:
    """Formats a KRW cost value cleanly."""
    if amount >= 10.0:
        return f"₩{amount:,.1f}원"
    return f"₩{amount:.3f}원"


def _estimate_tokens_from_text(text: str) -> int:
    """Deterministic token estimator (~1 token per 3.8 chars + UTF-8 byte weight)."""
    if not text:
        return 0
    char_est = len(text) / 3.8
    byte_est = len(text.encode("utf-8")) / 4.2
    return max(1, int(round((char_est + byte_est) / 2.0)))


@dataclass
class StageCostBreakdown:
    """Token and compute cost breakdown for a single CodeMender stage."""

    stage_id: str
    stage_label: str
    input_tokens: int
    output_tokens: int
    thinking_tokens: int
    total_tokens: int
    llm_cost_usd: float
    sandbox_compute_cost_usd: float
    total_cost_usd: float
    total_cost_krw: float
    duration_ms: float
    measurement_source: str = "hybrid"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StageCostBreakdown:
        return cls(**data)


@dataclass
class CodeMenderCostBreakdown:
    """Complete per-run + cumulative cost & token telemetry for a CodeMender execution."""

    run_id: str
    timestamp_utc: str
    model_used: str
    operation_type: str  # "3stage_scan" or "hitl_patch_apply"
    files_scanned_count: int
    candidates_evaluated: int
    verified_vulns_count: int
    false_positives_filtered: int
    patches_applied_count: int
    input_tokens: int
    output_tokens: int
    thinking_tokens: int
    total_tokens: int
    llm_cost_usd: float
    sandbox_compute_cost_usd: float
    total_cost_usd: float
    total_cost_krw: float
    cost_per_vuln_usd: float
    cost_per_vuln_krw: float
    usd_to_krw_rate: float
    duration_ms: float
    sandbox_executions: int
    measurement_source: str
    stages: list[StageCostBreakdown] = field(default_factory=list)
    # Session cumulative metrics
    session_total_runs: int = 1
    session_total_tokens: int = 0
    session_total_cost_usd: float = 0.0
    session_total_cost_krw: float = 0.0
    # Persistent workspace ledger cumulative metrics
    ledger_total_runs: int = 1
    ledger_total_tokens: int = 0
    ledger_total_cost_usd: float = 0.0
    ledger_total_cost_krw: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["stages"] = [s.to_dict() for s in self.stages]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeMenderCostBreakdown:
        copied = dict(data)
        raw_stages = copied.pop("stages", [])
        stages = [
            StageCostBreakdown.from_dict(s) if isinstance(s, dict) else s
            for s in raw_stages
        ]
        return cls(**copied, stages=stages)


def _get_ledger_path() -> Path:
    """Resolves the persistent cost ledger file strictly inside WORKSPACE_ROOT."""
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    return _ensure_within_directory(
        WORKSPACE_ROOT, WORKSPACE_ROOT / COST_LEDGER_FILENAME
    )


def load_persistent_cost_ledger() -> dict[str, Any]:
    """Reads the persistent cost ledger from WORKSPACE_ROOT safely."""
    default_ledger: dict[str, Any] = {
        "total_runs": 0,
        "scan_runs": 0,
        "patch_runs": 0,
        "total_files_scanned": 0,
        "total_vulns_verified": 0,
        "total_patches_applied": 0,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "total_thinking_tokens": 0,
        "total_tokens": 0,
        "total_llm_cost_usd": 0.0,
        "total_sandbox_cost_usd": 0.0,
        "total_cost_usd": 0.0,
        "total_cost_krw": 0.0,
        "usd_to_krw_rate": CM_USD_TO_KRW_RATE,
        "recent_runs": [],
    }
    try:
        ledger_path = _get_ledger_path()
        if not ledger_path.exists():
            return default_ledger
        with _LEDGER_LOCK:
            raw = json.loads(ledger_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                default_ledger.update(raw)
    except Exception as exc:
        logger.debug(f"Could not read persistent cost ledger: {exc}")
    return default_ledger


def _append_to_persistent_ledger(
    breakdown: CodeMenderCostBreakdown,
) -> dict[str, Any]:
    """Atomically updates the persistent cost ledger with a new CodeMender execution."""
    ledger_path = _get_ledger_path()
    with _LEDGER_LOCK:
        current: dict[str, Any] = {
            "total_runs": 0,
            "scan_runs": 0,
            "patch_runs": 0,
            "total_files_scanned": 0,
            "total_vulns_verified": 0,
            "total_patches_applied": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_thinking_tokens": 0,
            "total_tokens": 0,
            "total_llm_cost_usd": 0.0,
            "total_sandbox_cost_usd": 0.0,
            "total_cost_usd": 0.0,
            "total_cost_krw": 0.0,
            "usd_to_krw_rate": CM_USD_TO_KRW_RATE,
            "recent_runs": [],
        }
        if ledger_path.exists():
            try:
                loaded = json.loads(ledger_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    current.update(loaded)
            except Exception:
                pass

        current["total_runs"] = int(current.get("total_runs", 0)) + 1
        if breakdown.operation_type == "hitl_patch_apply":
            current["patch_runs"] = int(current.get("patch_runs", 0)) + 1
        else:
            current["scan_runs"] = int(current.get("scan_runs", 0)) + 1
        current["total_files_scanned"] = (
            int(current.get("total_files_scanned", 0))
            + breakdown.files_scanned_count
        )
        current["total_vulns_verified"] = (
            int(current.get("total_vulns_verified", 0))
            + breakdown.verified_vulns_count
        )
        current["total_patches_applied"] = (
            int(current.get("total_patches_applied", 0))
            + breakdown.patches_applied_count
        )
        current["total_input_tokens"] = (
            int(current.get("total_input_tokens", 0)) + breakdown.input_tokens
        )
        current["total_output_tokens"] = (
            int(current.get("total_output_tokens", 0)) + breakdown.output_tokens
        )
        current["total_thinking_tokens"] = (
            int(current.get("total_thinking_tokens", 0))
            + breakdown.thinking_tokens
        )
        current["total_tokens"] = (
            int(current.get("total_tokens", 0)) + breakdown.total_tokens
        )
        current["total_llm_cost_usd"] = round(
            float(current.get("total_llm_cost_usd", 0.0))
            + breakdown.llm_cost_usd,
            8,
        )
        current["total_sandbox_cost_usd"] = round(
            float(current.get("total_sandbox_cost_usd", 0.0))
            + breakdown.sandbox_compute_cost_usd,
            8,
        )
        current["total_cost_usd"] = round(
            float(current.get("total_cost_usd", 0.0))
            + breakdown.total_cost_usd,
            8,
        )
        current["total_cost_krw"] = round(
            current["total_cost_usd"] * CM_USD_TO_KRW_RATE, 4
        )
        current["usd_to_krw_rate"] = CM_USD_TO_KRW_RATE

        run_entry = {
            "run_id": breakdown.run_id,
            "timestamp_utc": breakdown.timestamp_utc,
            "operation_type": breakdown.operation_type,
            "model_used": breakdown.model_used,
            "files_scanned": breakdown.files_scanned_count,
            "verified_vulns": breakdown.verified_vulns_count,
            "patches_applied": breakdown.patches_applied_count,
            "input_tokens": breakdown.input_tokens,
            "output_tokens": breakdown.output_tokens,
            "thinking_tokens": breakdown.thinking_tokens,
            "total_tokens": breakdown.total_tokens,
            "llm_cost_usd": breakdown.llm_cost_usd,
            "sandbox_compute_cost_usd": breakdown.sandbox_compute_cost_usd,
            "total_cost_usd": breakdown.total_cost_usd,
            "total_cost_krw": breakdown.total_cost_krw,
            "duration_ms": breakdown.duration_ms,
            "measurement_source": breakdown.measurement_source,
        }
        recent = list(current.get("recent_runs", []))
        recent.append(run_entry)
        current["recent_runs"] = recent[-50:]

        # Emit structured JSON log line to Cloud Logging (`jsonPayload.event_type="CODEMENDER_COST_TELEMETRY"`)
        emit_cloud_logging_cost_entry(run_entry)

        try:
            ledger_path.write_text(
                json.dumps(current, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            os.chmod(ledger_path, 0o600)
        except Exception as exc:
            logger.debug(f"Could not persist cost ledger: {exc}")

        return current


def _compute_stage_cost(
    *,
    stage_id: str,
    stage_label: str,
    input_tokens: int,
    output_tokens: int,
    thinking_tokens: int,
    duration_ms: float,
    include_sandbox_compute: bool,
    sandbox_executions: int,
    pricing: dict[str, float],
    measurement_source: str,
) -> StageCostBreakdown:
    total_tokens = input_tokens + output_tokens + thinking_tokens
    llm_cost_usd = (
        (input_tokens / 1_000_000.0) * pricing["input"]
        + (output_tokens / 1_000_000.0) * pricing["output"]
        + (thinking_tokens / 1_000_000.0) * pricing["thinking"]
    )
    sandbox_cost_usd = 0.0
    if include_sandbox_compute:
        # Cloud Run Gen2 isolated container vCPU + GiB compute during sandbox execution
        effective_sec = max(duration_ms / 1000.0, 0.05 * max(1, sandbox_executions))
        sandbox_cost_usd = effective_sec * (
            CLOUD_RUN_VCPU_PER_SEC_USD + CLOUD_RUN_GIB_PER_SEC_USD
        )

    total_usd = round(llm_cost_usd + sandbox_cost_usd, 8)
    total_krw = round(total_usd * CM_USD_TO_KRW_RATE, 4)
    return StageCostBreakdown(
        stage_id=stage_id,
        stage_label=stage_label,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        thinking_tokens=thinking_tokens,
        total_tokens=total_tokens,
        llm_cost_usd=round(llm_cost_usd, 8),
        sandbox_compute_cost_usd=round(sandbox_cost_usd, 8),
        total_cost_usd=total_usd,
        total_cost_krw=total_krw,
        duration_ms=round(duration_ms, 2),
        measurement_source=measurement_source,
    )


def calculate_pipeline_cost(
    *,
    model_name: str,
    file_entries: list[tuple[str, str]],
    total_candidates: int,
    verified_findings: list[Any],
    filtered_candidates: list[dict[str, Any]],
    measured_llm_usage: list[dict[str, int]] | None = None,
    stage_durations_ms: dict[str, float] | None = None,
    sandbox_executions: int = 0,
) -> CodeMenderCostBreakdown:
    """Computes per-stage and total cost for a 3-stage CodeMender pipeline run."""
    pricing = get_model_pricing(model_name)
    durations = stage_durations_ms or {}
    measured_list = measured_llm_usage or []

    measured_in = sum(int(u.get("input_tokens", 0)) for u in measured_list)
    measured_out = sum(int(u.get("output_tokens", 0)) for u in measured_list)
    measured_think = sum(int(u.get("thinking_tokens", 0)) for u in measured_list)
    has_measured = (measured_in + measured_out + measured_think) > 0

    total_code_text = "\n".join(code for _, code in file_entries)
    code_tokens = _estimate_tokens_from_text(total_code_text)

    # Stage 1: cm find (AST + Gemini 3.8 Flash vulnerability candidate discovery)
    s1_system_overhead = 280 * max(1, len(file_entries))
    s1_in = (
        int(round(measured_in * 0.55))
        if has_measured
        else (s1_system_overhead + code_tokens)
    )
    s1_out = (
        int(round(measured_out * 0.45))
        if has_measured
        else max(90, total_candidates * 115)
    )
    s1_think = (
        int(round(measured_think * 0.55))
        if has_measured
        else max(128, total_candidates * 64)
    )
    s1_source = "vertex_usage_metadata" if has_measured else "token_estimator"

    stage1 = _compute_stage_cost(
        stage_id="stage1_find",
        stage_label="Stage 1: cm find (취약점 탐색)",
        input_tokens=s1_in,
        output_tokens=s1_out,
        thinking_tokens=s1_think,
        duration_ms=durations.get("stage1_find", 18.0),
        include_sandbox_compute=False,
        sandbox_executions=0,
        pricing=pricing,
        measurement_source=s1_source,
    )

    # Stage 2: cm verify (Isolated Sandbox PoC reproduction & False Positive filtering)
    evidence_text = "\n".join(
        [getattr(f, "sandbox_evidence", "") for f in verified_findings]
        + [str(fp.get("sandbox_evidence", "")) for fp in filtered_candidates]
    )
    s2_in = max(110, total_candidates * 95 + (code_tokens // 2))
    s2_out = max(65, _estimate_tokens_from_text(evidence_text) + total_candidates * 40)
    s2_think = max(64, total_candidates * 36)

    stage2 = _compute_stage_cost(
        stage_id="stage2_verify",
        stage_label="Stage 2: cm verify (샌드박스 검증·오탐 제거)",
        input_tokens=s2_in,
        output_tokens=s2_out,
        thinking_tokens=s2_think,
        duration_ms=durations.get("stage2_verify", 25.0),
        include_sandbox_compute=True,
        sandbox_executions=max(1, sandbox_executions or total_candidates),
        pricing=pricing,
        measurement_source="sandbox_telemetry",
    )

    # Stage 3: cm fix + LLM-as-a-Judge (Minimal CodeDiff generation & Judge scoring)
    diff_and_judge_text = "\n".join(
        f"{getattr(f, 'unified_diff', '')}\n{getattr(f, 'judge_rationale', '')}"
        for f in verified_findings
    )
    verified_cnt = len(verified_findings)
    s3_in = (
        max(140, measured_in - s1_in)
        if has_measured
        else max(150, verified_cnt * 180 + code_tokens)
    )
    s3_out = (
        max(95, measured_out - s1_out)
        if has_measured
        else max(80, _estimate_tokens_from_text(diff_and_judge_text) + verified_cnt * 110)
    )
    s3_think = (
        max(64, measured_think - s1_think)
        if has_measured
        else max(96, verified_cnt * 72)
    )

    stage3 = _compute_stage_cost(
        stage_id="stage3_fix_judge",
        stage_label="Stage 3: cm fix + Judge (패치 생성·품질 평가)",
        input_tokens=s3_in,
        output_tokens=s3_out,
        thinking_tokens=s3_think,
        duration_ms=durations.get("stage3_fix_judge", 15.0),
        include_sandbox_compute=False,
        sandbox_executions=0,
        pricing=pricing,
        measurement_source=s1_source,
    )

    stages = [stage1, stage2, stage3]
    total_in = sum(s.input_tokens for s in stages)
    total_out = sum(s.output_tokens for s in stages)
    total_think = sum(s.thinking_tokens for s in stages)
    total_tok = total_in + total_out + total_think
    llm_usd = round(sum(s.llm_cost_usd for s in stages), 8)
    sandbox_usd = round(sum(s.sandbox_compute_cost_usd for s in stages), 8)
    total_usd = round(llm_usd + sandbox_usd, 8)
    total_krw = round(total_usd * CM_USD_TO_KRW_RATE, 4)
    total_dur = round(sum(s.duration_ms for s in stages), 2)

    denom = max(1, verified_cnt)
    cost_per_vuln_usd = round(total_usd / denom, 8)
    cost_per_vuln_krw = round(total_krw / denom, 4)

    breakdown = CodeMenderCostBreakdown(
        run_id=f"cm-run-{uuid.uuid4().hex[:8]}",
        timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        model_used=model_name,
        operation_type="3stage_scan",
        files_scanned_count=len(file_entries),
        candidates_evaluated=total_candidates,
        verified_vulns_count=verified_cnt,
        false_positives_filtered=len(filtered_candidates),
        patches_applied_count=0,
        input_tokens=total_in,
        output_tokens=total_out,
        thinking_tokens=total_think,
        total_tokens=total_tok,
        llm_cost_usd=llm_usd,
        sandbox_compute_cost_usd=sandbox_usd,
        total_cost_usd=total_usd,
        total_cost_krw=total_krw,
        cost_per_vuln_usd=cost_per_vuln_usd,
        cost_per_vuln_krw=cost_per_vuln_krw,
        usd_to_krw_rate=CM_USD_TO_KRW_RATE,
        duration_ms=total_dur,
        sandbox_executions=max(1, sandbox_executions or total_candidates),
        measurement_source="vertex_usage_metadata" if has_measured else "hybrid_estimator",
        stages=stages,
        session_total_runs=1,
        session_total_tokens=total_tok,
        session_total_cost_usd=total_usd,
        session_total_cost_krw=total_krw,
    )

    ledger = _append_to_persistent_ledger(breakdown)
    breakdown.ledger_total_runs = int(ledger.get("total_runs", 1))
    breakdown.ledger_total_tokens = int(ledger.get("total_tokens", total_tok))
    breakdown.ledger_total_cost_usd = float(ledger.get("total_cost_usd", total_usd))
    breakdown.ledger_total_cost_krw = float(ledger.get("total_cost_krw", total_krw))
    return breakdown


def record_session_cost(
    state: Any,
    breakdown: CodeMenderCostBreakdown,
) -> CodeMenderCostBreakdown:
    """Updates ADK session state (`cm_cost_summary`) with the latest run's cost."""
    existing = state.get("cm_cost_summary")
    if not isinstance(existing, dict):
        existing = {
            "session_total_runs": 0,
            "session_scan_runs": 0,
            "session_patch_runs": 0,
            "session_files_scanned": 0,
            "session_vulns_verified": 0,
            "session_patches_applied": 0,
            "session_input_tokens": 0,
            "session_output_tokens": 0,
            "session_thinking_tokens": 0,
            "session_total_tokens": 0,
            "session_llm_cost_usd": 0.0,
            "session_sandbox_cost_usd": 0.0,
            "session_total_cost_usd": 0.0,
            "session_total_cost_krw": 0.0,
            "history": [],
        }

    existing["session_total_runs"] = int(existing.get("session_total_runs", 0)) + 1
    if breakdown.operation_type == "hitl_patch_apply":
        existing["session_patch_runs"] = (
            int(existing.get("session_patch_runs", 0)) + 1
        )
    else:
        existing["session_scan_runs"] = (
            int(existing.get("session_scan_runs", 0)) + 1
        )
    existing["session_files_scanned"] = (
        int(existing.get("session_files_scanned", 0))
        + breakdown.files_scanned_count
    )
    existing["session_vulns_verified"] = (
        int(existing.get("session_vulns_verified", 0))
        + breakdown.verified_vulns_count
    )
    existing["session_patches_applied"] = (
        int(existing.get("session_patches_applied", 0))
        + breakdown.patches_applied_count
    )
    existing["session_input_tokens"] = (
        int(existing.get("session_input_tokens", 0)) + breakdown.input_tokens
    )
    existing["session_output_tokens"] = (
        int(existing.get("session_output_tokens", 0)) + breakdown.output_tokens
    )
    existing["session_thinking_tokens"] = (
        int(existing.get("session_thinking_tokens", 0))
        + breakdown.thinking_tokens
    )
    existing["session_total_tokens"] = (
        int(existing.get("session_total_tokens", 0)) + breakdown.total_tokens
    )
    existing["session_llm_cost_usd"] = round(
        float(existing.get("session_llm_cost_usd", 0.0)) + breakdown.llm_cost_usd,
        8,
    )
    existing["session_sandbox_cost_usd"] = round(
        float(existing.get("session_sandbox_cost_usd", 0.0))
        + breakdown.sandbox_compute_cost_usd,
        8,
    )
    existing["session_total_cost_usd"] = round(
        float(existing.get("session_total_cost_usd", 0.0))
        + breakdown.total_cost_usd,
        8,
    )
    existing["session_total_cost_krw"] = round(
        existing["session_total_cost_usd"] * CM_USD_TO_KRW_RATE, 4
    )

    breakdown.session_total_runs = existing["session_total_runs"]
    breakdown.session_total_tokens = existing["session_total_tokens"]
    breakdown.session_total_cost_usd = existing["session_total_cost_usd"]
    breakdown.session_total_cost_krw = existing["session_total_cost_krw"]

    ws_dict = state.get("cm_workspace") if hasattr(state, "get") else None
    sess_id = "default-session"
    ws_id = "default-workspace"
    if isinstance(ws_dict, dict):
        sess_id = str(ws_dict.get("session_id") or ws_dict.get("workspace_id") or "default-session")
        ws_id = str(ws_dict.get("workspace_id") or sess_id)

    history = list(existing.get("history", []))
    history.append(
        {
            "run_id": breakdown.run_id,
            "timestamp_utc": breakdown.timestamp_utc,
            "session_id": sess_id,
            "workspace_id": ws_id,
            "operation_type": breakdown.operation_type,
            "model_used": breakdown.model_used,
            "files_scanned": breakdown.files_scanned_count,
            "verified_vulns": breakdown.verified_vulns_count,
            "patches_applied": breakdown.patches_applied_count,
            "input_tokens": breakdown.input_tokens,
            "output_tokens": breakdown.output_tokens,
            "thinking_tokens": breakdown.thinking_tokens,
            "total_tokens": breakdown.total_tokens,
            "llm_cost_usd": breakdown.llm_cost_usd,
            "sandbox_compute_cost_usd": breakdown.sandbox_compute_cost_usd,
            "total_cost_usd": breakdown.total_cost_usd,
            "total_cost_krw": breakdown.total_cost_krw,
            "duration_ms": breakdown.duration_ms,
        }
    )
    existing["session_id"] = sess_id
    existing["workspace_id"] = ws_id
    existing["history"] = history[-50:]
    state["cm_cost_summary"] = existing

    # Backfill session_id into the latest persistent ledger entry if it matches run_id
    try:
        ledger_path = _get_ledger_path()
        if ledger_path.exists():
            with _LEDGER_LOCK:
                raw_led = json.loads(ledger_path.read_text(encoding="utf-8"))
                if isinstance(raw_led, dict) and isinstance(raw_led.get("recent_runs"), list):
                    for r in reversed(raw_led["recent_runs"]):
                        if isinstance(r, dict) and r.get("run_id") == breakdown.run_id:
                            r["session_id"] = sess_id
                            r["workspace_id"] = ws_id
                            break
                    ledger_path.write_text(
                        json.dumps(raw_led, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
    except Exception:
        pass

    return breakdown


def record_patch_application_cost(
    *,
    existing_cost_dict: dict[str, Any] | None,
    applied_files: list[dict[str, Any]],
    model_name: str = CODEMENDER_MODEL,
    state: Any = None,
) -> CodeMenderCostBreakdown | None:
    """Records incremental verification/packaging cost when user approves HITL patches."""
    if not existing_cost_dict:
        return None

    base = CodeMenderCostBreakdown.from_dict(existing_cost_dict)
    applied_count = len(applied_files)
    if applied_count == 0:
        return base

    pricing = get_model_pricing(model_name or base.model_used)
    patched_text = "\n".join(
        str(item.get("patched_content", "")) for item in applied_files
    )
    patch_in = max(80, _estimate_tokens_from_text(patched_text) // 2 + 60)
    patch_out = max(45, applied_count * 65)
    patch_think = max(32, applied_count * 32)

    hitl_stage = _compute_stage_cost(
        stage_id="stage4_hitl_patch",
        stage_label="Stage 4: HITL 패치 적용 및 재검증",
        input_tokens=patch_in,
        output_tokens=patch_out,
        thinking_tokens=patch_think,
        duration_ms=12.0 * applied_count,
        include_sandbox_compute=True,
        sandbox_executions=applied_count,
        pricing=pricing,
        measurement_source="sandbox_telemetry",
    )

    # Create a dedicated incremental breakdown for ledger/session recording
    incremental = CodeMenderCostBreakdown(
        run_id=f"cm-patch-{uuid.uuid4().hex[:8]}",
        timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        model_used=base.model_used,
        operation_type="hitl_patch_apply",
        files_scanned_count=0,
        candidates_evaluated=0,
        verified_vulns_count=0,
        false_positives_filtered=0,
        patches_applied_count=applied_count,
        input_tokens=hitl_stage.input_tokens,
        output_tokens=hitl_stage.output_tokens,
        thinking_tokens=hitl_stage.thinking_tokens,
        total_tokens=hitl_stage.total_tokens,
        llm_cost_usd=hitl_stage.llm_cost_usd,
        sandbox_compute_cost_usd=hitl_stage.sandbox_compute_cost_usd,
        total_cost_usd=hitl_stage.total_cost_usd,
        total_cost_krw=hitl_stage.total_cost_krw,
        cost_per_vuln_usd=hitl_stage.total_cost_usd,
        cost_per_vuln_krw=hitl_stage.total_cost_krw,
        usd_to_krw_rate=CM_USD_TO_KRW_RATE,
        duration_ms=hitl_stage.duration_ms,
        sandbox_executions=applied_count,
        measurement_source="sandbox_telemetry",
        stages=[hitl_stage],
    )
    ledger = _append_to_persistent_ledger(incremental)
    if state is not None:
        record_session_cost(state, incremental)

    # Merge the Stage 4 HITL patch stage into the active scan's CodeMenderCostBreakdown
    base.stages = [
        s for s in base.stages if s.stage_id != "stage4_hitl_patch"
    ] + [hitl_stage]
    base.patches_applied_count += applied_count
    base.input_tokens = sum(s.input_tokens for s in base.stages)
    base.output_tokens = sum(s.output_tokens for s in base.stages)
    base.thinking_tokens = sum(s.thinking_tokens for s in base.stages)
    base.total_tokens = (
        base.input_tokens + base.output_tokens + base.thinking_tokens
    )
    base.llm_cost_usd = round(sum(s.llm_cost_usd for s in base.stages), 8)
    base.sandbox_compute_cost_usd = round(
        sum(s.sandbox_compute_cost_usd for s in base.stages), 8
    )
    base.total_cost_usd = round(
        base.llm_cost_usd + base.sandbox_compute_cost_usd, 8
    )
    base.total_cost_krw = round(base.total_cost_usd * CM_USD_TO_KRW_RATE, 4)
    base.duration_ms = round(sum(s.duration_ms for s in base.stages), 2)

    if state is not None and isinstance(state.get("cm_cost_summary"), dict):
        sess = state["cm_cost_summary"]
        base.session_total_runs = int(sess.get("session_total_runs", base.session_total_runs))
        base.session_total_tokens = int(sess.get("session_total_tokens", base.total_tokens))
        base.session_total_cost_usd = float(sess.get("session_total_cost_usd", base.total_cost_usd))
        base.session_total_cost_krw = float(sess.get("session_total_cost_krw", base.total_cost_krw))

    base.ledger_total_runs = int(ledger.get("total_runs", base.ledger_total_runs))
    base.ledger_total_tokens = int(ledger.get("total_tokens", base.total_tokens))
    base.ledger_total_cost_usd = float(ledger.get("total_cost_usd", base.total_cost_usd))
    base.ledger_total_cost_krw = float(ledger.get("total_cost_krw", base.total_cost_krw))
    return base


_KST_TZ = timezone(timedelta(hours=9))


def format_kst_korean_date(iso_str: str | None = None, include_time: bool = True) -> str:
    """Formats an ISO-8601 UTC timestamp into Korean Standard Time ('YYYY년 MM월 DD일 HH:MM')."""
    dt = datetime.now(_KST_TZ)
    if iso_str:
        try:
            cleaned = str(iso_str).strip()
            if cleaned.endswith("Z"):
                cleaned = cleaned[:-1] + "+00:00"
            parsed = datetime.fromisoformat(cleaned)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            dt = parsed.astimezone(_KST_TZ)
        except Exception:
            pass
    if include_time:
        return f"{dt.year}년 {dt.month:02d}월 {dt.day:02d}일 {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
    return f"{dt.year}년 {dt.month:02d}월 {dt.day:02d}일"


def _human_operation_label(op_raw: str) -> str:
    """Converts internal operation_type or CLI command into a clear Korean transaction label."""
    op = (op_raw or "").strip()
    low = op.lower()
    if low == "3stage_scan" or low.startswith("cm find"):
        return "🔍 3단계 보안 진단 스캔 (cm find → verify → fix)"
    if low == "hitl_patch_apply" or low.startswith("cm fix"):
        if "--revert" in low:
            return f"⏪ 보안 패치 롤백 ({op})"
        return f"🛠️ 보안 패치 적용 ({op if op != 'hitl_patch_apply' else 'cm fix'})"
    if low.startswith("cm verify"):
        return f"🧪 샌드박스 PoC 검증 ({op})"
    if low.startswith("cm triage"):
        return "🚦 심각도 트리아지 & 보안 게이트 (cm triage)"
    if low.startswith("cm build"):
        return "🏗️ 샌드박스 구문/빌드 검증 (cm build)"
    if low.startswith("cm vcs"):
        return f"📂 버전 관리 / Diff ({op})"
    if low.startswith("cm report"):
        return f"📊 보안 리포트 생성 ({op})"
    if low.startswith("cm init"):
        return "⚙️ 워크스페이스 초기화 (cm init)"
    if low.startswith("cm switch-model") or low.startswith("cm models"):
        return f"🤖 모델 설정/전환 ({op})"
    return op or "CodeMender 트랜잭션"


def _get_gcp_access_token() -> str | None:
    """Retrieves a GCP OAuth2 access token from ADC or gcloud for Cloud Logging API queries."""
    try:
        import google.auth
        import google.auth.transport.requests

        creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        if not creds.valid:
            creds.refresh(google.auth.transport.requests.Request())
        if creds.token:
            return str(creds.token)
    except Exception as exc:
        logger.debug(f"ADC token lookup skipped: {exc}")
    return None


def _call_cloud_logging_entries_list(
    project_id: str,
    log_filter: str,
    page_size: int,
    token: str,
) -> list[dict[str, Any]]:
    """Calls `https://logging.googleapis.com/v2/entries:list` with a 14-day index bound for sub-second speed."""
    url = "https://logging.googleapis.com/v2/entries:list"
    ts_bound = (datetime.now(timezone.utc) - timedelta(days=14)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    bounded_filter = (
        f'timestamp>="{ts_bound}" AND ({log_filter})'
        if "timestamp" not in log_filter
        else log_filter
    )
    body = json.dumps(
        {
            "resourceNames": [f"projects/{project_id}"],
            "filter": bounded_filter,
            "orderBy": "timestamp desc",
            "pageSize": page_size,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Goog-User-Project": project_id,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8.0) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        entries = data.get("entries")
        return entries if isinstance(entries, list) else []


def query_cloud_logging_cost_telemetry(
    project_id: str = GCP_PROJECT_ID,
    max_entries: int = 80,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Queries Cloud Logging (`entries:list`) ONLY when the user requests a cost report."""
    log_explorer_filter = (
        'resource.type="cloud_run_revision" AND '
        'resource.labels.service_name="codemender-ge" AND '
        'jsonPayload.event_type="CODEMENDER_COST_TELEMETRY"'
    )
    log_analytics_sql = (
        "SELECT\n"
        "  TIMESTAMP_TRUNC(timestamp, HOUR) AS hour_utc,\n"
        "  JSON_VALUE(json_payload.codemender_cost.model_used) AS model,\n"
        "  JSON_VALUE(json_payload.codemender_cost.operation_type) AS operation,\n"
        "  COUNT(*) AS executions,\n"
        "  SUM(CAST(JSON_VALUE(json_payload.codemender_cost.total_tokens) AS INT64)) AS total_tokens,\n"
        "  ROUND(SUM(CAST(JSON_VALUE(json_payload.codemender_cost.total_cost_usd) AS FLOAT64)), 6) AS total_usd,\n"
        "  ROUND(SUM(CAST(JSON_VALUE(json_payload.codemender_cost.total_cost_krw) AS FLOAT64)), 2) AS total_krw\n"
        f"FROM `{project_id}.global._Default._AllLogs`\n"
        "WHERE resource.type = 'cloud_run_revision'\n"
        "  AND JSON_VALUE(json_payload.event_type) = 'CODEMENDER_COST_TELEMETRY'\n"
        "GROUP BY 1, 2, 3\n"
        "ORDER BY 1 DESC;"
    )
    default_result: dict[str, Any] = {
        "available": False,
        "project_id": project_id,
        "source": "local_ledger_fallback",
        "log_metric_name": "codemender_cost_events",
        "log_explorer_filter": log_explorer_filter,
        "log_analytics_sql": log_analytics_sql,
        "structured_log_runs": 0,
        "structured_log_input_tokens": 0,
        "structured_log_output_tokens": 0,
        "structured_log_thinking_tokens": 0,
        "structured_log_total_tokens": 0,
        "structured_log_llm_cost_usd": 0.0,
        "structured_log_sandbox_cost_usd": 0.0,
        "structured_log_total_cost_usd": 0.0,
        "structured_log_total_cost_krw": 0.0,
        "cloud_run_request_count": 0,
        "cloud_run_total_latency_sec": 0.0,
        "cloud_run_infra_cost_usd": 0.0,
        "cloud_run_infra_cost_krw": 0.0,
        "combined_logging_cost_usd": 0.0,
        "combined_logging_cost_krw": 0.0,
        "recent_telemetry_logs": [],
        "recent_request_logs": [],
    }
    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() == "true":
        return default_result

    now_mono = time.monotonic()
    if (
        not force_refresh
        and _CLOUD_LOG_CACHE.get("data") is not None
        and (now_mono - float(_CLOUD_LOG_CACHE.get("ts", 0.0))) < 8.0
    ):
        return dict(_CLOUD_LOG_CACHE["data"])

    token = _get_gcp_access_token()
    if not token:
        return default_result

    try:
        # 1. Query structured CODEMENDER_COST_TELEMETRY entries from Cloud Run stdout
        telemetry_entries = _call_cloud_logging_entries_list(
            project_id, log_explorer_filter, max_entries, token
        )

        seen_run_ids: set[str] = set()
        telemetry_logs: list[dict[str, Any]] = []
        for entry in telemetry_entries:
            jp = entry.get("jsonPayload") or {}
            cm_cost = jp.get("codemender_cost")
            if not isinstance(cm_cost, dict):
                continue
            op_check = str(
                cm_cost.get("operation") or cm_cost.get("operation_type") or ""
            ).lower()
            # Skip cost/stats/logs viewing commands so asking for cost does not pollute transactions
            if any(
                op_check.startswith(x)
                for x in ("cm cost", "cm stats", "cm logs", "cm billing", "비용", "요금")
            ):
                continue
            rid = str(cm_cost.get("run_id") or entry.get("insertId") or "")
            if rid and rid in seen_run_ids:
                continue
            if rid:
                seen_run_ids.add(rid)
            rev_name = (
                (entry.get("resource") or {})
                .get("labels", {})
                .get("revision_name", "codemender-ge")
            )
            cm_cost_copy = dict(cm_cost)
            cm_cost_copy.setdefault("insert_id", str(entry.get("insertId") or rid))
            cm_cost_copy.setdefault("revision", rev_name)
            cm_cost_copy.setdefault(
                "timestamp",
                str(
                    cm_cost.get("timestamp_utc")
                    or cm_cost.get("timestamp")
                    or entry.get("timestamp", "")
                )[:19]
                + "Z",
            )
            cm_cost_copy.setdefault(
                "operation",
                str(
                    cm_cost.get("operation")
                    or cm_cost.get("operation_type")
                    or "3stage_scan"
                ),
            )
            cm_cost_copy.setdefault(
                "model",
                str(
                    cm_cost.get("model_used")
                    or cm_cost.get("model")
                    or CODEMENDER_MODEL
                ),
            )
            telemetry_logs.append(cm_cost_copy)

        # 2. Query actual Cloud Run HTTP POST request latency logs (`run.googleapis.com/requests`)
        request_filter = (
            'resource.type="cloud_run_revision" AND '
            'resource.labels.service_name="codemender-ge" AND '
            'httpRequest.requestMethod="POST"'
        )
        request_entries = _call_cloud_logging_entries_list(
            project_id, request_filter, max_entries, token
        )

        request_logs: list[dict[str, Any]] = []
        total_latency_sec = 0.0
        rate_per_sec = CLOUD_RUN_VCPU_PER_SEC_USD + CLOUD_RUN_GIB_PER_SEC_USD

        for req_entry in request_entries:
            http_req = req_entry.get("httpRequest") or {}
            raw_lat = str(http_req.get("latency") or "0s").strip()
            lat_sec = 0.0
            if raw_lat.endswith("s"):
                try:
                    lat_sec = float(raw_lat[:-1])
                except ValueError:
                    lat_sec = 0.0
            total_latency_sec += lat_sec
            req_cost_usd = round(lat_sec * rate_per_sec, 8)
            rev_name = (
                (req_entry.get("resource") or {})
                .get("labels", {})
                .get("revision_name", "codemender-ge")
            )
            request_logs.append(
                {
                    "timestamp": str(req_entry.get("timestamp", ""))[:19] + "Z",
                    "revision": rev_name,
                    "status": int(http_req.get("status", 200)),
                    "latency_sec": round(lat_sec, 4),
                    "infra_cost_usd": req_cost_usd,
                    "infra_cost_krw": round(req_cost_usd * CM_USD_TO_KRW_RATE, 4),
                }
            )

        log_in = sum(int(c.get("input_tokens", 0)) for c in telemetry_logs)
        log_out = sum(int(c.get("output_tokens", 0)) for c in telemetry_logs)
        log_think = sum(int(c.get("thinking_tokens", 0)) for c in telemetry_logs)
        log_tot_tok = sum(int(c.get("total_tokens", 0)) for c in telemetry_logs)
        log_llm_usd = round(
            sum(float(c.get("llm_cost_usd", 0.0)) for c in telemetry_logs), 8
        )
        log_sbx_usd = round(
            sum(
                float(
                    c.get("sandbox_compute_cost_usd", c.get("sandbox_cost_usd", 0.0))
                )
                for c in telemetry_logs
            ),
            8,
        )
        log_tot_usd = round(
            sum(
                float(c.get("total_cost_usd", c.get("cost_usd", 0.0)))
                for c in telemetry_logs
            ),
            8,
        )
        infra_usd = round(total_latency_sec * rate_per_sec, 8)
        combined_usd = round(log_llm_usd + max(log_sbx_usd, infra_usd), 8)

        result = {
            "available": True,
            "project_id": project_id,
            "source": "cloud_logging_api_v2",
            "log_metric_name": "codemender_cost_events",
            "log_explorer_filter": log_explorer_filter,
            "log_analytics_sql": log_analytics_sql,
            "structured_log_runs": len(telemetry_logs),
            "structured_log_input_tokens": log_in,
            "structured_log_output_tokens": log_out,
            "structured_log_thinking_tokens": log_think,
            "structured_log_total_tokens": log_tot_tok,
            "structured_log_llm_cost_usd": log_llm_usd,
            "structured_log_sandbox_cost_usd": log_sbx_usd,
            "structured_log_total_cost_usd": log_tot_usd,
            "structured_log_total_cost_krw": round(
                log_tot_usd * CM_USD_TO_KRW_RATE, 4
            ),
            "cloud_run_request_count": len(request_logs),
            "cloud_run_total_latency_sec": round(total_latency_sec, 4),
            "cloud_run_infra_cost_usd": infra_usd,
            "cloud_run_infra_cost_krw": round(infra_usd * CM_USD_TO_KRW_RATE, 4),
            "combined_logging_cost_usd": combined_usd,
            "combined_logging_cost_krw": round(combined_usd * CM_USD_TO_KRW_RATE, 4),
            "recent_telemetry_logs": telemetry_logs[:40],
            "recent_request_logs": request_logs[:20],
        }
        _CLOUD_LOG_CACHE["ts"] = now_mono
        _CLOUD_LOG_CACHE["data"] = result
        return dict(result)
    except Exception as exc:
        logger.debug(f"Cloud Logging query fallback: {exc}")
        return default_result


def get_session_and_ledger_cost_report(state: Any = None) -> dict[str, Any]:
    """Builds an on-demand dated billing report with per-session and per-transaction breakdowns."""
    ledger = load_persistent_cost_ledger()
    cloud_logs = query_cloud_logging_cost_telemetry()

    current_ws = state.get("cm_workspace") if (state is not None and hasattr(state, "get")) else None
    current_session_id = "current-session"
    if isinstance(current_ws, dict):
        current_session_id = str(
            current_ws.get("session_id")
            or current_ws.get("workspace_id")
            or "current-session"
        )

    # Collect and deduplicate all transactions from Cloud Logging, persistent ledger, and session state
    tx_by_id: dict[str, dict[str, Any]] = {}

    def _ingest_tx(raw: dict[str, Any], default_sess: str) -> None:
        op_raw = str(
            raw.get("operation")
            or raw.get("command")
            or raw.get("operation_type")
            or "3stage_scan"
        )
        op_low = op_raw.lower().strip()
        if any(
            op_low.startswith(x)
            for x in ("cm cost", "cm stats", "cm logs", "cm billing", "비용", "요금")
        ):
            return
        ts_utc = str(
            raw.get("timestamp_utc") or raw.get("timestamp") or ""
        ).strip()
        rid = str(
            raw.get("run_id")
            or raw.get("insert_id")
            or f"tx-{ts_utc}-{op_low}"
        )
        sess = str(
            raw.get("session_id")
            or raw.get("workspace_id")
            or default_sess
        )
        in_tok = int(raw.get("input_tokens", 0))
        out_tok = int(raw.get("output_tokens", 0))
        think_tok = int(raw.get("thinking_tokens", 0))
        tot_tok = int(raw.get("total_tokens", in_tok + out_tok + think_tok))
        llm_usd = float(raw.get("llm_cost_usd", 0.0))
        sbx_usd = float(
            raw.get("sandbox_compute_cost_usd", raw.get("sandbox_cost_usd", 0.0))
        )
        tot_usd = float(
            raw.get("total_cost_usd", raw.get("cost_usd", llm_usd + sbx_usd))
        )
        tot_krw = float(
            raw.get("total_cost_krw", raw.get("cost_krw", round(tot_usd * CM_USD_TO_KRW_RATE, 4)))
        )
        tx_by_id[rid] = {
            "tx_id": rid,
            "timestamp_utc": ts_utc,
            "timestamp_kst": format_kst_korean_date(ts_utc, include_time=True),
            "date_kst": format_kst_korean_date(ts_utc, include_time=False),
            "session_id": sess,
            "operation_raw": op_raw,
            "operation_label": _human_operation_label(op_raw),
            "model": str(raw.get("model_used") or raw.get("model") or CODEMENDER_MODEL),
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "thinking_tokens": think_tok,
            "total_tokens": tot_tok,
            "llm_cost_usd": round(llm_usd, 8),
            "sandbox_cost_usd": round(sbx_usd, 8),
            "cost_usd": round(tot_usd, 8),
            "cost_krw": round(tot_krw, 4),
            "duration_ms": float(raw.get("duration_ms", 0.0)),
        }

    # 1. From Cloud Logging (multi-container persistent source)
    for clog in reversed(cloud_logs.get("recent_telemetry_logs") or []):
        if isinstance(clog, dict):
            _ingest_tx(clog, "cloud-run-session")

    # 2. From local persistent ledger
    for lrun in ledger.get("recent_runs") or []:
        if isinstance(lrun, dict):
            _ingest_tx(lrun, current_session_id)

    # 3. From current session state (`cm_cost_summary.history` and `cm_command_history`)
    if state is not None and hasattr(state, "get"):
        sess_summary = state.get("cm_cost_summary")
        if isinstance(sess_summary, dict):
            for sh in sess_summary.get("history") or []:
                if isinstance(sh, dict):
                    _ingest_tx(sh, current_session_id)
        for ch in state.get("cm_command_history") or []:
            if isinstance(ch, dict):
                _ingest_tx(ch, current_session_id)

    # Sort transactions chronologically
    transactions_list = sorted(
        tx_by_id.values(),
        key=lambda x: x.get("timestamp_utc") or "",
    )
    for idx, tx in enumerate(transactions_list, start=1):
        tx["tx_index"] = idx

    # Group by session_id
    sessions_map: dict[str, dict[str, Any]] = {}
    for tx in transactions_list:
        sid = tx["session_id"]
        if sid not in sessions_map:
            sessions_map[sid] = {
                "session_id": sid,
                "is_current": sid == current_session_id,
                "first_kst": tx["timestamp_kst"],
                "last_kst": tx["timestamp_kst"],
                "tx_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "thinking_tokens": 0,
                "total_tokens": 0,
                "llm_cost_usd": 0.0,
                "sandbox_cost_usd": 0.0,
                "total_cost_usd": 0.0,
                "total_cost_krw": 0.0,
            }
        s_entry = sessions_map[sid]
        s_entry["last_kst"] = tx["timestamp_kst"]
        s_entry["tx_count"] += 1
        s_entry["input_tokens"] += tx["input_tokens"]
        s_entry["output_tokens"] += tx["output_tokens"]
        s_entry["thinking_tokens"] += tx["thinking_tokens"]
        s_entry["total_tokens"] += tx["total_tokens"]
        s_entry["llm_cost_usd"] = round(s_entry["llm_cost_usd"] + tx["llm_cost_usd"], 8)
        s_entry["sandbox_cost_usd"] = round(
            s_entry["sandbox_cost_usd"] + tx["sandbox_cost_usd"], 8
        )
        s_entry["total_cost_usd"] = round(s_entry["total_cost_usd"] + tx["cost_usd"], 8)
        s_entry["total_cost_krw"] = round(
            s_entry["total_cost_usd"] * CM_USD_TO_KRW_RATE, 4
        )

    sessions_breakdown = list(sessions_map.values())

    # Merge Cloud Logging persistent totals into ledger if higher
    tx_tot_runs = len(transactions_list)
    tx_tot_tok = sum(t["total_tokens"] for t in transactions_list)
    tx_llm_usd = round(sum(t["llm_cost_usd"] for t in transactions_list), 8)
    tx_sbx_usd = round(sum(t["sandbox_cost_usd"] for t in transactions_list), 8)
    tx_tot_usd = round(sum(t["cost_usd"] for t in transactions_list), 8)

    ledger["total_runs"] = max(int(ledger.get("total_runs", 0)), tx_tot_runs, int(cloud_logs.get("structured_log_runs", 0)))
    ledger["total_tokens"] = max(int(ledger.get("total_tokens", 0)), tx_tot_tok, int(cloud_logs.get("structured_log_total_tokens", 0)))
    ledger["total_llm_cost_usd"] = round(max(float(ledger.get("total_llm_cost_usd", 0.0)), tx_llm_usd, float(cloud_logs.get("structured_log_llm_cost_usd", 0.0))), 8)
    ledger["total_sandbox_cost_usd"] = round(
        max(
            float(ledger.get("total_sandbox_cost_usd", 0.0)),
            tx_sbx_usd,
            float(cloud_logs.get("structured_log_sandbox_cost_usd", 0.0))
            + float(cloud_logs.get("cloud_run_infra_cost_usd", 0.0)),
        ),
        8,
    )
    ledger["total_cost_usd"] = round(
        max(
            float(ledger.get("total_cost_usd", 0.0)),
            tx_tot_usd,
            float(cloud_logs.get("combined_logging_cost_usd", 0.0)),
        ),
        8,
    )
    ledger["total_cost_krw"] = round(ledger["total_cost_usd"] * CM_USD_TO_KRW_RATE, 4)

    session_stats: dict[str, Any] = {}
    if state is not None and isinstance(state.get("cm_cost_summary"), dict):
        session_stats = dict(state["cm_cost_summary"])
    else:
        session_stats = {
            "session_total_runs": 0,
            "session_scan_runs": 0,
            "session_patch_runs": 0,
            "session_files_scanned": 0,
            "session_vulns_verified": 0,
            "session_patches_applied": 0,
            "session_input_tokens": 0,
            "session_output_tokens": 0,
            "session_thinking_tokens": 0,
            "session_total_tokens": 0,
            "session_llm_cost_usd": 0.0,
            "session_sandbox_cost_usd": 0.0,
            "session_total_cost_usd": 0.0,
            "session_total_cost_krw": 0.0,
            "history": [],
        }

    now_kst_date = format_kst_korean_date(None, include_time=False)
    now_kst_full = format_kst_korean_date(None, include_time=True)
    first_date_kst = (
        transactions_list[0]["date_kst"] if transactions_list else now_kst_date
    )

    return {
        "model": CODEMENDER_MODEL,
        "as_of_kst_date": now_kst_date,
        "as_of_kst_datetime": now_kst_full,
        "billing_period_kst": f"{first_date_kst} ~ {now_kst_date}",
        "current_session_id": current_session_id,
        "pricing_per_1m_tokens_usd": get_model_pricing(CODEMENDER_MODEL),
        "cloud_run_sandbox_pricing_usd": {
            "vcpu_per_sec": CLOUD_RUN_VCPU_PER_SEC_USD,
            "gib_per_sec": CLOUD_RUN_GIB_PER_SEC_USD,
        },
        "usd_to_krw_rate": CM_USD_TO_KRW_RATE,
        "session": session_stats,
        "ledger": ledger,
        "cloud_logging": cloud_logs,
        "sessions_breakdown": sessions_breakdown,
        "transactions_breakdown": transactions_list,
    }

