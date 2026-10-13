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

"""Applies verified CodeMender security patches and produces downloadable artifacts."""

from __future__ import annotations

import difflib
import hashlib
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.ingestion.file_manager import (
    WorkspaceContext,
    _ensure_within_directory,
    _sanitize_relative_path,
)


@dataclass
class PatchApplicationResult:
    """Result of applying a human-approved security patch to a workspace file."""

    vuln_id: str
    file_path: str
    applied: bool
    patched_sha256: str
    unified_diff: str
    patched_content: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_unified_diff(
    file_path: str,
    before_text: str,
    after_text: str,
    context_lines: int = 3,
) -> str:
    """Computes a standard git-style unified diff between original and patched code."""
    before_lines = before_text.splitlines(keepends=True)
    after_lines = after_text.splitlines(keepends=True)
    diff_iter = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        n=context_lines,
    )
    return "".join(diff_iter)


def _fuzzy_replace_snippet(
    current_content: str,
    before_snippet: str,
    after_snippet: str,
    start_line: int | None = None,
    end_line: int | None = None,
    vuln_id: str = "",
    file_path: str = "",
) -> str | None:
    """Matches and replaces `before_snippet` in `current_content` even if the LLM trimmed leading indentation."""
    if not before_snippet and not after_snippet:
        return None
    if before_snippet and before_snippet in current_content:
        return current_content.replace(before_snippet, after_snippet, 1)

    cur_lines = current_content.splitlines()
    before_lines = [ln for ln in before_snippet.splitlines() if ln.strip()]
    after_lines = after_snippet.splitlines()

    # Tier 2: Consecutive stripped-line match
    if before_lines:
        n_b = len(before_lines)
        for idx in range(len(cur_lines)):
            # Try matching a window of lines whose stripped non-empty lines equal before_lines
            window_end = idx
            matched_count = 0
            while window_end < len(cur_lines) and matched_count < n_b:
                stripped_cur = cur_lines[window_end].strip()
                if not stripped_cur:
                    window_end += 1
                    continue
                if stripped_cur == before_lines[matched_count].strip():
                    matched_count += 1
                    window_end += 1
                else:
                    break
            if matched_count == n_b:
                # Determine base indentation of first matched line in current_content
                orig_first = cur_lines[idx]
                base_indent = orig_first[: len(orig_first) - len(orig_first.lstrip())]
                first_after_nonempty = next((ln for ln in after_lines if ln.strip()), "")
                after_base_indent = first_after_nonempty[
                    : len(first_after_nonempty) - len(first_after_nonempty.lstrip())
                ]
                reindented_after: list[str] = []
                for aln in after_lines:
                    if not aln.strip():
                        reindented_after.append("")
                    elif not after_base_indent and base_indent:
                        reindented_after.append(base_indent + aln)
                    else:
                        reindented_after.append(aln)
                new_lines = cur_lines[:idx] + reindented_after + cur_lines[window_end:]
                return "\n".join(new_lines) + ("\n" if current_content.endswith("\n") else "")

    # Tier 3: Line-number range fallback when start_line is provided by the scanner
    if start_line is not None and 1 <= start_line <= len(cur_lines) and after_lines:
        s_idx = max(0, start_line - 1)
        e_idx = min(len(cur_lines), (end_line if end_line and end_line >= start_line else start_line))
        orig_line = cur_lines[s_idx]
        base_indent = orig_line[: len(orig_line) - len(orig_line.lstrip())]
        comment_prefix = (
            "//"
            if file_path.endswith((".c", ".cpp", ".cc", ".h", ".hpp", ".js", ".ts", ".go", ".java", ".rs"))
            else "#"
        )
        remediated_block = [
            f"{base_indent}{comment_prefix} [CodeMender {vuln_id}] Applied verified security remediation:"
        ]
        first_after_nonempty = next((ln for ln in after_lines if ln.strip()), "")
        after_base_indent = first_after_nonempty[
            : len(first_after_nonempty) - len(first_after_nonempty.lstrip())
        ]
        for aln in after_lines:
            if not aln.strip():
                remediated_block.append("")
            elif not after_base_indent and base_indent:
                remediated_block.append(base_indent + aln)
            else:
                remediated_block.append(aln)
        new_lines = cur_lines[:s_idx] + remediated_block + cur_lines[e_idx:]
        return "\n".join(new_lines) + ("\n" if current_content.endswith("\n") else "")

    return None


def apply_patch_to_workspace(
    workspace: WorkspaceContext,
    *,
    vuln_id: str,
    file_path: str,
    before_snippet: str,
    after_snippet: str,
    full_patched_file: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
) -> PatchApplicationResult:
    """Applies a verified patch to the target file inside the isolated workspace."""
    safe_rel = _sanitize_relative_path(file_path)
    src_base = Path(workspace.src_dir)
    patched_base = Path(workspace.patched_dir)

    src_file = _ensure_within_directory(src_base, src_base / safe_rel)
    patched_file = _ensure_within_directory(patched_base, patched_base / safe_rel)

    if not patched_file.exists() and not src_file.exists():
        return PatchApplicationResult(
            vuln_id=vuln_id,
            file_path=safe_rel,
            applied=False,
            patched_sha256="",
            unified_diff="",
            patched_content="",
            message=f"Target file {safe_rel!r} not found in session workspace.",
        )

    current_content = (
        patched_file.read_text(encoding="utf-8")
        if patched_file.exists()
        else src_file.read_text(encoding="utf-8")
    )

    fuzzy_updated = _fuzzy_replace_snippet(
        current_content,
        before_snippet,
        after_snippet,
        start_line=start_line,
        end_line=end_line,
        vuln_id=vuln_id,
        file_path=safe_rel,
    )
    if fuzzy_updated is not None and fuzzy_updated != current_content:
        updated_content = fuzzy_updated
    elif full_patched_file:
        updated_content = full_patched_file
    elif after_snippet and after_snippet in current_content:
        # Patch was already applied idempotently
        updated_content = current_content
    else:
        return PatchApplicationResult(
            vuln_id=vuln_id,
            file_path=safe_rel,
            applied=False,
            patched_sha256="",
            unified_diff="",
            patched_content=current_content,
            message=f"Could not locate target snippet in {safe_rel!r} for patching.",
        )

    patched_bytes = updated_content.encode("utf-8")
    patched_file.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(patched_file.parent, 0o700)
    patched_file.write_bytes(patched_bytes)
    os.chmod(patched_file, 0o600)

    # Also keep src_file synchronized so subsequent sequential patches compose cleanly
    src_file.write_bytes(patched_bytes)
    os.chmod(src_file, 0o600)

    sha256_hex = hashlib.sha256(patched_bytes).hexdigest()
    unified = build_unified_diff(safe_rel, current_content, updated_content)

    for fmeta in workspace.files:
        if fmeta.relative_path == safe_rel:
            fmeta.current_content = updated_content
            fmeta.sha256 = sha256_hex

    return PatchApplicationResult(
        vuln_id=vuln_id,
        file_path=safe_rel,
        applied=True,
        patched_sha256=sha256_hex,
        unified_diff=unified,
        patched_content=updated_content,
        message=f"Patch for {vuln_id} successfully applied to {safe_rel} (SHA-256: {sha256_hex[:12]}).",
    )


def revert_patch_in_workspace(
    workspace: WorkspaceContext,
    *,
    vuln_id: str,
    file_path: str,
    before_snippet: str,
    after_snippet: str,
) -> PatchApplicationResult:
    """Reverts a previously applied security patch (`cm fix --revert <id>`)."""
    safe_rel = _sanitize_relative_path(file_path)
    src_base = Path(workspace.src_dir)
    orig_base = Path(workspace.orig_dir)
    patched_base = Path(workspace.patched_dir)

    src_file = _ensure_within_directory(src_base, src_base / safe_rel)
    orig_file = _ensure_within_directory(orig_base, orig_base / safe_rel)
    patched_file = _ensure_within_directory(patched_base, patched_base / safe_rel)

    if not src_file.exists() and not orig_file.exists():
        return PatchApplicationResult(
            vuln_id=vuln_id,
            file_path=safe_rel,
            applied=False,
            patched_sha256="",
            unified_diff="",
            patched_content="",
            message=f"Target file {safe_rel!r} not found in session workspace.",
        )

    current_content = (
        patched_file.read_text(encoding="utf-8")
        if patched_file.exists()
        else src_file.read_text(encoding="utf-8")
    )

    if after_snippet and after_snippet in current_content:
        reverted_content = current_content.replace(after_snippet, before_snippet, 1)
    elif orig_file.exists():
        reverted_content = orig_file.read_text(encoding="utf-8")
    else:
        reverted_content = current_content

    reverted_bytes = reverted_content.encode("utf-8")
    for target in (patched_file, src_file):
        target.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)
        target.write_bytes(reverted_bytes)
        os.chmod(target, 0o600)

    sha256_hex = hashlib.sha256(reverted_bytes).hexdigest()
    unified = build_unified_diff(safe_rel, current_content, reverted_content)

    for fmeta in workspace.files:
        if fmeta.relative_path == safe_rel:
            fmeta.current_content = reverted_content
            fmeta.sha256 = sha256_hex

    return PatchApplicationResult(
        vuln_id=vuln_id,
        file_path=safe_rel,
        applied=True,
        patched_sha256=sha256_hex,
        unified_diff=unified,
        patched_content=reverted_content,
        message=f"Reverted patch for {vuln_id} in {safe_rel} (SHA-256: {sha256_hex[:12]}).",
    )


def reset_workspace_to_original(workspace: WorkspaceContext) -> list[dict[str, str]]:
    """Resets all files in `src_dir` and `patched_dir` back to `orig_dir` (`cm vcs reset`)."""
    src_base = Path(workspace.src_dir)
    orig_base = Path(workspace.orig_dir)
    patched_base = Path(workspace.patched_dir)
    reset_files: list[dict[str, str]] = []

    for file_meta in workspace.files:
        safe_rel = _sanitize_relative_path(file_meta.relative_path)
        orig_file = _ensure_within_directory(orig_base, orig_base / safe_rel)
        src_file = _ensure_within_directory(src_base, src_base / safe_rel)
        patched_file = _ensure_within_directory(patched_base, patched_base / safe_rel)
        if not orig_file.exists():
            continue
        orig_bytes = orig_file.read_bytes()
        for target in (src_file, patched_file):
            target.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(target.parent, 0o700)
            target.write_bytes(orig_bytes)
            os.chmod(target, 0o600)
        sha256_hex = hashlib.sha256(orig_bytes).hexdigest()
        file_meta.current_content = orig_bytes.decode("utf-8", errors="replace")
        file_meta.sha256 = sha256_hex
        reset_files.append(
            {
                "file_path": safe_rel,
                "sha256": sha256_hex,
                "status": "RESET_TO_ORIGINAL",
            }
        )
    return reset_files


def compute_workspace_vcs_status(workspace: WorkspaceContext) -> list[dict[str, Any]]:
    """Computes `cm vcs status` and `cm vcs diff` between `orig_dir` and `patched_dir`/`src_dir`."""
    src_base = Path(workspace.src_dir)
    orig_base = Path(workspace.orig_dir)
    patched_base = Path(workspace.patched_dir)
    entries: list[dict[str, Any]] = []

    for file_meta in workspace.files:
        safe_rel = _sanitize_relative_path(file_meta.relative_path)
        orig_file = _ensure_within_directory(orig_base, orig_base / safe_rel)
        patched_file = _ensure_within_directory(patched_base, patched_base / safe_rel)
        src_file = _ensure_within_directory(src_base, src_base / safe_rel)

        orig_text = (
            orig_file.read_text(encoding="utf-8", errors="replace")
            if orig_file.exists()
            else ""
        )
        curr_target = patched_file if patched_file.exists() else src_file
        curr_text = (
            curr_target.read_text(encoding="utf-8", errors="replace")
            if curr_target.exists()
            else orig_text
        )
        orig_sha = hashlib.sha256(orig_text.encode("utf-8")).hexdigest()
        curr_sha = hashlib.sha256(curr_text.encode("utf-8")).hexdigest()
        modified = orig_sha != curr_sha
        diff_text = (
            build_unified_diff(safe_rel, orig_text, curr_text) if modified else ""
        )
        entries.append(
            {
                "file_path": safe_rel,
                "language": file_meta.language,
                "orig_sha256": orig_sha,
                "current_sha256": curr_sha,
                "status": "MODIFIED" if modified else "CLEAN",
                "unified_diff": diff_text,
                "current_content": curr_text,
            }
        )
    return entries

