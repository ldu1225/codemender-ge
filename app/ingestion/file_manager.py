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

"""Secure file ingestion, Zip-Slip protection, and isolated workspace manager."""

from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import shutil
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as DefusedET

from app.config import (
    ALLOWED_EXTENSIONS,
    MAX_ARCHIVE_FILES,
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_WORKSPACE_BYTES,
    WORKSPACE_ROOT,
)

# Forbidden binary magic headers (ELF, Mach-O, PE/MZ) to prevent executable uploads
_FORBIDDEN_BINARY_HEADERS: tuple[bytes, ...] = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
)
_ZIP_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
)
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class WorkspaceSecurityError(ValueError):
    """Raised when an uploaded file or archive violates security policies."""


@dataclass
class IngestedFile:
    """Metadata for a single validated and mounted source file."""

    file_id: str
    original_name: str
    relative_path: str
    stored_filename: str
    size_bytes: int
    sha256: str
    language: str
    orig_content: str = ""
    current_content: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkspaceContext:
    """Represents an isolated per-session source code workspace."""

    workspace_id: str
    session_id: str
    user_id: str
    root_dir: str
    src_dir: str
    orig_dir: str
    patched_dir: str
    files: list[IngestedFile] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "root_dir": self.root_dir,
            "src_dir": self.src_dir,
            "orig_dir": self.orig_dir,
            "patched_dir": self.patched_dir,
            "files": [f.to_dict() for f in self.files],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkspaceContext:
        files = [IngestedFile(**f) for f in data.get("files", [])]
        return cls(
            workspace_id=data["workspace_id"],
            session_id=data["session_id"],
            user_id=data["user_id"],
            root_dir=data["root_dir"],
            src_dir=data["src_dir"],
            orig_dir=data["orig_dir"],
            patched_dir=data["patched_dir"],
            files=files,
        )


def _ensure_within_directory(base_dir: Path, target_path: Path) -> Path:
    """Strictly verifies that target_path resolves inside base_dir with trailing sep."""
    resolved_base = os.path.realpath(str(base_dir))
    resolved_target = os.path.realpath(str(target_path))
    if not resolved_target.startswith(resolved_base + os.sep):
        raise WorkspaceSecurityError(
            "Security violation: Path traversal outside sandbox boundary detected."
        )
    return Path(resolved_target)


def _sanitize_relative_path(raw_path: str) -> str:
    """Sanitizes a filename or archive entry path against traversal sequences."""
    if not raw_path or "\x00" in raw_path:
        raise WorkspaceSecurityError("Invalid empty or NUL-containing filename.")
    # Normalize Windows backslashes and strip leading slashes
    normalized = raw_path.replace("\\", "/").lstrip("/")
    parts = [p for p in normalized.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        raise WorkspaceSecurityError(
            f"Directory traversal sequence detected in path: {raw_path!r}"
        )
    safe_parts: list[str] = []
    for part in parts:
        clean_part = os.path.basename(part)
        if not clean_part or clean_part in {".", ".."}:
            raise WorkspaceSecurityError(f"Unsafe path segment: {part!r}")
        if not _SAFE_SEGMENT_RE.match(clean_part):
            # Replace unsafe characters with underscores while preserving extension
            clean_part = re.sub(r"[^A-Za-z0-9._-]", "_", clean_part)
        safe_parts.append(clean_part)
    return "/".join(safe_parts)


def _detect_language(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".kt": "kotlin",
        ".swift": "swift",
        ".sh": "bash",
        ".sql": "sql",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".html": "html",
        ".css": "css",
    }
    return mapping.get(ext, "plaintext")


def _validate_file_content(relative_path: str, content: bytes) -> None:
    """Validates file extension, size, magic bytes, and XML safety."""
    # TODO(security): Integrate enterprise antivirus API & CDR scanning in production.
    if len(content) > MAX_SINGLE_FILE_BYTES:
        raise WorkspaceSecurityError(
            f"File {relative_path!r} exceeds maximum size of {MAX_SINGLE_FILE_BYTES} bytes."
        )

    ext = Path(relative_path).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise WorkspaceSecurityError(
            f"Extension {ext!r} is not in the allowed source code allow-list."
        )

    for magic in _FORBIDDEN_BINARY_HEADERS:
        if content.startswith(magic):
            raise WorkspaceSecurityError(
                f"Executable binary upload rejected for {relative_path!r}."
            )

    if ext == ".zip":
        if not content.startswith(_ZIP_MAGIC_PREFIXES):
            raise WorkspaceSecurityError(
                f"File {relative_path!r} has .zip extension but invalid ZIP magic header."
            )
        return

    # Source text files must not contain binary NUL bytes
    if b"\x00" in content:
        raise WorkspaceSecurityError(
            f"Binary or NUL-byte content rejected in source file {relative_path!r}."
        )

    # Harden XML parsing against XXE, DTD, and entity expansion attacks
    if ext == ".xml":
        try:
            DefusedET.fromstring(content.decode("utf-8", errors="strict"))
        except Exception as exc:
            raise WorkspaceSecurityError(
                f"Unsafe or malformed XML rejected for {relative_path!r}: {exc}"
            ) from exc


def get_or_create_workspace(
    session_id: str,
    user_id: str = "default_user",
    existing_context: dict[str, Any] | None = None,
) -> WorkspaceContext:
    """Creates or retrieves an isolated, non-executable workspace for the session."""
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(WORKSPACE_ROOT, 0o700)

    if existing_context and existing_context.get("session_id") == session_id:
        ctx = WorkspaceContext.from_dict(existing_context)
        for d_str in (ctx.root_dir, ctx.src_dir, ctx.orig_dir, ctx.patched_dir):
            d_path = Path(d_str)
            d_path.mkdir(parents=True, exist_ok=True)
            os.chmod(d_path, 0o700)
        # Re-hydrate files onto disk if container /tmp was recreated
        src_base = Path(ctx.src_dir)
        orig_base = Path(ctx.orig_dir)
        patched_base = Path(ctx.patched_dir)
        for fmeta in ctx.files:
            try:
                safe_rel = _sanitize_relative_path(fmeta.relative_path)
                orig_target = _ensure_within_directory(orig_base, orig_base / safe_rel)
                src_target = _ensure_within_directory(src_base, src_base / safe_rel)
                patched_target = _ensure_within_directory(patched_base, patched_base / safe_rel)
                if not orig_target.exists() and fmeta.orig_content:
                    orig_target.parent.mkdir(parents=True, exist_ok=True)
                    orig_target.write_text(fmeta.orig_content, encoding="utf-8")
                    os.chmod(orig_target, 0o600)
                curr_str = fmeta.current_content or fmeta.orig_content
                if curr_str:
                    for target in (src_target, patched_target):
                        if not target.exists():
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_text(curr_str, encoding="utf-8")
                            os.chmod(target, 0o600)
            except Exception:
                pass
        return ctx

    # Generate unpredictable UUID directory scoped to session
    safe_session = re.sub(r"[^A-Za-z0-9_-]", "", session_id)[:24] or "session"
    workspace_id = f"{safe_session}-{uuid.uuid4().hex[:12]}"
    root_dir = _ensure_within_directory(WORKSPACE_ROOT, WORKSPACE_ROOT / workspace_id)
    src_dir = root_dir / "src"
    orig_dir = root_dir / "orig"
    patched_dir = root_dir / "patched"

    for directory in (root_dir, src_dir, orig_dir, patched_dir):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)

    return WorkspaceContext(
        workspace_id=workspace_id,
        session_id=session_id,
        user_id=user_id,
        root_dir=str(root_dir),
        src_dir=str(src_dir),
        orig_dir=str(orig_dir),
        patched_dir=str(patched_dir),
        files=[],
    )


def _write_single_source_file(
    workspace: WorkspaceContext,
    relative_path: str,
    content: bytes,
) -> IngestedFile:
    """Validates and writes a single source file into src/ and orig/ with 0o600 perms."""
    safe_rel = _sanitize_relative_path(relative_path)
    _validate_file_content(safe_rel, content)

    current_total = sum(f.size_bytes for f in workspace.files)
    if current_total + len(content) > MAX_TOTAL_WORKSPACE_BYTES:
        raise WorkspaceSecurityError(
            "Workspace total size limit (50 MB) exceeded."
        )

    src_base = Path(workspace.src_dir)
    orig_base = Path(workspace.orig_dir)
    patched_base = Path(workspace.patched_dir)

    src_target = _ensure_within_directory(src_base, src_base / safe_rel)
    orig_target = _ensure_within_directory(orig_base, orig_base / safe_rel)
    patched_target = _ensure_within_directory(patched_base, patched_base / safe_rel)

    for target in (src_target, orig_target, patched_target):
        target.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)
        target.write_bytes(content)
        # Non-executable permissions on all uploaded source files
        os.chmod(target, 0o600)

    digest = hashlib.sha256(content).hexdigest()
    file_id = f"file-{uuid.uuid4().hex[:8]}"
    text_decoded = content.decode("utf-8", errors="replace")
    ingested = IngestedFile(
        file_id=file_id,
        original_name=os.path.basename(safe_rel),
        relative_path=safe_rel,
        stored_filename=f"{uuid.uuid4().hex}_{os.path.basename(safe_rel)}",
        size_bytes=len(content),
        sha256=digest,
        language=_detect_language(safe_rel),
        orig_content=text_decoded,
        current_content=text_decoded,
    )

    # Replace existing entry if same relative_path was re-uploaded
    workspace.files = [
        f for f in workspace.files if f.relative_path != safe_rel
    ] + [ingested]
    return ingested


def ingest_bytes_into_workspace(
    workspace: WorkspaceContext,
    filename: str,
    content: bytes,
) -> list[IngestedFile]:
    """Ingests a single source file or safely extracts a .zip archive into workspace."""
    safe_name = _sanitize_relative_path(os.path.basename(filename))
    _validate_file_content(safe_name, content)

    if safe_name.lower().endswith(".zip"):
        ingested_list: list[IngestedFile] = []
        try:
            with zipfile.ZipFile(io.BytesIO(content), "r") as zf:
                infos = [info for info in zf.infolist() if not info.is_dir()]
                if len(infos) > MAX_ARCHIVE_FILES:
                    raise WorkspaceSecurityError(
                        f"Archive contains {len(infos)} files, exceeding limit of {MAX_ARCHIVE_FILES}."
                    )
                total_uncompressed = 0
                for info in infos:
                    # Reject symlinks inside zip archives
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        raise WorkspaceSecurityError(
                            f"Symbolic links inside ZIP archives are forbidden: {info.filename!r}"
                        )
                    if info.file_size > MAX_SINGLE_FILE_BYTES:
                        raise WorkspaceSecurityError(
                            f"Archive entry {info.filename!r} exceeds single file size limit."
                        )
                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_TOTAL_WORKSPACE_BYTES:
                        raise WorkspaceSecurityError(
                            "Archive total uncompressed size exceeds 50 MB limit (Zip Bomb guard)."
                        )

                    entry_rel = _sanitize_relative_path(info.filename)
                    # Skip hidden macOS metadata files (__MACOSX, .DS_Store)
                    if (
                        entry_rel.startswith("__MACOSX/")
                        or os.path.basename(entry_rel).startswith("._")
                        or os.path.basename(entry_rel) == ".DS_Store"
                    ):
                        continue

                    entry_bytes = zf.read(info.filename)
                    ingested_list.append(
                        _write_single_source_file(workspace, entry_rel, entry_bytes)
                    )
        except zipfile.BadZipFile as exc:
            raise WorkspaceSecurityError(f"Corrupted ZIP archive: {exc}") from exc
        return ingested_list

    return [_write_single_source_file(workspace, safe_name, content)]


_FENCED_CODE_RE = re.compile(
    r"```(?P<lang>[A-Za-z0-9_+-]*)\s*\n(?P<code>.*?)```",
    re.DOTALL,
)
_LANG_TO_DEFAULT_FILENAME: dict[str, str] = {
    "python": "uploaded_snippet.py",
    "py": "uploaded_snippet.py",
    "javascript": "uploaded_snippet.js",
    "js": "uploaded_snippet.js",
    "typescript": "uploaded_snippet.ts",
    "ts": "uploaded_snippet.ts",
    "go": "uploaded_snippet.go",
    "java": "uploaded_snippet.java",
    "c": "uploaded_snippet.c",
    "cpp": "uploaded_snippet.cpp",
    "rust": "uploaded_snippet.rs",
    "sql": "uploaded_snippet.sql",
    "sh": "uploaded_snippet.sh",
    "bash": "uploaded_snippet.sh",
}


_A2A_DATAPART_PREFIX = b"<a2a_datapart_json>"


def _infer_extension_from_mime_or_content(mime: str, raw_bytes: bytes) -> str:
    """Infers a safe source code extension when display_name has no suffix."""
    mime_lower = (mime or "").lower()
    mime_ext_map = {
        "application/zip": ".zip",
        "application/x-zip-compressed": ".zip",
        "text/x-python": ".py",
        "application/x-python-code": ".py",
        "text/javascript": ".js",
        "application/javascript": ".js",
        "text/typescript": ".ts",
        "text/x-go": ".go",
        "text/x-java-source": ".java",
        "text/x-java": ".java",
        "text/x-c": ".c",
        "text/x-csrc": ".c",
        "text/x-chdr": ".h",
        "text/x-c++": ".cpp",
        "text/x-c++src": ".cpp",
        "application/json": ".json",
        "text/html": ".html",
        "text/xml": ".xml",
        "application/xml": ".xml",
        "text/x-sh": ".sh",
        "application/x-sh": ".sh",
    }
    if mime_lower in mime_ext_map:
        return mime_ext_map[mime_lower]
    if raw_bytes.startswith(_ZIP_MAGIC_PREFIXES):
        return ".zip"
    sample = raw_bytes[:1024].decode("utf-8", errors="ignore")
    if "#include" in sample or "int main(" in sample:
        return ".c"
    if "package " in sample and "func " in sample:
        return ".go"
    if "public class " in sample or "import java." in sample:
        return ".java"
    if "function " in sample or "const " in sample or "export " in sample:
        return ".js"
    return ".py"


def extract_files_from_genai_parts(
    parts: list[Any],
    workspace: WorkspaceContext,
) -> list[IngestedFile]:
    """Extracts uploaded files (inline_data or code blocks) from ADK/A2A message parts."""
    newly_ingested: list[IngestedFile] = []
    candidate_blobs: list[tuple[str, bytes]] = []

    for idx, part in enumerate(parts):
        # 1. Handle inline_data (Blob uploaded via Gemini Enterprise / A2A FilePart)
        inline_data = getattr(part, "inline_data", None)
        if inline_data and getattr(inline_data, "data", None):
            raw_bytes: bytes
            if isinstance(inline_data.data, bytes):
                raw_bytes = inline_data.data
            elif isinstance(inline_data.data, str):
                raw_bytes = base64.b64decode(inline_data.data)
            else:
                continue

            # Ignore internal ADK A2A DataPart wrappers (<a2a_datapart_json>...</a2a_datapart_json>)
            # and A2UI client capability metadata so they are never mistaken for source files.
            trimmed = raw_bytes.strip()
            if (
                trimmed.startswith(_A2A_DATAPART_PREFIX)
                or b'"a2uiClientCapabilities"' in trimmed
                or b'"a2ui_action"' in trimmed
            ):
                continue

            mime = (getattr(inline_data, "mime_type", "") or "").lower()
            display_name = (
                getattr(inline_data, "display_name", None)
                or getattr(part, "display_name", None)
                or ""
            ).strip()

            # If SaveFilesAsArtifactsPlugin generated 'artifact_<id>_0' without extension,
            # or if the uploaded file has no extension, infer an allowed extension.
            ext = Path(display_name).suffix.lower() if display_name else ""
            if not display_name or display_name.startswith("artifact_") or not ext:
                inferred_ext = _infer_extension_from_mime_or_content(mime, raw_bytes)
                base_stem = (
                    Path(display_name).stem
                    if (display_name and not display_name.startswith("artifact_"))
                    else f"uploaded_{idx + 1}"
                )
                display_name = f"{base_stem}{inferred_ext}"
            elif ext not in ALLOWED_EXTENSIONS:
                # Convert unsupported text extensions (e.g. .ps1, .bat, .conf) to .txt for scanning
                if b"\x00" not in raw_bytes and not any(
                    raw_bytes.startswith(m) for m in _FORBIDDEN_BINARY_HEADERS
                ):
                    display_name = f"{display_name}.txt"

            candidate_blobs.append((display_name, raw_bytes))

    if candidate_blobs:
        # Reset workspace file list for the new upload batch so only newly uploaded files are scanned
        workspace.files = []
        for display_name, raw_bytes in candidate_blobs:
            newly_ingested.extend(
                ingest_bytes_into_workspace(workspace, display_name, raw_bytes)
            )

    # 2. If no binary/file attachment was present, check if the user pasted a fenced code block
    if not newly_ingested:
        code_blobs: list[tuple[str, bytes]] = []
        for part in parts:
            text = getattr(part, "text", None)
            if not text or not isinstance(text, str):
                continue
            for match_idx, match in enumerate(_FENCED_CODE_RE.finditer(text)):
                lang = (match.group("lang") or "python").strip().lower()
                code_str = match.group("code")
                if not code_str or not code_str.strip():
                    continue
                default_name = _LANG_TO_DEFAULT_FILENAME.get(
                    lang, f"snippet_{match_idx + 1}.py"
                )
                code_blobs.append((default_name, code_str.encode("utf-8")))
        if code_blobs:
            workspace.files = []
            for default_name, raw_bytes in code_blobs:
                newly_ingested.extend(
                    ingest_bytes_into_workspace(workspace, default_name, raw_bytes)
                )

    return newly_ingested


def package_workspace_as_zip(workspace: WorkspaceContext, use_patched: bool = True) -> bytes:
    """Packages all files in patched_dir (or src_dir) into an in-memory .zip archive."""
    base_dir = Path(workspace.patched_dir if use_patched else workspace.src_dir)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_meta in workspace.files:
            target = _ensure_within_directory(base_dir, base_dir / file_meta.relative_path)
            if target.exists():
                zf.writestr(file_meta.relative_path, target.read_bytes())
    return buf.getvalue()


def cleanup_workspace(workspace: WorkspaceContext) -> None:
    """Safely removes the session's temporary workspace directory."""
    root_path = _ensure_within_directory(WORKSPACE_ROOT, Path(workspace.root_dir))
    if root_path.exists():
        shutil.rmtree(root_path, ignore_errors=True)


from app.config import GCP_PROJECT_ID as GCS_PROJECT_ID, GCS_ARTIFACT_BUCKET


def _get_gcs_access_token() -> str | None:
    """Retrieves an OAuth2 access token from ADC for GCS uploads."""
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
    except Exception:
        pass
    return None


def upload_artifact_to_gcs(
    workspace_id: str,
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
) -> dict[str, str]:
    """Uploads a patched file, ZIP archive, or report to GCS (`gs://<bucket>/codemender-patches/...`)
    with `Content-Disposition: attachment` so users in Gemini Enterprise can click once to download it."""
    import json
    import urllib.parse
    import urllib.request

    safe_ws = re.sub(r"[^A-Za-z0-9._-]", "_", workspace_id or "default-ws")
    safe_name = _sanitize_relative_path(filename).replace("/", "_")
    obj_name = f"codemender-patches/{safe_ws}/{safe_name}"
    encoded_obj = urllib.parse.quote(obj_name, safe="/")

    download_url = f"https://storage.cloud.google.com/{GCS_ARTIFACT_BUCKET}/{encoded_obj}"
    console_url = (
        f"https://console.cloud.google.com/storage/browser/_details/"
        f"{GCS_ARTIFACT_BUCKET}/{encoded_obj}?project={GCS_PROJECT_ID}"
    )
    gcs_uri = f"gs://{GCS_ARTIFACT_BUCKET}/{obj_name}"

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        token = _get_gcs_access_token()
        if token:
            try:
                boundary = f"===cm_gcs_{uuid.uuid4().hex}==="
                meta_bytes = json.dumps(
                    {
                        "name": obj_name,
                        "contentType": content_type,
                        "contentDisposition": f'attachment; filename="{safe_name}"',
                    }
                ).encode("utf-8")
                body = (
                    f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode(
                        "utf-8"
                    )
                    + meta_bytes
                    + f"\r\n--{boundary}\r\nContent-Type: {content_type}\r\n\r\n".encode(
                        "utf-8"
                    )
                    + content
                    + f"\r\n--{boundary}--\r\n".encode("utf-8")
                )
                upload_url = (
                    f"https://storage.googleapis.com/upload/storage/v1/b/"
                    f"{GCS_ARTIFACT_BUCKET}/o?uploadType=multipart"
                )
                req = urllib.request.Request(
                    upload_url,
                    data=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": f"multipart/related; boundary={boundary}",
                        "X-Goog-User-Project": GCS_PROJECT_ID,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=6.0):
                    pass
            except Exception:
                pass

    return {
        "filename": safe_name,
        "gcs_uri": gcs_uri,
        "download_url": download_url,
        "console_url": console_url,
    }


def publish_workspace_patched_files_to_gcs(
    workspace: WorkspaceContext,
    applied_files: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Uploads all patched source files and a full `.zip` bundle to GCS and returns download metadata."""
    patched_base = Path(workspace.patched_dir)
    published_files: list[dict[str, Any]] = []

    if applied_files:
        for item in applied_files:
            rel_path = str(item.get("file_path") or "patched_file.py")
            patched_name = f"patched_{Path(rel_path).name}"
            code_str = str(item.get("patched_content") or "")
            raw_bytes = code_str.encode("utf-8")
            urls = upload_artifact_to_gcs(
                workspace.workspace_id,
                patched_name,
                raw_bytes,
                content_type="application/octet-stream",
            )
            urls["original_path"] = rel_path
            urls["language"] = _detect_language(rel_path)
            urls["patched_content"] = code_str
            urls["local_container_path"] = str(patched_base / rel_path)
            published_files.append(urls)
    else:
        for fmeta in workspace.files:
            rel_path = fmeta.relative_path
            target = _ensure_within_directory(patched_base, patched_base / rel_path)
            code_str = (
                target.read_text(encoding="utf-8", errors="replace")
                if target.exists()
                else (fmeta.current_content or fmeta.orig_content)
            )
            patched_name = f"patched_{Path(rel_path).name}"
            urls = upload_artifact_to_gcs(
                workspace.workspace_id,
                patched_name,
                code_str.encode("utf-8"),
                content_type="application/octet-stream",
            )
            urls["original_path"] = rel_path
            urls["language"] = fmeta.language or _detect_language(rel_path)
            urls["patched_content"] = code_str
            urls["local_container_path"] = str(target)
            published_files.append(urls)

    zip_bytes = package_workspace_as_zip(workspace, use_patched=True)
    zip_info = upload_artifact_to_gcs(
        workspace.workspace_id,
        f"codemender_patched_{workspace.workspace_id}.zip",
        zip_bytes,
        content_type="application/zip",
    )
    return {
        "files": published_files,
        "zip_bundle": zip_info,
    }

