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

"""Unit tests for secure file ingestion, Zip-Slip prevention, and XXE/binary filtering."""

import io
import os
import zipfile
from pathlib import Path

import pytest

from app.ingestion.file_manager import (
    WorkspaceSecurityError,
    _ensure_within_directory,
    cleanup_workspace,
    get_or_create_workspace,
    ingest_bytes_into_workspace,
)


def test_single_file_ingestion_and_permissions() -> None:
    ws = get_or_create_workspace("sess-123")
    try:
        # Workspace directories must be 0700
        dir_mode = os.stat(ws.root_dir).st_mode & 0o777
        assert dir_mode == 0o700

        code = b"def add(a, b):\n    return a + b\n"
        ingested_list = ingest_bytes_into_workspace(ws, "math_utils.py", code)

        assert len(ingested_list) == 1
        ingested = ingested_list[0]
        assert ingested.relative_path == "math_utils.py"
        assert ingested.language == "python"

        src_file = Path(ws.src_dir) / ingested.relative_path
        assert "return a + b" in src_file.read_text(encoding="utf-8")

        # File must be non-executable (0600)
        file_mode = os.stat(src_file).st_mode & 0o777
        assert file_mode == 0o600
    finally:
        cleanup_workspace(ws)
        assert not os.path.exists(ws.root_dir)


def test_zip_archive_valid_and_zip_slip_rejection() -> None:
    ws = get_or_create_workspace("sess-zip")
    try:
        # 1. Valid multi-file zip archive
        valid_buf = io.BytesIO()
        with zipfile.ZipFile(valid_buf, "w") as zf:
            zf.writestr("app/main.py", "print('hello')\n")
            zf.writestr("app/utils.js", "console.log('ok');\n")

        ingested = ingest_bytes_into_workspace(ws, "bundle.zip", valid_buf.getvalue())
        assert [f.relative_path for f in ingested] == ["app/main.py", "app/utils.js"]

        # 2. Malicious Zip-Slip traversal entry must raise WorkspaceSecurityError
        slip_buf = io.BytesIO()
        with zipfile.ZipFile(slip_buf, "w") as zf:
            zf.writestr("../../etc/passwd.py", "malicious = True\n")

        with pytest.raises(WorkspaceSecurityError, match="Directory traversal"):
            ingest_bytes_into_workspace(ws, "evil.zip", slip_buf.getvalue())

        # 3. Binary ELF disguised as .py must raise WorkspaceSecurityError
        with pytest.raises(WorkspaceSecurityError, match="Executable binary upload"):
            ingest_bytes_into_workspace(
                ws, "exploit.py", b"\x7fELF\x02\x01\x01\x00binarypayload"
            )

        # 4. Disallowed extension (.exe) must raise WorkspaceSecurityError
        with pytest.raises(WorkspaceSecurityError, match="allow-list"):
            ingest_bytes_into_workspace(ws, "malware.exe", b"MZ\x90\x00")
    finally:
        cleanup_workspace(ws)


def test_xxe_xml_rejection() -> None:
    ws = get_or_create_workspace("sess-xml")
    try:
        malicious_xml = (
            b'<?xml version="1.0"?>\n'
            b'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
            b"<root>&xxe;</root>"
        )
        with pytest.raises(WorkspaceSecurityError, match="Unsafe or malformed XML"):
            ingest_bytes_into_workspace(ws, "config.xml", malicious_xml)
    finally:
        cleanup_workspace(ws)


def test_ensure_within_directory_blocks_sibling_prefix_escape(tmp_path: Path) -> None:
    base = tmp_path / "ws_base"
    base.mkdir()
    sibling = tmp_path / "ws_base_evil"
    sibling.mkdir()
    with pytest.raises(WorkspaceSecurityError, match="Path traversal"):
        _ensure_within_directory(base, sibling / "hack.py")
