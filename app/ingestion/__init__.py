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

"""Secure file ingestion and isolated workspace management for CodeMender."""

from .file_manager import (
    IngestedFile,
    WorkspaceContext,
    WorkspaceSecurityError,
    extract_files_from_genai_parts,
    get_or_create_workspace,
    ingest_bytes_into_workspace,
    package_workspace_as_zip,
    publish_workspace_patched_files_to_gcs,
    upload_artifact_to_gcs,
)

__all__ = [
    "IngestedFile",
    "WorkspaceContext",
    "WorkspaceSecurityError",
    "extract_files_from_genai_parts",
    "get_or_create_workspace",
    "ingest_bytes_into_workspace",
    "package_workspace_as_zip",
    "publish_workspace_patched_files_to_gcs",
    "upload_artifact_to_gcs",
]
