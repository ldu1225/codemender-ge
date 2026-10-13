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

"""A2UI v0.9 Schema Manager, Dual-Catalog Surface Builder, and Action Handler."""

from .action_handler import extract_a2ui_action_from_parts, handle_a2ui_patch_action
from .schema_manager import (
    CodeMenderA2uiEventConverter,
    format_a2ui_delimited_text,
    get_codemender_schema_manager,
    select_catalog_mode,
    validate_a2ui_payload,
    wrap_as_a2ui_datapart,
)
from .surface_builder import (
    build_cost_report_surface,
    build_patch_applied_surface,
    build_scan_report_surface,
    build_upload_prompt_surface,
)

__all__ = [
    "CodeMenderA2uiEventConverter",
    "build_cost_report_surface",
    "build_patch_applied_surface",
    "build_scan_report_surface",
    "build_upload_prompt_surface",
    "extract_a2ui_action_from_parts",
    "format_a2ui_delimited_text",
    "get_codemender_schema_manager",
    "handle_a2ui_patch_action",
    "select_catalog_mode",
    "validate_a2ui_payload",
    "wrap_as_a2ui_datapart",
]

