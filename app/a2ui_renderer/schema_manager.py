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

"""A2UI v0.9 Dual-Catalog Schema Manager (CodeMender Material + BasicCatalog)."""

from __future__ import annotations

import copy
import functools
import json
import logging
from pathlib import Path
from typing import Any

from a2a.types import Part as A2APart
from a2ui.basic_catalog.provider import BasicCatalog, BundledCatalogProvider
from a2ui.parser.parser import has_a2ui_parts, parse_response
from a2ui.schema.catalog import A2uiCatalog, CatalogConfig
from a2ui.schema.catalog_provider import A2uiCatalogProvider
from a2ui.schema.constants import A2UI_CLOSE_TAG, A2UI_OPEN_TAG, VERSION_0_9
from a2ui.schema.manager import A2uiSchemaManager
from google.adk.a2a import _compat
from google.adk.a2a.converters import part_converter as adk_part_converter
from google.adk.a2a.converters.event_converter import convert_event_to_a2a_events

from app.config import (
    A2UI_BASIC_CATALOG_ID,
    A2UI_MIME_TYPE,
    CODEMENDER_CUSTOM_CATALOG_ID,
)

logger = logging.getLogger(__name__)

CATALOG_CODEMENDER_MATERIAL = "codemender_material"
CATALOG_BASIC = "basic"

_CATALOG_JSON_PATH = (
    Path(__file__).resolve().parent / "catalogs" / "codemender_v0_9_catalog.json"
)


class CodeMenderMaterialCatalogProvider(A2uiCatalogProvider):
    """Provides the A2UI v0.9 CodeMender Material catalog merged on top of v0.9 BasicCatalog."""

    def load(self) -> dict[str, Any]:
        base_schema = copy.deepcopy(BundledCatalogProvider(VERSION_0_9).load())
        overlay = json.loads(_CATALOG_JSON_PATH.read_text(encoding="utf-8"))

        base_schema["catalogId"] = overlay.get(
            "catalogId", CODEMENDER_CUSTOM_CATALOG_ID
        )
        base_schema["title"] = overlay.get("title", base_schema.get("title", ""))
        base_schema["description"] = overlay.get(
            "description", base_schema.get("description", "")
        )

        custom_components = overlay.get("customComponents", {})
        base_components = base_schema.setdefault("components", {})
        any_comp_one_of = (
            base_schema.setdefault("$defs", {})
            .setdefault("anyComponent", {})
            .setdefault("oneOf", [])
        )
        existing_refs = {
            item.get("$ref") for item in any_comp_one_of if isinstance(item, dict)
        }

        for comp_name, comp_schema in custom_components.items():
            base_components[comp_name] = comp_schema
            ref_str = f"#/components/{comp_name}"
            if ref_str not in existing_refs:
                any_comp_one_of.append({"$ref": ref_str})

        return base_schema


@functools.cache
def get_codemender_schema_manager() -> A2uiSchemaManager:
    """Returns the singleton A2uiSchemaManager configured for Dual-Catalog v0.9."""
    codemender_config = CatalogConfig(
        name="codemender_material_v0_9",
        provider=CodeMenderMaterialCatalogProvider(),
        examples_path=None,
    )
    basic_config = BasicCatalog.get_config(version=VERSION_0_9, examples_path=None)

    return A2uiSchemaManager(
        version=VERSION_0_9,
        catalogs=[codemender_config, basic_config],
        accepts_inline_catalogs=True,
    )


def select_catalog_mode(
    client_ui_capabilities: dict[str, Any] | None = None,
) -> tuple[str, A2uiCatalog]:
    """Negotiates between 'codemender_material' and 'basic' A2UI v0.9 catalog modes.

    Defaults to standard 'basic' (https://a2ui.org/specification/v0_9/basic_catalog.json)
    for universal Gemini Enterprise Web UI compatibility unless the client explicitly
    advertises support for CODEMENDER_CUSTOM_CATALOG_ID.

    Returns:
        Tuple of (mode_name, A2uiCatalog) where mode_name is either
        'codemender_material' or 'basic'.
    """
    manager = get_codemender_schema_manager()
    if client_ui_capabilities and isinstance(client_ui_capabilities, dict):
        v09_caps = client_ui_capabilities.get("v0.9") or client_ui_capabilities
        supported_ids = v09_caps.get("supportedCatalogIds", [])
        if (
            isinstance(supported_ids, list)
            and CODEMENDER_CUSTOM_CATALOG_ID in supported_ids
        ):
            catalog = manager.get_selected_catalog(
                {"supportedCatalogIds": [CODEMENDER_CUSTOM_CATALOG_ID]}
            )
            return CATALOG_CODEMENDER_MATERIAL, catalog

    catalog = manager.get_selected_catalog(
        {"supportedCatalogIds": [A2UI_BASIC_CATALOG_ID]}
    )
    return CATALOG_BASIC, catalog


def validate_a2ui_payload(
    messages: list[dict[str, Any]],
    catalog_mode: str = CATALOG_CODEMENDER_MATERIAL,
) -> None:
    """Validates an array of A2UI v0.9 messages against the selected catalog validator."""
    manager = get_codemender_schema_manager()
    target_id = (
        A2UI_BASIC_CATALOG_ID
        if catalog_mode == CATALOG_BASIC
        else CODEMENDER_CUSTOM_CATALOG_ID
    )
    catalog = manager.get_selected_catalog({"supportedCatalogIds": [target_id]})
    catalog.validator.validate(messages)


def wrap_as_a2ui_datapart(message: dict[str, Any]) -> A2APart:
    """Wraps a single A2UI v0.9 message dict in an A2A v1.x DataPart (application/json+a2ui)."""
    return _compat.make_data_part(
        data=message,
        metadata={"mimeType": A2UI_MIME_TYPE},
    )


def format_a2ui_delimited_text(
    messages: list[dict[str, Any]],
    lead_text: str | None = None,
) -> str:
    """Formats validated A2UI v0.9 messages inside official A2UI parser tags with optional lead Markdown."""
    a2ui_block = (
        f"{A2UI_OPEN_TAG}\n{json.dumps(messages, ensure_ascii=False)}\n{A2UI_CLOSE_TAG}"
    )
    if lead_text and lead_text.strip():
        return f"{lead_text.strip()}\n\n{a2ui_block}"
    return a2ui_block


class CodeMenderA2uiEventConverter:
    """A2A EventConverter that converts A2UI v0.9 payloads into DataParts (application/json+a2ui)."""

    def __init__(self, catalog_mode: str = CATALOG_BASIC) -> None:
        self._default_catalog_mode = catalog_mode

    def _resolve_catalog_for_payload(
        self, a2ui_json: Any, fallback_catalog: A2uiCatalog
    ) -> A2uiCatalog:
        """Detects the catalogId inside createSurface to validate against the matching v0.9 catalog."""
        messages = a2ui_json if isinstance(a2ui_json, list) else [a2ui_json]
        for msg in messages:
            if isinstance(msg, dict) and isinstance(msg.get("createSurface"), dict):
                cat_id = msg["createSurface"].get("catalogId")
                if cat_id in (A2UI_BASIC_CATALOG_ID, CODEMENDER_CUSTOM_CATALOG_ID):
                    manager = get_codemender_schema_manager()
                    return manager.get_selected_catalog(
                        {"supportedCatalogIds": [cat_id]}
                    )
        return fallback_catalog

    def _make_part_converter(self, catalog: A2uiCatalog):
        def _convert_part(part: Any) -> list[A2APart] | A2APart | None:
            text = getattr(part, "text", None)
            if text and has_a2ui_parts(text):
                try:
                    response_parts = parse_response(text)
                    a2a_parts: list[A2APart] = []
                    for rp in response_parts:
                        if rp.text and rp.text.strip():
                            a2a_parts.append(_compat.make_text_part(rp.text.strip()))
                        if rp.a2ui_json:
                            effective_cat = self._resolve_catalog_for_payload(
                                rp.a2ui_json, catalog
                            )
                            effective_cat.validator.validate(rp.a2ui_json)
                            messages = (
                                rp.a2ui_json
                                if isinstance(rp.a2ui_json, list)
                                else [rp.a2ui_json]
                            )
                            for msg in messages:
                                a2a_parts.append(wrap_as_a2ui_datapart(msg))
                    if a2a_parts:
                        return a2a_parts
                except Exception as exc:
                    logger.warning(
                        f"A2UI v0.9 part conversion fallback due to validation error: {exc}"
                    )
            return adk_part_converter.convert_genai_part_to_a2a_part(part)

        return _convert_part

    def convert_part(self, part: Any) -> list[A2APart] | A2APart | None:
        """Default GenAIPartToA2APartConverter entrypoint for A2aAgentExecutorConfig."""
        _, catalog = select_catalog_mode(
            {"supportedCatalogIds": [A2UI_BASIC_CATALOG_ID]}
            if self._default_catalog_mode == CATALOG_BASIC
            else {"supportedCatalogIds": [CODEMENDER_CUSTOM_CATALOG_ID]}
        )
        return self._make_part_converter(catalog)(part)

    def convert_event_to_parts(
        self,
        event: Any,
        catalog_mode: str | None = None,
    ) -> list[A2APart]:
        """Helper to convert an ADK Event directly into a flat list of A2A Parts."""
        mode = catalog_mode or self._default_catalog_mode
        _, catalog = select_catalog_mode(
            {"supportedCatalogIds": [A2UI_BASIC_CATALOG_ID]}
            if mode == CATALOG_BASIC
            else {"supportedCatalogIds": [CODEMENDER_CUSTOM_CATALOG_ID]}
        )
        converter = self._make_part_converter(catalog)
        out: list[A2APart] = []
        if event and event.content and event.content.parts:
            for part in event.content.parts:
                res = converter(part)
                if isinstance(res, list):
                    out.extend(res)
                elif res is not None:
                    out.append(res)
        return out

    def __call__(
        self,
        event: Any,
        invocation_context: Any,
        task_id: str | None = None,
        context_id: str | None = None,
        part_converter_func: Any = adk_part_converter.convert_genai_part_to_a2a_part,
    ) -> list[Any]:
        state = (
            invocation_context.session.state
            if invocation_context and getattr(invocation_context, "session", None)
            else {}
        )
        _, catalog = select_catalog_mode(state.get("client_ui_capabilities"))
        effective_converter = self._make_part_converter(catalog)
        return convert_event_to_a2a_events(
            event,
            invocation_context,
            task_id,
            context_id,
            effective_converter,
        )

