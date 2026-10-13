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

"""Attach A2A (Agent2Agent) endpoints to the FastAPI app.

func:`attach_a2a_routes` registers the dynamic
agent-card endpoint and the JSON-RPC endpoint so the same app serves A2A
alongside the adk_api routes, reachable by A2A clients and Gemini Enterprise A2A
registration.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    add_a2a_routes_to_fastapi,
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.server.routes.common import DefaultServerCallContextBuilder
from a2a.server.tasks import TaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentExtension, AgentInterface
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
from a2ui.a2a.extension import get_a2ui_agent_extension
from google.adk.a2a.executor.a2a_agent_executor import A2aAgentExecutor
from google.adk.a2a.executor.config import (
    A2aAgentExecutorConfig,
    ExecuteInterceptor,
)
from google.adk.a2a.utils.agent_card_builder import AgentCardBuilder

from app.a2ui_renderer.schema_manager import CodeMenderA2uiEventConverter
from app.config import A2UI_BASIC_CATALOG_ID, CODEMENDER_CUSTOM_CATALOG_ID


class _A2AServerCallContextBuilder(DefaultServerCallContextBuilder):
    """Context builder that ensures A2A-Version defaults correctly when missing.

    Proxy infrastructure (e.g. Google Cloud API Gateways) can strip custom HTTP headers
    like 'A2A-Version'. This builder attempts to infer A2A-version from the method name
    when the header is missing.
    """

    def build(self, request):
        context = super().build(request)
        headers = context.state.setdefault("headers", {})
        existing_version = (
            headers.get("A2A-Version")
            or headers.get("a2a-version")
            or headers.get("x-a2a-version")
            or headers.get("X-A2A-Version")
        )
        if existing_version:
            headers["A2A-Version"] = existing_version
            return context

        # 0.3 uses method names that include a '/' like "message/send"
        # 1.0 uses PascalCase like "SendMessage"
        json_body = getattr(request, "_json", {}) or {}
        method = json_body.get("method") if isinstance(json_body, dict) else None

        if method and "/" in str(method):
            headers["A2A-Version"] = "0.3"
        else:
            headers["A2A-Version"] = "1.0"

        return context


if TYPE_CHECKING:
    from fastapi import FastAPI
    from google.adk.agents import BaseAgent
    from google.adk.runners import Runner

# URI advertised on the agent card describing the executor extension shipped
# by ADK. Kept as a module-level constant so callers can override or extend
# the capabilities list when needed.
_ADK_AGENT_EXECUTOR_EXTENSION_URI = (
    "https://google.github.io/adk-docs/a2a/a2a-extension/"
)


async def _add_v0_3_compat_interface(card: AgentCard) -> AgentCard:
    """Advertise a v0.3 JSON-RPC interface so the served card stays consumable by
    v0.3 A2A clients — notably Gemini Enterprise registration, whose validator
    still requires the 0.3 card shape (top-level ``url``/``protocolVersion``)."""
    if card.supported_interfaces and not any(
        iface.protocol_version == "0.3" for iface in card.supported_interfaces
    ):
        card.supported_interfaces.append(
            AgentInterface(
                protocol_binding="JSONRPC",
                protocol_version="0.3",
                url=card.supported_interfaces[0].url,
            )
        )
    return card


def _default_capabilities() -> AgentCapabilities:
    """Returns the default A2A capabilities including the A2UI v0.9 extension."""
    return AgentCapabilities(
        streaming=True,
        extensions=[
            get_a2ui_agent_extension(
                version="0.9",
                accepts_inline_catalogs=True,
                supported_catalog_ids=[
                    A2UI_BASIC_CATALOG_ID,
                    CODEMENDER_CUSTOM_CATALOG_ID,
                ],
            ),
        ],
    )


def _build_terminal_message_interceptor() -> ExecuteInterceptor:
    """Ensures the final COMPLETED TaskStatusUpdateEvent also carries status.message.

    This guarantees that A2A clients inspecting `task.status.message`, `task.history`,
    or `task.artifacts` all receive the full agent response (TextPart + A2UI DataParts).
    """
    latest_messages: dict[str, object] = {}

    async def _after_event(executor_context, a2a_event, adk_event):
        status = getattr(a2a_event, "status", None)
        if status is not None:
            has_msg = (
                status.HasField("message")
                if hasattr(status, "HasField")
                else bool(getattr(status, "message", None))
            )
            if has_msg and getattr(status.message, "parts", None):
                latest_messages[executor_context.session_id] = status.message
        return a2a_event

    async def _after_agent(executor_context, final_event):
        last_msg = latest_messages.pop(executor_context.session_id, None)
        status = getattr(final_event, "status", None)
        if last_msg is not None and status is not None:
            has_msg = (
                status.HasField("message")
                if hasattr(status, "HasField")
                else bool(getattr(status, "message", None))
            )
            if not has_msg:
                if hasattr(status.message, "CopyFrom"):
                    status.message.CopyFrom(last_msg)
                else:
                    status.message = last_msg
        return final_event

    return ExecuteInterceptor(after_event=_after_event, after_agent=_after_agent)


async def attach_a2a_routes(
    app: FastAPI,
    *,
    agent: BaseAgent,
    runner: Runner,
    task_store: TaskStore,
    rpc_path: str,
    capabilities: AgentCapabilities | None = None,
    agent_version: str | None = None,
    app_url: str | None = None,
) -> None:
    """Register A2A routes (JSON-RPC + agent-card endpoints) under ``rpc_path``.

    Builds a dynamic agent card from ``agent`` and mounts the routes on ``app``.
    The ``runner`` should share the session/artifact/memory services with the
    standard ADK path. ``capabilities``, ``agent_version``, and ``app_url``
    override their defaults (streaming + ADK extension, ``AGENT_VERSION``,
    ``APP_URL``). Call once per app — typically in a FastAPI ``lifespan``, since
    the card is built asynchronously; repeated calls register duplicate routes.
    """
    resolved_app_url = app_url or os.getenv("APP_URL", "http://127.0.0.1:8000")
    resolved_agent_version = agent_version or os.getenv("AGENT_VERSION", "0.1.0")
    resolved_capabilities = capabilities or _default_capabilities()

    agent_card = await AgentCardBuilder(
        agent=agent,
        capabilities=resolved_capabilities,
        rpc_url=f"{resolved_app_url}{rpc_path}",
        agent_version=resolved_agent_version,
    ).build()
    del agent_card.default_input_modes[:]
    agent_card.default_input_modes.extend(
        [
            "text/plain",
            "application/zip",
            "text/x-python",
            "application/octet-stream",
        ]
    )
    del agent_card.default_output_modes[:]
    agent_card.default_output_modes.extend(
        [
            "text/plain",
            "application/json+a2ui",
        ]
    )

    a2ui_converter = CodeMenderA2uiEventConverter()
    executor_config = A2aAgentExecutorConfig(
        event_converter=a2ui_converter,
        gen_ai_part_converter=a2ui_converter.convert_part,
    )
    request_handler = DefaultRequestHandler(
        agent_executor=A2aAgentExecutor(
            runner=runner,
            config=executor_config,
            use_legacy=True,
        ),
        task_store=task_store,
        agent_card=agent_card,
    )

    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(
            agent_card,
            card_modifier=_add_v0_3_compat_interface,
            card_url=f"{rpc_path}{AGENT_CARD_WELL_KNOWN_PATH}",
        ),
        jsonrpc_routes=create_jsonrpc_routes(
            request_handler,
            rpc_url=rpc_path,
            context_builder=_A2AServerCallContextBuilder(),
            enable_v0_3_compat=True,
        ),
    )
