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

"""Centralized configuration for the CodeMender x Gemini Enterprise A2UI agent."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

def _load_dotenv_if_present() -> None:
    """Loads `.env` from repository root if present without overriding existing environment variables."""
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if not env_file.exists():
        return
    # [CodeMender CM-CWE-703-013] Applied verified security remediation:
    try:
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip().removeprefix("export ").strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ and val:
                os.environ[key] = val
    except OSError:
        # File reading/permission errors are logged or safely ignored without masking system/runtime exceptions
        pass
        pass


_load_dotenv_if_present()

# GCP & Gemini Enterprise target configuration (100% customer-configurable via .env or env vars)
GCP_PROJECT_ID: str = (
    os.getenv("GOOGLE_CLOUD_PROJECT")
    or os.getenv("GCP_PROJECT_ID")
    or "your-gcp-project"
)
GCP_LOCATION: str = os.getenv("GOOGLE_CLOUD_LOCATION", "global")
GE_LOCATION: str = os.getenv("GE_LOCATION", "us")
GE_ENGINE_ID: str = os.getenv("GE_ENGINE_ID", "gemini-enterprise")
GEMINI_ENTERPRISE_APP_ID: str = os.getenv(
    "GEMINI_ENTERPRISE_APP_ID",
    f"projects/{GCP_PROJECT_ID}/locations/{GE_LOCATION}/collections/default_collection/engines/{GE_ENGINE_ID}",
)
GCS_ARTIFACT_BUCKET: str = (
    os.getenv("CM_GCS_ARTIFACT_BUCKET") or f"{GCP_PROJECT_ID}-a2a-bucket"
)

# Single Model Specification: gemini-3.8-flash across Find, Verify, Fix, and Judge
CODEMENDER_MODEL: str = os.getenv("CODEMENDER_MODEL", "gemini-3.8-flash")
CODEMENDER_FALLBACK_MODEL: str = os.getenv(
    "CODEMENDER_FALLBACK_MODEL", "gemini-3.7-flash"
)

# [CodeMender CM-CWE-400-014] Applied verified security remediation:
ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".java",
        ".c",
        ".cpp",
        ".cc",
        ".h",
        ".hpp",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".kt",
        ".swift",
        ".sh",
        ".sql",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".xml",
        ".html",
        ".css",
        ".dockerfile",
        ".txt",
        ".md",
    }
)
        ".swift",
        ".sh",
        ".sql",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".xml",
        ".html",
        ".css",
        ".dockerfile",
        ".txt",
        ".md",
    }
)

# A2UI v0.9 Protocol & Catalog Identifiers
A2UI_EXTENSION_URI: str = "https://a2ui.org/a2a-extension/a2ui/v0.9"
A2UI_MIME_TYPE: str = "application/json+a2ui"
A2UI_BASIC_CATALOG_ID: str = (
    "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"
)
CODEMENDER_CUSTOM_CATALOG_ID: str = os.getenv(
    "CODEMENDER_CUSTOM_CATALOG_ID",
    "https://codemender.ge/specification/v0_9/catalogs/codemender_material/catalog.json",
)

# CodeMender Cost & Token Usage Tracking Configuration
CM_USD_TO_KRW_RATE: float = float(os.getenv("CM_USD_TO_KRW_RATE", "1400.0"))
CM_INPUT_COST_PER_1M_USD: float = float(
    os.getenv("CM_INPUT_COST_PER_1M_USD", "0.15")
)
CM_OUTPUT_COST_PER_1M_USD: float = float(
    os.getenv("CM_OUTPUT_COST_PER_1M_USD", "0.60")
)
CM_THINKING_COST_PER_1M_USD: float = float(
    os.getenv("CM_THINKING_COST_PER_1M_USD", "0.60")
)
CM_CACHED_INPUT_COST_PER_1M_USD: float = float(
    os.getenv("CM_CACHED_INPUT_COST_PER_1M_USD", "0.0375")
)

# Cloud Run Gen2 Sandbox Compute Pricing (us-central1 tier-1 rates)
CLOUD_RUN_VCPU_PER_SEC_USD: float = float(
    os.getenv("CLOUD_RUN_VCPU_PER_SEC_USD", "0.000024")
)
CLOUD_RUN_GIB_PER_SEC_USD: float = float(
    os.getenv("CLOUD_RUN_GIB_PER_SEC_USD", "0.0000025")
)

MODEL_PRICING_PER_1M_TOKENS: dict[str, dict[str, float]] = {
    "gemini-3.8-flash": {
        "input": CM_INPUT_COST_PER_1M_USD,
        "output": CM_OUTPUT_COST_PER_1M_USD,
        "thinking": CM_THINKING_COST_PER_1M_USD,
        "cached_input": CM_CACHED_INPUT_COST_PER_1M_USD,
    },
    "gemini-3.8-flash-cyber": {
        "input": 0.20,
        "output": 0.80,
        "thinking": 0.80,
        "cached_input": 0.05,
    },
    "gemini-3.7-flash": {
        "input": 0.12,
        "output": 0.48,
        "thinking": 0.48,
        "cached_input": 0.03,
    },
    "gemini-2.5-flash": {
        "input": 0.15,
        "output": 0.60,
        "thinking": 0.60,
        "cached_input": 0.0375,
    },
    "gemini-2.5-pro": {
        "input": 1.25,
        "output": 10.00,
        "thinking": 10.00,
        "cached_input": 0.3125,
    },
}

COST_LEDGER_FILENAME: str = "codemender_cost_ledger.json"

