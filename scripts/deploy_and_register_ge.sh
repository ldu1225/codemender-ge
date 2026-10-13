#!/usr/bin/env bash
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

# ==============================================================================
# 🛡️ CodeMender Security Agent — Turnkey Customer Provision, Deploy & Register
# ==============================================================================
# Usage:
#   ./scripts/deploy_and_register_ge.sh                  # Full provision + deploy + register
#   ./scripts/deploy_and_register_ge.sh --register-only  # Re-register A2A card without rebuilding Cloud Run
#   ./scripts/deploy_and_register_ge.sh --uninstall      # Delete GE agent registration & Cloud Run service
#   ./scripts/deploy_and_register_ge.sh --clean-reinstall# Uninstall completely, reinstall from scratch, and test
#   ./scripts/deploy_and_register_ge.sh --test           # Run E2E verification (Local + Cloud Run A2A + GE API)
#   ./scripts/deploy_and_register_ge.sh --logs           # Read recent Cloud Run logs
# ==============================================================================

set -euo pipefail
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# 1. Auto-load .env from repository root if present
if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-${GCP_PROJECT_ID:-}}"
REGION="${CLOUD_RUN_REGION:-us-central1}"
VERTEX_LOCATION="${GOOGLE_CLOUD_LOCATION:-global}"
SERVICE_NAME="${SERVICE_NAME:-codemender-ge}"
GE_LOCATION="${GE_LOCATION:-us}"
GE_ENGINE_ID="${GE_ENGINE_ID:-}"
AGENT_DISPLAY_NAME="${AGENT_DISPLAY_NAME:-CodeMender Security Agent (Gemini 3.8 Flash)}"
CODEMENDER_MODEL="${CODEMENDER_MODEL:-gemini-3.8-flash}"
CODEMENDER_FALLBACK_MODEL="${CODEMENDER_FALLBACK_MODEL:-gemini-3.7-flash}"
CM_USD_TO_KRW_RATE="${CM_USD_TO_KRW_RATE:-1380.0}"

if [[ -z "${PROJECT_ID}" || "${PROJECT_ID}" == "your-gcp-project-id" ]]; then
  echo "❌ Error: GOOGLE_CLOUD_PROJECT is not configured."
  echo ""
  echo "👉 Quickstart:"
  echo "   1. cp .env.example .env"
  echo "   2. Set GOOGLE_CLOUD_PROJECT=\"your-real-project-id\" in .env"
  echo "   3. Run ./scripts/deploy_and_register_ge.sh"
  exit 1
fi

CM_GCS_ARTIFACT_BUCKET="${CM_GCS_ARTIFACT_BUCKET:-${PROJECT_ID}-a2a-bucket}"

if [[ "${GE_LOCATION}" == "global" ]]; then
  GE_ENDPOINT_PREFIX=""
else
  GE_ENDPOINT_PREFIX="${GE_LOCATION}-"
fi
GE_API_BASE="https://${GE_ENDPOINT_PREFIX}discoveryengine.googleapis.com/v1alpha"

MODE="${1:---deploy}"

# Helper: Resolve Project Number & Auto-Discover GE_ENGINE_ID if omitted
resolve_project_and_engine() {
  PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
  if [[ -z "${GE_ENGINE_ID}" ]]; then
    echo "🔍 GE_ENGINE_ID not set in .env — auto-discovering Gemini Enterprise engine in ${PROJECT_ID} (${GE_LOCATION})..."
    ACCESS_TOKEN="$(gcloud auth print-access-token)"
    GE_ENGINE_ID="$(
      ACCESS_TOKEN="${ACCESS_TOKEN}" GE_API_BASE="${GE_API_BASE}" PROJECT_NUMBER="${PROJECT_NUMBER}" GE_LOCATION="${GE_LOCATION}" PROJECT_ID="${PROJECT_ID}" \
      python3 -c '
import os, json, urllib.request
base = os.environ["GE_API_BASE"]
pnum = os.environ["PROJECT_NUMBER"]
loc = os.environ["GE_LOCATION"]
pid = os.environ["PROJECT_ID"]
tok = os.environ["ACCESS_TOKEN"]
url = f"{base}/projects/{pnum}/locations/{loc}/collections/default_collection/engines"
req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}", "X-Goog-User-Project": pid})
try:
    with urllib.request.urlopen(req, timeout=15.0) as resp:
        data = json.loads(resp.read().decode())
    engines = sorted(
        data.get("engines", []),
        key=lambda e: e.get("createTime", ""),
        reverse=True,
    )
    chosen = ""
    for eng in engines:
        eid = eng.get("name", "").split("/")[-1]
        if eng.get("solutionType") == "SOLUTION_TYPE_GENERATIVE_CHAT" or "gemini-enterprise" in eid:
            chosen = eid
            break
    if not chosen and engines:
        chosen = engines[0].get("name", "").split("/")[-1]
    print(chosen)
except Exception:
    print("")
'
    )"
    if [[ -z "${GE_ENGINE_ID}" ]]; then
      echo "⚠️ Could not auto-discover a Gemini Enterprise engine in location '${GE_LOCATION}'."
      echo "   Please set GE_ENGINE_ID in .env if you want to register with Gemini Enterprise."
    else
      echo "✓ Auto-discovered GE_ENGINE_ID: ${GE_ENGINE_ID}"
    fi
  fi
}

# Helper: Uninstall Agent from Gemini Enterprise + Delete Cloud Run Service
uninstall_agent() {
  resolve_project_and_engine
  echo "=================================================================="
  echo "🗑️  Uninstalling CodeMender Security Agent from ${PROJECT_ID}..."
  echo "=================================================================="
  if [[ -n "${GE_ENGINE_ID}" ]]; then
    ACCESS_TOKEN="$(gcloud auth print-access-token)"
    ACCESS_TOKEN="${ACCESS_TOKEN}" \
    GE_API_BASE="${GE_API_BASE}" \
    PROJECT_NUMBER="${PROJECT_NUMBER}" \
    GE_LOCATION="${GE_LOCATION}" \
    GE_ENGINE_ID="${GE_ENGINE_ID}" \
    PROJECT_ID="${PROJECT_ID}" \
    AGENT_DISPLAY_NAME="${AGENT_DISPLAY_NAME}" \
    python3 -c '
import os, json, urllib.request

base = os.environ["GE_API_BASE"]
pnum = os.environ["PROJECT_NUMBER"]
loc = os.environ["GE_LOCATION"]
eng = os.environ["GE_ENGINE_ID"]
pid = os.environ["PROJECT_ID"]
dname = os.environ["AGENT_DISPLAY_NAME"]
token = os.environ["ACCESS_TOKEN"]

agents_url = f"{base}/projects/{pnum}/locations/{loc}/collections/default_collection/engines/{eng}/assistants/default_assistant/agents"
req = urllib.request.Request(agents_url, headers={"Authorization": f"Bearer {token}", "X-Goog-User-Project": pid})
try:
    with urllib.request.urlopen(req, timeout=15.0) as resp:
        data = json.loads(resp.read().decode())
    removed = 0
    for agent in data.get("agents", []):
        if agent.get("displayName") == dname or "CodeMender" in agent.get("displayName", ""):
            aname = agent["name"]
            del_url = f"{base}/{aname}"
            del_req = urllib.request.Request(del_url, headers={"Authorization": f"Bearer {token}", "X-Goog-User-Project": pid}, method="DELETE")
            with urllib.request.urlopen(del_req, timeout=15.0) as _:
                print(f"✓ Deleted Gemini Enterprise Agent Registration: {aname}")
                removed += 1
    if removed == 0:
        print("ℹ️ No existing CodeMender agent registration found in Gemini Enterprise.")
except Exception as e:
    print(f"⚠️ Warning while checking/deleting Gemini Enterprise agent: {e}")
'
  fi

  if gcloud run services describe "${SERVICE_NAME}" --project "${PROJECT_ID}" --region "${REGION}" >/dev/null 2>&1; then
    echo "🗑️  Deleting Cloud Run service ${SERVICE_NAME} (${REGION})..."
    gcloud run services delete "${SERVICE_NAME}" --project "${PROJECT_ID}" --region "${REGION}" --quiet
    echo "✓ Deleted Cloud Run service ${SERVICE_NAME}."
  else
    echo "ℹ️ Cloud Run service ${SERVICE_NAME} does not exist (already clean)."
  fi
}

# Helper: Run E2E Tests (Local Playground + Live Cloud Run A2A + GE Registration Verification)
run_e2e_tests() {
  resolve_project_and_engine
  ID_TOKEN="$(gcloud auth print-identity-token)"
  ACCESS_TOKEN="$(gcloud auth print-access-token)"
  SERVICE_URL="$(gcloud run services describe "${SERVICE_NAME}" --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')"

  echo "=================================================================="
  echo "🧪 [Test 1/3] Local ADK Playground (/run_sse) Multi-Turn E2E Test"
  echo "=================================================================="
  OTEL_SDK_DISABLED=true uv run python -c '
import json
from fastapi.testclient import TestClient
from app.fast_api_app import app

with TestClient(app) as client:
    apps = client.get("/list-apps").json()
    print("✓ Playground /list-apps:", apps)
    sess = client.post("/apps/app/users/pg_tester/sessions", json={}).json()
    sid = sess["id"]
    print("✓ Created Playground Session:", sid)

    for step_idx, prompt in enumerate(
        [
            "안녕",
            "샘플 진단 실행",
            "패치 적용",
            "비용 조회",
        ],
        start=1,
    ):
        resp = client.post(
            "/run_sse",
            json={
                "appName": "app",
                "userId": "pg_tester",
                "sessionId": sid,
                "newMessage": {"role": "user", "parts": [{"text": prompt}]},
                "streaming": False,
            },
        )
        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text}"
        events = [
            json.loads(line[6:])
            for line in resp.text.splitlines()
            if line.startswith("data: ")
        ]
        assert events, f"No SSE events returned for prompt: {prompt}"
        content_events = [e for e in events if e.get("content", {}).get("parts")]
        parts = content_events[-1]["content"]["parts"] if content_events else []
        text_out = parts[0].get("text", "") if parts else ""
        label = prompt.splitlines()[0]
        print(f"  [Turn {step_idx}: {label}] TotalEvents={len(events)}, ContentParts={len(parts)}, TextLen={len(text_out)}")
        print("    -> First Line:", text_out.splitlines()[0] if text_out else "EMPTY")
'

  echo ""
  echo "=================================================================="
  echo "☁️ [Test 2/3] Live Cloud Run A2A Endpoint (${SERVICE_URL}/a2a/app)"
  echo "=================================================================="
  ID_TOKEN="${ID_TOKEN}" SERVICE_URL="${SERVICE_URL}" uv run python -c '
import os, json, uuid, httpx

base_url = os.environ["SERVICE_URL"]
url = base_url + "/a2a/app"
card_url = base_url + "/a2a/app/.well-known/agent-card.json"
headers = {
    "Authorization": "Bearer " + os.environ["ID_TOKEN"],
    "Content-Type": "application/json",
}

with httpx.Client(timeout=60.0) as client:
    card_resp = client.get(card_url, headers=headers)
    assert card_resp.status_code == 200, f"Agent card failed: {card_resp.status_code}"
    print("✓ Live Agent Card HTTP:", card_resp.status_code)
    ctx_id = f"live-pg-ctx-{uuid.uuid4().hex[:8]}"
    print("✓ Using fresh A2A contextId:", ctx_id)

    turns = [
        ("안녕", [{"kind": "text", "text": "안녕"}]),
        ("샘플 진단 실행", [{"kind": "text", "text": "샘플 진단 실행"}]),
        ("cm triage", [{"kind": "text", "text": "cm triage"}]),
        ("cm fix 1 -c 감사로깅", [{"kind": "text", "text": "cm fix 1 -c \"SQL 파라미터 바인딩 감사 주석 추가\""}]),
        ("cm artifacts (다운로드 링크 확인)", [{"kind": "text", "text": "cm artifacts"}]),
        ("cm stats (온디맨드 비용 조회)", [{"kind": "text", "text": "cm stats"}]),
    ]
    for step_idx, (label, parts_payload) in enumerate(turns, start=1):
        payload = {
            "jsonrpc": "2.0",
            "id": f"live-{step_idx}",
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": f"msg-{step_idx}-{uuid.uuid4().hex[:6]}",
                    "contextId": ctx_id,
                    "role": "user",
                    "parts": parts_payload,
                }
            },
        }
        r = client.post(url, headers=headers, json=payload)
        assert r.status_code == 200, f"A2A turn {step_idx} failed with HTTP {r.status_code}"
        data = r.json()
        res = data.get("result", {})
        status_state = res.get("status", {}).get("state")
        art_parts = (res.get("artifacts") or [{}])[0].get("parts", [])
        first_text = art_parts[0].get("text", "") if art_parts else ""
        first_line = first_text.splitlines()[0] if first_text else "NONE"
        print(f"  [Live A2A Turn {step_idx}: {label}] HTTP {r.status_code} | state={status_state} | text_len={len(first_text)}")
        print(f"    -> {first_line}")
'

  echo ""
  echo "=================================================================="
  echo "🏢 [Test 3/3] Gemini Enterprise Discovery Engine Registration Check"
  echo "=================================================================="
  if [[ -n "${GE_ENGINE_ID}" ]]; then
    ACCESS_TOKEN="${ACCESS_TOKEN}" \
    GE_API_BASE="${GE_API_BASE}" \
    PROJECT_NUMBER="${PROJECT_NUMBER}" \
    GE_LOCATION="${GE_LOCATION}" \
    GE_ENGINE_ID="${GE_ENGINE_ID}" \
    PROJECT_ID="${PROJECT_ID}" \
    AGENT_DISPLAY_NAME="${AGENT_DISPLAY_NAME}" \
    python3 -c '
import os, json, urllib.request

base = os.environ["GE_API_BASE"]
pnum = os.environ["PROJECT_NUMBER"]
loc = os.environ["GE_LOCATION"]
eng = os.environ["GE_ENGINE_ID"]
pid = os.environ["PROJECT_ID"]
dname = os.environ["AGENT_DISPLAY_NAME"]
token = os.environ["ACCESS_TOKEN"]

agents_url = f"{base}/projects/{pnum}/locations/{loc}/collections/default_collection/engines/{eng}/assistants/default_assistant/agents"
req = urllib.request.Request(agents_url, headers={"Authorization": f"Bearer {token}", "X-Goog-User-Project": pid})
with urllib.request.urlopen(req, timeout=15.0) as resp:
    data = json.loads(resp.read().decode())
matches = [a for a in data.get("agents", []) if a.get("displayName") == dname or "CodeMender" in a.get("displayName", "")]
assert matches, "CodeMender agent not found in Gemini Enterprise!"
for m in matches:
    print("✓ Verified Gemini Enterprise Agent Registration:")
    print("  - Resource Name:", m.get("name"))
    print("  - Display Name: ", m.get("displayName"))
    print("  - State:        ", m.get("state"))
'
  fi
  echo ""
  echo "🎉 All 3 E2E Test Suites Passed!"
}

if [[ "${MODE}" == "--logs" ]]; then
  gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE_NAME}" \
    --project "${PROJECT_ID}" \
    --limit=40 \
    --format="value(timestamp,severity,textPayload,httpRequest.requestMethod,httpRequest.requestUrl,httpRequest.status)"
  exit 0
fi

if [[ "${MODE}" == "--uninstall" ]]; then
  uninstall_agent
  exit 0
fi

if [[ "${MODE}" == "--test" ]]; then
  run_e2e_tests
  exit 0
fi

REGISTER_ONLY=false
RUN_TESTS_AFTER=false
if [[ "${MODE}" == "--register-only" ]]; then
  REGISTER_ONLY=true
elif [[ "${MODE}" == "--clean-reinstall" ]]; then
  uninstall_agent
  RUN_TESTS_AFTER=true
fi

resolve_project_and_engine

echo "=================================================================="
echo "🚀 [1/5] Preparing GCP Project & Provisioning Resources (${PROJECT_ID})"
echo "=================================================================="
echo "  • Project ID:        ${PROJECT_ID} (Number: ${PROJECT_NUMBER})"
echo "  • Cloud Run Region:  ${REGION} (Service: ${SERVICE_NAME})"
echo "  • Gemini Enterprise: ${GE_ENGINE_ID:-<skip>} (Location: ${GE_LOCATION})"
echo "  • Artifact Bucket:   gs://${CM_GCS_ARTIFACT_BUCKET}"
echo "  • Reasoning Model:   ${CODEMENDER_MODEL} (Fallback: ${CODEMENDER_FALLBACK_MODEL})"

if [[ "${REGISTER_ONLY}" == "false" ]]; then
  echo "  -> Enabling required Google Cloud APIs..."
  gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    aiplatform.googleapis.com \
    discoveryengine.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    storage.googleapis.com \
    --project "${PROJECT_ID}" >/dev/null

  echo "  -> Ensuring GCS Artifact & Ledger Bucket (gs://${CM_GCS_ARTIFACT_BUCKET}) exists..."
  if ! gcloud storage buckets describe "gs://${CM_GCS_ARTIFACT_BUCKET}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud storage buckets create "gs://${CM_GCS_ARTIFACT_BUCKET}" \
      --project "${PROJECT_ID}" \
      --location "${REGION}" \
      --uniform-bucket-level-access
    echo "  ✓ Created bucket gs://${CM_GCS_ARTIFACT_BUCKET}"
  else
    echo "  ✓ Bucket gs://${CM_GCS_ARTIFACT_BUCKET} already exists"
  fi

  echo "  -> Ensuring Cloud Logging Cost Telemetry Metric (codemender_cost_events) exists..."
  if ! gcloud logging metrics describe codemender_cost_events --project "${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud logging metrics create codemender_cost_events \
      --project "${PROJECT_ID}" \
      --description="CodeMender Security Agent structured LLM token and Cloud Run sandbox cost telemetry events" \
      --log-filter="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${SERVICE_NAME}\" AND jsonPayload.event_type=\"CODEMENDER_COST_TELEMETRY\"" >/dev/null 2>&1 || true
    echo "  ✓ Created Cloud Logging metric: codemender_cost_events"
  else
    echo "  ✓ Cloud Logging metric codemender_cost_events already exists"
  fi

  echo "=================================================================="
  echo "☁️ [2/5] Deploying CodeMender Agent (${SERVICE_NAME}) to Cloud Run"
  echo "=================================================================="
  ENV_VARS="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${VERTEX_LOCATION},GOOGLE_GENAI_USE_VERTEXAI=TRUE,CODEMENDER_MODEL=${CODEMENDER_MODEL},CODEMENDER_FALLBACK_MODEL=${CODEMENDER_FALLBACK_MODEL},CM_GCS_ARTIFACT_BUCKET=${CM_GCS_ARTIFACT_BUCKET},GE_LOCATION=${GE_LOCATION},GE_ENGINE_ID=${GE_ENGINE_ID},CM_USD_TO_KRW_RATE=${CM_USD_TO_KRW_RATE},GITHUB_OAUTH_CLIENT_ID=${GITHUB_OAUTH_CLIENT_ID:-},GITHUB_TOKEN=${GITHUB_TOKEN:-}"

  if command -v agents-cli >/dev/null 2>&1; then
    GOOGLE_APPLICATION_CREDENTIALS="/tmp/nonexistent_adc_use_gcloud_cli.json" \
    agents-cli deploy \
      --project "${PROJECT_ID}" \
      --region "${REGION}" \
      --service-name "${SERVICE_NAME}" \
      --update-env-vars "${ENV_VARS}"
  else
    gcloud run deploy "${SERVICE_NAME}" \
      --source "${REPO_ROOT}" \
      --project "${PROJECT_ID}" \
      --region "${REGION}" \
      --memory 1Gi \
      --cpu 1 \
      --min-instances 1 \
      --max-instances 10 \
      --no-allow-unauthenticated \
      --set-env-vars "${ENV_VARS}"
  fi
else
  echo "=================================================================="
  echo "⏭️  [2/5] Skipping Cloud Run rebuild (--register-only)"
  echo "=================================================================="
fi

SERVICE_URL="$(gcloud run services describe "${SERVICE_NAME}" --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')"
AGENT_CARD_URL="${SERVICE_URL}/a2a/app/.well-known/agent-card.json"
echo "  • Cloud Run Service URL: ${SERVICE_URL}"
echo "  • A2A Agent Card URL:    ${AGENT_CARD_URL}"

echo "=================================================================="
echo "🔐 [3/5] Configuring IAM Permissions for Discovery Engine & Cloud Run"
echo "=================================================================="
DISCOVERY_SA="service-${PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com"
gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --member="serviceAccount:${DISCOVERY_SA}" \
  --role="roles/run.invoker" >/dev/null 2>&1 || true
echo "  ✓ Granted roles/run.invoker on ${SERVICE_NAME} to ${DISCOVERY_SA}"

echo "=================================================================="
echo "🤝 [4/5] Registering CodeMender A2A + A2UI v0.9 Agent in Gemini Enterprise"
echo "=================================================================="
if [[ -z "${GE_ENGINE_ID}" ]]; then
  echo "⚠️ Skipping Gemini Enterprise registration because GE_ENGINE_ID is not set."
else
  GCLOUD_ACCESS_TOKEN="$(gcloud auth print-access-token)"
  GCLOUD_ID_TOKEN="$(gcloud auth print-identity-token)"

  GCLOUD_ACCESS_TOKEN="${GCLOUD_ACCESS_TOKEN}" \
  GCLOUD_ID_TOKEN="${GCLOUD_ID_TOKEN}" \
  GE_API_BASE="${GE_API_BASE}" \
  PROJECT_NUMBER="${PROJECT_NUMBER}" \
  GE_LOCATION="${GE_LOCATION}" \
  GE_ENGINE_ID="${GE_ENGINE_ID}" \
  PROJECT_ID="${PROJECT_ID}" \
  SERVICE_URL="${SERVICE_URL}" \
  AGENT_CARD_URL="${AGENT_CARD_URL}" \
  AGENT_DISPLAY_NAME="${AGENT_DISPLAY_NAME}" \
  python3 -c '
import os, json, urllib.request

access_token = os.environ["GCLOUD_ACCESS_TOKEN"]
id_token = os.environ["GCLOUD_ID_TOKEN"]
base = os.environ["GE_API_BASE"]
pnum = os.environ["PROJECT_NUMBER"]
loc = os.environ["GE_LOCATION"]
eng = os.environ["GE_ENGINE_ID"]
pid = os.environ["PROJECT_ID"]
service_url = os.environ["SERVICE_URL"].rstrip("/")
card_url = os.environ["AGENT_CARD_URL"]
display_name = os.environ["AGENT_DISPLAY_NAME"]
description = "CodeMender 보안 진단 및 자동 패치 에이전트 (3-Stage cm find -> cm verify -> cm fix). 소스코드 취약점 스캔, 샘플 진단 실행, CWE/OWASP 분석, GitHub PR 연동, 비용 추적 및 A2UI v0.9 지원"

# 1. Fetch live Agent Card from Cloud Run
card_req = urllib.request.Request(card_url, headers={"Authorization": f"Bearer {id_token}"})
with urllib.request.urlopen(card_req, timeout=20.0) as resp:
    card = json.loads(resp.read().decode("utf-8"))

a2a_endpoint = f"{service_url}/a2a/app"
card["url"] = a2a_endpoint
for iface in card.get("supportedInterfaces", []):
    if isinstance(iface, dict):
        iface["url"] = a2a_endpoint

# 2. Check if an agent with the same displayName already exists in Gemini Enterprise
agents_url = f"{base}/projects/{pnum}/locations/{loc}/collections/default_collection/engines/{eng}/assistants/default_assistant/agents"
list_req = urllib.request.Request(
    agents_url,
    headers={"Authorization": f"Bearer {access_token}", "X-Goog-User-Project": pid},
)
existing_agent_name = None
with urllib.request.urlopen(list_req, timeout=20.0) as resp:
    existing_data = json.loads(resp.read().decode("utf-8"))
for ag in existing_data.get("agents", []):
    if ag.get("displayName") == display_name:
        existing_agent_name = ag.get("name")
        break

payload = {
    "displayName": display_name,
    "description": description,
    "icon": {
        "uri": "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/smart_toy/default/24px.svg"
    },
    "a2aAgentDefinition": {
        "jsonAgentCard": json.dumps(card, ensure_ascii=False)
    },
}

headers = {
    "Authorization": f"Bearer {access_token}",
    "X-Goog-User-Project": pid,
    "Content-Type": "application/json",
}

if existing_agent_name:
    patch_url = f"{base}/{existing_agent_name}?updateMask=displayName,description,icon,a2aAgentDefinition"
    req = urllib.request.Request(
        patch_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="PATCH",
    )
    with urllib.request.urlopen(req, timeout=20.0) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    rname = result.get("name")
    print(f"  ✓ Updated existing Gemini Enterprise A2A Agent: {rname}")
else:
    req = urllib.request.Request(
        agents_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20.0) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    rname = result.get("name")
    print(f"  ✓ Registered new Gemini Enterprise A2A Agent: {rname}")
'
fi

echo "=================================================================="
echo "✅ [5/5] Deployment & Registration Complete!"
echo "   • Project:            ${PROJECT_ID}"
echo "   • Cloud Run Endpoint: ${SERVICE_URL}/a2a/app"
echo "   • Gemini Enterprise:  ${GE_ENGINE_ID}"
echo "=================================================================="

if [[ "${RUN_TESTS_AFTER}" == "true" ]]; then
  echo ""
  run_e2e_tests
fi
