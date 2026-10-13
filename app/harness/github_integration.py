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

"""GitHub OAuth Device Flow authentication, repository scanner, and autonomous PR/commit creator for CodeMender."""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import ALLOWED_EXTENSIONS
from app.ingestion.file_manager import (
    GCS_ARTIFACT_BUCKET,
    GCS_PROJECT_ID,
    WorkspaceContext,
    _get_gcs_access_token,
    ingest_bytes_into_workspace,
)

logger = logging.getLogger(__name__)

# Official public GitHub CLI (`gh`) OAuth App Client ID for RFC 8628 Device Flow when no custom OAuth App is provided
GITHUB_OAUTH_CLIENT_ID = (
    os.getenv("GITHUB_OAUTH_CLIENT_ID", "").strip()
    or os.getenv("CM_GITHUB_CLIENT_ID", "").strip()
    or "178c6fc778ccc68e1d6a"
)
GITHUB_OAUTH_SCOPES = "repo read:user user:email"
LOCAL_GITHUB_AUTH_DIR = Path(
    os.getenv("CM_GITHUB_AUTH_DIR", "/tmp/codemender_github_auth_sessions")
)
GCS_GITHUB_AUTH_PREFIX = "codemender-config/sessions"


def _resolve_session_id(state: Any = None, session_id: str | None = None) -> str:
    """Extracts a sanitized session identifier so each conversation has strictly isolated GitHub auth."""
    raw_sid = session_id or ""
    if not raw_sid and state is not None and hasattr(state, "get"):
        raw_sid = str(
            state.get("_cm_session_id")
            or state.get("session_id")
            or state.get("workspace_id")
            or ""
        )
    cleaned = "".join(
        ch if (ch.isalnum() or ch in ("-", "_")) else "_" for ch in str(raw_sid).strip()
    )
    return cleaned or "ephemeral_local"


def _get_session_local_auth_path(session_id: str) -> Path:
    return LOCAL_GITHUB_AUTH_DIR / f"github_auth_{session_id}.json"


def _get_session_gcs_auth_object(session_id: str) -> str:
    return f"{GCS_GITHUB_AUTH_PREFIX}/{session_id}/github_auth_state.json"


def _load_persisted_github_state(
    state: Any = None, session_id: str | None = None
) -> dict[str, Any]:
    """Loads persisted GitHub auth state strictly scoped to the current user session."""
    # 1. Check environment variable override first (only if explicitly configured)
    env_token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if env_token and env_token.strip():
        return {"access_token": env_token.strip(), "source": "env"}

    sid = _resolve_session_id(state, session_id)
    if sid == "ephemeral_local" and state is not None and hasattr(state, "get"):
        sess_auth = state.get("cm_github_auth")
        return dict(sess_auth) if isinstance(sess_auth, dict) else {}

    # 2. Check session-scoped GCS config object (so only this user's session survives Cloud Run scaling)
    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        gcs_token = _get_gcs_access_token()
        if gcs_token:
            try:
                gcs_obj = _get_session_gcs_auth_object(sid)
                encoded = urllib.parse.quote(gcs_obj, safe="")
                url = (
                    f"https://storage.googleapis.com/storage/v1/b/"
                    f"{GCS_ARTIFACT_BUCKET}/o/{encoded}?alt=media"
                )
                req = urllib.request.Request(
                    url,
                    headers={
                        "Authorization": f"Bearer {gcs_token}",
                        "X-Goog-User-Project": GCS_PROJECT_ID,
                    },
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    if isinstance(data, dict) and data:
                        return data
            except Exception:
                pass

    # 3. Fallback to session-scoped local file
    local_path = _get_session_local_auth_path(sid)
    if local_path.exists():
        try:
            data = json.loads(local_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def _save_persisted_github_state(
    data: dict[str, Any], state: Any = None, session_id: str | None = None
) -> None:
    """Saves GitHub auth state strictly under the current session's local file (`0o600`) and GCS path."""
    sid = _resolve_session_id(state, session_id)
    local_path = _get_session_local_auth_path(sid)
    try:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        os.chmod(local_path, 0o600)
    except Exception:
        pass

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() != "true":
        gcs_token = _get_gcs_access_token()
        if gcs_token:
            try:
                gcs_obj = _get_session_gcs_auth_object(sid)
                encoded = urllib.parse.quote(gcs_obj, safe="")
                url = (
                    f"https://storage.googleapis.com/upload/storage/v1/b/"
                    f"{GCS_ARTIFACT_BUCKET}/o?uploadType=media&name={encoded}"
                )
                req = urllib.request.Request(
                    url,
                    data=json.dumps(data, ensure_ascii=False).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {gcs_token}",
                        "Content-Type": "application/json; charset=utf-8",
                        "X-Goog-User-Project": GCS_PROJECT_ID,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5.0):
                    pass
            except Exception:
                pass


def _github_api_request(
    method: str,
    path: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """Executes an authenticated GitHub REST API v3 request."""
    url = (
        path
        if path.startswith("https://")
        else f"https://api.github.com/{path.lstrip('/')}"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "CodeMender-Security-Agent-GE/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    raw_data = None
    if body is not None:
        raw_data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"

    req = urllib.request.Request(
        url, data=raw_data, headers=headers, method=method.upper()
    )
    try:
        with urllib.request.urlopen(req, timeout=12.0) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return resp.status, (json.loads(text) if text.strip() else {})
    except urllib.error.HTTPError as err:
        err_text = err.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(err_text)
        except Exception:
            err_json = {"message": err_text}
        return err.code, err_json
    except Exception as exc:
        return 500, {"message": str(exc)}


def start_github_device_flow(state: Any = None) -> dict[str, Any]:
    """Initiates GitHub OAuth 2.0 Device Flow and stores `device_code` for subsequent verification."""
    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() == "true":
        mock_flow = {
            "pending_device_code": "mock_device_code_12345",
            "user_code": "CMGE-2026",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "started_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        if state is not None and hasattr(state, "__setitem__"):
            state["cm_github_auth"] = mock_flow
        return mock_flow

    payload = urllib.parse.urlencode(
        {
            "client_id": GITHUB_OAUTH_CLIENT_ID,
            "scope": GITHUB_OAUTH_SCOPES,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        "https://github.com/login/device/code",
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "CodeMender-Security-Agent-GE/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        res = json.loads(resp.read().decode("utf-8"))

    persisted = _load_persisted_github_state(state=state)
    persisted.update(
        {
            "pending_device_code": res.get("device_code", ""),
            "user_code": res.get("user_code", ""),
            "verification_uri": res.get(
                "verification_uri", "https://github.com/login/device"
            ),
            "expires_in": int(res.get("expires_in", 900)),
            "interval": int(res.get("interval", 5)),
            "started_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
    )
    _save_persisted_github_state(persisted, state=state)
    if state is not None and hasattr(state, "__setitem__"):
        state["cm_github_auth"] = persisted
    return persisted


def poll_or_verify_github_auth(
    state: Any = None,
    explicit_token: str | None = None,
) -> dict[str, Any]:
    """Checks if a user is authenticated with GitHub, or exchanges a pending `device_code` for an `access_token`."""
    persisted = _load_persisted_github_state(state=state)
    if state is not None and hasattr(state, "get"):
        sess_auth = state.get("cm_github_auth")
        if isinstance(sess_auth, dict):
            # Merge session auth with persisted
            for k, v in sess_auth.items():
                if v and not persisted.get(k):
                    persisted[k] = v

    if explicit_token and explicit_token.strip():
        persisted["access_token"] = explicit_token.strip()
        persisted.pop("pending_device_code", None)

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() == "true":
        if explicit_token or persisted.get("access_token") or persisted.get("pending_device_code"):
            auth_info = {
                "authenticated": True,
                "access_token": explicit_token or "gho_mock_token_codemender",
                "login": "codemender-user",
                "name": "CodeMender User (Verified)",
                "html_url": "https://github.com/codemender-user",
                "public_repos": 12,
                "total_private_repos": 8,
                "authenticated_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
            if state is not None and hasattr(state, "__setitem__"):
                state["cm_github_auth"] = auth_info
            return auth_info
        return {"authenticated": False, "reason": "not_started"}

    # 1. If there is a pending device_code, attempt to exchange it for an access_token first
    pending_dc = persisted.get("pending_device_code")
    if pending_dc and not explicit_token:
        try:
            payload = urllib.parse.urlencode(
                {
                    "client_id": GITHUB_OAUTH_CLIENT_ID,
                    "device_code": str(pending_dc),
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                "https://github.com/login/oauth/access_token",
                data=payload,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "CodeMender-Security-Agent-GE/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                token_res = json.loads(resp.read().decode("utf-8"))
            if isinstance(token_res, dict) and token_res.get("access_token"):
                persisted["access_token"] = token_res["access_token"]
                persisted["scope"] = token_res.get("scope", GITHUB_OAUTH_SCOPES)
                persisted.pop("pending_device_code", None)
                persisted.pop("user_code", None)
                _save_persisted_github_state(persisted, state=state)
            elif isinstance(token_res, dict) and token_res.get("error") in (
                "expired_token",
                "access_denied",
            ):
                persisted.pop("pending_device_code", None)
                _save_persisted_github_state(persisted, state=state)
                return {
                    "authenticated": False,
                    "reason": token_res.get("error"),
                    "error_description": token_res.get("error_description", ""),
                }
        except Exception as exc:
            logger.debug(f"GitHub device code poll skipped: {exc}")

    # 2. Verify active access_token against `GET /user`
    token = str(persisted.get("access_token") or "").strip()
    if token:
        status, user_data = _github_api_request("GET", "/user", token)
        if status == 200 and isinstance(user_data, dict) and user_data.get("login"):
            persisted.update(
                {
                    "authenticated": True,
                    "login": user_data.get("login"),
                    "name": user_data.get("name") or user_data.get("login"),
                    "email": user_data.get("email") or "",
                    "html_url": user_data.get("html_url")
                    or f"https://github.com/{user_data.get('login')}",
                    "public_repos": int(user_data.get("public_repos", 0)),
                    "total_private_repos": int(
                        user_data.get("total_private_repos")
                        or user_data.get("owned_private_repos")
                        or 0
                    ),
                    "authenticated_at": persisted.get("authenticated_at")
                    or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            )
            _save_persisted_github_state(persisted, state=state)
            if state is not None and hasattr(state, "__setitem__"):
                state["cm_github_auth"] = persisted
            return persisted
        else:
            # Invalid/revoked token
            persisted.pop("access_token", None)
            persisted["authenticated"] = False
            _save_persisted_github_state(persisted, state=state)

    if persisted.get("pending_device_code"):
        return {
            "authenticated": False,
            "reason": "authorization_pending",
            "user_code": persisted.get("user_code", ""),
            "verification_uri": persisted.get(
                "verification_uri", "https://github.com/login/device"
            ),
        }

    return {"authenticated": False, "reason": "not_authenticated"}


def logout_github_auth(state: Any = None) -> None:
    """Clears stored GitHub authentication state for the current session."""
    _save_persisted_github_state({}, state=state)
    if state is not None and hasattr(state, "__setitem__"):
        state["cm_github_auth"] = {}


def list_user_github_repos(token: str, limit: int = 20) -> list[dict[str, Any]]:
    """Lists the authenticated user's recently updated GitHub repositories (including private repos)."""
    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() == "true":
        return [
            {
                "full_name": "codemender-user/payment-gateway-service",
                "private": True,
                "default_branch": "main",
                "language": "Python",
                "updated_at": "2026-10-12T12:00:00Z",
                "html_url": "https://github.com/codemender-user/payment-gateway-service",
                "description": "Enterprise payment gateway microservice",
            },
            {
                "full_name": "codemender-user/codemender-security-demo",
                "private": False,
                "default_branch": "main",
                "language": "C",
                "updated_at": "2026-10-11T09:30:00Z",
                "html_url": "https://github.com/codemender-user/codemender-security-demo",
                "description": "CodeMender C/Python vulnerability testbed",
            },
        ]

    status, data = _github_api_request(
        "GET",
        f"/user/repos?sort=updated&direction=desc&per_page={limit}&affiliation=owner,collaborator,organization_member",
        token,
    )
    if status != 200 or not isinstance(data, list):
        return []
    repos: list[dict[str, Any]] = []
    for r in data[:limit]:
        if not isinstance(r, dict):
            continue
        repos.append(
            {
                "full_name": r.get("full_name", ""),
                "private": bool(r.get("private", False)),
                "default_branch": r.get("default_branch", "main"),
                "language": r.get("language") or "-",
                "updated_at": str(r.get("updated_at") or "")[:19].replace("T", " "),
                "html_url": r.get("html_url", ""),
                "description": (r.get("description") or "")[:60],
            }
        )
    return repos


def fetch_github_repo_files_into_workspace(
    *,
    token: str,
    repo_full_name: str,
    workspace: WorkspaceContext,
    subpath: str = "",
    branch: str = "",
    max_files: int = 8,
    state: Any = None,
) -> dict[str, Any]:
    """Fetches source files from a GitHub repository (`owner/repo`) and mounts them into the CodeMender workspace."""
    clean_repo = repo_full_name.strip().removeprefix("https://github.com/").strip("/")
    parts = clean_repo.split("/")
    if len(parts) >= 2:
        clean_repo = f"{parts[0]}/{parts[1]}"
        if not subpath and len(parts) > 2:
            # Handle URLs like owner/repo/blob/main/path/to/file.py
            if parts[2] in ("blob", "tree") and len(parts) >= 4:
                branch = branch or parts[3]
                subpath = "/".join(parts[4:])
            else:
                subpath = "/".join(parts[2:])

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() == "true":
        sample_code = (
            "import sqlite3\nimport subprocess\n\n"
            "def query_account(cursor, user_id):\n"
            "    cursor.execute(f\"SELECT * FROM accounts WHERE id = '{user_id}'\")\n"
            "    return cursor.fetchall()\n\n"
            "def diag_ping(target_host):\n"
            "    return subprocess.run(f\"ping -c 1 {target_host}\", shell=True, check=False)\n"
        )
        workspace.files = []
        ingest_bytes_into_workspace(
            workspace, "github_service.py", sample_code.encode("utf-8")
        )
        return {
            "status": "ok",
            "repo": clean_repo,
            "branch": branch or "main",
            "fetched_files": ["github_service.py"],
            "file_shas": {"github_service.py": "mock_sha_12345"},
        }

    # 1. Get repository metadata to resolve default_branch
    st_repo, repo_meta = _github_api_request("GET", f"/repos/{clean_repo}", token)
    if st_repo != 200 or not isinstance(repo_meta, dict):
        return {
            "status": "error",
            "message": f"GitHub 레포지토리 `{clean_repo}`를 찾을 수 없거나 접근 권한이 없습니다: {repo_meta.get('message', st_repo)}",
        }
    target_branch = branch or str(repo_meta.get("default_branch") or "main")

    # 2. If subpath points to a single file, fetch it directly; otherwise use git recursive tree
    fetched_files: list[str] = []
    file_shas: dict[str, str] = {}
    file_github_paths: dict[str, str] = {}
    workspace.files = []

    if subpath and Path(subpath).suffix.lower() in ALLOWED_EXTENSIONS:
        st_f, f_data = _github_api_request(
            "GET",
            f"/repos/{clean_repo}/contents/{subpath.lstrip('/')}?ref={urllib.parse.quote(target_branch)}",
            token,
        )
        if st_f == 200 and isinstance(f_data, dict) and f_data.get("content"):
            raw_bytes = base64.b64decode(f_data["content"])
            fname = Path(subpath).name
            ingest_bytes_into_workspace(workspace, fname, raw_bytes)
            fetched_files.append(fname)
            file_shas[fname] = str(f_data.get("sha") or "")
            file_github_paths[fname] = subpath.lstrip("/")
    else:
        st_tree, tree_data = _github_api_request(
            "GET",
            f"/repos/{clean_repo}/git/trees/{urllib.parse.quote(target_branch)}?recursive=1",
            token,
        )
        if st_tree == 200 and isinstance(tree_data, dict):
            tree_items = tree_data.get("tree") or []
            candidate_items = []
            for item in tree_items:
                if not isinstance(item, dict) or item.get("type") != "blob":
                    continue
                p_str = str(item.get("path") or "")
                if subpath and not p_str.startswith(subpath.strip("/")):
                    continue
                ext = Path(p_str).suffix.lower()
                # Prioritize code files over config/markdown files
                if ext in {
                    ".py",
                    ".c",
                    ".cpp",
                    ".cc",
                    ".h",
                    ".js",
                    ".ts",
                    ".go",
                    ".java",
                    ".rs",
                    ".php",
                    ".rb",
                    ".cs",
                } and int(item.get("size", 0)) <= 200_000:
                    candidate_items.append(item)

            # Sort so primary source files (non-hidden directories, non-__init__.py) come first
            candidate_items.sort(
                key=lambda it: (
                    1 if str(it.get("path") or "").startswith(".") else 0,
                    1 if Path(str(it.get("path") or "")).name == "__init__.py" else 0,
                    str(it.get("path") or ""),
                )
            )

            for item in candidate_items[:max_files]:
                p_str = str(item.get("path") or "")
                st_f, f_data = _github_api_request(
                    "GET",
                    f"/repos/{clean_repo}/contents/{urllib.parse.quote(p_str)}?ref={urllib.parse.quote(target_branch)}",
                    token,
                )
                if (
                    st_f == 200
                    and isinstance(f_data, dict)
                    and f_data.get("content")
                ):
                    try:
                        raw_bytes = base64.b64decode(f_data["content"])
                        safe_rel = p_str.replace("/", "_")
                        ingest_bytes_into_workspace(workspace, safe_rel, raw_bytes)
                        fetched_files.append(safe_rel)
                        file_shas[safe_rel] = str(f_data.get("sha") or "")
                        file_github_paths[safe_rel] = p_str
                    except Exception:
                        continue

    if not fetched_files:
        return {
            "status": "error",
            "message": f"GitHub 레포지토리 `{clean_repo}` (브랜치: `{target_branch}`)에서 스캔 가능한 소스 코드 파일을 찾지 못했습니다.",
        }

    repo_ctx = {
        "status": "ok",
        "repo": clean_repo,
        "branch": target_branch,
        "html_url": repo_meta.get("html_url", f"https://github.com/{clean_repo}"),
        "fetched_files": fetched_files,
        "file_shas": file_shas,
        "file_github_paths": file_github_paths,
    }
    try:
        persisted = _load_persisted_github_state(state=state, session_id=workspace.session_id)
        if isinstance(persisted, dict):
            persisted["last_github_repo_context"] = repo_ctx
            _save_persisted_github_state(persisted, state=state, session_id=workspace.session_id)
    except Exception:
        pass
    return repo_ctx


def create_github_pr_or_push_patches(
    *,
    token: str,
    login: str,
    workspace: WorkspaceContext,
    pipeline_result: Any,
    target_repo: str = "",
    create_new_repo_if_missing: bool = True,
    state: Any = None,
) -> dict[str, Any]:
    """Commits CodeMender's verified security patches to a GitHub branch and opens a real Pull Request."""
    gh_meta = (
        state.get("cm_github_repo_context")
        if (state is not None and hasattr(state, "get"))
        else None
    )
    persisted = _load_persisted_github_state(state=state, session_id=workspace.session_id)
    if not isinstance(gh_meta, dict) or not gh_meta.get("repo"):
        persisted_ctx = (
            persisted.get("last_github_repo_context")
            if isinstance(persisted, dict)
            else None
        )
        if isinstance(persisted_ctx, dict) and persisted_ctx.get("repo"):
            gh_meta = persisted_ctx
        else:
            gh_meta = {}

    repo_full_name = (
        target_repo.strip().removeprefix("https://github.com/").strip("/")
        or str(gh_meta.get("repo") or "").strip()
    )

    if os.getenv("CM_DISABLE_LLM_NETWORK", "false").lower() == "true":
        if not repo_full_name:
            repo_full_name = f"{login}/codemender-security-patches"
        elif "/" not in repo_full_name:
            repo_full_name = f"{login}/{repo_full_name}"
        return {
            "status": "ok",
            "repo": repo_full_name,
            "base_branch": "main",
            "patch_branch": "codemender/security-fix-20261012",
            "committed_files": [f.relative_path for f in workspace.files],
            "pr_number": 1,
            "pr_url": f"https://github.com/{repo_full_name}/pull/1",
            "branch_url": f"https://github.com/{repo_full_name}/tree/codemender/security-fix-20261012",
            "repo_url": f"https://github.com/{repo_full_name}",
        }

    # Auto-detect scanned repository from user's GitHub repos if repo_full_name was not in session state
    ws_filenames = {f.relative_path for f in workspace.files}
    if not repo_full_name and ws_filenames and ws_filenames != {"sample_payment_service.py"}:
        user_repos = list_user_github_repos(token, limit=15)
        for ur in user_repos:
            cand_repo = str(ur.get("full_name") or "")
            cand_br = str(ur.get("default_branch") or "main")
            if not cand_repo:
                continue
            st_t, t_data = _github_api_request(
                "GET",
                f"/repos/{cand_repo}/git/trees/{urllib.parse.quote(cand_br)}?recursive=1",
                token,
            )
            if st_t == 200 and isinstance(t_data, dict):
                tree_paths = {
                    str(it.get("path") or "").replace("/", "_"): str(it.get("path") or "")
                    for it in (t_data.get("tree") or [])
                    if isinstance(it, dict) and it.get("type") == "blob"
                }
                if ws_filenames & set(tree_paths.keys()):
                    repo_full_name = cand_repo
                    gh_meta = {
                        "repo": cand_repo,
                        "branch": cand_br,
                        "file_github_paths": tree_paths,
                    }
                    break

    if not repo_full_name:
        repo_full_name = f"{login}/codemender-security-patches"
    elif "/" not in repo_full_name:
        repo_full_name = f"{login}/{repo_full_name}"

    # 1. Check if target repository exists; if not and create_new_repo_if_missing is True, create it!
    st_repo, repo_info = _github_api_request("GET", f"/repos/{repo_full_name}", token)
    created_new = False
    if st_repo == 404 and create_new_repo_if_missing:
        repo_short_name = repo_full_name.split("/")[-1]
        st_create, create_info = _github_api_request(
            "POST",
            "/user/repos",
            token,
            body={
                "name": repo_short_name,
                "description": "Automated security patches verified by CodeMender Security Agent (Gemini Enterprise)",
                "private": False,
                "auto_init": True,
            },
        )
        if st_create in (200, 201) and isinstance(create_info, dict):
            repo_info = create_info
            repo_full_name = str(create_info.get("full_name") or repo_full_name)
            created_new = True
            time.sleep(1.2)
        else:
            return {
                "status": "error",
                "message": f"GitHub 레포지토리 `{repo_full_name}` 생성 실패: {create_info.get('message', st_create)}",
            }
    elif st_repo != 200 or not isinstance(repo_info, dict):
        return {
            "status": "error",
            "message": f"GitHub 레포지토리 `{repo_full_name}` 조회 실패: {repo_info.get('message', st_repo)}",
        }

    base_branch = str(
        gh_meta.get("branch") or repo_info.get("default_branch") or "main"
    )

    # Resolve flattened workspace filenames back to real GitHub tree paths if needed
    file_github_paths: dict[str, str] = dict(gh_meta.get("file_github_paths") or {})
    if not created_new and any(f.relative_path not in file_github_paths for f in workspace.files):
        st_t, t_data = _github_api_request(
            "GET",
            f"/repos/{repo_full_name}/git/trees/{urllib.parse.quote(base_branch)}?recursive=1",
            token,
        )
        if st_t == 200 and isinstance(t_data, dict):
            for it in t_data.get("tree") or []:
                if isinstance(it, dict) and it.get("type") == "blob":
                    raw_p = str(it.get("path") or "")
                    file_github_paths.setdefault(raw_p.replace("/", "_"), raw_p)
                    file_github_paths.setdefault(raw_p, raw_p)

    # If the user invoked `cm github pr <owner/repo>` directly without scanning that repo into the current workspace first,
    # fetch and scan the target repo now so we patch actual files from `repo_full_name`!
    if (
        not created_new
        and repo_full_name != f"{login}/codemender-security-patches"
        and (
            not workspace.files
            or {f.relative_path for f in workspace.files} == {"sample_payment_service.py"}
        )
    ):
        fetch_res = fetch_github_repo_files_into_workspace(
            token=token,
            repo_full_name=repo_full_name,
            workspace=workspace,
            branch=base_branch,
        )
        if fetch_res.get("status") == "ok":
            file_github_paths.update(fetch_res.get("file_github_paths") or {})
            from app.harness import CodeMenderRunner

            runner = CodeMenderRunner()
            pipeline_result = runner.run_pipeline(workspace)
            if state is not None and hasattr(state, "__setitem__"):
                state["cm_workspace"] = workspace.to_dict()
                state["cm_pipeline_result"] = pipeline_result.to_dict()
                state["cm_github_repo_context"] = fetch_res

    orig_dir = Path(workspace.orig_dir)
    patched_dir = Path(workspace.patched_dir)

    # 2. If we just created a new repo, also commit the original vulnerable file onto base_branch first so the PR shows a real diff!
    if created_new:
        for fmeta in workspace.files:
            orig_file = orig_dir / fmeta.relative_path
            orig_bytes = (
                orig_file.read_bytes()
                if orig_file.exists()
                else fmeta.orig_content.encode("utf-8")
            )
            gh_path = file_github_paths.get(
                fmeta.relative_path, fmeta.relative_path
            )
            st_ex, ex_data = _github_api_request(
                "GET",
                f"/repos/{repo_full_name}/contents/{urllib.parse.quote(gh_path)}?ref={urllib.parse.quote(base_branch)}",
                token,
            )
            put_body: dict[str, Any] = {
                "message": f"chore: add original source {gh_path} before CodeMender patch",
                "content": base64.b64encode(orig_bytes).decode("ascii"),
                "branch": base_branch,
            }
            if st_ex == 200 and isinstance(ex_data, dict) and ex_data.get("sha"):
                put_body["sha"] = ex_data["sha"]
            _github_api_request(
                "PUT",
                f"/repos/{repo_full_name}/contents/{urllib.parse.quote(gh_path)}",
                token,
                body=put_body,
            )

    # 3. Get latest commit SHA of base_branch
    st_ref, ref_data = _github_api_request(
        "GET", f"/repos/{repo_full_name}/git/ref/heads/{base_branch}", token
    )
    if st_ref != 200 or not isinstance(ref_data, dict):
        return {
            "status": "error",
            "message": f"`{repo_full_name}`의 기본 브랜치(`{base_branch}`) SHA 조회 실패: {ref_data.get('message', st_ref)}",
        }
    base_sha = str((ref_data.get("object") or {}).get("sha") or "")

    # 4. Create new branch `codemender/security-fix-<timestamp>`
    ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    patch_branch = f"codemender/security-fix-{ts_slug}"
    st_br, br_data = _github_api_request(
        "POST",
        f"/repos/{repo_full_name}/git/refs",
        token,
        body={"ref": f"refs/heads/{patch_branch}", "sha": base_sha},
    )
    if st_br not in (200, 201):
        return {
            "status": "error",
            "message": f"패치 브랜치 `{patch_branch}` 생성 실패: {br_data.get('message', st_br)}",
        }

    # 5. Ensure patches are applied to workspace files before committing
    from app.harness.patch_applier import apply_patch_to_workspace

    if pipeline_result is not None:
        for finding in pipeline_result.findings:
            res_patch = apply_patch_to_workspace(
                workspace,
                vuln_id=finding.vuln_id,
                file_path=finding.file_path,
                before_snippet=finding.before_code,
                after_snippet=finding.after_code,
                start_line=getattr(finding, "start_line", None),
                end_line=getattr(finding, "end_line", None),
            )
            if res_patch.applied:
                finding.patch_status = "APPLIED"

    committed_files: list[str] = []
    commit_urls: list[str] = []
    for fmeta in workspace.files:
        o_file = orig_dir / fmeta.relative_path
        p_file = patched_dir / fmeta.relative_path
        orig_bytes = (
            o_file.read_bytes()
            if o_file.exists()
            else (fmeta.orig_content or "").encode("utf-8")
        )
        patched_bytes = (
            p_file.read_bytes()
            if p_file.exists()
            else (fmeta.current_content or fmeta.orig_content).encode("utf-8")
        )
        # Skip untouched files unless a brand-new repo was created
        if not created_new and patched_bytes == orig_bytes:
            continue

        gh_path = file_github_paths.get(
            fmeta.relative_path, fmeta.relative_path
        )
        st_cur, cur_data = _github_api_request(
            "GET",
            f"/repos/{repo_full_name}/contents/{urllib.parse.quote(gh_path)}?ref={urllib.parse.quote(patch_branch)}",
            token,
        )
        put_payload: dict[str, Any] = {
            "message": f"fix(security): apply CodeMender verified patches to {gh_path}",
            "content": base64.b64encode(patched_bytes).decode("ascii"),
            "branch": patch_branch,
        }
        if st_cur == 200 and isinstance(cur_data, dict) and cur_data.get("sha"):
            put_payload["sha"] = cur_data["sha"]

        st_put, put_res = _github_api_request(
            "PUT",
            f"/repos/{repo_full_name}/contents/{urllib.parse.quote(gh_path)}",
            token,
            body=put_payload,
        )
        if st_put in (200, 201) and isinstance(put_res, dict):
            committed_files.append(gh_path)
            c_url = (put_res.get("commit") or {}).get("html_url")
            if c_url:
                commit_urls.append(str(c_url))

    # 6. Build PR summary and also commit SECURITY_AUDIT_CODEMENDER.md if no source file diff was committed yet
    findings_list = pipeline_result.findings if pipeline_result is not None else []
    cwes = sorted({f.cwe_id for f in findings_list})
    pr_title = (
        f"fix(security): remediate {len(findings_list)} verified vulnerabilities ({', '.join(cwes)})"
        if cwes
        else "fix(security): apply CodeMender verified security patches"
    )
    pr_body_lines = [
        "## 🛡️ CodeMender Autonomous Security Remediation Pull Request",
        "",
        f"- **Inference & Verification Model**: `{getattr(pipeline_result, 'model_used', 'gemini-3.8-flash')}`",
        f"- **Verified Vulnerabilities Fixed**: **{len(findings_list)}** (`{', '.join(cwes) or 'N/A'}`)",
        f"- **Modified Files**: `{', '.join(committed_files) or 'SECURITY_AUDIT_CODEMENDER.md'}`",
        f"- **False Positives Filtered in Sandbox**: **{getattr(pipeline_result, 'false_positives_filtered', 0)}**",
        "",
        "### 📋 Verified Findings & LLM-as-a-Judge Verdicts",
        "| Vuln ID | Severity | CWE | Location | Title | Judge Verdict |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for f in findings_list:
        orig_loc = file_github_paths.get(f.file_path, f.file_path)
        pr_body_lines.append(
            f"| `{f.vuln_id}` | **{f.severity}** | `{f.cwe_id}` | `{orig_loc}:{f.start_line}` | {f.title} | **{f.judge_score}/10 ({f.judge_verdict})** |"
        )
    pr_body_lines.extend(
        [
            "",
            "---",
            "*Generated autonomously by CodeMender Security Agent on Google Cloud Gemini Enterprise.*",
        ]
    )
    pr_body_md = "\n".join(pr_body_lines)

    if not committed_files:
        audit_path = "SECURITY_AUDIT_CODEMENDER.md"
        st_aud, aud_data = _github_api_request(
            "GET",
            f"/repos/{repo_full_name}/contents/{audit_path}?ref={urllib.parse.quote(patch_branch)}",
            token,
        )
        aud_payload: dict[str, Any] = {
            "message": "docs(security): add CodeMender verified security audit & remediation report",
            "content": base64.b64encode(pr_body_md.encode("utf-8")).decode("ascii"),
            "branch": patch_branch,
        }
        if st_aud == 200 and isinstance(aud_data, dict) and aud_data.get("sha"):
            aud_payload["sha"] = aud_data["sha"]
        st_put_aud, put_res_aud = _github_api_request(
            "PUT",
            f"/repos/{repo_full_name}/contents/{audit_path}",
            token,
            body=aud_payload,
        )
        if st_put_aud in (200, 201) and isinstance(put_res_aud, dict):
            committed_files.append(audit_path)
            c_url = (put_res_aud.get("commit") or {}).get("html_url")
            if c_url:
                commit_urls.append(str(c_url))

    st_pr, pr_data = _github_api_request(
        "POST",
        f"/repos/{repo_full_name}/pulls",
        token,
        body={
            "title": pr_title,
            "head": patch_branch,
            "base": base_branch,
            "body": pr_body_md,
        },
    )
    pr_url = ""
    pr_number = 0
    if st_pr in (200, 201) and isinstance(pr_data, dict):
        pr_url = str(pr_data.get("html_url") or "")
        pr_number = int(pr_data.get("number") or 0)

    return {
        "status": "ok",
        "repo": repo_full_name,
        "created_new_repo": created_new,
        "base_branch": base_branch,
        "patch_branch": patch_branch,
        "committed_files": committed_files,
        "commit_urls": commit_urls,
        "pr_number": pr_number,
        "pr_url": pr_url,
        "pr_body": pr_body_md,
        "branch_url": f"https://github.com/{repo_full_name}/tree/{patch_branch}",
        "repo_url": f"https://github.com/{repo_full_name}",
    }
