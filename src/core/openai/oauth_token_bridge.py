"""
OAuth token completion for the V2 registration flow.
"""

import base64
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from curl_cffi import requests as curl_requests

from ...config.settings import get_settings
from .chatgpt_flow_utils import (
    decode_jwt_payload,
    extract_flow_state,
    generate_datadog_trace,
    generate_pkce,
    seed_oai_device_cookie,
)
from .sentinel_token_v2 import build_sentinel_token


logger = logging.getLogger(__name__)

AUTH_BASE = "https://auth.openai.com"
_CHROME_PROFILES = [
    {
        "major": 131,
        "impersonate": "chrome131",
        "build": 6778,
        "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133,
        "impersonate": "chrome133a",
        "build": 6943,
        "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136,
        "impersonate": "chrome136",
        "build": 7103,
        "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
]
_LANGUAGE_PROFILES = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "en,en-US;q=0.9",
    "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
]


@dataclass
class OAuthCompletionResult:
    """OAuth 补全结果。"""

    success: bool
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    expires_in: int = 0
    account_id: str = ""
    user_id: str = ""
    workspace_id: str = ""
    error_message: str = ""
    raw_token: Dict[str, Any] = None


class OAuthTokenBridge:
    """在 V2 注册成功后补全标准 OAuth token 套件。"""

    def __init__(
        self,
        *,
        proxy_url: Optional[str] = None,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.proxy_url = proxy_url
        self.log_fn = log_fn or (lambda msg: logger.info(msg))
        self.settings = get_settings()
        self._rotate_browser_profile()

    def _log(self, message: str) -> None:
        self.log_fn(message)

    def _rotate_browser_profile(self):
        profile = secrets.choice(_CHROME_PROFILES)
        patch_low, patch_high = profile["patch_range"]
        patch = int(secrets.randbelow(patch_high - patch_low + 1)) + patch_low
        self.impersonate = profile["impersonate"]
        self.chrome_full = f"{profile['major']}.0.{profile['build']}.{patch}"
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.chrome_full} Safari/537.36"
        )
        self.sec_ch_ua = profile["sec_ch_ua"]
        self.accept_language = secrets.choice(_LANGUAGE_PROFILES)

    def _common_headers(self) -> Dict[str, str]:
        return {
            "accept": "application/json",
            "accept-language": self.accept_language,
            "content-type": "application/json",
            "origin": AUTH_BASE,
            "user-agent": self.user_agent,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "priority": "u=1, i",
        }

    def _navigate_headers(self) -> Dict[str, str]:
        return {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": self.accept_language,
            "user-agent": self.user_agent,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
        }

    def _create_session(self):
        self._rotate_browser_profile()
        session = curl_requests.Session(impersonate=self.impersonate, timeout=30, verify=False)
        if self.proxy_url:
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept-Language": self.accept_language,
                "sec-ch-ua": self.sec_ch_ua,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
        )
        return session

    def _seed_device_cookie(self, session, device_id: str) -> None:
        seed_oai_device_cookie(session, device_id)

    def _build_headers(self, session, device_id: str, referer: str, with_sentinel: bool = False, flow: str = "") -> Dict[str, str]:
        headers = self._common_headers()
        headers["referer"] = referer
        headers["oai-device-id"] = device_id
        headers.update(generate_datadog_trace())
        if with_sentinel:
            token = build_sentinel_token(
                session,
                device_id,
                flow=flow or "authorize_continue",
                user_agent=self.user_agent,
                sec_ch_ua=self.sec_ch_ua,
                impersonate=self.impersonate,
            )
            if token:
                headers["openai-sentinel-token"] = token
        return headers

    def _extract_code_from_url(self, url: str) -> str:
        if not url or "code=" not in url:
            return ""
        try:
            return str(parse_qs(urlparse(url).query).get("code", [""])[0] or "").strip()
        except Exception:
            return ""

    def _follow_and_extract_code(self, session, url: str, max_depth: int = 10) -> str:
        current_url = str(url or "").strip()
        for _ in range(max_depth):
            if not current_url:
                return ""
            try:
                response = session.get(current_url, headers=self._navigate_headers(), timeout=30, allow_redirects=False)
            except Exception as exc:
                return self._extract_code_from_url(str(exc))

            redirect_url = str(response.headers.get("Location") or "").strip()
            if response.status_code in {301, 302, 303, 307, 308} and redirect_url:
                code = self._extract_code_from_url(redirect_url)
                if code:
                    return code
                current_url = f"{AUTH_BASE}{redirect_url}" if redirect_url.startswith("/") else redirect_url
                continue

            return self._extract_code_from_url(str(response.url))

        return ""

    def _decode_auth_session(self, session) -> Dict[str, Any]:
        for cookie in session.cookies.jar:
            if cookie.name != "oai-client-auth-session":
                continue
            raw = str(cookie.value or "").split(".")[0]
            if not raw:
                continue
            raw += "=" * ((4 - len(raw) % 4) % 4)
            try:
                import base64

                decoded = base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8")
                data = json.loads(decoded)
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
        return {}

    def _extract_code_from_exception(self, exc: Exception) -> str:
        text = str(exc)
        start = text.find("http://localhost")
        if start == -1:
            start = text.find("https://localhost")
        if start == -1:
            return ""
        candidate = text[start:].split()[0].strip('\'"')
        return self._extract_code_from_url(candidate)

    def _post_token_exchange(self, session, code: str, code_verifier: str) -> OAuthCompletionResult:
        token_url = self.settings.openai_token_url
        response = session.post(
            token_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.settings.openai_redirect_uri,
                "client_id": self.settings.openai_client_id,
                "code_verifier": code_verifier,
            },
            timeout=60,
        )

        if response.status_code != 200:
            return OAuthCompletionResult(
                success=False,
                error_message=f"/oauth/token 返回 HTTP {response.status_code}: {response.text[:200]}",
            )

        try:
            token_data = response.json()
        except Exception as exc:
            return OAuthCompletionResult(success=False, error_message=f"/oauth/token 返回非 JSON: {exc}")

        access_token = str(token_data.get("access_token") or "").strip()
        refresh_token = str(token_data.get("refresh_token") or "").strip()
        id_token = str(token_data.get("id_token") or "").strip()

        jwt_payload = decode_jwt_payload(id_token) or decode_jwt_payload(access_token)
        auth_claims = jwt_payload.get("https://api.openai.com/auth") or {}
        account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()
        user_id = (
            str(auth_claims.get("chatgpt_user_id") or "").strip()
            or str(auth_claims.get("user_id") or "").strip()
        )
        organization_id = (
            str(auth_claims.get("organization_id") or "").strip()
            or str(auth_claims.get("org_id") or "").strip()
            or account_id
        )

        return OAuthCompletionResult(
            success=bool(access_token),
            access_token=access_token,
            refresh_token=refresh_token,
            id_token=id_token,
            expires_in=int(token_data.get("expires_in") or 0),
            account_id=account_id,
            user_id=user_id,
            workspace_id=organization_id,
            error_message="" if access_token else "OAuth token 响应缺少 access_token",
            raw_token=token_data,
        )

    def complete_from_authenticated_session(
        self,
        *,
        session,
        device_id: str,
        user_agent: str,
        sec_ch_ua: str,
        impersonate: str,
    ) -> OAuthCompletionResult:
        """复用已认证会话推进 OAuth consent/code exchange。"""
        self.user_agent = user_agent
        self.sec_ch_ua = sec_ch_ua
        self.impersonate = impersonate
        self.accept_language = self.accept_language or "en-US,en;q=0.9"
        code_verifier, code_challenge = generate_pkce()
        state = secrets.token_urlsafe(32)
        authorize_url = (
            f"{self.settings.openai_auth_url}?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": self.settings.openai_client_id,
                    "redirect_uri": self.settings.openai_redirect_uri,
                    "scope": self.settings.openai_scope,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "state": state,
                }
            )
        )

        self._log("[OAuth补全] 正在复用已认证会话发起 OAuth authorize...")
        authorize_resp = session.get(authorize_url, headers=self._navigate_headers(), allow_redirects=True, timeout=30)
        final_url = str(authorize_resp.url)
        auth_code = self._extract_code_from_url(final_url)
        if not auth_code and authorize_resp.history:
            for history_response in authorize_resp.history:
                auth_code = self._extract_code_from_url(str(history_response.headers.get("Location") or "").strip())
                if auth_code:
                    break

        if auth_code:
            self._log("[OAuth补全] authorize 直接返回 code，准备兑换 token...")
            return self._post_token_exchange(session, auth_code, code_verifier)

        consent_state = extract_flow_state(current_url=final_url)
        consent_url = consent_state.continue_url or consent_state.current_url
        if consent_url.startswith("/"):
            consent_url = f"{AUTH_BASE}{consent_url}"
        if not consent_url:
            raise RuntimeError("OAuth 登录后未获得 consent URL")

        self._log("[OAuth补全] 正在推进 consent / workspace / organization 链路...")
        auth_code = ""
        consent_resp = session.get(consent_url, headers=self._navigate_headers(), timeout=30, allow_redirects=False)
        if consent_resp.status_code in {301, 302, 303, 307, 308}:
            redirect_url = str(consent_resp.headers.get("Location") or "").strip()
            auth_code = self._extract_code_from_url(redirect_url) or self._follow_and_extract_code(
                session,
                f"{AUTH_BASE}{redirect_url}" if redirect_url.startswith("/") else redirect_url,
            )

        if not auth_code:
            session_data = self._decode_auth_session(session)
            workspaces = session_data.get("workspaces") or []
            workspace_id = str((workspaces[0] or {}).get("id") or "").strip() if workspaces else ""
            if workspace_id:
                workspace_url = f"{AUTH_BASE}/api/accounts/workspace/select"
                workspace_resp = session.post(
                    workspace_url,
                    json={"workspace_id": workspace_id},
                    headers={**self._common_headers(), "referer": consent_url, "oai-device-id": device_id, **generate_datadog_trace()},
                    timeout=30,
                    allow_redirects=False,
                )
                if workspace_resp.status_code in {301, 302, 303, 307, 308}:
                    auth_code = self._extract_code_from_url(str(workspace_resp.headers.get("Location") or "").strip())
                elif workspace_resp.status_code == 200:
                    workspace_data = workspace_resp.json()
                    next_url = str(workspace_data.get("continue_url") or "").strip()
                    orgs = ((workspace_data.get("data") or {}).get("orgs")) or []
                    org = orgs[0] if orgs else {}
                    org_id = str((org or {}).get("id") or "").strip()
                    projects = (org or {}).get("projects") or []
                    project_id = str((projects[0] or {}).get("id") or "").strip() if projects else ""

                    if org_id:
                        org_url = f"{AUTH_BASE}/api/accounts/organization/select"
                        body = {"org_id": org_id}
                        if project_id:
                            body["project_id"] = project_id
                        org_resp = session.post(
                            org_url,
                            json=body,
                            headers={**self._common_headers(), "referer": next_url or consent_url, "oai-device-id": device_id, **generate_datadog_trace()},
                            timeout=30,
                            allow_redirects=False,
                        )
                        if org_resp.status_code in {301, 302, 303, 307, 308}:
                            redirect_url = str(org_resp.headers.get("Location") or "").strip()
                            auth_code = self._extract_code_from_url(redirect_url) or self._follow_and_extract_code(
                                session,
                                f"{AUTH_BASE}{redirect_url}" if redirect_url.startswith("/") else redirect_url,
                            )
                        elif org_resp.status_code == 200:
                            org_data = org_resp.json()
                            next_url = str(org_data.get("continue_url") or "").strip()
                            if next_url:
                                auth_code = self._follow_and_extract_code(
                                    session,
                                    f"{AUTH_BASE}{next_url}" if next_url.startswith("/") else next_url,
                                )
                    elif next_url:
                        auth_code = self._follow_and_extract_code(
                            session,
                            f"{AUTH_BASE}{next_url}" if next_url.startswith("/") else next_url,
                        )

        if not auth_code:
            fallback_resp = session.get(consent_url, headers=self._navigate_headers(), timeout=30, allow_redirects=True)
            auth_code = self._extract_code_from_url(str(fallback_resp.url))
            if not auth_code:
                for history_response in fallback_resp.history:
                    auth_code = self._extract_code_from_url(str(history_response.headers.get("Location") or "").strip())
                    if auth_code:
                        break

        if not auth_code:
            raise RuntimeError("OAuth consent 链路未提取到 authorization code")

        self._log("[OAuth补全] 已拿到 authorization code，正在兑换 token...")
        return self._post_token_exchange(session, auth_code, code_verifier)
