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
)
from .sentinel_token_v2 import build_sentinel_token


logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)
DEFAULT_SEC_CH_UA = '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"'
AUTH_BASE = "https://auth.openai.com"
COMMON_HEADERS = {
    "accept": "application/json",
    "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "content-type": "application/json",
    "origin": AUTH_BASE,
    "user-agent": DEFAULT_USER_AGENT,
    "sec-ch-ua": DEFAULT_SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}
NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "user-agent": DEFAULT_USER_AGENT,
    "sec-ch-ua": DEFAULT_SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}


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

    def _log(self, message: str) -> None:
        self.log_fn(message)

    def _create_session(self):
        session = curl_requests.Session(impersonate="chrome136")
        if self.proxy_url:
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        return session

    def _seed_device_cookie(self, session, device_id: str) -> None:
        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")

    def _build_headers(self, session, device_id: str, referer: str, with_sentinel: bool = False, flow: str = "") -> Dict[str, str]:
        headers = dict(COMMON_HEADERS)
        headers["referer"] = referer
        headers["oai-device-id"] = device_id
        headers.update(generate_datadog_trace())
        if with_sentinel:
            token = build_sentinel_token(
                session,
                device_id,
                flow=flow or "authorize_continue",
                user_agent=DEFAULT_USER_AGENT,
                sec_ch_ua=DEFAULT_SEC_CH_UA,
                impersonate="chrome136",
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
                response = session.get(current_url, headers=NAVIGATE_HEADERS, timeout=30, allow_redirects=False)
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

    def complete_after_registration(
        self,
        *,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        birthdate: str,
        email_adapter=None,
    ) -> OAuthCompletionResult:
        """注册成功后，用独立 OAuth 登录流程补全 refresh_token。"""
        session = self._create_session()
        device_id = str(uuid.uuid4())
        self._seed_device_cookie(session, device_id)

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

        self._log("[OAuth补全] 正在初始化独立授权会话...")
        session.get(authorize_url, headers=NAVIGATE_HEADERS, allow_redirects=True, timeout=30)

        self._log("[OAuth补全] 正在提交登录邮箱...")
        email_url = f"{AUTH_BASE}/api/accounts/authorize/continue"
        email_resp = session.post(
            email_url,
            json={"username": {"kind": "email", "value": email}},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/log-in", True, "authorize_continue"),
            timeout=30,
        )
        if email_resp.status_code != 200:
            raise RuntimeError(f"OAuth 登录提交邮箱失败: HTTP {email_resp.status_code}: {email_resp.text[:200]}")

        self._log("[OAuth补全] 正在提交登录密码...")
        password_url = f"{AUTH_BASE}/api/accounts/password/verify"
        password_resp = session.post(
            password_url,
            json={"password": password},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/log-in/password", True, "password_verify"),
            timeout=30,
            allow_redirects=False,
        )
        if password_resp.status_code != 200:
            raise RuntimeError(f"OAuth 登录密码验证失败: HTTP {password_resp.status_code}: {password_resp.text[:200]}")

        data = password_resp.json()
        continue_url = str(data.get("continue_url") or "").strip()
        page_type = str(((data.get("page") or {}).get("type")) or "").strip().lower()

        if page_type == "email_otp_verification" or "email-verification" in continue_url:
            if email_adapter is None:
                raise RuntimeError("OAuth 登录触发二次邮箱验证，但当前没有可用邮箱适配器")
            self._log("[OAuth补全] 触发二次邮箱验证，正在等待新验证码...")
            otp_code = email_adapter.wait_for_verification_code(email, timeout=60)
            if not otp_code:
                raise RuntimeError("OAuth 登录未收到二次邮箱验证码")

            otp_url = f"{AUTH_BASE}/api/accounts/email-otp/validate"
            otp_resp = session.post(
                otp_url,
                json={"code": otp_code},
                headers=self._build_headers(session, device_id, f"{AUTH_BASE}/email-verification"),
                timeout=30,
            )
            if otp_resp.status_code != 200:
                raise RuntimeError(f"OAuth 登录二次邮箱验证失败: HTTP {otp_resp.status_code}: {otp_resp.text[:200]}")

            data = otp_resp.json()
            continue_url = str(data.get("continue_url") or "").strip()
            page_type = str(((data.get("page") or {}).get("type")) or "").strip().lower()

            if continue_url and "about-you" in continue_url:
                about_url = f"{AUTH_BASE}/about-you"
                about_headers = dict(NAVIGATE_HEADERS)
                about_headers["referer"] = f"{AUTH_BASE}/email-verification"
                about_resp = session.get(about_url, headers=about_headers, timeout=30, allow_redirects=True)

                final_about_url = str(about_resp.url)
                if "consent" in final_about_url or "organization" in final_about_url:
                    continue_url = final_about_url
                else:
                    create_url = f"{AUTH_BASE}/api/accounts/create_account"
                    create_headers = self._build_headers(session, device_id, about_url)
                    create_headers["openai-sentinel-token"] = build_sentinel_token(
                        session,
                        device_id,
                        user_agent=DEFAULT_USER_AGENT,
                        sec_ch_ua=DEFAULT_SEC_CH_UA,
                        impersonate="chrome136",
                    )
                    create_resp = session.post(
                        create_url,
                        json={"name": f"{first_name} {last_name}", "birthdate": birthdate},
                        headers=create_headers,
                        timeout=30,
                    )
                    if create_resp.status_code == 200:
                        continue_url = str((create_resp.json() or {}).get("continue_url") or "").strip()

            if "consent" in page_type and not continue_url:
                continue_url = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"

        consent_url = continue_url
        if not consent_url:
            consent_state = extract_flow_state(data, current_url=str(password_resp.url))
            consent_url = consent_state.continue_url or consent_state.current_url
        if consent_url.startswith("/"):
            consent_url = f"{AUTH_BASE}{consent_url}"
        if not consent_url:
            raise RuntimeError("OAuth 登录后未获得 consent URL")

        self._log("[OAuth补全] 正在推进 consent / workspace / organization 链路...")
        auth_code = ""
        consent_resp = session.get(consent_url, headers=NAVIGATE_HEADERS, timeout=30, allow_redirects=False)
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
                    headers={**COMMON_HEADERS, "referer": consent_url, "oai-device-id": device_id, **generate_datadog_trace()},
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
                            headers={**COMMON_HEADERS, "referer": next_url or consent_url, "oai-device-id": device_id, **generate_datadog_trace()},
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
            fallback_resp = session.get(consent_url, headers=NAVIGATE_HEADERS, timeout=30, allow_redirects=True)
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
