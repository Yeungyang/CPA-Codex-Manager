"""
Legacy OAuth registration engine.
"""

import json
from typing import Any, Dict

from .register_auto import AutoStyleRegistrationEngine, AUTH_BASE
from .openai.oauth_legacy import OAuthManager


class LegacyOAuthRegistrationEngine(AutoStyleRegistrationEngine):
    """Restore the pre-V2 OAuth callback exchange path as a third engine."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.oauth_manager = OAuthManager(
            client_id=self.settings.openai_client_id,
            auth_url=self.settings.openai_auth_url,
            token_url=self.settings.openai_token_url,
            redirect_uri=self.settings.openai_redirect_uri,
            scope=self.settings.openai_scope,
            proxy_url=self.proxy_url,
        )

    def _follow_and_extract_callback_url(self, session, url: str, max_depth: int = 12) -> str:
        current_url = str(url or "").strip()
        for _ in range(max_depth):
            if not current_url:
                return ""
            try:
                resp = session.get(current_url, headers=self._navigate_headers(), timeout=30, allow_redirects=False)
            except Exception as exc:
                text = str(exc)
                if "code=" in text:
                    start = text.find("http://localhost")
                    if start == -1:
                        start = text.find("https://localhost")
                    if start != -1:
                        return text[start:].split()[0].strip("'\"")
                return ""

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = str(resp.headers.get("Location") or "").strip()
                if "code=" in loc:
                    return loc if "://" in loc else f"{AUTH_BASE}{loc}"
                current_url = f"{AUTH_BASE}{loc}" if loc.startswith("/") else loc
                continue

            final_url = str(resp.url)
            if "code=" in final_url:
                return final_url
            return ""
        return ""

    def _login_and_get_token(self, email: str, password: str, first_name: str, last_name: str, birthdate: str) -> tuple[bool, Dict[str, Any] | str]:
        self._log("[LegacyOAuth分支] 正在使用旧版 OAuth 链路获取 Token...")
        session = self._create_session()
        device_id = self._prepare_device_cookie(session)

        oauth_start = self.oauth_manager.start_oauth()
        session.get(oauth_start.auth_url, headers=self._navigate_headers(), timeout=30, allow_redirects=True)

        resp = session.post(
            f"{AUTH_BASE}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/log-in", True, "authorize_continue"),
            timeout=30,
        )
        if resp.status_code != 200:
            return False, f"旧版链路-提交邮箱失败: HTTP {resp.status_code}"

        resp = session.post(
            f"{AUTH_BASE}/api/accounts/password/verify",
            json={"password": password},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/log-in/password", True, "password_verify"),
            timeout=30,
            allow_redirects=False,
        )
        if resp.status_code != 200:
            return False, f"旧版链路-密码验证失败: HTTP {resp.status_code}: {resp.text[:200]}"

        data = resp.json()
        continue_url = str(data.get("continue_url") or "").strip()
        page_type = str(((data.get("page") or {}).get("type")) or "").strip()

        if page_type == "email_otp_verification" or "email-verification" in continue_url:
            self._log("[LegacyOAuth分支] 触发二次邮箱验证，等待新验证码...")
            otp_code = self._wait_for_verification_code(timeout=60)
            if not otp_code:
                return False, "旧版链路-未收到二次验证码"

            resp = session.post(
                f"{AUTH_BASE}/api/accounts/email-otp/validate",
                json={"code": otp_code},
                headers=self._build_headers(session, device_id, f"{AUTH_BASE}/email-verification"),
                timeout=30,
            )
            if resp.status_code != 200:
                return False, f"旧版链路-验证码验证失败: HTTP {resp.status_code}"

            data = resp.json()
            continue_url = str(data.get("continue_url") or "").strip()
            page_type = str(((data.get("page") or {}).get("type")) or "").strip()

            if continue_url and "about-you" in continue_url:
                about_headers = self._navigate_headers()
                about_headers["referer"] = f"{AUTH_BASE}/email-verification"
                about_resp = session.get(f"{AUTH_BASE}/about-you", headers=about_headers, timeout=30, allow_redirects=True)
                if "consent" in str(about_resp.url) or "organization" in str(about_resp.url):
                    continue_url = str(about_resp.url)
                else:
                    create_headers = self._build_headers(session, device_id, f"{AUTH_BASE}/about-you")
                    resp_create = session.post(
                        f"{AUTH_BASE}/api/accounts/create_account",
                        json={"name": f"{first_name} {last_name}", "birthdate": birthdate},
                        headers=create_headers,
                        timeout=30,
                    )
                    if resp_create.status_code == 200:
                        continue_url = str((resp_create.json() or {}).get("continue_url") or "").strip()
                    elif resp_create.status_code == 400 and "already_exists" in resp_create.text:
                        continue_url = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"

            if "consent" in page_type and not continue_url:
                continue_url = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"

        consent_url = f"{AUTH_BASE}{continue_url}" if continue_url.startswith("/") else continue_url
        if not consent_url:
            return False, "旧版链路-未获取到 consent URL"

        callback_url = self._follow_and_extract_callback_url(session, consent_url)
        if not callback_url:
            session_data = self._decode_auth_session(session)
            workspaces = session_data.get("workspaces", [])
            workspace_id = str((workspaces[0] or {}).get("id") or "").strip() if workspaces else ""
            if workspace_id:
                ws_resp = session.post(
                    f"{AUTH_BASE}/api/accounts/workspace/select",
                    json={"workspace_id": workspace_id},
                    headers={**self._common_headers(), "referer": consent_url, "oai-device-id": device_id, **self._trace_headers()},
                    timeout=30,
                    allow_redirects=False,
                )
                if ws_resp.status_code in (301, 302, 303, 307, 308):
                    loc = str(ws_resp.headers.get("Location") or "").strip()
                    callback_url = loc if "code=" in loc else self._follow_and_extract_callback_url(session, f"{AUTH_BASE}{loc}" if loc.startswith("/") else loc)
                elif ws_resp.status_code == 200:
                    ws_data = ws_resp.json()
                    ws_next = str(ws_data.get("continue_url") or "").strip()
                    if ws_next:
                        callback_url = self._follow_and_extract_callback_url(session, f"{AUTH_BASE}{ws_next}" if ws_next.startswith("/") else ws_next)

        if not callback_url:
            return False, "旧版链路-未获取到 callback URL"

        token_info = self.oauth_manager.handle_callback(
            callback_url=callback_url,
            expected_state=oauth_start.state,
            code_verifier=oauth_start.code_verifier,
        )

        if isinstance(token_info, str):
            token_data = json.loads(token_info)
        else:
            token_data = token_info

        token_data["session_token"] = str(session.cookies.get("__Secure-next-auth.session-token") or "").strip()
        token_data["workspace_id"] = token_data.get("account_id", "")
        token_data["user_id"] = ""
        return True, token_data

    def _prepare_device_cookie(self, session) -> str:
        import uuid
        from .openai.chatgpt_flow_utils import seed_oai_device_cookie

        device_id = str(uuid.uuid4())
        seed_oai_device_cookie(session, device_id)
        return device_id

    def _trace_headers(self):
        from .openai.chatgpt_flow_utils import generate_datadog_trace
        return generate_datadog_trace()
