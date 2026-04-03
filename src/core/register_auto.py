"""
Auto.py style registration engine.
"""

import base64
import json
import logging
import random
import secrets
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import urllib3
from curl_cffi import requests as cffi_requests

from ..config.settings import get_settings
from ..database import crud
from ..database.session import get_db
from .registration_result import RegistrationResult
from .openai.chatgpt_flow_utils import decode_jwt_payload, generate_datadog_trace, generate_pkce
from .openai.sentinel_token_v2 import build_sentinel_token

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

AUTH_BASE = "https://auth.openai.com"
_CHROME_PROFILES = [
    {
        "major": 122,
        "impersonate": "chrome122",
        "build": 6261,
        "patch_range": (57, 129),
        "sec_ch_ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    },
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


class AutoStyleRegistrationEngine:
    """Use auto.py like two-phase flow to register and exchange OAuth tokens."""

    def __init__(
        self,
        email_service,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None,
        status_callback: Optional[Callable[[str, Any], None]] = None,
        check_cancelled: Optional[Callable[[], bool]] = None,
        max_retries: Optional[int] = None,
    ):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid
        self.status_callback = status_callback
        self.check_cancelled = check_cancelled or (lambda: False)

        settings = get_settings()
        self.max_retries = max(1, int(max_retries or settings.registration_max_retries or 3))
        self.default_password_length = max(12, int(getattr(settings, "registration_default_password_length", 12) or 12))
        self.settings = settings

        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.email_info: Optional[Dict[str, Any]] = None
        self.logs: List[str] = []
        self._rotate_browser_profile()

    def _rotate_browser_profile(self):
        profile = random.choice(_CHROME_PROFILES)
        patch = random.randint(*profile["patch_range"])
        self.impersonate = profile["impersonate"]
        self.chrome_major = profile["major"]
        self.chrome_full = f"{profile['major']}.0.{profile['build']}.{patch}"
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.chrome_full} Safari/537.36"
        )
        self.sec_ch_ua = profile["sec_ch_ua"]
        self.accept_language = random.choice(_LANGUAGE_PROFILES)

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

    def _is_cancelled(self) -> bool:
        return bool(self.check_cancelled and self.check_cancelled())

    def _raise_if_cancelled(self):
        if self._is_cancelled():
            raise RuntimeError("任务已取消")

    def _log(self, message: str, level: str = "info"):
        tags = {
            "info": "信息",
            "success": "成功",
            "warning": "警告",
            "error": "错误",
            "system": "系统",
        }
        log_message = f"[{tags.get(level.lower(), level.upper())}] {message}"
        self.logs.append(log_message)
        self.callback_logger(log_message)
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def _create_session(self):
        self._rotate_browser_profile()
        session = cffi_requests.Session(impersonate=self.impersonate, timeout=30, verify=False)
        if self.proxy_url:
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        return session

    def _generate_password(self) -> str:
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
        return "".join(secrets.choice(chars) for _ in range(self.default_password_length))

    def _generate_profile(self) -> tuple[str, str, str]:
        from .openai.chatgpt_flow_utils import generate_random_birthday, generate_random_name

        first_name, last_name = generate_random_name()
        birthdate = generate_random_birthday()
        return first_name, last_name, birthdate

    def _prepare_email(self) -> bool:
        try:
            self._raise_if_cancelled()
            self._log(f"正在准备 {self.email_service.service_type.value} 邮箱账户...")
            self.email_info = self.email_service.create_email()
            email = str((self.email_info or {}).get("email") or "").strip()
            if not email:
                self._log("邮箱创建失败: 返回信息不完整", "error")
                return False
            self.email = email
            self._log(f"成功创建邮箱: {self.email}")
            if self.status_callback:
                self.status_callback("running", email=self.email)
            return True
        except Exception as exc:
            self._log(f"创建邮箱失败: {exc}", "error")
            return False

    def _wait_for_verification_code(self, timeout: int = 60) -> str:
        started = time.time()
        used_codes = set()
        self._log(f"正在等待邮箱 {self.email} 的验证码 ({timeout}s)...")
        while time.time() - started < timeout:
            self._raise_if_cancelled()
            kwargs = {
                "email": self.email,
                "email_id": (self.email_info or {}).get("service_id"),
                "timeout": min(8, max(1, int(timeout - (time.time() - started)))),
            }
            try:
                code = self.email_service.get_verification_code(**kwargs)
            except TypeError:
                code = self.email_service.get_verification_code(email=self.email, timeout=kwargs["timeout"])
            if code and code not in used_codes:
                used_codes.add(code)
                self._log(f"成功获取验证码: {code}")
                return code
        return ""

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
            )
            if token:
                headers["openai-sentinel-token"] = token
        return headers

    @staticmethod
    def _extract_code_from_url(url: str) -> str:
        try:
            return str(parse_qs(urlparse(url).query).get("code", [""])[0] or "").strip()
        except Exception:
            return ""

    def _extract_code_from_exception(self, exc: Exception) -> str:
        text = str(exc)
        for marker in ("http://localhost", "https://localhost"):
            idx = text.find(marker)
            if idx != -1:
                return self._extract_code_from_url(text[idx:].split()[0].strip("'\""))
        return ""

    def _follow_and_extract_code(self, session, url: str, max_depth: int = 10) -> str:
        current_url = str(url or "").strip()
        for _ in range(max_depth):
            if not current_url:
                return ""
            try:
                resp = session.get(current_url, headers=self._navigate_headers(), timeout=30, allow_redirects=False)
            except Exception as exc:
                return self._extract_code_from_exception(exc)

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = str(resp.headers.get("Location") or "").strip()
                code = self._extract_code_from_url(loc)
                if code:
                    return code
                current_url = f"{AUTH_BASE}{loc}" if loc.startswith("/") else loc
                continue
            return self._extract_code_from_url(str(resp.url))
        return ""

    def _decode_auth_session(self, session) -> Dict[str, Any]:
        for cookie in session.cookies:
            if cookie.name != "oai-client-auth-session":
                continue
            raw = str(cookie.value or "").split(".")[0]
            raw += "=" * ((4 - len(raw) % 4) % 4)
            try:
                decoded = base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8")
                data = json.loads(decoded)
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
        return {}

    def _exchange_code(self, session, code: str, code_verifier: str) -> Dict[str, Any]:
        resp = session.post(
            self.settings.openai_token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.settings.openai_redirect_uri,
                "client_id": self.settings.openai_client_id,
                "code_verifier": code_verifier,
            },
            timeout=60,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"兑换 Token 失败: HTTP {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def _register_account(self, email: str, password: str, first_name: str, last_name: str, birthdate: str) -> tuple[bool, str]:
        self._log("[阶段 2] 正在初始化授权会话...")
        session = self._create_session()
        device_id = str(uuid.uuid4())
        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")

        code_verifier, code_challenge = generate_pkce()
        authorize_params = {
            "response_type": "code",
            "client_id": self.settings.openai_client_id,
            "redirect_uri": self.settings.openai_redirect_uri,
            "scope": self.settings.openai_scope,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(32),
            "screen_hint": "signup",
            "prompt": "login",
        }
        session.get(f"{AUTH_BASE}/oauth/authorize?{urlencode(authorize_params)}", headers=self._navigate_headers(), timeout=30)

        self._log("[阶段 2] 正在提交身份核验...")
        resp = session.post(
            f"{AUTH_BASE}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}, "screen_hint": "signup"},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/create-account", True, "authorize_continue"),
            timeout=30,
        )
        if resp.status_code != 200:
            return False, f"提交邮箱失败: HTTP {resp.status_code}"

        self._log("[阶段 3] 正在配置账号凭据...")
        resp = session.post(
            f"{AUTH_BASE}/api/accounts/user/register",
            json={"username": email, "password": password},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/create-account/password", True, "password_verify"),
            timeout=30,
        )
        if resp.status_code not in (200, 301, 302):
            return False, f"注册密码失败: HTTP {resp.status_code}"
        self._log("账号凭据配置完成")

        self._log("[阶段 4] 正在分发验证码...")
        nav_headers = self._navigate_headers()
        nav_headers["referer"] = f"{AUTH_BASE}/create-account/password"
        session.get(f"{AUTH_BASE}/api/accounts/email-otp/send", headers=nav_headers, timeout=30)

        self._log("[阶段 5] 正在同步邮箱数据...")
        otp_code = self._wait_for_verification_code(timeout=60)
        if not otp_code:
            return False, "未收到验证码"

        self._log("[阶段 6] 正在核验身份信息...")
        resp = session.post(
            f"{AUTH_BASE}/api/accounts/email-otp/validate",
            json={"code": otp_code},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/email-verification"),
            timeout=30,
        )
        if resp.status_code != 200:
            return False, f"验证码验证失败: HTTP {resp.status_code}"
        self._log("身份核验完成")

        self._log("[阶段 7] 正在完成账户配置...")
        headers = self._build_headers(session, device_id, f"{AUTH_BASE}/about-you")
        headers["openai-sentinel-token"] = build_sentinel_token(session, device_id, user_agent=self.user_agent, sec_ch_ua=self.sec_ch_ua)
        resp = session.post(
            f"{AUTH_BASE}/api/accounts/create_account",
            json={"name": f"{first_name} {last_name}", "birthdate": birthdate},
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 403:
            headers["openai-sentinel-token"] = build_sentinel_token(session, device_id, user_agent=self.user_agent, sec_ch_ua=self.sec_ch_ua)
            resp = session.post(
                f"{AUTH_BASE}/api/accounts/create_account",
                json={"name": f"{first_name} {last_name}", "birthdate": birthdate},
                headers=headers,
                timeout=30,
            )
        if resp.status_code != 200:
            return False, f"创建账户资料失败: HTTP {resp.status_code}: {resp.text[:200]}"
        self._log("账户配置完成")
        self._log("注册主流程已完成")
        return True, "注册成功"

    def _login_and_get_token(self, email: str, password: str, first_name: str, last_name: str, birthdate: str) -> tuple[bool, Dict[str, Any] | str]:
        self._log("[Auto分支] 正在使用独立 OAuth 会话获取 Token...")
        session = self._create_session()
        device_id = str(uuid.uuid4())
        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")

        code_verifier, code_challenge = generate_pkce()
        authorize_params = {
            "response_type": "code",
            "client_id": self.settings.openai_client_id,
            "redirect_uri": self.settings.openai_redirect_uri,
            "scope": self.settings.openai_scope,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(32),
        }
        authorize_url = f"{AUTH_BASE}/oauth/authorize?{urlencode(authorize_params)}"
        session.get(authorize_url, headers=self._navigate_headers(), timeout=30, allow_redirects=True)

        resp = session.post(
            f"{AUTH_BASE}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/log-in", True, "authorize_continue"),
            timeout=30,
        )
        if resp.status_code != 200:
            return False, f"阶段二-提交邮箱失败: HTTP {resp.status_code}"

        resp = session.post(
            f"{AUTH_BASE}/api/accounts/password/verify",
            json={"password": password},
            headers=self._build_headers(session, device_id, f"{AUTH_BASE}/log-in/password", True, "password_verify"),
            timeout=30,
            allow_redirects=False,
        )
        if resp.status_code != 200:
            return False, f"阶段二-密码验证失败: HTTP {resp.status_code}: {resp.text[:200]}"

        data = resp.json()
        continue_url = str(data.get("continue_url") or "").strip()
        page_type = str(((data.get("page") or {}).get("type")) or "").strip()

        if page_type == "email_otp_verification" or "email-verification" in continue_url:
            self._log("[Auto分支] 触发新账号首次登录二次邮箱验证，等待新验证码...")
            otp_code = self._wait_for_verification_code(timeout=60)
            if not otp_code:
                return False, "阶段二-未收到二次验证码"

            resp = session.post(
                f"{AUTH_BASE}/api/accounts/email-otp/validate",
                json={"code": otp_code},
                headers=self._build_headers(session, device_id, f"{AUTH_BASE}/email-verification"),
                timeout=30,
            )
            if resp.status_code != 200:
                return False, f"阶段二-验证码验证失败: HTTP {resp.status_code}"

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

            if not continue_url or "email-verification" in continue_url:
                return False, "邮箱验证后未获取到 consent URL"

        consent_url = f"{AUTH_BASE}{continue_url}" if continue_url.startswith("/") else continue_url
        auth_code = ""

        try:
            r3 = session.get(consent_url, headers=self._navigate_headers(), timeout=30, allow_redirects=False)
            if r3.status_code in (301, 302, 303, 307, 308):
                loc = str(r3.headers.get("Location") or "").strip()
                auth_code = self._extract_code_from_url(loc)
                if not auth_code:
                    auth_code = self._follow_and_extract_code(session, f"{AUTH_BASE}{loc}" if loc.startswith("/") else loc)
        except Exception as exc:
            auth_code = self._extract_code_from_exception(exc)

        if not auth_code:
            session_data = self._decode_auth_session(session)
            workspaces = session_data.get("workspaces", [])
            workspace_id = str((workspaces[0] or {}).get("id") or "").strip() if workspaces else ""
            if workspace_id:
                ws_resp = session.post(
                    f"{AUTH_BASE}/api/accounts/workspace/select",
                    json={"workspace_id": workspace_id},
                    headers={**self._common_headers(), "referer": consent_url, "oai-device-id": device_id, **generate_datadog_trace()},
                    timeout=30,
                    allow_redirects=False,
                )
                if ws_resp.status_code in (301, 302, 303, 307, 308):
                    auth_code = self._extract_code_from_url(str(ws_resp.headers.get("Location") or "").strip())
                elif ws_resp.status_code == 200:
                    ws_data = ws_resp.json()
                    ws_next = str(ws_data.get("continue_url") or "").strip()
                    ws_page = str(((ws_data.get("page") or {}).get("type")) or "").strip()
                    if "organization" in ws_next or "organization" in ws_page:
                        orgs = ((ws_data.get("data") or {}).get("orgs")) or []
                        org = orgs[0] if orgs else {}
                        org_id = str((org or {}).get("id") or "").strip()
                        projects = (org or {}).get("projects") or []
                        project_id = str((projects[0] or {}).get("id") or "").strip() if projects else ""
                        if org_id:
                            body = {"org_id": org_id}
                            if project_id:
                                body["project_id"] = project_id
                            org_resp = session.post(
                                f"{AUTH_BASE}/api/accounts/organization/select",
                                json=body,
                                headers={**self._common_headers(), "referer": ws_next or consent_url, "oai-device-id": device_id, **generate_datadog_trace()},
                                timeout=30,
                                allow_redirects=False,
                            )
                            if org_resp.status_code in (301, 302, 303, 307, 308):
                                loc = str(org_resp.headers.get("Location") or "").strip()
                                auth_code = self._extract_code_from_url(loc)
                                if not auth_code:
                                    auth_code = self._follow_and_extract_code(session, f"{AUTH_BASE}{loc}" if loc.startswith("/") else loc)
                            elif org_resp.status_code == 200:
                                org_next = str((org_resp.json() or {}).get("continue_url") or "").strip()
                                if org_next:
                                    auth_code = self._follow_and_extract_code(session, f"{AUTH_BASE}{org_next}" if org_next.startswith("/") else org_next)
                    elif ws_next:
                        auth_code = self._follow_and_extract_code(session, f"{AUTH_BASE}{ws_next}" if ws_next.startswith("/") else ws_next)

        if not auth_code:
            try:
                fallback = session.get(consent_url, headers=self._navigate_headers(), timeout=30, allow_redirects=True)
                auth_code = self._extract_code_from_url(str(fallback.url))
                if not auth_code:
                    for hist in fallback.history:
                        auth_code = self._extract_code_from_url(str(hist.headers.get("Location") or "").strip())
                        if auth_code:
                            break
            except Exception as exc:
                auth_code = self._extract_code_from_exception(exc)

        if not auth_code:
            return False, "提取 Code 失败(已被拦截或未响应)"

        token_data = self._exchange_code(session, auth_code, code_verifier)
        access_token = str(token_data.get("access_token") or "").strip()
        refresh_token = str(token_data.get("refresh_token") or "").strip()
        id_token = str(token_data.get("id_token") or "").strip()
        jwt_payload = decode_jwt_payload(id_token) or decode_jwt_payload(access_token)
        auth_claims = jwt_payload.get("https://api.openai.com/auth") or {}
        token_data["account_id"] = str(auth_claims.get("chatgpt_account_id") or "").strip()
        token_data["workspace_id"] = (
            str(auth_claims.get("organization_id") or "").strip()
            or str(auth_claims.get("org_id") or "").strip()
            or token_data["account_id"]
        )
        token_data["user_id"] = (
            str(auth_claims.get("chatgpt_user_id") or "").strip()
            or str(auth_claims.get("user_id") or "").strip()
        )
        token_data["session_token"] = str(session.cookies.get("__Secure-next-auth.session-token") or "").strip()
        token_data["access_token"] = access_token
        token_data["refresh_token"] = refresh_token
        token_data["id_token"] = id_token
        return True, token_data

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)
        last_error = ""
        try:
            for attempt in range(self.max_retries):
                try:
                    self._raise_if_cancelled()
                    if attempt == 0:
                        self._log("-" * 40)
                        self._log("注册引擎: 流程启动")
                        self._log("-" * 40)
                    else:
                        self._log(f"整流程重试 {attempt + 1}/{self.max_retries} ...")
                        time.sleep(1)

                    self.email = None
                    self.email_info = None
                    self.password = None
                    self._log("[阶段 1] 正在开通邮箱账户...")
                    if not self._prepare_email():
                        result.error_message = "邮箱账户开通失败"
                        return result

                    result.email = self.email or ""
                    pwd = self._generate_password()
                    self.password = pwd
                    result.password = pwd
                    first_name, last_name, birthdate = self._generate_profile()
                    self._log(f"邮箱账户: {result.email}")

                    ok, msg = self._register_account(result.email, pwd, first_name, last_name, birthdate)
                    if not ok:
                        last_error = str(msg)
                        if attempt < self.max_retries - 1:
                            self._log(f"注册流失败，准备整流程重试: {last_error}", "warning")
                            continue
                        result.error_message = last_error
                        return result

                    self._log("[阶段 8] 正在通过 OAuth 登录补全 Token...")
                    ok, token_or_error = self._login_and_get_token(result.email, pwd, first_name, last_name, birthdate)
                    if not ok:
                        last_error = str(token_or_error)
                        if attempt < self.max_retries - 1:
                            self._log(f"Token 获取失败，准备整流程重试: {last_error}", "warning")
                            continue
                        result.error_message = last_error
                        return result

                    token_data = token_or_error
                    result.success = True
                    result.access_token = str(token_data.get("access_token") or "")
                    result.refresh_token = str(token_data.get("refresh_token") or "")
                    result.id_token = str(token_data.get("id_token") or "")
                    result.session_token = str(token_data.get("session_token") or "")
                    result.account_id = str(token_data.get("account_id") or "")
                    result.workspace_id = str(token_data.get("workspace_id") or "")
                    result.source = "register"
                    result.metadata = {
                        "email_service": self.email_service.service_type.value,
                        "proxy_used": self.proxy_url,
                        "registered_at": datetime.now().isoformat(),
                        "registration_engine": "legacy_auto",
                        "oauth_user_id": str(token_data.get("user_id") or ""),
                        "oauth_expires_in": int(token_data.get("expires_in") or 0),
                        "oauth_token_type": str(token_data.get("token_type") or ""),
                    }
                    self._log("-" * 40)
                    self._log("注册: 流程执行成功", "success")
                    self._log(f"邮箱账户: {result.email}")
                    if result.account_id:
                        self._log(f"账号 ID: {result.account_id}")
                    if result.workspace_id:
                        self._log(f"组织 ID: {result.workspace_id}")
                    self._log("-" * 40)
                    return result
                except Exception as exc:
                    last_error = str(exc)
                    if attempt < self.max_retries - 1:
                        self._log(f"本轮出现异常，准备整流程重试: {last_error}", "warning")
                        continue
                    raise
            result.error_message = last_error or "注册失败"
            return result
        except Exception as exc:
            if str(exc) == "任务已取消":
                self._log("注册流程已收到取消信号", "warning")
                result.error_message = "任务已取消"
                return result
            self._log(f"Auto 注册全流程执行异常: {exc}", "error")
            result.error_message = str(exc)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        if not result.success:
            return False
        try:
            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=self.settings.openai_client_id,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=(self.email_info or {}).get("service_id"),
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source,
                )
                self._log(f"数据持久化操作完成. 数据库 ID: {account.id}")
                return True
        except Exception as exc:
            self._log(f"保存到数据库失败: {exc}", "error")
            return False
