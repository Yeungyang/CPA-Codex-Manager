"""
Legacy full registration engine restored from pre-V2 flow.
"""

import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Tuple

from curl_cffi import requests as cffi_requests

from .openai.oauth_legacy import OAuthManager, OAuthStart
from .http_client import OpenAIHTTPClient
from .registration_result import RegistrationResult
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
)
from ..config.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass
class SignupFormResult:
    success: bool
    page_type: str = ""
    is_existing_account: bool = False
    response_data: Dict[str, Any] = None
    error_message: str = ""


class LegacyFullRegistrationEngine:
    """Complete legacy registration flow with OAuth callback exchange."""

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

        self.http_client = OpenAIHTTPClient(proxy_url=proxy_url)
        settings = get_settings()
        self.oauth_manager = OAuthManager(
            client_id=settings.openai_client_id,
            auth_url=settings.openai_auth_url,
            token_url=settings.openai_token_url,
            redirect_uri=settings.openai_redirect_uri,
            scope=settings.openai_scope,
            proxy_url=proxy_url,
        )
        self.max_retries = max(1, int(max_retries or settings.registration_max_retries or 3))

        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.email_info: Optional[Dict[str, Any]] = None
        self.oauth_start: Optional[OAuthStart] = None
        self.session: Optional[cffi_requests.Session] = None
        self.session_token: Optional[str] = None
        self.logs = []
        self._otp_sent_at: Optional[float] = None
        self._is_existing_account: bool = False
        self._token_acquisition_requires_login: bool = False

    def _raise_if_cancelled(self):
        if self.check_cancelled and self.check_cancelled():
            raise RuntimeError("任务已取消")

    def _log(self, message: str, level: str = "info"):
        tags = {"info": "信息", "success": "成功", "warning": "警告", "error": "错误", "system": "系统"}
        log_message = f"[{tags.get(level.lower(), level.upper())}] {message}"
        self.logs.append(log_message)
        self.callback_logger(log_message)
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception:
                pass

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        return "".join(secrets.choice(PASSWORD_CHARSET) for _ in range(length))

    def _check_ip_location(self) -> Tuple[bool, Optional[str]]:
        try:
            return self.http_client.check_ip_location()
        except Exception as exc:
            self._log(f"检查 IP 地理位置失败: {exc}", "error")
            return False, None

    def _create_email(self) -> bool:
        try:
            self._log(f"正在准备 {self.email_service.service_type.value} 邮箱账户...")
            self.email_info = self.email_service.create_email()
            if not self.email_info or "email" not in self.email_info:
                self._log("邮箱创建失败: 返回信息不完整", "error")
                return False
            self.email = self.email_info["email"]
            self._log(f"成功创建邮箱: {self.email}")
            if self.status_callback:
                self.status_callback("running", email=self.email)
            return True
        except Exception as exc:
            self._log(f"创建邮箱失败: {exc}", "error")
            return False

    def _start_oauth(self) -> bool:
        try:
            self.oauth_start = self.oauth_manager.start_oauth()
            self._log(f"已生成授权 URL: {self.oauth_start.auth_url[:60]}...")
            return True
        except Exception as exc:
            self._log(f"生成 OAuth URL 失败: {exc}", "error")
            return False

    def _init_session(self) -> bool:
        try:
            self.session = self.http_client.session
            return True
        except Exception as exc:
            self._log(f"初始化会话失败: {exc}", "error")
            return False

    def _get_device_id(self) -> Optional[str]:
        if not self.oauth_start:
            return None
        for attempt in range(1, 4):
            try:
                if not self.session:
                    self.session = self.http_client.session
                response = self.session.get(self.oauth_start.auth_url, timeout=20)
                did = self.session.cookies.get("oai-did")
                if did:
                    self._log(f"Device ID: {did}")
                    return did
                self._log(f"获取 Device ID 失败: 未返回 oai-did (HTTP {response.status_code}, 第 {attempt}/3 次尝试)", "warning")
            except Exception as exc:
                self._log(f"获取 Device ID 异常: {exc} (第 {attempt}/3 次尝试)", "warning")
            time.sleep(attempt)
            self.http_client.close()
            self.session = self.http_client.session
        return None

    def _check_sentinel(self, did: str) -> Optional[str]:
        try:
            sen_token = self.http_client.check_sentinel(did)
            if sen_token:
                self._log("Sentinel token 获取成功")
                return sen_token
            self._log("Sentinel 检查失败: 未获取到 token", "warning")
            return None
        except Exception as exc:
            self._log(f"Sentinel 检查异常: {exc}", "warning")
            return None

    def _submit_auth_start(self, did: str, sen_token: Optional[str], *, screen_hint: str, referer: str, log_label: str, record_existing_account: bool = True) -> SignupFormResult:
        try:
            request_body = json.dumps({"username": {"value": self.email, "kind": "email"}, "screen_hint": screen_hint})
            headers = {"referer": referer, "accept": "application/json", "content-type": "application/json"}
            if sen_token:
                headers["openai-sentinel-token"] = json.dumps({"p": "", "t": "", "c": sen_token, "id": did, "flow": "authorize_continue"})
            response = self.session.post(OPENAI_API_ENDPOINTS["signup"], headers=headers, data=request_body)
            self._log(f"{log_label}状态: {response.status_code}")
            if response.status_code != 200:
                return SignupFormResult(success=False, error_message=f"HTTP {response.status_code}: {response.text[:200]}")
            response_data = response.json()
            page_type = response_data.get("page", {}).get("type", "")
            is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
            if is_existing:
                self._otp_sent_at = time.time()
                if record_existing_account:
                    self._log("检测到已存在账号; 自动切换至登录流程")
                    self._is_existing_account = True
            return SignupFormResult(success=True, page_type=page_type, is_existing_account=is_existing, response_data=response_data)
        except Exception as exc:
            self._log(f"{log_label}失败: {exc}", "error")
            return SignupFormResult(success=False, error_message=str(exc))

    def _submit_signup_form(self, did: str, sen_token: Optional[str], *, record_existing_account: bool = True) -> SignupFormResult:
        return self._submit_auth_start(
            did,
            sen_token,
            screen_hint="signup",
            referer="https://auth.openai.com/create-account",
            log_label="提交注册表单",
            record_existing_account=record_existing_account,
        )

    def _submit_login_start(self, did: str, sen_token: Optional[str]) -> SignupFormResult:
        return self._submit_auth_start(
            did,
            sen_token,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            log_label="提交登录入口",
            record_existing_account=False,
        )

    def _submit_login_password(self) -> SignupFormResult:
        try:
            response = self.session.post(
                OPENAI_API_ENDPOINTS["password_verify"],
                headers={"referer": "https://auth.openai.com/log-in/password", "accept": "application/json", "content-type": "application/json"},
                data=json.dumps({"password": self.password}),
            )
            self._log(f"提交登录密码状态: {response.status_code}")
            if response.status_code != 200:
                return SignupFormResult(success=False, error_message=f"HTTP {response.status_code}: {response.text[:200]}")
            response_data = response.json()
            page_type = response_data.get("page", {}).get("type", "")
            is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
            if is_existing:
                self._otp_sent_at = time.time()
                self._log("密码验证成功; 正在等待邮件验证码...")
            return SignupFormResult(success=True, page_type=page_type, is_existing_account=is_existing, response_data=response_data)
        except Exception as exc:
            self._log(f"提交登录密码失败: {exc}", "error")
            return SignupFormResult(success=False, error_message=str(exc))

    def _reset_auth_flow(self):
        self.http_client.close()
        self.session = None
        self.oauth_start = None
        self.session_token = None
        self._otp_sent_at = None

    def _prepare_authorize_flow(self, label: str) -> Tuple[Optional[str], Optional[str]]:
        self._log(f"[{label}] 正在初始化会话...")
        if not self._init_session():
            return None, None
        self._log(f"[{label}] 正在发起 OAuth 流程...")
        if not self._start_oauth():
            return None, None
        self._log(f"[{label}] 正在获取 Device ID...")
        did = self._get_device_id()
        if not did:
            return None, None
        self._log(f"[{label}] 正在进行 Sentinel POW 校验...")
        sen_token = self._check_sentinel(did)
        if not sen_token:
            return did, None
        self._log(f"[{label}] 授权前置检查完成")
        return did, sen_token

    def _send_verification_code(self) -> bool:
        try:
            self._otp_sent_at = time.time()
            response = self.session.get(
                OPENAI_API_ENDPOINTS["send_otp"],
                headers={"referer": "https://auth.openai.com/create-account/password", "accept": "application/json"},
            )
            self._log(f"验证码发送状态: {response.status_code}")
            return response.status_code == 200
        except Exception as exc:
            self._log(f"发送验证码失败: {exc}", "error")
            return False

    def _get_verification_code(self) -> Optional[str]:
        try:
            email_id = self.email_info.get("service_id") if self.email_info else None
            code = self.email_service.get_verification_code(
                email=self.email,
                email_id=email_id,
                timeout=30,
                pattern=OTP_CODE_PATTERN,
                otp_sent_at=self._otp_sent_at,
            )
            if code:
                self._log(f"OTP successfully retrieved: {code}")
                return code
            self._log("OTP synchronization timeout", "error")
            return None
        except Exception as exc:
            self._log(f"获取验证码失败: {exc}", "error")
            return None

    def _validate_verification_code(self, code: str) -> bool:
        try:
            response = self.session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers={"referer": "https://auth.openai.com/email-verification", "accept": "application/json", "content-type": "application/json"},
                data=json.dumps({"code": code}),
            )
            self._log(f"OTP validation status: HTTP {response.status_code}")
            return response.status_code == 200
        except Exception as exc:
            self._log(f"OTP validation error: {exc}", "error")
            return False

    def _create_user_account(self) -> bool:
        try:
            user_info = generate_random_user_info()
            self._log(f"Generating profile: {user_info['name']}, DOB: {user_info['birthdate']}")
            response = self.session.post(
                OPENAI_API_ENDPOINTS["create_account"],
                headers={"referer": "https://auth.openai.com/about-you", "accept": "application/json", "content-type": "application/json"},
                data=json.dumps(user_info),
            )
            self._log(f"Profile creation status: HTTP {response.status_code}")
            if response.status_code != 200:
                self._log(f"Profile finalization failed: {response.text[:100]}", "warning")
                return False
            return True
        except Exception as exc:
            self._log(f"Profile creation error: {exc}", "error")
            return False

    def _get_workspace_id(self) -> Optional[str]:
        try:
            auth_cookie = self.session.cookies.get("oai-client-auth-session")
            if not auth_cookie:
                self._log("未能获取到授权 Cookie", "error")
                return None
            segments = auth_cookie.split(".")
            payload = segments[0]
            pad = "=" * ((4 - (len(payload) % 4)) % 4)
            decoded = json.loads(__import__("base64").urlsafe_b64decode((payload + pad).encode("ascii")).decode("utf-8"))
            workspaces = decoded.get("workspaces") or []
            if not workspaces:
                self._log("授权 Cookie 里没有 workspace 信息", "error")
                return None
            workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
            if not workspace_id:
                self._log("Workspace context parsing failed", "error")
                return None
            self._log(f"Workspace context synchronized: {workspace_id}")
            return workspace_id
        except Exception as exc:
            self._log(f"Workspace ID retrieval failed: {exc}", "error")
            return None

    def _select_workspace(self, workspace_id: str) -> Optional[str]:
        try:
            response = self.session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers={"referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent", "content-type": "application/json"},
                data=json.dumps({"workspace_id": workspace_id}),
            )
            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None
            continue_url = str((response.json() or {}).get("continue_url") or "").strip()
            if not continue_url:
                self._log("workspace/select 响应里缺少 continue_url", "error")
                return None
            self._log(f"Continue URL: {continue_url[:100]}...")
            return continue_url
        except Exception as exc:
            self._log(f"选择 Workspace 失败: {exc}", "error")
            return None

    def _follow_redirects(self, start_url: str) -> Optional[str]:
        try:
            current_url = start_url
            for idx in range(6):
                self._log(f"重定向 {idx + 1}/6: {current_url[:100]}...")
                response = self.session.get(current_url, allow_redirects=False, timeout=15)
                location = response.headers.get("Location") or ""
                if response.status_code not in [301, 302, 303, 307, 308]:
                    break
                if not location:
                    break
                import urllib.parse
                next_url = urllib.parse.urljoin(current_url, location)
                if "code=" in next_url and "state=" in next_url:
                    self._log(f"找到回调 URL: {next_url[:100]}...")
                    return next_url
                current_url = next_url
            self._log("未能在重定向链中找到回调 URL", "error")
            return None
        except Exception as exc:
            self._log(f"跟随重定向失败: {exc}", "error")
            return None

    def _handle_oauth_callback(self, callback_url: str) -> Optional[Dict[str, Any]]:
        try:
            if not self.oauth_start:
                self._log("OAuth 流程未初始化", "error")
                return None
            self._log("Processing OAuth callback handshake")
            token_info = self.oauth_manager.handle_callback(
                callback_url=callback_url,
                expected_state=self.oauth_start.state,
                code_verifier=self.oauth_start.code_verifier,
            )
            self._log("OAuth authorization successful")
            return token_info
        except Exception as exc:
            self._log(f"处理 OAuth 回调失败: {exc}", "error")
            return None

    def _complete_token_exchange(self, result: RegistrationResult) -> bool:
        self._log("正在等待邮件验证码...")
        code = self._get_verification_code()
        if not code:
            result.error_message = "获取验证码失败"
            return False
        self._log("正在校验验证码...")
        if not self._validate_verification_code(code):
            result.error_message = "验证码校验失败"
            return False
        self._log("正在获取 Workspace ID...")
        workspace_id = self._get_workspace_id()
        if not workspace_id:
            result.error_message = "获取 Workspace ID 失败"
            return False
        result.workspace_id = workspace_id
        self._log("正在选择 Workspace 上下文...")
        continue_url = self._select_workspace(workspace_id)
        if not continue_url:
            result.error_message = "选择 Workspace 失败"
            return False
        self._log("正在跟随重定向链...")
        callback_url = self._follow_redirects(continue_url)
        if not callback_url:
            result.error_message = "跟随重定向链失败"
            return False
        self._log("正在处理 OAuth 回调交换...")
        token_info = self._handle_oauth_callback(callback_url)
        if not token_info:
            result.error_message = "处理 OAuth 回调失败"
            return False
        result.account_id = token_info.get("account_id", "")
        result.access_token = token_info.get("access_token", "")
        result.refresh_token = token_info.get("refresh_token", "")
        result.id_token = token_info.get("id_token", "")
        result.password = self.password or ""
        result.source = "login" if self._is_existing_account else "register"
        session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
        if session_cookie:
            self.session_token = session_cookie
            result.session_token = session_cookie
            self._log("会话令牌 (Session Token) 同步成功")
        return True

    def _restart_login_flow(self) -> Tuple[bool, str]:
        self._token_acquisition_requires_login = True
        self._log("正在发起后续登录流程以获取授权令牌...")
        self._reset_auth_flow()
        did, sen_token = self._prepare_authorize_flow("重新登录")
        if not did:
            return False, "重新登录时获取 Device ID 失败"
        if not sen_token:
            return False, "重新登录时 Sentinel POW 验证失败"
        login_start_result = self._submit_login_start(did, sen_token)
        if not login_start_result.success:
            return False, f"重新登录提交邮箱失败: {login_start_result.error_message}"
        if login_start_result.page_type != OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
            return False, f"重新登录未进入密码页面: {login_start_result.page_type or 'unknown'}"
        password_result = self._submit_login_password()
        if not password_result.success:
            return False, f"重新登录提交密码失败: {password_result.error_message}"
        if not password_result.is_existing_account:
            return False, f"重新登录未进入验证码页面: {password_result.page_type or 'unknown'}"
        return True, ""

    def _register_password(self) -> Tuple[bool, Optional[str]]:
        try:
            password = self._generate_password()
            self.password = password
            self._log(f"生成密码: {password}")
            response = self.session.post(
                OPENAI_API_ENDPOINTS["register"],
                headers={"referer": "https://auth.openai.com/create-account/password", "accept": "application/json", "content-type": "application/json"},
                data=json.dumps({"password": password, "username": self.email}),
            )
            self._log(f"提交密码状态: {response.status_code}")
            if response.status_code != 200:
                self._log(f"密码注册失败: {response.text[:500]}", "warning")
                return False, None
            return True, password
        except Exception as exc:
            self._log(f"密码注册失败: {exc}", "error")
            return False, None

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)
        try:
            self._is_existing_account = False
            self._token_acquisition_requires_login = False
            self._otp_sent_at = None

            self._log("-" * 40)
            self._log("注册引擎: 流程启动")
            self._log("-" * 40)

            self._log("[阶段 1] 正在校验 IP 归属地...")
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                result.error_message = f"IP 归属地不受支持: {location}"
                self._log(f"IP 校验失败: {location}", "error")
                return result

            self._log(f"IP 归属地已确认: {location}")
            self._log("[阶段 2] 正在开通邮箱账户...")
            if not self._create_email():
                result.error_message = "邮箱账户开通失败"
                return result

            result.email = self.email
            did, sen_token = self._prepare_authorize_flow("阶段 3: 授权初始化")
            if not did:
                result.error_message = "获取 Device ID 失败"
                return result
            if not sen_token:
                result.error_message = "Sentinel 校验失败"
                return result

            self._log("[阶段 4] 正在提交身份核验...")
            signup_result = self._submit_signup_form(did, sen_token)
            if not signup_result.success:
                result.error_message = f"提交注册表单失败: {signup_result.error_message}"
                return result

            if self._is_existing_account:
                self._log("状态: 检测到存量账号; 正在直接获取身份信息")
            else:
                self._log("[阶段 5] 正在配置账号凭据...")
                password_ok, _ = self._register_password()
                if not password_ok:
                    result.error_message = "凭据配置失败"
                    return result
                self._log("[阶段 6] 正在分发验证码...")
                if not self._send_verification_code():
                    result.error_message = "验证码分发失败"
                    return result
                self._log("[阶段 7] 正在同步邮箱数据...")
                code = self._get_verification_code()
                if not code:
                    result.error_message = "验证码同步失败"
                    return result
                self._log("[阶段 8] 正在核验身份信息...")
                if not self._validate_verification_code(code):
                    result.error_message = "身份核验失败"
                    return result
                self._log("[阶段 9] 正在完成账户配置...")
                if not self._create_user_account():
                    result.error_message = "账户配置失败"
                    return result
                login_ready, login_error = self._restart_login_flow()
                if not login_ready:
                    result.error_message = login_error
                    return result

            if not self._complete_token_exchange(result):
                return result

            self._log("-" * 40)
            self._log(f"{'登录' if self._is_existing_account else '注册'}: 流程执行成功")
            self._log(f"邮箱账户: {result.email}")
            self._log(f"账号 ID: {result.account_id}")
            self._log(f"组织 ID: {result.workspace_id}")
            self._log("-" * 40)
            result.success = True
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "is_existing_account": self._is_existing_account,
                "token_acquired_via_relogin": self._token_acquisition_requires_login,
                "registration_engine": "legacy_full",
            }
            return result
        except Exception as exc:
            self._log(f"CRITICAL: Unhandled execution failure during registration lifecycle: {exc}", "error")
            result.error_message = str(exc)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        if not result.success:
            return False
        try:
            settings = get_settings()
            with get_db() as db:
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
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
