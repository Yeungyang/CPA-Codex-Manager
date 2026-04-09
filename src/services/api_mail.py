"""
API Mail 邮箱服务实现
对接 /admin/mails 管理接口，支持基于收件地址轮询验证码。
"""

import random
import re
import string
import time
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import Any, Dict, List, Optional, Tuple

import requests

from .base import BaseEmailService, EmailServiceError, EmailServiceType
from ..config.constants import OTP_CODE_PATTERN


DEFAULT_DOMAINS = [
    "sshdyssd.site",
    "cloudwork.indevs.in",
    "major.indevs.in",
    "routecode.indevs.in",
    "majormapper.site",
]


class ApiMailService(BaseEmailService):
    """CloudWork API Mail 服务。"""

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(EmailServiceType.API_MAIL, name)

        default_config = {
            "mail_api_endpoint": "https://apimail.cloudwork.indevs.in/admin/mails",
            "mail_api_admin_auth": "",
            "mail_api_fingerprint": "",
            "mail_api_lang": "zh",
            "mail_api_limit": 100,
            "mail_api_offset": 0,
            "mail_api_poll_interval_seconds": 3,
            "delete_after_consume": True,
            "domains": DEFAULT_DOMAINS,
            "proxy_url": None,
        }
        self.config = {**default_config, **(config or {})}
        self.config["mail_api_endpoint"] = str(self.config["mail_api_endpoint"]).rstrip("/")

        domains = self.config.get("domains") or self.config.get("domain") or DEFAULT_DOMAINS
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",") if d.strip()]
        self.domains: List[str] = domains if isinstance(domains, list) and domains else list(DEFAULT_DOMAINS)

        self.session = requests.Session()
        self.session.trust_env = False
        proxy_url = (self.config.get("proxy_url") or "").strip()
        if proxy_url:
            if not proxy_url.startswith(("http://", "https://", "socks5://", "socks5h://")):
                proxy_url = f"http://{proxy_url}"
            self.session.proxies = {"http": proxy_url, "https": proxy_url}

    def _headers(self, include_fingerprint: bool = True) -> Dict[str, str]:
        headers = {
            "x-admin-auth": str(self.config.get("mail_api_admin_auth") or ""),
            "x-lang": str(self.config.get("mail_api_lang") or "zh"),
        }
        if include_fingerprint:
            headers["x-fingerprint"] = str(self.config.get("mail_api_fingerprint") or "")
        return headers

    def _fetch_page(self, endpoint: str) -> List[dict]:
        params = {
            "limit": int(self.config.get("mail_api_limit") or 100),
            "offset": int(self.config.get("mail_api_offset") or 0),
        }
        resp = self.session.get(endpoint, headers=self._headers(include_fingerprint=True), params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", []) if isinstance(data, dict) else []

    def _fetch_page_by_address(self, endpoint: str, address: str) -> List[dict]:
        params = {
            "limit": int(self.config.get("mail_api_limit") or 100),
            "offset": int(self.config.get("mail_api_offset") or 0),
            "address": address,
        }
        resp = self.session.get(endpoint, headers=self._headers(include_fingerprint=True), params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", []) if isinstance(data, dict) else []

    def _fetch_all(self) -> List[dict]:
        base = self.config["mail_api_endpoint"]
        endpoints = [base, f"{base}_unknow"]
        result: List[dict] = []
        for endpoint in endpoints:
            try:
                result.extend(self._fetch_page(endpoint))
            except Exception:
                # _unknow 端点可能不存在，忽略该分支错误。
                continue
        return result

    def _fetch_by_address(self, address: str) -> List[dict]:
        base = self.config["mail_api_endpoint"]
        endpoints = [base, f"{base}_unknow"]
        result: List[dict] = []
        for endpoint in endpoints:
            try:
                result.extend(self._fetch_page_by_address(endpoint, address))
            except Exception:
                continue
        return result

    def _parse_raw(self, raw_text: str) -> Tuple[str, str]:
        if not raw_text:
            return "", ""
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw_text.encode("utf-8", errors="ignore"))
            subject = str(message.get("subject", "") or "")
            body_parts: List[str] = []
            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_maintype() == "multipart":
                        continue
                    try:
                        body_parts.append(str(part.get_content()))
                    except Exception:
                        payload = part.get_payload(decode=True) or b""
                        body_parts.append(payload.decode(errors="ignore"))
            else:
                try:
                    body_parts.append(str(message.get_content()))
                except Exception:
                    payload = message.get_payload(decode=True) or b""
                    body_parts.append(payload.decode(errors="ignore"))
            return subject, "\n".join(body_parts)
        except Exception:
            return "", raw_text

    def _extract_code(self, subject: str, body: str, pattern: str) -> str:
        texts = [subject or "", body or ""]
        targeted = [
            r"代码为\s*(\d{6})",
            r"验证码(?:是|为)?\s*[:：]?\s*(\d{6})",
            r"临时验证码(?:是|为)?\s*[:：]?\s*(\d{6})",
            r"code\s*(?:is|:)?\s*(\d{6})",
            pattern or OTP_CODE_PATTERN,
        ]
        for text in texts:
            for pt in targeted:
                m = re.search(pt, text, re.IGNORECASE)
                if m:
                    return m.group(1)
        return ""

    def _parse_created_at(self, created_at: str) -> Optional[float]:
        if not created_at:
            return None
        text = str(created_at).strip()
        try:
            if text.endswith("Z"):
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return None

    def _delete_remote_mail(self, mail_id: int) -> bool:
        base = self.config["mail_api_endpoint"]
        urls = [f"{base}/{mail_id}", f"{base}_unknow/{mail_id}"]
        last_error = None
        for url in urls:
            try:
                resp = self.session.delete(url, headers=self._headers(include_fingerprint=False), timeout=15)
                resp.raise_for_status()
                return True
            except Exception as e:
                last_error = e
        if last_error:
            raise EmailServiceError(f"删除邮件失败: {last_error}")
        return False

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        req_config = config or {}
        domain = req_config.get("domain")
        if not domain:
            domain = random.choice(self.domains)
        local = req_config.get("name")
        if not local:
            local = random.choice(string.ascii_lowercase) + "".join(
                random.choices(string.ascii_lowercase + string.digits, k=9)
            )
        email = f"{local}@{domain}".lower()
        return {
            "email": email,
            "service_id": email,
            "id": email,
            "created_at": time.time(),
        }

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
        exclude_codes=None,
    ) -> Optional[str]:
        target = (email or email_id or "").strip().lower()
        if not target:
            return None

        exclude = set(exclude_codes or [])
        start = time.time()
        poll = max(1, int(self.config.get("mail_api_poll_interval_seconds") or 3))

        while time.time() - start < timeout:
            try:
                for item in self._fetch_by_address(target):
                    address = str(item.get("address") or "").strip().lower()
                    if address != target:
                        continue

                    if otp_sent_at:
                        created_ts = self._parse_created_at(str(item.get("created_at") or ""))
                        if created_ts and created_ts < float(otp_sent_at) - 2:
                            continue

                    raw = str(item.get("raw") or "")
                    subject, body = self._parse_raw(raw)
                    code = self._extract_code(subject, body, pattern)
                    if not code or code in exclude:
                        continue

                    if self.config.get("delete_after_consume", True) and item.get("id"):
                        try:
                            self._delete_remote_mail(int(item["id"]))
                        except Exception:
                            pass
                    self.update_status(True)
                    return code
            except Exception as e:
                self.update_status(False, e)

            time.sleep(poll)
        return None

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for item in self._fetch_all():
            rows.append(
                {
                    "id": item.get("id"),
                    "address": item.get("address"),
                    "source": item.get("source"),
                    "created_at": item.get("created_at"),
                }
            )
        return rows

    def delete_email(self, email_id: str) -> bool:
        try:
            mail_id = int(email_id)
        except Exception:
            return False
        return self._delete_remote_mail(mail_id)

    def check_health(self) -> bool:
        try:
            base = self.config["mail_api_endpoint"]
            resp = self.session.get(
                base,
                headers=self._headers(include_fingerprint=True),
                params={"limit": 1, "offset": 0},
                timeout=10,
            )
            resp.raise_for_status()
            self.update_status(True)
            return True
        except Exception as e:
            self.update_status(False, e)
            return False
