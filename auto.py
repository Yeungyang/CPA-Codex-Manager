# 标准库
import base64
import hashlib
import json
import logging
import os
import random
import re
import secrets
import sqlite3
import string
import sys
import time
import traceback
import uuid
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, parse_qs, urlencode

# 第三方库
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from imap_tools import MailBox
from routecode_realtime_sync import (
    sync_account as sync_routecode_account,
    query_realtime_replenish_plan,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 确保终端输出支持 UTF-8
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ═══════════════════════════════════════════════════════
# 配置文件管理
# ═══════════════════════════════════════════════════════
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

def _get_cli_value(flag_name):
    prefix = f"--{flag_name}="
    for arg in sys.argv[1:]:
        if arg.startswith(prefix):
            return arg[len(prefix):]
    return None

def load_config():
    if not os.path.exists(CONFIG_PATH):
        print(f"❌ 配置文件不存在: {CONFIG_PATH}")
        exit(1)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)
    for key, default in [("token_dir", "tokens"), ("log_dir", "logs")]:
        val = config.get(key, default)
        if not os.path.isabs(val):
            config[key] = os.path.join(SCRIPT_DIR, val)
    return config

def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(value)

cfg = load_config()

# 基础配置
_domain_cfg = _get_cli_value("domain")
if _domain_cfg is None:
    _domain_cfg = cfg["domain"]
if isinstance(_domain_cfg, list):
    DOMAINS = [str(d).strip() for d in _domain_cfg if str(d).strip()]
elif isinstance(_domain_cfg, str):
    # 兼容逗号分隔字符串： "a.com,b.com"
    DOMAINS = [d.strip() for d in _domain_cfg.split(",") if d.strip()]
else:
    DOMAINS = []

if not DOMAINS:
    raise ValueError("config.json 中 domain 配置无效：请提供字符串或字符串数组")
IMAP_HOST = cfg["imap_host"]
IMAP_PORT = cfg["imap_port"]
IMAP_USER = cfg["imap_user"]
IMAP_PASS = cfg["imap_pass"]
MAIL_FETCH_MODE = (cfg.get("mail_fetch_mode", "imap") or "imap").strip().lower()
MAIL_API_ENDPOINT = cfg.get("mail_api_endpoint", "https://apimail.cloudwork.indevs.in/admin/mails")
MAIL_API_ADMIN_AUTH = cfg.get("mail_api_admin_auth", "")
MAIL_API_FINGERPRINT = cfg.get("mail_api_fingerprint", "")
MAIL_API_LANG = cfg.get("mail_api_lang", "zh")
MAIL_API_LIMIT = int(cfg.get("mail_api_limit", 100) or 100)
MAIL_API_OFFSET = int(cfg.get("mail_api_offset", 0) or 0)
MAIL_API_INITIAL_DELAY_SECONDS = int(cfg.get("mail_api_initial_delay_seconds", 5) or 5)
MAIL_API_POLL_INTERVAL_SECONDS = int(cfg.get("mail_api_poll_interval_seconds", 5) or 5)
MAIL_API_CACHE_POLL_INTERVAL_SECONDS = int(cfg.get("mail_api_cache_poll_interval_seconds", 1) or 1)
FAILURE_SAMPLE_LIMIT = int(cfg.get("failure_sample_limit", 10) or 10)
SAVE_TOKEN_FILES_ENABLED = _as_bool(cfg.get("save_token_files_enabled", False), False)
PROXY_ENABLED = _as_bool(cfg.get("proxy_enabled", False), False)
PROXY = cfg.get("proxy", None) if PROXY_ENABLED else None
TOKEN_DIR = cfg["token_dir"]
LOG_DIR = cfg.get("log_dir", os.path.join(SCRIPT_DIR, "logs"))
RUN_COUNT = cfg.get("run_count", 1)
RUN_INTERVAL = cfg.get("run_interval", 60)
LOG_ENABLED = cfg.get("log_enabled", False)
EMAIL_PREFIX = cfg.get("email_prefix", "auto")
EMAIL_OTP_TIMEOUT = int(cfg.get("email_otp_timeout", 300) or 300)
EMAIL_MAX_AGE_SECONDS = int(cfg.get("email_max_age_seconds", 1200) or 1200)
SUB2API_EXPORT_FILE = cfg.get("sub2api_export_file", os.path.join(SCRIPT_DIR, "sub2api_data.json"))
SUB2API_EXPORT_DIR = cfg.get("sub2api_export_dir", os.path.join(SCRIPT_DIR, "sub2api_exports"))
SQLITE_MAIN_DB_PATH = cfg.get("sqlite_main_db_path", cfg.get("sqlite_db_path", os.path.join(SCRIPT_DIR, "accounts.db")))
SQLITE_MAIL_DB_PATH = cfg.get("sqlite_mail_db_path", os.path.join(SCRIPT_DIR, "mail_cache.db"))
SQLITE_BUSY_TIMEOUT_MS = int(cfg.get("sqlite_busy_timeout_ms", 10000) or 10000)

FIXED_PASSWORD = "yangyyang123"

# OAuth 常量
OAUTH_ISSUER = "https://auth.openai.com"
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_REDIRECT_URI = "http://localhost:1455/auth/callback"
OPENAI_AUTH_BASE = "https://auth.openai.com"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

COMMON_HEADERS = {
    "accept": "application/json",
    "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "content-type": "application/json",
    "origin": OPENAI_AUTH_BASE,
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}

COLLECTED_REFRESH_TOKENS =[]
RUN_SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
CN_TZ = timezone(timedelta(hours=8))

# ═══════════════════════════════════════════════════════
# 辅助工具
# ═══════════════════════════════════════════════════════
def create_session():
    session = requests.Session()
    # 强制忽略系统环境变量残留，防止 ProxyError
    session.trust_env = False
    session.verify = False

    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    if PROXY:
        proxy = str(PROXY).strip()
        if not proxy.startswith("http") and not proxy.startswith("socks"):
            proxy = f"http://{proxy}"
        session.proxies = {"http": proxy, "https": proxy}

    return session

def generate_device_id():
    return str(uuid.uuid4())

def generate_western_profile():
    first_names = [
        "James", "Michael", "David", "Daniel", "Christopher", "Matthew", "Andrew", "Joshua", "Joseph", "Samuel",
        "Benjamin", "Elijah", "Alexander", "Ethan", "Noah", "Liam", "Lucas", "Mason", "Logan", "Jacob",
        "Emma", "Olivia", "Sophia", "Isabella", "Ava", "Mia", "Charlotte", "Amelia", "Harper", "Evelyn",
        "Abigail", "Emily", "Elizabeth", "Sofia", "Ella", "Scarlett", "Grace", "Chloe", "Lily", "Hannah"
    ]
    last_names = [
        "Smith", "Johnson", "Brown", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin",
        "Thompson", "Garcia", "Martinez", "Robinson", "Clark", "Rodriguez", "Lewis", "Lee", "Walker", "Hall",
        "Allen", "Young", "King", "Wright", "Scott", "Green", "Baker", "Adams", "Nelson", "Hill",
        "Campbell", "Mitchell", "Carter", "Roberts", "Phillips", "Evans", "Turner", "Torres", "Parker", "Collins"
    ]
    year = random.randint(1991, 2004)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return random.choice(first_names), random.choice(last_names), f"{year:04d}-{month:02d}-{day:02d}"

def generate_datadog_trace():
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), '016x')
    parent_hex = format(int(parent_id), '016x')
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }

def generate_pkce():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge

def _get_cli_bool_override(flag_name):
    value = _get_cli_value(flag_name)
    if value is None:
        return None
    return _as_bool(value, False)

def _resolve_main_db_path():
    db_path = SQLITE_MAIN_DB_PATH
    if not os.path.isabs(db_path):
        db_path = os.path.join(SCRIPT_DIR, db_path)
    return db_path

def _resolve_mail_db_path():
    db_path = SQLITE_MAIL_DB_PATH
    if not os.path.isabs(db_path):
        db_path = os.path.join(SCRIPT_DIR, db_path)
    return db_path

def _connect_sqlite(db_path):
    conn = sqlite3.connect(db_path, timeout=max(SQLITE_BUSY_TIMEOUT_MS / 1000, 1))
    conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    return conn

def init_accounts_db():
    db_path = _resolve_main_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with _connect_sqlite(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL DEFAULT '',
                birthdate TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS registered_account_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL DEFAULT '',
                birthdate TEXT NOT NULL DEFAULT '',
                password TEXT NOT NULL DEFAULT '',
                registration_status TEXT NOT NULL DEFAULT 'pending',
                token_status TEXT NOT NULL DEFAULT 'pending',
                registration_message TEXT NOT NULL DEFAULT '',
                token_message TEXT NOT NULL DEFAULT '',
                id_token TEXT NOT NULL DEFAULT '',
                access_token TEXT NOT NULL DEFAULT '',
                refresh_token TEXT NOT NULL DEFAULT '',
                expires_in INTEGER NOT NULL DEFAULT 0,
                token_type TEXT NOT NULL DEFAULT '',
                organization_id TEXT NOT NULL DEFAULT '',
                chatgpt_account_id TEXT NOT NULL DEFAULT '',
                chatgpt_user_id TEXT NOT NULL DEFAULT '',
                raw_token_json TEXT NOT NULL DEFAULT '',
                extracted_to_sub2api INTEGER NOT NULL DEFAULT 0,
                extracted_priority INTEGER,
                extracted_batch_file TEXT NOT NULL DEFAULT '',
                extracted_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                registration_completed_at TEXT NOT NULL DEFAULT '',
                token_obtained_at TEXT NOT NULL DEFAULT '',
                last_error TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sub2api_export_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                export_file TEXT NOT NULL UNIQUE,
                priority INTEGER NOT NULL,
                account_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    return db_path

def _cn_now_str():
    return datetime.now(CN_TZ).strftime("%Y-%m-%d %H:%M:%S")

def account_email_exists(email: str) -> bool:
    db_path = _resolve_main_db_path()
    with _connect_sqlite(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM accounts WHERE email = ? LIMIT 1",
            (email,),
        ).fetchone()
    return row is not None

def save_account_profile(email: str, full_name: str, birthdate: str):
    db_path = _resolve_main_db_path()
    with _connect_sqlite(db_path) as conn:
        conn.execute(
            """
            INSERT INTO accounts (email, full_name, birthdate, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (email, full_name, birthdate, _utc_now_iso_z()),
        )
        conn.commit()

def upsert_registered_account_detail(email: str, full_name: str, birthdate: str, password: str):
    now = _utc_now_iso_z()
    db_path = _resolve_main_db_path()
    with _connect_sqlite(db_path) as conn:
        conn.execute(
            """
            INSERT INTO registered_account_details (
                email, full_name, birthdate, password, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                full_name = excluded.full_name,
                birthdate = excluded.birthdate,
                password = excluded.password,
                updated_at = excluded.updated_at
            """,
            (email, full_name, birthdate, password, now, now),
        )
        conn.commit()

def mark_registration_success(email: str, message: str = "注册成功"):
    now = _utc_now_iso_z()
    db_path = _resolve_main_db_path()
    with _connect_sqlite(db_path) as conn:
        conn.execute(
            """
            UPDATE registered_account_details
            SET registration_status = 'registered',
                registration_message = ?,
                registration_completed_at = ?,
                updated_at = ?,
                last_error = ''
            WHERE email = ?
            """,
            (message, now, now, email),
        )
        conn.commit()

def mark_token_success(email: str, token_data: dict):
    now = _utc_now_iso_z()
    credentials = _build_sub2api_credentials(token_data)
    db_path = _resolve_main_db_path()
    with _connect_sqlite(db_path) as conn:
        conn.execute(
            """
            UPDATE registered_account_details
            SET token_status = 'token_ready',
                token_message = 'Token 获取成功',
                id_token = ?,
                access_token = ?,
                refresh_token = ?,
                expires_in = ?,
                token_type = ?,
                organization_id = ?,
                chatgpt_account_id = ?,
                chatgpt_user_id = ?,
                raw_token_json = ?,
                token_obtained_at = ?,
                updated_at = ?,
                last_error = ''
            WHERE email = ?
            """,
            (
                token_data.get("id_token", "") or "",
                token_data.get("access_token", "") or "",
                token_data.get("refresh_token", "") or "",
                int(token_data.get("expires_in", 0) or 0),
                token_data.get("token_type", "") or "",
                credentials.get("organization_id", "") or "",
                credentials.get("chatgpt_account_id", "") or "",
                credentials.get("chatgpt_user_id", "") or "",
                json.dumps(token_data, ensure_ascii=False),
                now,
                now,
                email,
            ),
        )
        conn.commit()

def mark_account_failure(email: str, *, registration_message=None, token_message=None, last_error=None):
    updates = []
    params = []

    if registration_message is not None:
        updates.extend(["registration_status = 'failed'", "registration_message = ?"])
        params.append(registration_message)
    if token_message is not None:
        updates.extend(["token_status = 'failed'", "token_message = ?"])
        params.append(token_message)
    if last_error is not None:
        updates.append("last_error = ?")
        params.append(last_error)

    updates.append("updated_at = ?")
    params.append(_utc_now_iso_z())
    params.append(email)

    db_path = _resolve_main_db_path()
    with _connect_sqlite(db_path) as conn:
        conn.execute(
            f"UPDATE registered_account_details SET {', '.join(updates)} WHERE email = ?",
            params,
        )
        conn.commit()

def record_failure(failure_counter, recent_failures, email, category, detail):
    failure_counter[category] += 1
    recent_failures.append(f"{email} -> {detail}")

def print_run_stats(success_count, fail_count, failure_counter, recent_failures):
    print("\n" + "-" * 60)
    print("📊 当前运行统计")
    print(f"✅ 成功: {success_count}")
    print(f"❌ 失败: {fail_count}")
    if failure_counter:
        print("📌 失败原因汇总:")
        for idx, (reason, count) in enumerate(failure_counter.most_common(), 1):
            print(f"   {idx}. {reason}: {count}")
    else:
        print("📌 失败原因汇总: 暂无")

    if recent_failures:
        print(f"🧾 最近 {len(recent_failures)} 条失败样本:")
        for idx, reason in enumerate(recent_failures, 1):
            print(f"   {idx}. {reason}")
    else:
        print("🧾 最近失败样本: 暂无")
    print("-" * 60)

def _decode_email_from_token_filename(filename: str):
    if not filename.lower().endswith(".json"):
        return None

    stem = os.path.splitext(filename)[0]
    if "_at_" not in stem:
        return None

    email = stem.replace("_at_", "@").replace("_", ".")
    return email if "@" in email else None

def import_emails_from_token_dir():
    imported_count = 0
    skipped_count = 0

    if not os.path.isdir(TOKEN_DIR):
        return imported_count, skipped_count

    db_path = _resolve_main_db_path()
    with _connect_sqlite(db_path) as conn:
        for name in os.listdir(TOKEN_DIR):
            email = _decode_email_from_token_filename(name)
            if not email:
                continue
            try:
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO accounts (email, full_name, birthdate, created_at)
                    VALUES (?, '', '', ?)
                    """,
                    (email, _utc_now_iso_z()),
                )
                if cursor.rowcount == 1:
                    imported_count += 1
                else:
                    skipped_count += 1
            except Exception:
                skipped_count += 1
        conn.commit()

    return imported_count, skipped_count

def generate_unique_email(reserved_emails=None, max_attempts=1000):
    if reserved_emails is None:
        reserved_emails = set()

    for _ in range(max_attempts):
        domain = random.choice(DOMAINS)
        email = f"{EMAIL_PREFIX}{random.randint(10000, 99999)}@{domain}"
        if email in reserved_emails:
            continue
        if account_email_exists(email):
            continue
        reserved_emails.add(email)
        return email

    raise RuntimeError(f"生成唯一邮箱失败，已尝试 {max_attempts} 次")

# ═══════════════════════════════════════════════════════
# Sentinel Token (PoW)
# ═══════════════════════════════════════════════════════
class SentinelTokenGenerator:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id=None):
        self.device_id = device_id or generate_device_id()
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text):
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = ((h * 16777619) & 0xFFFFFFFF)
        h ^= (h >> 16)
        h = ((h * 2246822507) & 0xFFFFFFFF)
        h ^= (h >> 13)
        h = ((h * 3266489909) & 0xFFFFFFFF)
        h ^= (h >> 16)
        return format(h & 0xFFFFFFFF, '08x')

    def _get_config(self):
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        perf_now = random.uniform(1000, 50000)
        nav_prop = random.choice(["vendorSub", "productSub", "vendor", "maxTouchPoints", "plugins"])
        return[
            "1920x1080", date_str, 4294705152, random.random(), USER_AGENT,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js", None, None,
            "zh-CN", "zh-CN,zh;q=0.9", random.random(), f"{nav_prop}−undefined",
            random.choice(["location", "URL", "documentURI"]),
            random.choice(["Object", "Function", "Array"]),
            perf_now, self.sid, "", random.choice([4, 8, 12, 16]), time.time() * 1000 - perf_now,
                                                                   ]

    @staticmethod
    def _base64_encode(data):
        return base64.b64encode(json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).decode('ascii')

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        if hash_hex[:len(difficulty)] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        seed = seed or self.requirements_seed
        difficulty = difficulty or "0"
        start_time = time.time()
        config = self._get_config()
        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(config)

def build_sentinel_token(session, device_id, flow="authorize_continue"):
    gen = SentinelTokenGenerator(device_id=device_id)
    p_token = gen.generate_requirements_token()
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "User-Agent": USER_AGENT,
        "Origin": "https://sentinel.openai.com",
    }
    try:
        resp = session.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            data=json.dumps({"p": p_token, "id": device_id, "flow": flow}),
            headers=headers, timeout=15, verify=False,
        )
        if resp.status_code == 200:
            challenge = resp.json()
            c_value = challenge.get("token", "")
            pow_data = challenge.get("proofofwork", {})
            if pow_data.get("required") and pow_data.get("seed"):
                p_value = gen.generate_token(seed=pow_data["seed"], difficulty=pow_data.get("difficulty", "0"))
            else:
                p_value = gen.generate_requirements_token()
            return json.dumps({"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow})
    except Exception as e:
        pass
    return None

# ═══════════════════════════════════════════════════════
# IMAP 邮件获取 (增加 UID 排重机制)
# ═══════════════════════════════════════════════════════
def _recipient_matches_email(msg, email_lower: str):
    if any(email_lower in t.lower() for t in msg.to):
        return True

    for header_name in ("delivered-to", "x-original-to", "x-forwarded-to"):
        vals = msg.headers.get(header_name) or []
        if any(email_lower in v.lower() for v in vals):
            return True

    body_check = msg.text or msg.html or ""
    if email_lower in body_check.lower():
        return True

    return False

def _extract_otp_code_from_message(msg):
    subject = msg.subject or ""
    body = msg.text or msg.html or ""

    patterns = [
        subject,
        body,
    ]

    targeted_patterns = [
        r'代码为\s*(\d{6})',
        r'验证码(?:是|为)?\s*[:：]?\s*(\d{6})',
        r'临时验证码(?:是|为)?\s*[:：]?\s*(\d{6})',
        r'code\s*(?:is|:)?\s*(\d{6})',
    ]

    for text in patterns:
        for pattern in targeted_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

    match = re.search(r'\b(\d{6})\b', subject)
    if match:
        return match.group(1)

    match = re.search(r'\b(\d{6})\b', body)
    if match:
        return match.group(1)

    return None

def _extract_otp_code_from_text(subject, body):
    patterns = [subject or "", body or ""]
    targeted_patterns = [
        r'代码为\s*(\d{6})',
        r'验证码(?:是|为)?\s*[:：]?\s*(\d{6})',
        r'临时验证码(?:是|为)?\s*[:：]?\s*(\d{6})',
        r'code\s*(?:is|:)?\s*(\d{6})',
    ]
    for text in patterns:
        for pattern in targeted_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

    for text in patterns:
        match = re.search(r'\b(\d{6})\b', text)
        if match:
            return match.group(1)
    return None

def _parse_mail_api_created_at(created_at):
    if not created_at:
        return None
    try:
        return datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None

def _extract_otp_code_from_raw_email(raw_text):
    if not raw_text:
        return None, "", ""
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_text.encode("utf-8", errors="ignore"))
        subject = message.get("subject", "") or ""
        body_parts = []
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    body_parts.append(payload.decode(errors="ignore"))
        else:
            try:
                body_parts.append(message.get_content())
            except Exception:
                payload = message.get_payload(decode=True) or b""
                body_parts.append(payload.decode(errors="ignore"))
        body = "\n".join(str(part) for part in body_parts if part is not None)
        return _extract_otp_code_from_text(subject, body), subject, body
    except Exception:
        return _extract_otp_code_from_text("", raw_text), "", raw_text

def _consume_cached_mail_otp(email: str):
    db_path = _resolve_mail_db_path()
    email_lower = email.lower()
    now = _cn_now_str()
    with _connect_sqlite(db_path) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT id, mail_id, otp_code, created_at
            FROM mail_api_cache
            WHERE lower(address) = ?
              AND consumed = 0
              AND otp_code != ''
            ORDER BY mail_id DESC
            LIMIT 1
            """,
            (email_lower,),
        ).fetchone()
        if not row:
            conn.commit()
            return None

        created_dt = _parse_mail_api_created_at(row["created_at"])
        if created_dt and (time.time() - created_dt.timestamp()) > EMAIL_MAX_AGE_SECONDS:
            conn.commit()
            return None

        updated = conn.execute(
            """
            UPDATE mail_api_cache
            SET consumed = 1,
                consumed_by = ?,
                consumed_at = ?,
                updated_at = ?
            WHERE id = ? AND consumed = 0
            """,
            (email, now, now, row["id"]),
        )
        conn.commit()
        if updated.rowcount != 1:
            return None
        return {
            "mail_id": row["mail_id"],
            "otp_code": row["otp_code"],
            "created_at": row["created_at"],
        }

def poll_verification_code_api(email: str, timeout=60, seen_uids=None):
    print("⏳ 等待 API 邮件验证码...")
    if seen_uids is None:
        seen_uids = set()

    if not MAIL_API_ADMIN_AUTH or not MAIL_API_FINGERPRINT:
        print("❌ 获取邮件错误: mail_api_admin_auth 或 mail_api_fingerprint 未配置")
        return None

    mail_api_cache_enabled = _as_bool(cfg.get("mail_api_cache_enabled", False), False)
    start = time.time()
    email_lower = email.lower()

    if mail_api_cache_enabled:
        if MAIL_API_INITIAL_DELAY_SECONDS > 0:
            time.sleep(MAIL_API_INITIAL_DELAY_SECONDS)
        while time.time() - start < timeout:
            cached = _consume_cached_mail_otp(email)
            if cached:
                print(f"✅ 验证码: {cached['otp_code']} (邮件时间: {cached['created_at']})")
                return cached["otp_code"]
            time.sleep(MAIL_API_CACHE_POLL_INTERVAL_SECONDS)
        return None

    session = requests.Session()
    session.trust_env = False
    if PROXY:
        proxy = str(PROXY).strip()
        if not proxy.startswith("http") and not proxy.startswith("socks"):
            proxy = f"http://{proxy}"
        session.proxies = {"http": proxy, "https": proxy}
    headers = {
        "x-admin-auth": MAIL_API_ADMIN_AUTH,
        "x-fingerprint": MAIL_API_FINGERPRINT,
        "x-lang": MAIL_API_LANG,
    }

    if MAIL_API_INITIAL_DELAY_SECONDS > 0:
        time.sleep(MAIL_API_INITIAL_DELAY_SECONDS)

    while time.time() - start < timeout:
        try:
            resp = session.get(
                MAIL_API_ENDPOINT,
                headers=headers,
                params={"limit": MAIL_API_LIMIT, "offset": MAIL_API_OFFSET, "address": email},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", []) if isinstance(data, dict) else []

            for item in results:
                mail_id = item.get("id")
                seen_key = f"api:{mail_id}"
                if seen_key in seen_uids:
                    continue

                address = (item.get("address") or "").strip().lower()
                if address != email_lower:
                    continue

                created_dt = _parse_mail_api_created_at(item.get("created_at"))
                if created_dt and (time.time() - created_dt.timestamp()) > EMAIL_MAX_AGE_SECONDS:
                    continue

                raw_text = item.get("raw") or ""
                otp_code, subject, _ = _extract_otp_code_from_raw_email(raw_text)
                if otp_code:
                    print(f"✅ 验证码: {otp_code} (邮件时间: {created_dt or item.get('created_at')})")
                    seen_uids.add(seen_key)
                    return otp_code
            time.sleep(MAIL_API_POLL_INTERVAL_SECONDS)
        except Exception as e:
            print(f"❌ 获取邮件错误: {e}")
            time.sleep(MAIL_API_POLL_INTERVAL_SECONDS)
    return None

def poll_verification_code_imap(email: str, timeout=60, seen_uids=None):
    print("⏳ 等待 IMAP 验证码...")
    if seen_uids is None:
        seen_uids = set()
    start = time.time()
    email_lower = email.lower()
    try:
        with MailBox(IMAP_HOST, port=IMAP_PORT).login(IMAP_USER, IMAP_PASS) as mailbox:
            round_idx = 0
            while time.time() - start < timeout:
                round_idx += 1
                try: mailbox.client.noop()
                except: pass

                messages = list(mailbox.fetch(limit=10, reverse=True))
                # print(f"📬 第 {round_idx} 次轮询，最近邮件数: {len(messages)}，目标收件人: {email}")

                for msg in messages:
                    msg_subject = (msg.subject or "").strip()
                    msg_from = (msg.from_ or "").strip()
                    msg_date = msg.date

                    if msg.uid in seen_uids:
                        # print(f"↪️ 跳过 UID {msg.uid}：已处理过，主题: {msg_subject}")
                        continue

                    if msg.date and (time.time() - msg.date.timestamp()) > EMAIL_MAX_AGE_SECONDS:
                        age_seconds = int(time.time() - msg.date.timestamp())
                        # print(
                        #     f"↪️ 跳过 UID {msg.uid}：邮件过旧 {age_seconds} 秒，"
                        #     f"主题: {msg_subject}，发件人: {msg_from}，时间: {msg_date}"
                        # )
                        continue

                    recipient_matched = _recipient_matches_email(msg, email_lower)
                    # print(
                    #     f"🔎 检查 UID {msg.uid}：发件人: {msg_from}，时间: {msg_date}，"
                    #     f"主题: {msg_subject}，收件人匹配: {'是' if recipient_matched else '否'}"
                    # )

                    if not recipient_matched:
                        continue

                    otp_code = _extract_otp_code_from_message(msg)
                    if otp_code:
                        print(f"✅ 验证码: {otp_code} (邮件时间: {msg.date})")
                        seen_uids.add(msg.uid)
                        try:
                            mailbox.delete(msg.uid)
                            mailbox.client.expunge()
                        except: pass
                        return otp_code
                    else:
                        pass
                        # print(f"⚠️ UID {msg.uid} 已匹配当前收件人，但未提取到验证码，主题: {msg_subject}")
                time.sleep(2)
    except Exception as e:
        print(f"❌ 获取邮件错误: {e}")
    return None

def poll_verification_code(email: str, timeout=60, seen_uids=None):
    if MAIL_FETCH_MODE == "api":
        return poll_verification_code_api(email, timeout=timeout, seen_uids=seen_uids)
    return poll_verification_code_imap(email, timeout=timeout, seen_uids=seen_uids)

# ═══════════════════════════════════════════════════════
# OAuth 辅助函数
# ═══════════════════════════════════════════════════════
def _extract_code_from_url(url):
    if not url or "code=" not in url: return None
    try: return parse_qs(urlparse(url).query).get("code", [None])[0]
    except: return None

def _follow_and_extract_code(session_obj, url, max_depth=10):
    if max_depth <= 0: return None
    try:
        r = session_obj.get(url, headers=NAVIGATE_HEADERS, verify=False, timeout=15, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            code = _extract_code_from_url(loc)
            if code: return code
            if loc.startswith("/"): loc = f"{OAUTH_ISSUER}{loc}"
            return _follow_and_extract_code(session_obj, loc, max_depth - 1)
        elif r.status_code == 200:
            return _extract_code_from_url(r.url)
    except requests.exceptions.ConnectionError as e:
        url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
        if url_match: return _extract_code_from_url(url_match.group(1))
    except: pass
    return None

def _decode_auth_session(session_obj):
    for c in session_obj.cookies:
        if c.name == "oai-client-auth-session":
            val = c.value.split(".")[0]
            val += "=" * (4 - len(val) % 4 if len(val) % 4 != 0 else 0)
            try: return json.loads(base64.urlsafe_b64decode(val).decode("utf-8"))
            except: pass
    return None

def codex_exchange_code(session, code, code_verifier):
    print("🔄 正在兑换 Token...")
    try:
        resp = session.post(
            f"{OAUTH_ISSUER}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": OAUTH_REDIRECT_URI,
                "client_id": OAUTH_CLIENT_ID,
                "code_verifier": code_verifier,
            },
            verify=False, timeout=60,
        )
        if resp.status_code == 200:
            print("✅ Token 兑换成功！")
            return resp.json()
    except Exception as e:
        print(f"❌ Token 兑换失败: {e}")
    return None

def save_tokens(email, token_data):
    os.makedirs(TOKEN_DIR, exist_ok=True)
    safe_email = email.replace("@", "_at_").replace(".", "_")
    filepath = os.path.join(TOKEN_DIR, f"{safe_email}.json")
    save_data = {
        "type": "codex",
        "email": email,
        "id_token": token_data.get("id_token", ""),
        "access_token": token_data.get("access_token", ""),
        "refresh_token": token_data.get("refresh_token", ""),
        "expires_in": token_data.get("expires_in", 0),
        "token_type": token_data.get("token_type", ""),
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(save_data, f, indent=2, ensure_ascii=False)
    print(f"💾 Token 已保存到: {filepath}")
    return filepath

def _utc_now_iso_z():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _decode_jwt_payload_unverified(token: str):
    if not token or token.count(".") < 2:
        return {}
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        raw = base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8")
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def _build_sub2api_credentials(token_data):
    access_token = token_data.get("access_token", "") or ""
    refresh_token = token_data.get("refresh_token", "") or ""
    expires_in = int(token_data.get("expires_in", 0) or 0)
    payload = _decode_jwt_payload_unverified(access_token)

    exp_from_jwt = payload.get("exp")
    try:
        exp_from_jwt = int(exp_from_jwt) if exp_from_jwt is not None else None
    except Exception:
        exp_from_jwt = None

    auth_claim = payload.get("https://api.openai.com/auth", {})
    if not isinstance(auth_claim, dict):
        auth_claim = {}

    organization_id = (
        token_data.get("organization_id")
        or auth_claim.get("organization_id")
        or auth_claim.get("org_id")
        or ""
    )
    chatgpt_account_id = auth_claim.get("chatgpt_account_id", "") or ""
    chatgpt_user_id = auth_claim.get("chatgpt_user_id", "") or ""
    expires_at = exp_from_jwt if exp_from_jwt is not None else int(time.time()) + max(expires_in, 0)

    return {
        "access_token": access_token,
        "chatgpt_account_id": chatgpt_account_id,
        "chatgpt_user_id": chatgpt_user_id,
        "expires_at": expires_at,
        "expires_in": expires_in,
        "organization_id": organization_id,
        "refresh_token": refresh_token,
        "model_mapping": {
            "claude-haiku-4-5-20251001": "gpt-5.2-codex",
            "claude-opus-4-6": "gpt-5.2-codex",
            "claude-sonnet-4-6": "gpt-5.2-codex",
            "gpt-5.3": "gpt-5.2-codex",
            "gpt-5.3-codex-spark": "gpt-5.2-codex",
            "gpt-5.3-codex": "gpt-5.2-codex",
            "gpt-5.4": "gpt-5.2-codex"
        },
    }

def _resolve_next_sub2api_priority(base_dir, current_export_path):
    default_priority = 20
    try:
        candidates = []
        for name in os.listdir(base_dir):
            path = os.path.join(base_dir, name)
            if not os.path.isfile(path):
                continue
            if os.path.abspath(path) == os.path.abspath(current_export_path):
                continue
            if not name.lower().endswith(".json"):
                continue
            candidates.append(path)

        if not candidates:
            return default_priority

        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for prev_file in candidates:
            try:
                with open(prev_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue

            accounts = data.get("accounts", []) if isinstance(data, dict) else []
            if not isinstance(accounts, list) or not accounts:
                continue

            prev_priority = accounts[0].get("priority", default_priority)
            try:
                prev_priority = int(prev_priority)
            except Exception:
                prev_priority = default_priority
            return prev_priority + 2

        return default_priority
    except Exception:
        return default_priority

def init_sub2api_export_file():
    export_path = SUB2API_EXPORT_FILE
    if not os.path.isabs(export_path):
        export_path = os.path.join(SCRIPT_DIR, export_path)

    base_dir = SUB2API_EXPORT_DIR
    if not os.path.isabs(base_dir):
        base_dir = os.path.join(SCRIPT_DIR, base_dir)

    base_name = os.path.basename(export_path)
    name, ext = os.path.splitext(base_name)
    if not ext:
        ext = ".json"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_export_name = f"{name}_{ts}{ext}"
    export_path = os.path.join(base_dir, run_export_name)

    os.makedirs(base_dir, exist_ok=True)
    run_priority = _resolve_next_sub2api_priority(base_dir, export_path)

    init_data = {
        "type": "sub2api-data",
        "version": 1,
        "exported_at": _utc_now_iso_z(),
        "proxies": [],
        "accounts": [],
    }
    with open(export_path, "w", encoding="utf-8") as f:
        json.dump(init_data, f, indent=2, ensure_ascii=False)
    print(f"🆕 sub2api 导出文件已创建: {export_path}")
    print(f"📌 本轮账号 priority: {run_priority}")
    return export_path, run_priority

def append_sub2api_account(export_path, email, token_data, run_priority):
    try:
        with open(export_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {
            "type": "sub2api-data",
            "version": 1,
            "exported_at": _utc_now_iso_z(),
            "proxies": [],
            "accounts": [],
        }

    if not isinstance(data, dict):
        data = {
            "type": "sub2api-data",
            "version": 1,
            "exported_at": _utc_now_iso_z(),
            "proxies": [],
            "accounts": [],
        }

    accounts = data.get("accounts")
    if not isinstance(accounts, list):
        accounts = []
        data["accounts"] = accounts

    accounts.append({
        "name": email,
        "platform": "openai",
        "type": "oauth",
        "credentials": _build_sub2api_credentials(token_data),
        "extra": {"email": email},
        "concurrency": 1,
        "priority": run_priority,
        "rate_multiplier": 1,
        "auto_pause_on_expired": True,
    })

    with open(export_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"📝 sub2api 已追加账号: {email}")

# ═══════════════════════════════════════════════════════
# 纯 HTTP 注册及两段式登录流程
# ═══════════════════════════════════════════════════════
class ProtocolRegistrar:
    def __init__(self):
        self.seen_uids = set()  # 防止跨阶段读取到同一封旧邮件的验证码

    def _build_headers(self, session, device_id, referer, with_sentinel=False, flow=""):
        headers = dict(COMMON_HEADERS)
        headers["referer"] = referer
        headers["oai-device-id"] = device_id
        headers.update(generate_datadog_trace())
        if with_sentinel:
            token = build_sentinel_token(session, device_id, flow=flow)
            if token: headers["openai-sentinel-token"] = token
        return headers

    def register_account(self, email, password, first_name, last_name, birthdate):
        """阶段一：注册账号"""
        print("▶️ [阶段一] 开始注册账号信息...")
        session = create_session()
        device_id = generate_device_id()
        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")

        # 1. 授权初始化
        cv, cc = generate_pkce()
        state = secrets.token_urlsafe(32)
        authorize_params = {
            "response_type": "code", "client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT_URI,
            "scope": "openid profile email offline_access", "code_challenge": cc, "code_challenge_method": "S256",
            "state": state, "screen_hint": "signup", "prompt": "login",
        }
        session.get(f"{OPENAI_AUTH_BASE}/oauth/authorize?{urlencode(authorize_params)}", headers=NAVIGATE_HEADERS, verify=False)

        # 2. 提交邮箱
        headers = self._build_headers(session, device_id, f"{OPENAI_AUTH_BASE}/create-account", True, "authorize_continue")
        r1 = session.post(f"{OPENAI_AUTH_BASE}/api/accounts/authorize/continue", json={"username": {"kind": "email", "value": email}, "screen_hint": "signup"}, headers=headers, verify=False)
        if r1.status_code != 200: return False, "提交邮箱失败"

        # 3. 提交密码
        headers = self._build_headers(session, device_id, f"{OPENAI_AUTH_BASE}/create-account/password", True, "password_verify")
        r2 = session.post(f"{OPENAI_AUTH_BASE}/api/accounts/user/register", json={"username": email, "password": password}, headers=headers, verify=False)
        if r2.status_code not in (200, 301, 302): return False, "注册密码失败"

        # 4. 触发验证码发送
        headers_nav = dict(NAVIGATE_HEADERS)
        headers_nav["referer"] = f"{OPENAI_AUTH_BASE}/create-account/password"
        session.get(f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/send", headers=headers_nav, verify=False)

        # 5. 读取并验证
        otp_code = poll_verification_code(email, timeout=EMAIL_OTP_TIMEOUT, seen_uids=self.seen_uids)
        if not otp_code: return False, "未收到验证码"
        headers = self._build_headers(session, device_id, f"{OPENAI_AUTH_BASE}/email-verification")
        r4 = session.post(f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/validate", json={"code": otp_code}, headers=headers, verify=False)
        if r4.status_code != 200: return False, "验证码验证失败"

        # 6. 完善个人资料
        headers = self._build_headers(session, device_id, f"{OPENAI_AUTH_BASE}/about-you")
        headers["openai-sentinel-token"] = build_sentinel_token(session, device_id)
        r5 = session.post(f"{OPENAI_AUTH_BASE}/api/accounts/create_account", json={"name": f"{first_name} {last_name}", "birthdate": birthdate}, headers=headers, verify=False)
        if r5.status_code == 403:
            headers["openai-sentinel-token"] = build_sentinel_token(session, device_id)
            r5 = session.post(f"{OPENAI_AUTH_BASE}/api/accounts/create_account", json={"name": f"{first_name} {last_name}", "birthdate": birthdate}, headers=headers, verify=False)
        if r5.status_code != 200:
            return False, f"创建账户资料失败 (HTTP {r5.status_code}): {r5.text[:500]}"

        print("✅ 账号注册成功！(准备开启新会话换取Token)")
        return True, "注册成功"

    def login_and_get_token(self, email, password, first_name, last_name, birthdate):
        """阶段二：使用全新 Session 登录并抓取 Token，并完全按照参考代码处理 Workspace 与 Org"""
        print("▶️ [阶段二] 全新会话登录，抓取 Token...")
        session = create_session()
        device_id = generate_device_id()
        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")

        code_verifier, code_challenge = generate_pkce()
        state = secrets.token_urlsafe(32)

        authorize_params = {
            "response_type": "code",
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        authorize_url = f"{OAUTH_ISSUER}/oauth/authorize?{urlencode(authorize_params)}"

        # 步骤1：请求授权地址
        try:
            session.get(authorize_url, headers=NAVIGATE_HEADERS, allow_redirects=True, verify=False, timeout=30)
        except Exception as e:
            return False, f"阶段二-授权请求失败: {e}"

        # 步骤2：提交邮箱
        headers = self._build_headers(session, device_id, f"{OAUTH_ISSUER}/log-in", True, "authorize_continue")
        resp = session.post(
            f"{OAUTH_ISSUER}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}},
            headers=headers, verify=False, timeout=30
        )
        if resp.status_code != 200: return False, "阶段二-提交邮箱失败"

        # 步骤3：提交密码
        headers = self._build_headers(session, device_id, f"{OAUTH_ISSUER}/log-in/password", True, "password_verify")
        resp = session.post(
            f"{OAUTH_ISSUER}/api/accounts/password/verify",
            json={"password": password},
            headers=headers, verify=False, timeout=30, allow_redirects=False
        )
        if resp.status_code != 200: return False, "阶段二-密码验证失败"

        data = resp.json()
        continue_url = data.get("continue_url", "")
        page_type = data.get("page", {}).get("type", "")

        # 步骤3.5：处理新号首次登录强制二次邮箱验证
        if page_type == "email_otp_verification" or "email-verification" in continue_url:
            print("⏳ [阶段二] 触发新账号首次登录二次邮箱验证，等待新验证码...")
            otp_code = poll_verification_code(email, timeout=EMAIL_OTP_TIMEOUT, seen_uids=self.seen_uids)
            if not otp_code: return False, "阶段二-未收到二次验证码"

            h_val = self._build_headers(session, device_id, f"{OAUTH_ISSUER}/email-verification")
            resp = session.post(
                f"{OAUTH_ISSUER}/api/accounts/email-otp/validate",
                json={"code": otp_code}, headers=h_val, verify=False, timeout=30
            )
            if resp.status_code != 200: return False, "阶段二-验证码验证失败"
            print("✅ [阶段二] 二次邮箱验证通过！")

            data = resp.json()
            continue_url = data.get("continue_url", "")
            page_type = data.get("page", {}).get("type", "")

            # 处理走过场的 about-you 环节
            if continue_url and "about-you" in continue_url:
                h_about = dict(NAVIGATE_HEADERS)
                h_about["referer"] = f"{OAUTH_ISSUER}/email-verification"
                resp_about = session.get(f"{OAUTH_ISSUER}/about-you", headers=h_about, verify=False, timeout=30, allow_redirects=True)

                if "consent" in resp_about.url or "organization" in resp_about.url:
                    continue_url = resp_about.url
                else:
                    h_create = self._build_headers(session, device_id, f"{OAUTH_ISSUER}/about-you")
                    resp_create = session.post(
                        f"{OAUTH_ISSUER}/api/accounts/create_account",
                        json={"name": f"{first_name} {last_name}", "birthdate": birthdate},
                        headers=h_create, verify=False, timeout=30
                    )
                    if resp_create.status_code == 200:
                        continue_url = resp_create.json().get("continue_url", "")
                    elif resp_create.status_code == 400 and "already_exists" in resp_create.text:
                        continue_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"

            if "consent" in page_type:
                continue_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"

            if not continue_url or "email-verification" in continue_url:
                return False, "邮箱验证后未获取到 consent URL"

        # 步骤4：Consent 流程 (严格对齐 1132.py 的多重拦截处理逻辑)
        if continue_url.startswith("/"):
            consent_url = f"{OAUTH_ISSUER}{continue_url}"
        else:
            consent_url = continue_url

        auth_code = None

        # 4a. 尝试 GET consent
        try:
            r3 = session.get(consent_url, headers=NAVIGATE_HEADERS, verify=False, timeout=30, allow_redirects=False)
            if r3.status_code in (301, 302, 303, 307, 308):
                loc = r3.headers.get("Location", "")
                auth_code = _extract_code_from_url(loc)
                if not auth_code:
                    auth_code = _follow_and_extract_code(session, loc)
        except requests.exceptions.ConnectionError as e:
            m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
            if m: auth_code = _extract_code_from_url(m.group(1))

        # 4b. 拦截处理: workspace/select
        if not auth_code:
            print("⏳ 处理 Workspace/Org 拦截...")
            session_data = _decode_auth_session(session)
            workspace_id = None
            if session_data:
                workspaces = session_data.get("workspaces",[])
                if workspaces:
                    workspace_id = workspaces[0].get("id")

            if workspace_id:
                h_consent = dict(COMMON_HEADERS)
                h_consent["referer"] = consent_url
                h_consent["oai-device-id"] = device_id
                h_consent.update(generate_datadog_trace())

                try:
                    r_ws = session.post(
                        f"{OAUTH_ISSUER}/api/accounts/workspace/select",
                        json={"workspace_id": workspace_id}, headers=h_consent, verify=False, timeout=30, allow_redirects=False
                    )
                    if r_ws.status_code in (301, 302, 303, 307, 308):
                        auth_code = _extract_code_from_url(r_ws.headers.get("Location", ""))
                    elif r_ws.status_code == 200:
                        ws_data = r_ws.json()
                        ws_next = ws_data.get("continue_url", "")
                        ws_page = ws_data.get("page", {}).get("type", "")

                        # 4c. 拦截处理: organization/select (带 project_id 提取)
                        if "organization" in ws_next or "organization" in ws_page:
                            org_url = ws_next if ws_next.startswith("http") else f"{OAUTH_ISSUER}{ws_next}"
                            org_id = None
                            project_id = None
                            ws_orgs = ws_data.get("data", {}).get("orgs",[])
                            if ws_orgs:
                                org_id = ws_orgs[0].get("id")
                                projects = ws_orgs[0].get("projects", [])
                                if projects:
                                    project_id = projects[0].get("id")

                            if org_id:
                                body = {"org_id": org_id}
                                if project_id:
                                    body["project_id"] = project_id
                                h_org = dict(COMMON_HEADERS)
                                h_org["referer"] = org_url
                                h_org["oai-device-id"] = device_id
                                h_org.update(generate_datadog_trace())

                                r_org = session.post(
                                    f"{OAUTH_ISSUER}/api/accounts/organization/select",
                                    json=body, headers=h_org, verify=False, timeout=30, allow_redirects=False
                                )
                                if r_org.status_code in (301, 302, 303, 307, 308):
                                    loc = r_org.headers.get("Location", "")
                                    auth_code = _extract_code_from_url(loc)
                                    if not auth_code:
                                        auth_code = _follow_and_extract_code(session, loc)
                                elif r_org.status_code == 200:
                                    org_next = r_org.json().get("continue_url", "")
                                    if org_next:
                                        auth_code = _follow_and_extract_code(session, f"{OAUTH_ISSUER}{org_next}" if org_next.startswith("/") else org_next)
                            else:
                                auth_code = _follow_and_extract_code(session, org_url)
                        elif ws_next:
                            auth_code = _follow_and_extract_code(session, f"{OAUTH_ISSUER}{ws_next}" if ws_next.startswith("/") else ws_next)
                except Exception as e:
                    print(f"⚠️ Workspace 选择异常: {e}")

        # 4d. 备用策略
        if not auth_code:
            try:
                r_fallback = session.get(consent_url, headers=NAVIGATE_HEADERS, verify=False, timeout=30, allow_redirects=True)
                auth_code = _extract_code_from_url(r_fallback.url)
                if not auth_code and r_fallback.history:
                    for r_hist in r_fallback.history:
                        loc = r_hist.headers.get("Location", "")
                        auth_code = _extract_code_from_url(loc)
                        if auth_code:
                            break
            except requests.exceptions.ConnectionError as e:
                url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                if url_match:
                    auth_code = _extract_code_from_url(url_match.group(1))
            except Exception:
                pass

        if not auth_code:
            return False, "提取 Code 失败(已被拦截或未响应)"

        # 步骤5：兑换 Token
        token_data = codex_exchange_code(session, auth_code, code_verifier)
        if token_data:
            return True, token_data
        return False, "兑换 Token 失败"

# ═══════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════
def main():
    print("\n" + "#" * 60)
    print(f"# 批量注册模式: 纯 HTTP (双会话解耦合策略)")
    print(f"# 计划次数: {'无限' if RUN_COUNT == 0 else RUN_COUNT} 次, 间隔 {RUN_INTERVAL} 秒")
    print(f"# 代理状态: {PROXY if PROXY else '直连'}")
    print(f"# Token 文件保存: {'开启' if SAVE_TOKEN_FILES_ENABLED else '关闭'}")
    print(f"# Routecode 实时保存: {'开启' if _as_bool(cfg.get('routecode_realtime_save_enabled', False), False) else '关闭'}")
    print("#" * 60)

    db_path = init_accounts_db()
    success_count = 0
    fail_count = 0
    failure_counter = Counter()
    recent_failures = deque(maxlen=FAILURE_SAMPLE_LIMIT)
    reserved_emails = set()
    routecode_sync_enabled = _as_bool(cfg.get("routecode_realtime_save_enabled", False), False)
    current_batch_target = None
    current_batch_completed = 0
    print(f"🗃️ SQLite 数据库: {db_path}")

    while True:
        if routecode_sync_enabled:
            if current_batch_target is None:
                plan = query_realtime_replenish_plan()
                if plan.get("status") != "ok":
                    print(f"⚠️ Routecode 可用账号查询失败: {plan.get('message', plan)}")
                    poll_interval = int(cfg.get("routecode_poll_interval_seconds", 180) or 180)
                    print(f"⏳ {poll_interval} 秒后重试轮询...")
                    time.sleep(poll_interval)
                    continue

                available_count = int(plan["available_count"])
                threshold = int(plan["replenish_threshold"])
                target = int(plan["replenish_target"])
                needed_count = int(plan["needed_count"])
                poll_interval = int(plan["poll_interval_seconds"])
                print("\n" + "-" * 60)
                print("📡 Routecode 轮询结果")
                print(f"   分组: {plan['group_name']}")
                print(f"   active_account_count: {plan['active_account_count']}")
                print(f"   rate_limited_account_count: {plan['rate_limited_account_count']}")
                print(f"   当前可用账号: {available_count}")
                print(f"   补量阈值: {threshold}")
                print(f"   补量目标: {target}")
                print(f"   本轮需补充: {needed_count}")
                print("-" * 60)

                if needed_count <= 0:
                    print(
                        f"✅ 当前可用账号已达到阈值 {threshold}，无需补充。"
                        f"{poll_interval} 秒后继续轮询..."
                    )
                    time.sleep(poll_interval)
                    continue

                current_batch_target = needed_count
                current_batch_completed = 0
                success_count = 0
                fail_count = 0
                failure_counter = Counter()
                recent_failures = deque(maxlen=FAILURE_SAMPLE_LIMIT)
                print(f"🧮 低于阈值 {threshold}，开始补充账号，本轮目标补充 {needed_count} 个，补到 {target} 为止。")

            if current_batch_completed >= current_batch_target:
                print(f"✅ 本轮补充完成，共补充 {current_batch_completed}/{current_batch_target} 个，重新开始轮询。")
                current_batch_target = None
                current_batch_completed = 0
                continue

            current_index = current_batch_completed + 1
            current_total = current_batch_target
        else:
            if RUN_COUNT != 0 and success_count + fail_count >= RUN_COUNT:
                break
            current_index = success_count + fail_count + 1
            current_total = RUN_COUNT

        print(f"\n{'='*60}")
        print(f"📌 第 {current_index}{f'/{current_total}' if current_total and current_total > 0 else ''} 轮注册")
        print(f"{'='*60}")

        email = generate_unique_email(reserved_emails=reserved_emails)
        first_name, last_name, birthday = generate_western_profile()
        full_name = f"{first_name} {last_name}"

        print(f"📋 注册信息:")
        print(f"   邮箱: {email}")
        print(f"   姓名: {full_name}")
        print(f"   生日: {birthday}")
        print(f"   密码: {FIXED_PASSWORD}\n")

        try:
            registrar = ProtocolRegistrar()
            # --- 阶段一：纯粹注册 ---
            reg_ok, reg_msg = registrar.register_account(email, FIXED_PASSWORD, first_name, last_name, birthday)

            if reg_ok:
                save_account_profile(email, full_name, birthday)
                upsert_registered_account_detail(email, full_name, birthday, FIXED_PASSWORD)
                mark_registration_success(email, reg_msg)
                print(f"🗃️ 账号基础信息已写入 SQLite: {email}")
                time.sleep(2)  # 给后端一点缓冲时间
                # --- 阶段二：全新会话登录获取 Token ---
                login_ok, result = registrar.login_and_get_token(email, FIXED_PASSWORD, first_name, last_name, birthday)

                if login_ok:
                    token_data = result
                    mark_token_success(email, token_data)
                    token_filepath = None
                    if SAVE_TOKEN_FILES_ENABLED:
                        token_filepath = save_tokens(email, token_data)
                    refresh_token = token_data.get("refresh_token", "")
                    if refresh_token:
                        COLLECTED_REFRESH_TOKENS.append(refresh_token)
                    if routecode_sync_enabled:
                        routecode_result = sync_routecode_account(email)
                        routecode_status = routecode_result.get("status")
                        routecode_message = routecode_result.get("message", "")
                        if routecode_status == "saved":
                            print(f"🛰️ Routecode 实时保存成功: {routecode_message}")
                            current_batch_completed += 1
                        elif routecode_status == "exists":
                            print(f"ℹ️ Routecode 已存在，跳过保存: {routecode_message}")
                        elif routecode_status == "disabled":
                            print(f"ℹ️ Routecode 实时保存未开启: {routecode_message}")
                        else:
                            print(f"⚠️ Routecode 实时保存失败: {routecode_message}")

                    print("\n" + "=" * 60)
                    print("🎉🎉🎉 全流程完成！注册 + Token 获取成功！")
                    print("=" * 60)
                    print(f"📧 邮箱:          {email}")
                    print(f"🔑 Access Token:  {token_data.get('access_token', '')[:40]}...")
                    print(f"🔄 Refresh Token: {refresh_token[:40]}...")
                    if token_filepath:
                        print(f"💾 Token 文件:    {token_filepath}")
                    print("💾 数据库存储:    SQLite 数据库 registered_account_details")
                    print("=" * 60)
                    success_count += 1
                else:
                    mark_account_failure(email, token_message=str(result), last_error=str(result))
                    record_failure(failure_counter, recent_failures, email, str(result), f"Token 失败: {result}")
                    print(f"❌ 获取 Token 失败: {result}")
                    fail_count += 1
            else:
                record_failure(failure_counter, recent_failures, email, str(reg_msg), f"注册失败: {reg_msg}")
                print(f"❌ 注册失败: {reg_msg}")
                fail_count += 1

        except KeyboardInterrupt:
            print("\n⏹️ 用户主动中断...")
            break
        except Exception as e:
            record_failure(failure_counter, recent_failures, email, "运行异常", f"运行异常: {e}")
            print(f"❌ 运行异常: {e}")
            traceback.print_exc()
            fail_count += 1

        print_run_stats(success_count, fail_count, failure_counter, recent_failures)

        if routecode_sync_enabled:
            if current_batch_target is not None and current_batch_completed >= current_batch_target:
                print("🔁 当前补充批次已完成，马上恢复轮询检查。")
            elif RUN_INTERVAL > 0:
                wait_seconds = random.randint(0, RUN_INTERVAL)
                print(f"\n>>> 随机等待 {wait_seconds} 秒后开始下一轮... (范围: 0~{RUN_INTERVAL})")
                time.sleep(wait_seconds)
        elif RUN_COUNT == 0 or success_count + fail_count < RUN_COUNT:
            if RUN_INTERVAL > 0:
                wait_seconds = random.randint(0, RUN_INTERVAL)
                print(f"\n>>> 随机等待 {wait_seconds} 秒后开始下一轮... (范围: 0~{RUN_INTERVAL})")
                time.sleep(wait_seconds)

    print(f"\n{'#'*60}")
    print(f"# 全部完成! 成功: {success_count}, 失败: {fail_count}")
    print(f"# 数据库存储: {db_path}")
    print(f"{'#'*60}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
