import os, uuid, httpx, asyncio, base64, csv, io, re, json, socket, ipaddress, hashlib, secrets, shutil
import html as _html   # aliased: one function uses a local named `html`
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import List, Optional
from urllib.parse import urlparse, urljoin

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel

import psycopg2, psycopg2.extras
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import JWTError, jwt

load_dotenv()

SECRET_KEY         = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    import secrets as _secrets
    SECRET_KEY = _secrets.token_hex(32)
    print("[WARN] SECRET_KEY not set in .env — generated a random one. JWTs will invalidate on restart. Set SECRET_KEY in .env!")
ALGORITHM          = "HS256"
TOKEN_EXPIRE       = int(os.getenv("TOKEN_EXPIRE_MINUTES", "120"))   # default 2h, was 8h
ALLOWED_ORIGINS    = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = ["*"]   # fallback — set ALLOWED_ORIGINS in .env for production
ADMIN_DEFAULT_USER = "admin"
ADMIN_DEFAULT_PASS = "TFeed@99"
VT_API_KEY         = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
HIBP_API_KEY       = os.getenv("HIBP_API_KEY", "")
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY", "")
NVD_API_KEY        = os.getenv("NVD_API_KEY", "")
GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "")
# Groq retires models without notice and the call then fails with a bare 404.
# llama-3.3-70b-versatile was decommissioned and silently broke five features
# (query builder, query explainer, diff explanation, advisory generator, CVE
# report). Keep this in one place so the next retirement is a config change,
# and check https://api.groq.com/openai/v1/models when AI features start 502ing.
GROQ_MODEL         = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
URLHAUS_AUTH_KEY   = os.getenv("URLHAUS_AUTH_KEY", "")  # required since abuse.ch mandated auth (30 Jun 2025) — free at https://auth.abuse.ch/
ENCRYPTION_KEY     = os.getenv("ENCRYPTION_KEY", "")  # generate: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
DAILY_FREE_QUOTA   = 10   # free platform-key checks per user per day (no personal key)
CACHE_HOURS        = 24

# Platform keys map — used when user has no personal key
PLATFORM_KEYS = {
    "virustotal":  VT_API_KEY,
    "abuseipdb":   ABUSEIPDB_API_KEY,
    "hibp":        HIBP_API_KEY,
    "shodan":      SHODAN_API_KEY,
    "nvd":         NVD_API_KEY,
    "groq":        GROQ_API_KEY,
    "urlhaus":     URLHAUS_AUTH_KEY,
}

# ── ENCRYPTION ────────────────────────────────────────────────────────────────
def _get_fernet():
    from cryptography.fernet import Fernet
    if ENCRYPTION_KEY:
        return Fernet(ENCRYPTION_KEY.encode())
    # Derive a key from SECRET_KEY as fallback (less secure but functional)
    import base64, hashlib
    key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
    return Fernet(key)

def encrypt_key(plaintext: str) -> str:
    if not plaintext: return ""
    return _get_fernet().encrypt(plaintext.encode()).decode()

def decrypt_key(ciphertext: str) -> str:
    if not ciphertext: return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except Exception:
        return ""

def mask_key(key: str) -> str:
    """Show only first 4 and last 4 characters."""
    if not key or len(key) < 10: return "••••••••"
    return key[:4] + "••••••••" + key[-4:]

# ── KEY RESOLUTION + QUOTA ────────────────────────────────────────────────────
def get_user_daily_usage(conn, user_id: str, service: str) -> int:
    """How many platform-key calls has this user made today for this service."""
    cur = conn.cursor()
    cur.execute("""SELECT COUNT(*) FROM api_usage_log
        WHERE user_id = %s AND api_name = %s AND cache_hit = FALSE
        AND created_at >= CURRENT_DATE""", (user_id, service))
    return cur.fetchone()[0]

def resolve_api_key(conn, service: str, user: dict) -> tuple:
    """
    Returns (key, using_personal_key, quota_remaining).
    
    Admin priority:
      1. Admin's own personal key
      2. Platform .env key
      3. Any other user's key (pooled fallback — admin only)
    
    Regular user priority:
      1. User's own personal key (unlimited)
      2. Platform key within daily quota (10/day)
      3. Quota exhausted → empty string
    """
    user_id  = user["id"]
    is_admin = user["role"] == "admin"
    cur      = conn.cursor()

    # 1. Check user's own personal key
    cur.execute("SELECT api_key_encrypted FROM user_api_keys WHERE user_id=%s AND service=%s",
                (user_id, service))
    row = cur.fetchone()
    if row and row[0]:
        key = decrypt_key(row[0])
        if key: return key, True, None

    # 2. Admin: try platform key
    if is_admin:
        platform_key = PLATFORM_KEYS.get(service, "")
        if platform_key: return platform_key, False, None

        # 3. Admin fallback: use any other user's key from the pool
        cur.execute("""SELECT api_key_encrypted FROM user_api_keys
            WHERE service=%s AND user_id != %s AND api_key_encrypted != ''
            ORDER BY updated_at DESC LIMIT 1""", (service, user_id))
        pool_row = cur.fetchone()
        if pool_row:
            pool_key = decrypt_key(pool_row[0])
            if pool_key: return pool_key, False, None

        return "", False, None  # admin but no keys available anywhere

    # 4. Regular user: check daily quota
    used      = get_user_daily_usage(conn, user_id, service)
    remaining = max(0, DAILY_FREE_QUOTA - used)
    if remaining > 0:
        platform_key = PLATFORM_KEYS.get(service, "")
        return platform_key, False, remaining
    else:
        return "", False, 0  # quota exhausted

def get_all_quota_status(conn, user_id: str, is_admin: bool) -> dict:
    """Returns quota info for all services for a user."""
    services = ["virustotal","abuseipdb","urlhaus","shodan","hibp","groq","nvd"]
    result = {}
    cur = conn.cursor()
    for svc in services:
        # check personal key
        cur.execute("SELECT api_key_encrypted FROM user_api_keys WHERE user_id=%s AND service=%s",
                    (user_id, svc))
        has_personal = bool(cur.fetchone())
        if is_admin or has_personal:
            result[svc] = {"has_personal_key": has_personal, "quota_remaining": None,
                           "quota_total": None, "unlimited": True}
        else:
            used = get_user_daily_usage(conn, user_id, svc)
            result[svc] = {"has_personal_key": False,
                           "quota_used": used,
                           "quota_remaining": max(0, DAILY_FREE_QUOTA - used),
                           "quota_total": DAILY_FREE_QUOTA,
                           "unlimited": False}
    return result

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2  = OAuth2PasswordBearer(tokenUrl="/auth/login")

limiter = Limiter(key_func=get_remote_address)
app     = FastAPI(title="ThreatFeed Intelligence Platform")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"])

TLP_IDS = {
    "WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "GREEN": "marking-definition--34098fce-860f-479d-8c64-8f43c57026f1",
    "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "RED":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
PATTERNS = {
    "IPv4":   "[ipv4-addr:value = '{v}']",
    "IPv6":   "[ipv6-addr:value = '{v}']",
    "Domain": "[domain-name:value = '{v}']",
    "URL":    "[url:value = '{v}']",
    "MD5":    "[file:hashes.MD5 = '{v}']",
    "SHA1":   "[file:hashes.'SHA-1' = '{v}']",
    "SHA256": "[file:hashes.'SHA-256' = '{v}']",
    "Email":  "[email-addr:value = '{v}']",
    "CVE":    "[vulnerability:name = '{v}']",
}
COLLECTION_ID = "a45ef559-3f21-4b78-9cde-ef0123456789"
SERVER_URL    = os.getenv("SERVER_URL", "https://YOUR_DOMAIN")

# ── DEFANG ────────────────────────────────────────────────────────────────────
def refang(v: str) -> str:
    v = v.strip()
    v = re.sub(r'hxxps?', lambda m: m.group().replace('xx','tt'), v, flags=re.IGNORECASE)
    v = v.replace('[.]','.').replace('(dot)','.').replace('[dot]','.').replace('\\.','.')
    v = v.replace('[:]',':').replace('[/]','/').replace('[@]','@').replace('[at]','@')
    return v

def defang(value: str, ioc_type: str) -> str:
    v = value
    if ioc_type in ("IPv4","IPv6"): v = v.replace('.','[.]')
    elif ioc_type == "Domain": v = '[.]'.join(v.split('.'))
    elif ioc_type == "URL":
        v = re.sub(r'^https?', lambda m: m.group().replace('tt','xx'), v, flags=re.IGNORECASE)
        try:
            from urllib.parse import urlparse
            p = urlparse(value)
            v = v.replace(p.netloc, p.netloc.replace('.','[.]'))
        except Exception: pass
    elif ioc_type == "Email": v = v.replace('@','[@]')
    return v

SUSPICIOUS_FILE_EXTS = ("exe","scr","bat","cmd","pif","vbs","js","jar",
                         "ps1","hta","wsf","dll","msi","lnk","apk","jse","vbe",
                         "wsh","msc","cpl","gadget")
DOCUMENT_FILE_EXTS = ("pdf","doc","docx","xls","xlsx","ppt","pptx","zip","rar",
                       "7z","iso","txt","csv","rtf")

def detect_type(val: str) -> str:
    val = val.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val): return "IPv4"
    if re.match(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$', val) and val.count(':') >= 2:
        return "IPv6"
    if re.match(r'^[0-9a-fA-F]{32}$', val): return "MD5"
    if re.match(r'^[0-9a-fA-F]{40}$', val): return "SHA1"
    if re.match(r'^[0-9a-fA-F]{64}$', val): return "SHA256"
    if re.match(r'^https?://', val, re.IGNORECASE): return "URL"
    if re.match(r'^CVE-\d{4}-\d{4,}$', val, re.IGNORECASE): return "CVE"
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', val): return "Email"
    # Filename: ends with a known executable/script/document extension
    fn_match = re.match(r'^[\w \-.]+\.([A-Za-z0-9]{1,5})$', val)
    if fn_match and fn_match.group(1).lower() in SUSPICIOUS_FILE_EXTS + DOCUMENT_FILE_EXTS:
        return "Filename"
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', val): return "Domain"
    return "Unknown"

def check_filename_heuristics(filename: str) -> list:
    """Heuristic red flags for a filename — no internet lookup available for bare filenames."""
    flags = []
    fn = filename.lower()
    double_ext = re.search(
        r'\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|csv)\.(exe|scr|bat|cmd|com|pif|vbs|js|jar|ps1|hta|wsf)$', fn)
    if double_ext:
        flags.append(f"Double extension masking ('{double_ext.group()}') — classic malware disguise technique")
    elif any(fn.endswith("."+ext) for ext in SUSPICIOUS_FILE_EXTS):
        flags.append("Executable or script extension — exercise caution before running")
    if re.search(r'[\u202e\u200f\u200e]', filename):
        flags.append("Contains Unicode right-to-left override character — likely extension spoofing")
    if len(filename) > 100:
        flags.append("Unusually long filename")
    if re.search(r'(invoice|receipt|statement|payment|urgent|resume|cv)[\w\-. ]*\.(exe|scr|js|vbs|bat)$', fn):
        flags.append("Social-engineering filename pattern combined with executable extension")
    return flags

def compute_verdict(enrichment: dict) -> dict:
    """Aggregate per-source enrichment results into a single verdict."""
    vt = enrichment.get("virustotal", {}) or {}
    ab = enrichment.get("abuseipdb", {}) or {}
    uh = enrichment.get("urlhaus", {}) or {}

    vt_mal   = vt.get("malicious", 0)
    vt_total = vt.get("total", 0)
    ab_score = ab.get("abuse_score", 0)
    uh_found = uh.get("found", False)

    reasons = []
    if vt_mal > 0:
        reasons.append(f"VirusTotal: {vt_mal}/{vt_total} engines flagged malicious")
    if ab_score >= 25:
        reasons.append(f"AbuseIPDB: {ab_score}% abuse confidence")
    if uh_found:
        reasons.append(f"URLhaus: listed for {uh.get('threat','malware')} distribution")

    if vt_mal >= 3 or ab_score >= 75 or uh_found:
        return {"verdict":"malicious", "score": max(vt_mal*10, ab_score, 90 if uh_found else 0),
                "reason": " | ".join(reasons) or "Multiple sources flagged as malicious"}
    if vt_mal >= 1 or ab_score >= 25:
        return {"verdict":"suspicious", "score": max(vt_mal*10, ab_score),
                "reason": " | ".join(reasons) or "Some indicators of suspicious activity"}

    checked_sources = [v for v in (vt, ab, uh) if v and not v.get("skipped") and not v.get("error")]
    if checked_sources:
        return {"verdict":"clean", "score": 0, "reason": "No malicious activity found in any checked source"}

    return {"verdict":"unknown", "score": 0,
            "reason": "No API keys configured or daily quota exhausted — add a personal key in Settings"}

def parse_bulk_input(text: str) -> list:
    """
    Parse a free-text blob of indicators (one or many per line, mixed
    fanged/defanged). Handles list markers, comma/semicolon-separated
    lines, and strips surrounding punctuation/quotes.
    """
    if not text or not text.strip():
        return []
    tokens = []
    for raw_line in text.strip().split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        # Strip leading bullet/number markers: "- ", "* ", "1. ", "1) "
        # Require whitespace after the marker so "8.8.8.8" is never mistaken for "8. "
        line = re.sub(r'^[\-\*\u2022]\s+', '', line)
        line = re.sub(r'^\d{1,3}[\.\)]\s+', '', line)
        # Split multiple indicators on one line by comma/semicolon —
        # but not if the line looks like a single URL (commas can appear in query strings)
        if 'http' not in line.lower() and re.search(r'[,;]', line):
            parts = re.split(r'[,;]\s*', line)
        else:
            parts = [line]
        for p in parts:
            p = p.strip().strip('"\'()[]<>')
            if p:
                tokens.append(p)
    seen, deduped = set(), []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(host=os.getenv("DB_HOST"), dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"), password=os.getenv("DB_PASS"))
    try: yield conn
    finally: conn.close()

def get_db_direct():
    return psycopg2.connect(host=os.getenv("DB_HOST"), dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"), password=os.getenv("DB_PASS"))

# ── STARTUP ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    conn = get_db_direct(); cur = conn.cursor()

    tables = [
        """CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(100) PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
            password TEXT NOT NULL, role VARCHAR(20) DEFAULT 'analyst',
            email VARCHAR(255), active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS stored_files (
            id VARCHAR(100) PRIMARY KEY,
            filename VARCHAR(300) NOT NULL,
            stored_name VARCHAR(100) NOT NULL,
            size_bytes BIGINT NOT NULL DEFAULT 0,
            content_type VARCHAR(150),
            sha256 VARCHAR(64),
            share_token VARCHAR(64) UNIQUE,
            uploaded_by VARCHAR(100),
            download_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS access_requests (
            id VARCHAR(100) PRIMARY KEY, user_id VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL, message TEXT,
            status VARCHAR(20) DEFAULT 'pending', granted_role VARCHAR(20),
            requested_at TIMESTAMP DEFAULT NOW(), decided_at TIMESTAMP, decided_by VARCHAR(100))""",
        """CREATE TABLE IF NOT EXISTS admin_notes (
            id VARCHAR(100) PRIMARY KEY,
            title TEXT DEFAULT '',
            content TEXT DEFAULT '',
            note_type VARCHAR(20) DEFAULT 'text',
            color VARCHAR(30) DEFAULT 'default',
            pinned BOOLEAN DEFAULT FALSE,
            archived BOOLEAN DEFAULT FALSE,
            tags TEXT[] DEFAULT '{}',
            checklist JSONB DEFAULT '[]',
            linked_iocs TEXT[] DEFAULT '{}',
            linked_cves TEXT[] DEFAULT '{}',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS invite_codes (
            code VARCHAR(64) PRIMARY KEY, role VARCHAR(20) DEFAULT 'analyst',
            created_by VARCHAR(100), used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS campaigns (
            id VARCHAR(100) PRIMARY KEY, name VARCHAR(200) UNIQUE NOT NULL,
            description TEXT, threat_actor VARCHAR(200), industry_targets TEXT[],
            created_by VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS iocs (
            id VARCHAR(100) PRIMARY KEY, type VARCHAR(20) NOT NULL,
            value TEXT NOT NULL, value_defanged TEXT, industry VARCHAR(50),
            tlp VARCHAR(10) DEFAULT 'AMBER', confidence INTEGER DEFAULT 75,
            description TEXT, tags TEXT[], created_by VARCHAR(100),
            enrichment JSONB, valid_until TIMESTAMP,
            false_positive BOOLEAN DEFAULT FALSE, fp_reason TEXT,
            mitre_techniques TEXT[], campaign_id VARCHAR(100),
            created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS ioc_relationships (
            id SERIAL PRIMARY KEY, source_id VARCHAR(100) NOT NULL,
            target_id VARCHAR(100) NOT NULL, relationship_type VARCHAR(50) DEFAULT 'related_to',
            note TEXT, created_by VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS ioc_notes (
            id SERIAL PRIMARY KEY, ioc_id VARCHAR(100) NOT NULL,
            note TEXT NOT NULL, username VARCHAR(50), user_id VARCHAR(100),
            created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS ioc_score_history (
            id SERIAL PRIMARY KEY, ioc_id VARCHAR(100) NOT NULL,
            old_score INTEGER, new_score INTEGER, delta INTEGER,
            reason TEXT, triggered_by VARCHAR(50), created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS api_usage_log (
            id SERIAL PRIMARY KEY, api_name VARCHAR(50) NOT NULL,
            ioc_value TEXT, cache_hit BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY, action VARCHAR(20) NOT NULL,
            ioc_id VARCHAR(100), ioc_value TEXT, ioc_type VARCHAR(20),
            username VARCHAR(50), user_id VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            type VARCHAR(50) NOT NULL,
            title TEXT NOT NULL,
            body TEXT,
            severity VARCHAR(20) DEFAULT 'info',
            read BOOLEAN DEFAULT FALSE,
            metadata JSONB,
            created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS user_api_keys (
            id SERIAL PRIMARY KEY,
            user_id VARCHAR(100) NOT NULL,
            service VARCHAR(50) NOT NULL,
            api_key_encrypted TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(user_id, service))""",
        """CREATE TABLE IF NOT EXISTS assets (
            id VARCHAR(100) PRIMARY KEY, name VARCHAR(200) NOT NULL,
            vendor VARCHAR(200), version VARCHAR(100),
            asset_type VARCHAR(50) DEFAULT 'application',
            criticality VARCHAR(20) DEFAULT 'high',
            cpe TEXT, description TEXT, created_by VARCHAR(100),
            active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS cve_findings (
            id VARCHAR(100) PRIMARY KEY, cve_id VARCHAR(50) NOT NULL,
            asset_id VARCHAR(100) REFERENCES assets(id) ON DELETE CASCADE,
            UNIQUE(cve_id, asset_id),
            asset_id VARCHAR(100), title TEXT, description TEXT,
            cvss_score FLOAT, cvss_severity VARCHAR(20), cvss_vector TEXT,
            epss_score FLOAT, epss_percentile FLOAT,
            kev_listed BOOLEAN DEFAULT FALSE, kev_date TEXT,
            cwe TEXT, affected_versions TEXT,
            published_date TEXT, modified_date TEXT,
            patch_available BOOLEAN DEFAULT FALSE, patch_url TEXT,
            patch_detected_at TIMESTAMP,
            "references" JSONB, iocs_extracted TEXT[],
            created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS cve_ioc_links (
            cve_id VARCHAR(50), ioc_id VARCHAR(100), PRIMARY KEY (cve_id, ioc_id))""",
        """CREATE TABLE IF NOT EXISTS cve_poll_log (
            id SERIAL PRIMARY KEY, assets_polled INTEGER DEFAULT 0,
            new_cves INTEGER DEFAULT 0, new_iocs INTEGER DEFAULT 0,
            patches_detected INTEGER DEFAULT 0, error TEXT,
            polled_at TIMESTAMP DEFAULT NOW())""",
    ]

    for sql in tables:
        try: cur.execute(sql)
        except Exception: conn.rollback()

    # migrations
    for col, defn in [
        ("value_defanged","TEXT"), ("valid_until","TIMESTAMP"), ("enrichment","JSONB"),
        ("created_by","VARCHAR(100)"), ("false_positive","BOOLEAN DEFAULT FALSE"),
        ("fp_reason","TEXT"), ("mitre_techniques","TEXT[]"), ("campaign_id","VARCHAR(100)"),
    ]:
        try: cur.execute(f"ALTER TABLE iocs ADD COLUMN IF NOT EXISTS {col} {defn}")
        except Exception: conn.rollback()

    # add user_id to api_usage_log if missing
    try: cur.execute("ALTER TABLE api_usage_log ADD COLUMN IF NOT EXISTS user_id VARCHAR(100)")
    except Exception: conn.rollback()

    # add email to users if missing (needed for explorer → access-request flow)
    try: cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)")
    except Exception: conn.rollback()

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (id,username,password,role) VALUES (%s,%s,%s,%s)",
            (f"user--{uuid.uuid4()}", ADMIN_DEFAULT_USER, pwd_ctx.hash(ADMIN_DEFAULT_PASS), "admin"))
        print("[startup] Default admin created")

    conn.commit(); cur.close(); conn.close()

    # start scheduler
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.interval import IntervalTrigger
        from apscheduler.triggers.cron   import CronTrigger
        scheduler = AsyncIOScheduler()
        scheduler.add_job(scheduled_cve_poll, IntervalTrigger(hours=6),
                          id="cve_poll", replace_existing=True, misfire_grace_time=300)
        # Daily brief — hour/minute read from DB settings at runtime
        scheduler.add_job(send_daily_brief_job, CronTrigger(hour=8, minute=0),
                          id="daily_brief", replace_existing=True, misfire_grace_time=600)
        # Weekly summary — every Sunday at 8 AM
        scheduler.add_job(send_weekly_summary_job, CronTrigger(day_of_week="sun", hour=8, minute=0),
                          id="weekly_summary", replace_existing=True, misfire_grace_time=600)
        # Threat feed connectors — daily sync of ThreatFox/MalwareBazaar/URLhaus
        scheduler.add_job(scheduled_connector_sync, IntervalTrigger(hours=24),
                          id="connector_sync", replace_existing=True, misfire_grace_time=3600)
        scheduler.start()
        print("[scheduler] CVE poll every 6h | Daily brief 08:00 | Weekly Sundays | Connectors every 24h")
    except ImportError:
        print("[scheduler] apscheduler not installed — run: pip install apscheduler")

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN DAILY BRIEF — CVE digest + Gold rates
# ═══════════════════════════════════════════════════════════════════════════════

NOTIF_SETTINGS_KEY = "admin_notification_settings"

async def get_notif_settings(conn) -> dict:
    """Load notification settings from DB (stored as a JSON system setting)."""
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT value FROM system_settings WHERE key = %s",
                    (NOTIF_SETTINGS_KEY,))
        row = cur.fetchone()
        if row:
            import json as _j
            return _j.loads(row["value"])
    except Exception: pass
    return {}


async def fetch_daily_cve_digest() -> list:
    """
    Get the most critical/exploitable CVEs for today's brief:
    - CISA KEV additions in the last 7 days
    - CVEs in our DB with high EPSS (> 0.7) added recently
    - Critical unpatched CVEs from monitored assets
    """
    items = []
    try:
        # 1. Latest KEV additions
        kev = await fetch_kev_catalog()
        kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(kev_url)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities",[])
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
            recent_kev = [v for v in vulns
                          if v.get("dateAdded","") >= cutoff]
            for v in recent_kev[:5]:
                items.append({
                    "cve_id":      v.get("cveID",""),
                    "name":        v.get("vulnerabilityName",""),
                    "vendor":      v.get("vendorProject",""),
                    "product":     v.get("product",""),
                    "description": v.get("shortDescription","")[:200],
                    "kev_date":    v.get("dateAdded",""),
                    "due_date":    v.get("dueDate",""),
                    "source":      "CISA KEV",
                    "severity":    "CRITICAL",
                })
    except Exception: pass

    try:
        # 2. High-EPSS CVEs from NVD (EPSS ≥ 0.7 = top 70th percentile)
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get("https://api.first.org/data/v1/epss",
                params={"percentile-gte":"0.95","limit":"10","order":"!epss"})
        if r.status_code == 200:
            for e in r.json().get("data",[])[:5]:
                cve = e.get("cve","")
                if not any(x["cve_id"] == cve for x in items):
                    items.append({
                        "cve_id":      cve,
                        "name":        f"High Exploitation Probability",
                        "vendor":      "Multiple",
                        "product":     "See NVD",
                        "description": f"EPSS: {float(e.get('epss',0))*100:.1f}% exploitation probability (top {(1-float(e.get('percentile',0)))*100:.0f}%)",
                        "kev_date":    "",
                        "source":      "EPSS Top 5%",
                        "severity":    "HIGH",
                    })
    except Exception: pass

    return items[:8]

def format_brief_message(cve_items: list, is_weekly: bool = False) -> dict:
    """Format notification content for push/email."""
    now    = datetime.now(timezone.utc)
    prefix = "📊 TFII Weekly Summary" if is_weekly else "🔔 TFII Daily Brief"
    date   = now.strftime("%A, %d %b %Y")

    # ── CVE section ──────────────────────────────────────────────────────────
    cve_text = ""
    if cve_items:
        cve_text = f"\n🛡️ HIGH-RISK CVEs ({len(cve_items)} alerts)\n"
        cve_text += "─" * 35 + "\n"
        for c in cve_items:
            cve_text += f"\n🔴 {c['cve_id']} [{c['source']}]\n"
            if c.get('name') and c['name'] != "High Exploitation Probability":
                cve_text += f"   {c['name']}\n"
            if c.get('vendor') or c.get('product'):
                cve_text += f"   Affected: {c.get('vendor','')} {c.get('product','')}\n"
            if c.get('description'):
                cve_text += f"   {c['description'][:150]}\n"
            if c.get('due_date'):
                cve_text += f"   ⚠️ CISA Remediation Due: {c['due_date']}\n"
    else:
        cve_text = "\n🛡️ No new critical CVEs in the last 7 days ✅\n"

    title = f"{prefix} — {date}"
    body  = cve_text

    # HTML version for email
    html = f"""<html><body style="font-family:monospace;background:#0f172a;color:#e2e8f0;padding:20px;">
<h2 style="color:#10b981;">{title}</h2>
<pre style="line-height:1.7;font-size:13px;">{body}</pre>
<hr style="border-color:#334155;"/>
<p style="color:#64748b;font-size:11px;">Sent by TFII — ThreatFeed Intelligence Platform</p>
</body></html>"""

    return {"title": title, "body": body.strip(), "html": html}

async def send_notification(title: str, body: str, html: str, settings: dict):
    """Send notification via configured channel(s)."""
    errors = []

    # ── ntfy.sh ──────────────────────────────────────────────────────────────
    if settings.get("ntfy_topic"):
        try:
            server   = settings.get("ntfy_server","https://ntfy.sh").rstrip("/")
            topic    = settings["ntfy_topic"]
            priority = settings.get("ntfy_priority","urgent")  # urgent bypasses Android Doze via FCM
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.post(f"{server}/{topic}",
                    content=body.encode("utf-8"),
                    headers={
                        "Title":    title,
                        "Priority": priority,
                        "Tags":     "warning,shield",
                        "Markdown": "yes",
                        "Content-Type": "text/plain",
                    })
            if r.status_code not in (200,201):
                errors.append(f"ntfy: HTTP {r.status_code}")
            else:
                print(f"[notify] ntfy.sh sent ({priority}): {title}")
        except Exception as e:
            errors.append(f"ntfy error: {e}")

    # ── Telegram ─────────────────────────────────────────────────────────────
    if settings.get("telegram_token") and settings.get("telegram_chat_id"):
        try:
            bot   = settings["telegram_token"]
            chat  = settings["telegram_chat_id"]
            # Telegram has 4096 char limit — truncate body
            msg   = f"*{title}*\n\n```\n{body[:3800]}\n```"
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.post(f"https://api.telegram.org/bot{bot}/sendMessage",
                    json={"chat_id": chat, "text": msg,
                          "parse_mode": "Markdown", "disable_web_page_preview": True})
            if r.status_code != 200:
                errors.append(f"telegram: HTTP {r.status_code} — {r.text[:100]}")
            else:
                print(f"[notify] Telegram sent: {title}")
        except Exception as e:
            errors.append(f"telegram error: {e}")

    # ── Email (SMTP) ──────────────────────────────────────────────────────────
    if settings.get("email_to") and settings.get("smtp_host"):
        try:
            import smtplib, email.mime.multipart, email.mime.text
            msg = email.mime.multipart.MIMEMultipart("alternative")
            msg["Subject"] = title
            msg["From"]    = settings.get("smtp_from", settings.get("smtp_user",""))
            msg["To"]      = settings["email_to"]
            msg.attach(email.mime.text.MIMEText(body, "plain"))
            msg.attach(email.mime.text.MIMEText(html,  "html"))
            with smtplib.SMTP(settings["smtp_host"],
                              int(settings.get("smtp_port", 587))) as smtp:
                smtp.ehlo(); smtp.starttls(); smtp.ehlo()
                smtp.login(settings["smtp_user"], settings["smtp_pass"])
                smtp.sendmail(msg["From"], msg["To"], msg.as_string())
            print(f"[notify] Email sent to {settings['email_to']}: {title}")
        except Exception as e:
            errors.append(f"email error: {e}")

    return errors

async def send_daily_brief_job():
    """APScheduler job — daily brief."""
    print("[notify] Running daily brief job...")
    conn = None
    try:
        conn = get_db_direct()
        settings = await get_notif_settings(conn)
        if not settings.get("enabled"): return
        if not settings.get("daily_enabled", True): return
        cve_items = await fetch_daily_cve_digest()
        msg = format_brief_message(cve_items, is_weekly=False)
        errors = await send_notification(msg["title"], msg["body"], msg["html"], settings)
        if errors: print(f"[notify] Send errors: {errors}")
    except Exception as e:
        print(f"[notify] Daily brief error: {e}")
    finally:
        if conn: conn.close()

async def send_weekly_summary_job():
    """APScheduler job — weekly summary (Sunday)."""
    print("[notify] Running weekly summary job...")
    conn = None
    try:
        conn = get_db_direct()
        settings = await get_notif_settings(conn)
        if not settings.get("enabled"): return
        if not settings.get("weekly_enabled", True): return
        cve_items = await fetch_daily_cve_digest()
        msg = format_brief_message(cve_items, is_weekly=True)
        errors = await send_notification(msg["title"], msg["body"], msg["html"], settings)
        if errors: print(f"[notify] Send errors: {errors}")
    except Exception as e:
        print(f"[notify] Weekly summary error: {e}")
    finally:
        if conn: conn.close()

# ── Admin notification endpoints ─────────────────────────────────────────────

class NotifSettingsBody(BaseModel):
    enabled:          bool    = True
    daily_enabled:    bool    = True
    weekly_enabled:   bool    = True
    ntfy_topic:       Optional[str] = None
    ntfy_server:      Optional[str] = "https://ntfy.sh"
    ntfy_priority:    Optional[str] = "urgent"
    telegram_token:   Optional[str] = None
    telegram_chat_id: Optional[str] = None
    email_to:         Optional[str] = None
    smtp_host:        Optional[str] = None
    smtp_port:        Optional[int] = 587
    smtp_user:        Optional[str] = None
    smtp_pass:        Optional[str] = None
    smtp_from:        Optional[str] = None


# ── AUTH ──────────────────────────────────────────────────────────────────────
def create_token(data: dict) -> str:
    p = data.copy()
    p["exp"] = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE)
    return jwt.encode(p, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2), conn=Depends(get_db)):
    exc = HTTPException(status_code=401, detail="Invalid or expired token",
                        headers={"WWW-Authenticate":"Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        if not uid: raise exc
    except JWTError: raise exc
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE id = %s AND active = TRUE", (uid,))
    user = cur.fetchone()
    if not user: raise exc
    return user

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# The file store is deliberately narrower than the admin role: it is restricted
# to the single named owner account, so promoting someone to admin does not hand
# them the ability to publish files from this domain.
ROOT_ADMIN_USERNAME = os.getenv("ROOT_ADMIN_USERNAME", "admin")

def require_root_admin(user=Depends(get_current_user)):
    if user["username"] != ROOT_ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Not permitted")
    return user

def require_full_access(user=Depends(get_current_user)):
    """
    Blocks the 'explorer' role from sensitive data — the personal IOC
    feed, monitored assets, and campaigns. Explorers can still use every
    stateless tool (CVE lookup, KQL/SPL builder, OSINT, CVE Wall, and
    read-only Bulk IOC Lookup) but can't see or modify the owner's
    actual tracked threat-intel data.
    """
    if user["role"] == "explorer":
        raise HTTPException(status_code=403,
            detail="This is part of the live workspace, not available in demo/explorer mode. Request full access to unlock it.")
    return user

# ── MODELS ────────────────────────────────────────────────────────────────────
class IOCIn(BaseModel):
    type: str; value: str; industry: Optional[str] = "General"
    tlp: Optional[str] = "AMBER"; confidence: Optional[int] = 75
    description: Optional[str] = ""; tags: Optional[List[str]] = []
    valid_days: Optional[int] = 90
    mitre_techniques: Optional[List[str]] = []
    campaign_id: Optional[str] = None

class UserCreate(BaseModel):
    username: str; password: str; role: Optional[str] = "analyst"

class SignupRequest(BaseModel):
    username: str; password: str; invite_code: Optional[str] = None

class PasswordChange(BaseModel):
    current_password: str; new_password: str

class InviteCreate(BaseModel):
    role: Optional[str] = "analyst"

class CampaignIn(BaseModel):
    name: str; description: Optional[str] = ""
    threat_actor: Optional[str] = ""; industry_targets: Optional[List[str]] = []

# Named IocNoteIn, not NoteIn: a second, unrelated NoteIn (the workspace note
# model) is declared later in this file and silently shadowed this one, so
# add_note received the workspace model and raised AttributeError on body.note.
# Adding a note to an IOC returned 500 for as long as both names collided.
class IocNoteIn(BaseModel):
    note: str

class FPUpdate(BaseModel):
    false_positive: bool; reason: Optional[str] = ""

class RelationshipIn(BaseModel):
    target_id: str
    relationship_type: Optional[str] = "related_to"
    note: Optional[str] = ""

class STIXImport(BaseModel):
    bundle: dict

class TAXIIPoll(BaseModel):
    server_url: str; collection_id: str
    token: Optional[str] = None; api_key: Optional[str] = None

class MISPPull(BaseModel):
    misp_url: str; misp_key: str; limit: Optional[int] = 100

class OSINTRequest(BaseModel):
    target: str; target_type: str

class AssetIn(BaseModel):
    name: str; vendor: Optional[str] = ""; version: Optional[str] = ""
    asset_type: Optional[str] = "application"; criticality: Optional[str] = "high"
    cpe: Optional[str] = ""; description: Optional[str] = ""

class AIEnrichRequest(BaseModel):
    ioc_type: str; value: str; industry: str

class IntelNewsRequest(BaseModel):
    category: str = "all"

# ── NOTIFICATIONS ─────────────────────────────────────────────────────────────

@app.get("/admin/notify/settings")
def get_notify_settings(admin=Depends(require_admin), conn=Depends(get_db)):
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("CREATE TABLE IF NOT EXISTS system_settings (key VARCHAR PRIMARY KEY, value TEXT)")
        cur.execute("SELECT value FROM system_settings WHERE key=%s", (NOTIF_SETTINGS_KEY,))
        row = cur.fetchone()
        conn.commit()
        if row:
            import json as _j
            s = _j.loads(row["value"])
            # Mask secrets in response
            if s.get("smtp_pass"):    s["smtp_pass"]       = "••••••••"
            if s.get("telegram_token"): s["telegram_token"] = s["telegram_token"][:8]+"..."
            return s
    except Exception: pass
    return {}

@app.post("/admin/notify/settings")
def save_notify_settings(body: NotifSettingsBody, admin=Depends(require_admin), conn=Depends(get_db)):
    import json as _j
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS system_settings (key VARCHAR PRIMARY KEY, value TEXT)")
    # Preserve masked secrets — if client sends '••••••••' keep the original
    existing = {}
    cur.execute("SELECT value FROM system_settings WHERE key=%s", (NOTIF_SETTINGS_KEY,))
    row = cur.fetchone()
    if row:
        try: existing = _j.loads(row[0])
        except Exception: pass
    data = body.dict()
    if data.get("smtp_pass") == "••••••••": data["smtp_pass"] = existing.get("smtp_pass","")
    if data.get("telegram_token","").endswith("..."): data["telegram_token"] = existing.get("telegram_token","")
    cur.execute("INSERT INTO system_settings (key,value) VALUES (%s,%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                (NOTIF_SETTINGS_KEY, _j.dumps(data)))
    conn.commit()
    return {"status":"saved"}

@app.post("/admin/notify/test")
async def test_notification(admin=Depends(require_admin), conn=Depends(get_db)):
    settings = await get_notif_settings(conn)
    if not settings:
        raise HTTPException(status_code=400, detail="No notification settings configured. Save settings first.")
    msg = format_brief_message(
        [{"cve_id":"CVE-2024-TEST","name":"Test Notification","vendor":"TFII","product":"Platform",
          "description":"This is a test notification from your ThreatFeed Intelligence Platform.",
          "source":"Test","severity":"INFO","kev_date":"","due_date":""}],
        is_weekly=False
    )
    errors = await send_notification(
        f"🧪 TFII Test — {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M')} UTC",
        msg["body"], msg["html"], settings
    )
    if errors:
        raise HTTPException(status_code=500, detail=f"Send errors: {'; '.join(errors)}")
    return {"status":"sent", "channels": [k for k in
        ["ntfy","telegram","email"] if settings.get(f"{k}_topic" if k=="ntfy" else f"{k}_token" if k=="telegram" else "email_to")]}

@app.post("/admin/notify/send-now")
async def send_brief_now(type: str = "daily", admin=Depends(require_admin), conn=Depends(get_db)):
    """Manually trigger a brief immediately."""
    settings = await get_notif_settings(conn)
    if not settings:
        raise HTTPException(status_code=400, detail="No notification settings configured.")
    cve_items = await fetch_daily_cve_digest()
    is_weekly = (type == "weekly")
    msg    = format_brief_message(cve_items, is_weekly=is_weekly)
    errors = await send_notification(msg["title"], msg["body"], msg["html"], settings)
    if errors:
        raise HTTPException(status_code=500, detail=f"Send errors: {'; '.join(errors)}")
    return {"status":"sent","cves_found":len(cve_items)}

@app.get("/admin/notify/preview")
async def preview_brief(type: str = "daily", admin=Depends(require_admin)):
    """Preview what the next brief will look like (no send)."""
    cve_items = await fetch_daily_cve_digest()
    msg = format_brief_message(cve_items, is_weekly=(type=="weekly"))
    return {**msg, "cves": cve_items}

# ═══════════════════════════════════════════════════════════════════════════════
# ACCESS REQUESTS — explorer (demo) users requesting full-access upgrade
# ═══════════════════════════════════════════════════════════════════════════════

REPO_URL = "https://github.com/sherifrahim/TFII"

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN WORKSPACE — personal notes / checklists (admin-only, like Google Keep)
# ═══════════════════════════════════════════════════════════════════════════════

class NoteIn(BaseModel):
    title:        Optional[str]   = ""
    content:      Optional[str]   = ""
    note_type:    Optional[str]   = "text"        # "text" | "checklist"
    color:        Optional[str]   = "default"
    pinned:       Optional[bool]  = False
    archived:     Optional[bool]  = False
    tags:         Optional[List[str]] = []
    checklist:    Optional[list]  = []            # [{text, checked}]
    linked_iocs:  Optional[List[str]] = []
    linked_cves:  Optional[List[str]] = []

@app.get("/workspace/notes")
def list_notes(
    q: str = "",
    tag: str = "",
    archived: bool = False,
    note_type: str = "",
    admin=Depends(require_admin), conn=Depends(get_db)
):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    filters = ["archived = %s"]; params = [archived]
    if q:
        filters.append("(title ILIKE %s OR content ILIKE %s)")
        params += [f"%{q}%", f"%{q}%"]
    if tag:
        filters.append("%s = ANY(tags)")
        params.append(tag)
    if note_type:
        filters.append("note_type = %s")
        params.append(note_type)
    where = " AND ".join(filters)
    cur.execute(f"""
        SELECT * FROM admin_notes
        WHERE {where}
        ORDER BY pinned DESC, updated_at DESC
    """, params)
    return cur.fetchall()

@app.post("/workspace/notes", status_code=201)
def create_note(body: NoteIn, admin=Depends(require_admin), conn=Depends(get_db)):
    note_id = f"note--{uuid.uuid4()}"
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO admin_notes
            (id,title,content,note_type,color,pinned,archived,tags,checklist,linked_iocs,linked_cves)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (note_id, body.title, body.content, body.note_type, body.color,
          body.pinned, body.archived, body.tags or [],
          psycopg2.extras.Json(body.checklist or []),
          body.linked_iocs or [], body.linked_cves or []))
    conn.commit()
    cur2 = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur2.execute("SELECT * FROM admin_notes WHERE id = %s", (note_id,))
    return cur2.fetchone()

@app.patch("/workspace/notes/{note_id}")
def update_note(note_id: str, body: NoteIn, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("""
        UPDATE admin_notes SET
            title=%s, content=%s, note_type=%s, color=%s,
            pinned=%s, archived=%s, tags=%s, checklist=%s,
            linked_iocs=%s, linked_cves=%s,
            updated_at=NOW()
        WHERE id=%s
    """, (body.title, body.content, body.note_type, body.color,
          body.pinned, body.archived, body.tags or [],
          psycopg2.extras.Json(body.checklist or []),
          body.linked_iocs or [], body.linked_cves or [], note_id))
    conn.commit()
    cur2 = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur2.execute("SELECT * FROM admin_notes WHERE id = %s", (note_id,))
    return cur2.fetchone()

@app.delete("/workspace/notes/{note_id}")
def delete_note(note_id: str, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("DELETE FROM admin_notes WHERE id = %s", (note_id,))
    conn.commit()
    return {"deleted": True}



async def send_welcome_email(to_email: str, username: str, conn) -> bool:
    """
    Sends the approval/welcome email to a newly-upgraded user. Reuses the
    same SMTP settings configured for the admin Daily Brief feature —
    one SMTP config, two uses.
    """
    settings = await get_notif_settings(conn)
    if not (settings.get("smtp_host") and settings.get("smtp_user")):
        return False
    try:
        import smtplib, email.mime.multipart, email.mime.text
        title = "You're approved — welcome to TFII"
        body_text = (
            f"Hi {username},\n\n"
            f"Your request for full access to TFII (ThreatFeed Intelligence Platform) has been approved.\n\n"
            f"Log back in with your existing username and password — the IOC Feed, CVE Monitor, "
            f"and Campaigns sections are now unlocked.\n\n"
            f"TFII is open source. If you'd like to look at the code, self-host your own instance, "
            f"or contribute, it's here:\n{REPO_URL}\n\n"
            f"Thanks for trying it out.\n"
        )
        body_html = f"""<html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:24px;">
<h2 style="color:#10b981;">You're approved — welcome to TFII</h2>
<p>Hi {username},</p>
<p>Your request for full access to <b>TFII (ThreatFeed Intelligence Platform)</b> has been approved.</p>
<p>Log back in with your existing username and password — the IOC Feed, CVE Monitor, and Campaigns
sections are now unlocked.</p>
<p>TFII is open source. If you'd like to look at the code, self-host your own instance, or contribute:<br/>
<a href="{REPO_URL}" style="color:#10b981;">{REPO_URL}</a></p>
<p>Thanks for trying it out.</p>
</body></html>"""
        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Subject"] = title
        msg["From"]    = settings.get("smtp_from", settings.get("smtp_user",""))
        msg["To"]      = to_email
        msg.attach(email.mime.text.MIMEText(body_text, "plain"))
        msg.attach(email.mime.text.MIMEText(body_html, "html"))
        with smtplib.SMTP(settings["smtp_host"], int(settings.get("smtp_port", 587))) as smtp:
            smtp.ehlo(); smtp.starttls(); smtp.ehlo()
            smtp.login(settings["smtp_user"], settings["smtp_pass"])
            smtp.sendmail(msg["From"], msg["To"], msg.as_string())
        return True
    except Exception as e:
        print(f"[access-request] Welcome email failed for {to_email}: {e}")
        return False

class AccessRequestIn(BaseModel):
    email: str
    message: Optional[str] = None

@app.post("/access-requests", status_code=201)
async def submit_access_request(body: AccessRequestIn, user=Depends(get_current_user), conn=Depends(get_db)):
    if user["role"] != "explorer":
        raise HTTPException(status_code=400, detail="Only explorer/demo accounts need to request access.")
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id FROM access_requests WHERE user_id = %s AND status = 'pending'", (user["id"],))
    if cur.fetchone():
        raise HTTPException(status_code=400, detail="You already have a pending request — sit tight.")
    rid = f"req--{uuid.uuid4()}"
    cur2 = conn.cursor()
    cur2.execute("""INSERT INTO access_requests (id,user_id,email,message) VALUES (%s,%s,%s,%s)""",
        (rid, user["id"], body.email.strip(), (body.message or "").strip()[:1000]))
    cur2.execute("UPDATE users SET email = %s WHERE id = %s", (body.email.strip(), user["id"]))
    conn.commit()

    # Notify admin via configured channels (ntfy/Telegram/email)
    try:
        settings = await get_notif_settings(conn)
        if settings:
            note   = f"\n\"{body.message.strip()[:200]}\"" if body.message else ""
            title  = f"🔓 TFII — New Access Request"
            body_t = (f"User: {user['username']}\n"
                      f"Email: {body.email}{note}\n\n"
                      f"Review in Settings → Access Requests.")
            await send_notification(title, body_t, body_t, settings)
    except Exception as e:
        print(f"[access-request] Admin notify failed (non-critical): {e}")

    return {"status":"submitted","id":rid}

@app.get("/access-requests/me")
def my_access_request(user=Depends(get_current_user), conn=Depends(get_db)):
    """So the explorer's UI can show 'request pending' instead of the request form again."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM access_requests WHERE user_id = %s ORDER BY requested_at DESC LIMIT 1",
        (user["id"],))
    return cur.fetchone() or {}

@app.get("/admin/access-requests")
def list_access_requests(status: str = "pending", admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if status == "all":
        cur.execute("""SELECT r.*, u.username FROM access_requests r
            JOIN users u ON r.user_id = u.id ORDER BY r.requested_at DESC""")
    else:
        cur.execute("""SELECT r.*, u.username FROM access_requests r
            JOIN users u ON r.user_id = u.id WHERE r.status = %s ORDER BY r.requested_at DESC""", (status,))
    return cur.fetchall()

class AccessDecision(BaseModel):
    role: Optional[str] = "analyst"

@app.post("/admin/access-requests/{request_id}/approve")
async def approve_access_request(request_id: str, body: AccessDecision,
                                  admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM access_requests WHERE id = %s", (request_id,))
    req = cur.fetchone()
    if not req: raise HTTPException(status_code=404, detail="Request not found")
    if req["status"] != "pending": raise HTTPException(status_code=400, detail=f"Request already {req['status']}")
    granted_role = body.role if body.role in ("analyst","admin") else "analyst"
    cur2 = conn.cursor()
    cur2.execute("UPDATE users SET role = %s WHERE id = %s", (granted_role, req["user_id"]))
    cur2.execute("""UPDATE access_requests SET status='approved', granted_role=%s,
        decided_at=NOW(), decided_by=%s WHERE id=%s""", (granted_role, admin["id"], request_id))
    conn.commit()
    cur.execute("SELECT username FROM users WHERE id = %s", (req["user_id"],))
    u = cur.fetchone()
    email_sent = await send_welcome_email(req["email"], u["username"] if u else "there", conn)
    return {"status":"approved","granted_role":granted_role,"email_sent":email_sent}

@app.post("/admin/access-requests/{request_id}/deny")
def deny_access_request(request_id: str, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("""UPDATE access_requests SET status='denied', decided_at=NOW(), decided_by=%s
        WHERE id=%s AND status='pending'""", (admin["id"], request_id))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Pending request not found")
    conn.commit()
    return {"status":"denied"}


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT FEED CONNECTORS
# Purpose-built IOC feeds from sources that *only* publish threat indicators —
# not CVE advisories, not PoC links, not vendor summaries. These are the
# only automated IOC sources. Everything else requires explicit user action.
#
# Connectors:
#   ThreatFox    — C2 IPs, domains, URLs tagged to malware families (abuse.ch)
#   MalwareBazaar — malware file hashes with family + tag info (abuse.ch)
#   URLhaus       — malware distribution URLs (abuse.ch)
#
# All require the same URLHAUS_AUTH_KEY / abuse.ch Auth-Key.
# ═══════════════════════════════════════════════════════════════════════════════

CONNECTOR_SETTINGS_KEY = "connector_settings"

async def get_connector_settings(conn) -> dict:
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT value FROM system_settings WHERE key = %s", (CONNECTOR_SETTINGS_KEY,))
        row = cur.fetchone()
        if row: return json.loads(row["value"])
    except Exception: pass
    return {}

async def run_threatfox_connector(conn, auth_key: str, days_back: int = 1) -> dict:
    """
    Pull recent IOCs from ThreatFox (abuse.ch).
    Returns C2 IPs, domains, URLs, and hashes tagged to specific malware families.
    Only adds indicators with confidence >= 50 and a known malware family tag.
    """
    added = 0; skipped = 0; errors = []
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post("https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": min(days_back, 7)},
                headers={"Auth-Key": auth_key})
        if r.status_code == 401:
            return {"ok": False, "error": "Invalid Auth-Key"}
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        data = r.json()
        if data.get("query_status") != "ok":
            return {"ok": False, "error": data.get("query_status", "unknown error")}

        iocs = data.get("data") or []
        cur = conn.cursor()

        for item in iocs:
            try:
                ioc_val  = (item.get("ioc") or "").strip()
                ioc_type = item.get("ioc_type", "")
                malware  = item.get("malware", "") or item.get("malware_printable", "")
                confidence = int(item.get("confidence_level", 50))
                threat_type = item.get("threat_type", "")
                tags     = [t for t in (item.get("tags") or []) if t]

                if not ioc_val or confidence < 50:
                    skipped += 1; continue

                # Map ThreatFox types to TFII types
                type_map = {
                    "ip:port":  "IPv4",   # strip the port
                    "domain":   "Domain",
                    "url":      "URL",
                    "md5_hash": "MD5",
                    "sha256_hash": "SHA256",
                }
                tfii_type = type_map.get(ioc_type)
                if not tfii_type:
                    skipped += 1; continue

                # Strip port from ip:port format
                if ioc_type == "ip:port" and ":" in ioc_val:
                    ioc_val = ioc_val.split(":")[0]
                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_val):
                        skipped += 1; continue

                canonical = refang(ioc_val)
                defanged  = defang(canonical, tfii_type)
                tlp       = "RED" if confidence >= 75 else "AMBER"
                desc      = f"ThreatFox: {malware or threat_type or 'unknown'}"
                if item.get("comment"): desc += f" — {item['comment'][:200]}"

                ioc_tags  = ["threatfox", "connector"]
                if malware: ioc_tags.append(malware.lower().replace(" ","_")[:30])
                if tags: ioc_tags.extend(tags[:3])

                cur.execute("""
                    INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,
                        description,tags,enrichment,valid_until)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING
                """, (
                    f"indicator--{uuid.uuid4()}", tfii_type, canonical, defanged,
                    "General", tlp, confidence, desc, ioc_tags,
                    psycopg2.extras.Json({
                        "source": "ThreatFox",
                        "malware_family": malware,
                        "threat_type": threat_type,
                        "threatfox_id": item.get("id"),
                        "enriched_at": datetime.now(timezone.utc).isoformat(),
                    }),
                    datetime.now(timezone.utc) + timedelta(days=90)
                ))
                if cur.rowcount > 0: added += 1
                else: skipped += 1
            except Exception as e:
                errors.append(str(e)[:80])

        conn.commit()
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}

    return {"ok": True, "added": added, "skipped": skipped,
            "total_received": len(iocs), "errors": errors[:5]}

async def run_malwarebazaar_connector(conn, auth_key: str, limit: int = 100) -> dict:
    """
    Pull recent malware samples from MalwareBazaar (abuse.ch).
    Returns SHA256, MD5, SHA1 hashes with malware family and tags.
    Only pure hash IOCs — no URLs, no advisory noise.
    """
    added = 0; skipped = 0; errors = []
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post("https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_recent", "selector": "time"},
                headers={"Auth-Key": auth_key})
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        data = r.json()
        if data.get("query_status") not in ("ok", "OK"):
            return {"ok": False, "error": data.get("query_status", "error")}

        samples = (data.get("data") or [])[:limit]
        cur = conn.cursor()

        for sample in samples:
            try:
                sha256 = (sample.get("sha256_hash") or "").strip()
                md5    = (sample.get("md5_hash") or "").strip()
                malware = sample.get("signature") or sample.get("tags", ["unknown"])[0] if sample.get("tags") else "unknown"
                tags   = sample.get("tags") or []
                file_type = sample.get("file_type", "")

                for hash_val, hash_type in [(sha256, "SHA256"), (md5, "MD5")]:
                    if not hash_val: continue
                    ioc_tags = ["malwarebazaar", "connector", "malware-hash"]
                    if malware and malware != "unknown":
                        ioc_tags.append(malware.lower().replace(" ","_")[:30])
                    if file_type: ioc_tags.append(file_type.lower()[:20])

                    cur.execute("""
                        INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,
                            description,tags,enrichment,valid_until)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT DO NOTHING
                    """, (
                        f"indicator--{uuid.uuid4()}", hash_type, hash_val, hash_val,
                        "General", "RED", 85,
                        f"MalwareBazaar: {malware} ({file_type})" if file_type else f"MalwareBazaar: {malware}",
                        ioc_tags,
                        psycopg2.extras.Json({
                            "source": "MalwareBazaar",
                            "malware_family": malware,
                            "file_type": file_type,
                            "sha256": sha256,
                            "md5": md5,
                            "enriched_at": datetime.now(timezone.utc).isoformat(),
                        }),
                        datetime.now(timezone.utc) + timedelta(days=180)
                    ))
                    if cur.rowcount > 0: added += 1
                    else: skipped += 1
            except Exception as e:
                errors.append(str(e)[:80])

        conn.commit()
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}

    return {"ok": True, "added": added, "skipped": skipped,
            "total_received": len(samples), "errors": errors[:5]}

async def run_urlhaus_connector(conn, auth_key: str, limit: int = 100) -> dict:
    """
    Pull recent malware distribution URLs from URLhaus (abuse.ch).
    Only online/unknown status URLs — not cleaned-up ones.
    """
    added = 0; skipped = 0; errors = []
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            # abuse.ch requires GET here — a POST is answered with
            # {"query_status": "http_get_expected"} and no data, which the
            # connector then reported as a successful pull of zero URLs.
            r = await c.get("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"Auth-Key": auth_key})
        if r.status_code == 401:
            return {"ok": False, "error": "Invalid Auth-Key"}
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        data = r.json()
        urls = (data.get("urls") or [])[:limit]  # slice to configured limit
        cur = conn.cursor()

        for item in urls:
            try:
                url_val = (item.get("url") or "").strip()
                status  = item.get("url_status", "")
                threat  = item.get("threat", "")
                tags    = [t.get("tag","") for t in (item.get("tags") or [])]

                # Only ingest active or recently active malware URLs
                if not url_val or status == "offline":
                    skipped += 1; continue

                canonical = refang(url_val)
                ioc_tags  = ["urlhaus", "connector", "malware-url"]
                if threat: ioc_tags.append(threat.lower().replace(" ","_")[:30])
                if tags:   ioc_tags.extend([t.lower() for t in tags[:3] if t])

                cur.execute("""
                    INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,
                        description,tags,enrichment,valid_until)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING
                """, (
                    f"indicator--{uuid.uuid4()}", "URL", canonical, defang(canonical,"URL"),
                    "General", "RED", 85,
                    f"URLhaus: {threat or 'malware distribution URL'} [{status}]",
                    ioc_tags,
                    psycopg2.extras.Json({
                        "source": "URLhaus",
                        "url_status": status,
                        "threat": threat,
                        "urlhaus_id": item.get("id"),
                        "urlhaus_reference": item.get("urlhaus_reference",""),
                        "enriched_at": datetime.now(timezone.utc).isoformat(),
                    }),
                    datetime.now(timezone.utc) + timedelta(days=30)  # shorter TTL — URLs go offline fast
                ))
                if cur.rowcount > 0: added += 1
                else: skipped += 1
            except Exception as e:
                errors.append(str(e)[:80])

        conn.commit()
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}

    return {"ok": True, "added": added, "skipped": skipped,
            "total_received": len(urls), "errors": errors[:5]}

def log_connector_run(conn, connector: str, result: dict):
    """Store connector run result in system_settings for status display."""
    try:
        key = f"connector_last_run_{connector}"
        val = json.dumps({**result, "ran_at": datetime.now(timezone.utc).isoformat()})
        cur = conn.cursor()
        cur.execute("""INSERT INTO system_settings (key,value) VALUES (%s,%s)
            ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""", (key, val))
        conn.commit()
    except Exception: pass

# ── Connector endpoints (admin-only) ─────────────────────────────────────────

class ConnectorSettingsBody(BaseModel):
    threatfox_enabled:     bool = False
    malwarebazaar_enabled: bool = False
    urlhaus_enabled:       bool = False
    threatfox_days:        int  = 1     # how many days back to pull
    malwarebazaar_limit:   int  = 100   # max recent samples
    urlhaus_limit:         int  = 100   # max recent URLs
    schedule_hours:        int  = 24    # how often to auto-sync

@app.get("/admin/connectors/settings")
def get_connector_settings_ep(admin=Depends(require_admin), conn=Depends(get_db)):
    import asyncio as _a
    settings = _a.get_event_loop().run_until_complete(get_connector_settings(conn)) if False else {}
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("SELECT key, value FROM system_settings WHERE key LIKE 'connector%'")
        rows = {r["key"]: json.loads(r["value"]) for r in cur.fetchall()}
        cfg = rows.get(CONNECTOR_SETTINGS_KEY, {})
        last_runs = {
            k.replace("connector_last_run_", ""): v
            for k, v in rows.items() if k.startswith("connector_last_run_")
        }
        return {**cfg, "last_runs": last_runs}
    except Exception:
        return {"last_runs": {}}

@app.post("/admin/connectors/settings")
def save_connector_settings_ep(body: ConnectorSettingsBody, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("""INSERT INTO system_settings (key,value) VALUES (%s,%s)
        ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""",
        (CONNECTOR_SETTINGS_KEY, json.dumps(body.dict())))
    conn.commit()
    return {"status": "saved"}

@app.post("/admin/connectors/sync")
async def sync_connectors(connectors: str = "all", admin=Depends(require_admin), conn=Depends(get_db)):
    """
    Manually trigger connector sync. connectors= all | threatfox | malwarebazaar | urlhaus
    """
    auth_key = URLHAUS_AUTH_KEY or resolve_api_key(conn, "urlhaus", admin)[0]
    if not auth_key:
        raise HTTPException(status_code=400,
            detail="No abuse.ch Auth-Key configured. Add URLHAUS_AUTH_KEY to .env or save it in Settings → API Keys.")

    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT value FROM system_settings WHERE key = %s", (CONNECTOR_SETTINGS_KEY,))
    row = cur.fetchone()
    cfg = json.loads(row["value"]) if row else {}

    results = {}
    run_all = connectors == "all"

    if run_all or connectors == "threatfox":
        r = await run_threatfox_connector(conn, auth_key, days_back=cfg.get("threatfox_days",1))
        results["threatfox"] = r
        log_connector_run(conn, "threatfox", r)

    if run_all or connectors == "malwarebazaar":
        r = await run_malwarebazaar_connector(conn, auth_key, limit=cfg.get("malwarebazaar_limit",100))
        results["malwarebazaar"] = r
        log_connector_run(conn, "malwarebazaar", r)

    if run_all or connectors == "urlhaus":
        r = await run_urlhaus_connector(conn, auth_key, limit=cfg.get("urlhaus_limit",100))
        results["urlhaus"] = r
        log_connector_run(conn, "urlhaus", r)

    total_added = sum(v.get("added",0) for v in results.values())
    return {"status": "complete", "results": results, "total_added": total_added}

async def scheduled_connector_sync():
    """APScheduler job — runs all enabled connectors on schedule."""
    conn = None
    try:
        conn = get_db_direct()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT value FROM system_settings WHERE key = %s", (CONNECTOR_SETTINGS_KEY,))
        row = cur.fetchone()
        if not row: return
        cfg = json.loads(row["value"])

        auth_key = URLHAUS_AUTH_KEY
        if not auth_key: return

        if cfg.get("threatfox_enabled"):
            r = await run_threatfox_connector(conn, auth_key, days_back=cfg.get("threatfox_days",1))
            log_connector_run(conn, "threatfox", r)
            print(f"[connector] ThreatFox: +{r.get('added',0)} IOCs")

        if cfg.get("malwarebazaar_enabled"):
            r = await run_malwarebazaar_connector(conn, auth_key, limit=cfg.get("malwarebazaar_limit",100))
            log_connector_run(conn, "malwarebazaar", r)
            print(f"[connector] MalwareBazaar: +{r.get('added',0)} IOCs")

        if cfg.get("urlhaus_enabled"):
            r = await run_urlhaus_connector(conn, auth_key, limit=cfg.get("urlhaus_limit",100))
            log_connector_run(conn, "urlhaus", r)
            print(f"[connector] URLhaus: +{r.get('added',0)} IOCs")
    except Exception as e:
        print(f"[connector] Scheduled sync error: {e}")
    finally:
        if conn: conn.close()

# ─────────────────────────────────────────────────────────────────────────────
def create_notification(conn, type_: str, title: str, body: str,
                         severity: str = "info", metadata: dict = None):
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO notifications (type, title, body, severity, metadata)
            VALUES (%s,%s,%s,%s,%s)""",
            (type_, title, body, severity, psycopg2.extras.Json(metadata or {})))
    except Exception as e:
        print(f"[notification] Failed: {e}")

@app.get("/notifications")
def list_notifications(unread_only: bool = False,
                        admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    query = "SELECT * FROM notifications"
    if unread_only: query += " WHERE read = FALSE"
    query += " ORDER BY created_at DESC LIMIT 100"
    cur.execute(query)
    return cur.fetchall()

@app.get("/notifications/count")
def notification_count(user=Depends(get_current_user), conn=Depends(get_db)):
    if user["role"] != "admin": return {"count": 0}
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM notifications WHERE read = FALSE")
    return {"count": cur.fetchone()[0]}

@app.patch("/notifications/{notif_id}/read")
def mark_read(notif_id: int, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE notifications SET read = TRUE WHERE id = %s", (notif_id,))
    conn.commit(); return {"status": "ok"}

@app.patch("/notifications/read-all")
def mark_all_read(admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE notifications SET read = TRUE WHERE read = FALSE")
    conn.commit(); return {"status": "ok"}

# ── API USAGE ─────────────────────────────────────────────────────────────────
def log_api_call(conn, api_name: str, ioc_value: str, cache_hit: bool, user_id: str = None):
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO api_usage_log (api_name,ioc_value,cache_hit,user_id) VALUES (%s,%s,%s,%s)",
                    (api_name, ioc_value, cache_hit, user_id))
    except Exception: pass

def is_cache_fresh(enrichment_data: dict) -> bool:
    if not enrichment_data: return False
    enriched_at = enrichment_data.get("enriched_at")
    if not enriched_at: return False
    try:
        ts = datetime.fromisoformat(enriched_at.replace("Z","")).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds() < CACHE_HOURS * 3600
    except Exception: return False

# ── ENRICHMENT ────────────────────────────────────────────────────────────────
async def vt_ip(ip, conn=None, key: str = None, user_id: str = None):
    k = key if key is not None else VT_API_KEY
    if not k: return {"source":"VirusTotal","skipped":True}
    if conn: log_api_call(conn,"virustotal",ip,False,user_id)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey":k})
    if r.status_code == 401: return {"source":"VirusTotal","error":"Invalid API key"}
    if r.status_code == 429: return {"source":"VirusTotal","error":"Rate limit reached"}
    if r.status_code != 200: return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    attrs = r.json().get("data",{}).get("attributes",{})
    stats = attrs.get("last_analysis_stats",{})
    mal = stats.get("malicious",0); total = sum(stats.values()) or 1
    return {"source":"VirusTotal","malicious":mal,"total":total,"vt_score":round((mal/total)*100),
            "country":attrs.get("country","?"),"asn":str(attrs.get("asn","?")),
            "link":f"https://www.virustotal.com/gui/ip-address/{ip}"}

async def vt_domain(domain, conn=None, key: str = None, user_id: str = None):
    k = key if key is not None else VT_API_KEY
    if not k: return {"source":"VirusTotal","skipped":True}
    if conn: log_api_call(conn,"virustotal",domain,False,user_id)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey":k})
    if r.status_code == 401: return {"source":"VirusTotal","error":"Invalid API key"}
    if r.status_code == 429: return {"source":"VirusTotal","error":"Rate limit reached"}
    if r.status_code != 200: return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    attrs = r.json().get("data",{}).get("attributes",{})
    stats = attrs.get("last_analysis_stats",{})
    mal = stats.get("malicious",0); total = sum(stats.values()) or 1
    return {"source":"VirusTotal","malicious":mal,"total":total,"vt_score":round((mal/total)*100),
            "country":attrs.get("country","?"),"link":f"https://www.virustotal.com/gui/domain/{domain}"}

async def vt_hash(h, conn=None, key: str = None, user_id: str = None):
    k = key if key is not None else VT_API_KEY
    if not k: return {"source":"VirusTotal","skipped":True}
    if conn: log_api_call(conn,"virustotal",h,False,user_id)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={"x-apikey":k})
    if r.status_code == 404: return {"source":"VirusTotal","found":False,"vt_score":0}
    if r.status_code != 200: return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    attrs = r.json().get("data",{}).get("attributes",{})
    stats = attrs.get("last_analysis_stats",{})
    mal = stats.get("malicious",0); total = sum(stats.values()) or 1
    return {"source":"VirusTotal","found":True,"malicious":mal,"total":total,
            "file_name":attrs.get("meaningful_name","unknown"),
            "vt_score":round((mal/total)*100),"link":f"https://www.virustotal.com/gui/file/{h}"}

async def vt_url_lookup(url_val, conn=None, key: str = None, user_id: str = None):
    k = key if key is not None else VT_API_KEY
    if not k: return {"source":"VirusTotal","skipped":True}
    if conn: log_api_call(conn,"virustotal",url_val,False,user_id)
    url_id = base64.urlsafe_b64encode(url_val.encode()).decode().rstrip("=")
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers={"x-apikey":k})
        if r.status_code == 404:
            # URL not in VT yet — submit it for scanning, then re-check once
            try:
                submit_r = await c.post("https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey":k},
                    data={"url": url_val})
                if submit_r.status_code in (200, 201):
                    analysis_id = submit_r.json().get("data",{}).get("id","")
                    # Wait briefly and poll the analysis result
                    await asyncio.sleep(8)
                    poll_r = await c.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                         headers={"x-apikey":k})
                    if poll_r.status_code == 200:
                        attrs = poll_r.json().get("data",{}).get("attributes",{})
                        stats = attrs.get("stats",{})
                        mal   = stats.get("malicious",0); total = sum(stats.values()) or 1
                        if attrs.get("status") == "completed":
                            return {"source":"VirusTotal","malicious":mal,"total":total,
                                    "vt_score":round((mal/total)*100) if total else 0,
                                    "link":f"https://www.virustotal.com/gui/url/{url_id}",
                                    "note":"Newly submitted — first scan"}
            except Exception:
                pass
            return {"source":"VirusTotal","found":False,"vt_score":0,
                    "note":"Not previously scanned — submitted for analysis"}
        if r.status_code == 401: return {"source":"VirusTotal","error":"Invalid API key"}
        if r.status_code == 429: return {"source":"VirusTotal","error":"Rate limit reached — try again later"}
        if r.status_code != 200: return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    mal = stats.get("malicious",0); total = sum(stats.values()) or 1
    return {"source":"VirusTotal","malicious":mal,"total":total,
            "vt_score":round((mal/total)*100),"link":f"https://www.virustotal.com/gui/url/{url_id}"}

async def abuseipdb_lookup(ip, conn=None, key: str = None, user_id: str = None):
    k = key if key is not None else ABUSEIPDB_API_KEY
    if not k: return {"source":"AbuseIPDB","skipped":True}
    if conn: log_api_call(conn,"abuseipdb",ip,False,user_id)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get("https://api.abuseipdb.com/api/v2/check",
            headers={"Key":k,"Accept":"application/json"},
            params={"ipAddress":ip,"maxAgeInDays":90})
    if r.status_code != 200: return {"source":"AbuseIPDB","error":f"HTTP {r.status_code}"}
    d = r.json().get("data",{})
    return {"source":"AbuseIPDB","abuse_score":d.get("abuseConfidenceScore",0),
            "total_reports":d.get("totalReports",0),"country":d.get("countryCode","?"),
            "isp":d.get("isp","?"),"link":f"https://www.abuseipdb.com/check/{ip}"}

async def urlhaus_url_lookup(url_val, conn=None, key: str = None, user_id: str = None):
    k = key if key is not None else URLHAUS_AUTH_KEY
    if not k: return {"source":"URLhaus","skipped":True}
    if conn: log_api_call(conn,"urlhaus",url_val,False,user_id)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/url/",
            data={"url":url_val}, headers={"Auth-Key":k})
    if r.status_code == 401: return {"source":"URLhaus","error":"Invalid or expired Auth-Key — generate a new one at auth.abuse.ch"}
    if r.status_code != 200: return {"source":"URLhaus","error":f"HTTP {r.status_code}"}
    d = r.json()
    if d.get("query_status") == "no_results": return {"source":"URLhaus","found":False}
    return {"source":"URLhaus","found":True,"threat":d.get("threat","?"),
            "url_status":d.get("url_status","?"),"link":d.get("urlhaus_reference","")}

async def urlhaus_host_lookup(domain, conn=None, key: str = None, user_id: str = None):
    k = key if key is not None else URLHAUS_AUTH_KEY
    if not k: return {"source":"URLhaus","skipped":True}
    if conn: log_api_call(conn,"urlhaus",domain,False,user_id)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/host/",
            data={"host":domain}, headers={"Auth-Key":k})
    if r.status_code == 401: return {"source":"URLhaus","error":"Invalid or expired Auth-Key — generate a new one at auth.abuse.ch"}
    if r.status_code != 200: return {"source":"URLhaus","error":f"HTTP {r.status_code}"}
    d = r.json()
    if d.get("query_status") == "no_results": return {"source":"URLhaus","found":False}
    return {"source":"URLhaus","found":True,"urls_count":len(d.get("urls",[])),"link":d.get("urlhaus_reference","")}

# ── Geo / ASN / Org lookup (owner identification) ────────────────────────────
CLOUD_PROVIDER_KEYWORDS = [
    ("Amazon",       "AWS"),
    ("Microsoft",    "Azure"),
    ("Google",       "Google Cloud"),
    ("Cloudflare",   "Cloudflare"),
    ("Oracle",       "Oracle Cloud"),
    ("DigitalOcean", "DigitalOcean"),
    ("Akamai",       "Akamai"),
    ("Fastly",       "Fastly"),
    ("Linode",       "Linode"),
    ("OVH",          "OVH"),
    ("Hetzner",      "Hetzner"),
    ("Alibaba",      "Alibaba Cloud"),
    ("Tencent",      "Tencent Cloud"),
    ("IBM",          "IBM Cloud"),
    ("Vultr",        "Vultr"),
]

def detect_cloud_provider(org: str) -> Optional[str]:
    if not org: return None
    org_lc = org.lower()
    for keyword, label in CLOUD_PROVIDER_KEYWORDS:
        if keyword.lower() in org_lc:
            return label
    return None

async def geo_org_lookup_batch(ips: list) -> dict:
    """
    Batch IP geolocation + ASN/org lookup via ip-api.com (free, no API key).
    Up to 100 IPs in a single request. Returns {ip: {country, org, isp, as, ...}}.
    """
    if not ips: return {}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post("http://ip-api.com/batch",
                json=[{"query": ip, "fields": "query,status,country,countryCode,org,isp,as"}
                      for ip in ips[:100]])
        if r.status_code != 200: return {}
        return {item["query"]: item for item in r.json() if item.get("query")}
    except Exception:
        return {}

async def resolve_to_ip(value: str, ioc_type: str) -> Optional[str]:
    """Resolve a Domain or URL's hostname to an IP for geo lookup. Returns None on failure."""
    host = value
    if ioc_type == "URL":
        try:
            from urllib.parse import urlparse
            host = urlparse(value).hostname or value
        except Exception:
            return None
    if ioc_type not in ("Domain","URL"):
        return None
    try:
        return await asyncio.wait_for(asyncio.to_thread(socket.gethostbyname, host), timeout=4)
    except Exception:
        return None

def calc_confidence(results: dict, base: int) -> tuple:
    score = base; reasons = []
    vt = results.get("virustotal",{}); abuse = results.get("abuseipdb",{}); uh = results.get("urlhaus",{})
    vts = vt.get("vt_score",-1)
    if vts >= 0:
        if vts >= 50:   score = max(score,90); reasons.append(f"VirusTotal: {vt.get('malicious',0)}/{vt.get('total',0)} engines flagged (+confidence)")
        elif vts >= 20: score = max(score,75); reasons.append(f"VirusTotal: moderate detection {vts}% (+confidence)")
        elif vts >= 5:  score = max(score,60); reasons.append(f"VirusTotal: low detection {vts}%")
        elif vts == 0:  score = min(score,30); reasons.append("VirusTotal: no engines flagged (-confidence)")
    ab = abuse.get("abuse_score",-1)
    if ab >= 0:
        if ab >= 80:   score = max(score,92); reasons.append(f"AbuseIPDB: {ab}/100 with {abuse.get('total_reports',0)} reports (+confidence)")
        elif ab >= 50: score = max(score,80); reasons.append(f"AbuseIPDB: moderate abuse score {ab}/100 (+confidence)")
        elif ab >= 20: score = max(score,65); reasons.append(f"AbuseIPDB: low abuse score {ab}/100")
        elif ab == 0:  score = min(score,35); reasons.append("AbuseIPDB: zero abuse reports (-confidence)")
    if uh.get("found") is True:  score = max(score,85); reasons.append("URLhaus: found in malware URL database (+confidence)")
    if uh.get("found") is False: score = min(score,50); reasons.append("URLhaus: not found (-confidence)")
    if not reasons: reasons.append("No external sources returned data — using base confidence")
    return min(max(score,5),99), reasons

async def enrich(ioc_type: str, value: str, base: int, conn=None,
                 force: bool = False, existing: dict = None, user: dict = None) -> dict:
    if not force and existing and is_cache_fresh(existing):
        if conn and user:
            log_api_call(conn, "cache", value, True, user.get("id"))
        return existing

    results = {}
    user_id = user.get("id") if user else None

    def get_key(svc):
        if conn and user:
            key, personal, quota = resolve_api_key(conn, svc, user)
            return key, quota
        # fallback to platform key if no user context
        return PLATFORM_KEYS.get(svc, ""), None

    def quota_error(svc):
        return {"source": svc, "error": f"Daily quota of {DAILY_FREE_QUOTA} free checks reached. Add your personal {svc} API key in Settings to continue."}

    try:
        if ioc_type in ("IPv4","IPv6"):
            vt_key, vt_quota  = get_key("virustotal")
            ab_key, ab_quota  = get_key("abuseipdb")
            uh_key, uh_quota  = get_key("urlhaus")
            vt_task = vt_ip(value, conn, vt_key, user_id) if vt_key else asyncio.sleep(0, result=({"skipped":True} if vt_quota is None else quota_error("VirusTotal")))
            ab_task = abuseipdb_lookup(value, conn, ab_key, user_id) if ab_key else asyncio.sleep(0, result=({"skipped":True} if ab_quota is None else quota_error("AbuseIPDB")))
            # URLhaus /v1/host/ accepts IP addresses too, not just hostnames
            uh_task = urlhaus_host_lookup(value, conn, uh_key, user_id) if uh_key else asyncio.sleep(0, result=({"skipped":True} if uh_quota is None else quota_error("URLhaus")))
            vt_r, ab_r, uh_r = await asyncio.gather(vt_task, ab_task, uh_task, return_exceptions=True)
            if not isinstance(vt_r, Exception): results["virustotal"] = vt_r
            else: results["virustotal"] = {"source":"VirusTotal","error":str(vt_r)}
            if not isinstance(ab_r, Exception): results["abuseipdb"] = ab_r
            else: results["abuseipdb"] = {"source":"AbuseIPDB","error":str(ab_r)}
            if not isinstance(uh_r, Exception): results["urlhaus"] = uh_r
            else: results["urlhaus"] = {"source":"URLhaus","error":str(uh_r)}
        elif ioc_type == "Domain":
            vt_key, vt_quota = get_key("virustotal")
            uh_key, uh_quota = get_key("urlhaus")
            vt_task = vt_domain(value, conn, vt_key, user_id) if vt_key else asyncio.sleep(0, result=({"skipped":True} if vt_quota is None else quota_error("VirusTotal")))
            uh_task = urlhaus_host_lookup(value, conn, uh_key, user_id) if uh_key else asyncio.sleep(0, result=({"skipped":True} if uh_quota is None else quota_error("URLhaus")))
            vt_r, uh_r = await asyncio.gather(vt_task, uh_task, return_exceptions=True)
            if not isinstance(vt_r, Exception): results["virustotal"] = vt_r
            else: results["virustotal"] = {"source":"VirusTotal","error":str(vt_r)}
            if not isinstance(uh_r, Exception): results["urlhaus"] = uh_r
            else: results["urlhaus"] = {"source":"URLhaus","error":str(uh_r)}
        elif ioc_type == "URL":
            vt_key, vt_quota = get_key("virustotal")
            uh_key, uh_quota = get_key("urlhaus")
            vt_task = vt_url_lookup(value, conn, vt_key, user_id) if vt_key else asyncio.sleep(0, result=({"skipped":True} if vt_quota is None else quota_error("VirusTotal")))
            uh_task = urlhaus_url_lookup(value, conn, uh_key, user_id) if uh_key else asyncio.sleep(0, result=({"skipped":True} if uh_quota is None else quota_error("URLhaus")))
            vt_r, uh_r = await asyncio.gather(vt_task, uh_task, return_exceptions=True)
            if not isinstance(vt_r, Exception): results["virustotal"] = vt_r
            else: results["virustotal"] = {"source":"VirusTotal","error":str(vt_r)}
            if not isinstance(uh_r, Exception): results["urlhaus"] = uh_r
            else: results["urlhaus"] = {"source":"URLhaus","error":str(uh_r)}
        elif ioc_type in ("MD5","SHA1","SHA256"):
            vt_key, vt_quota = get_key("virustotal")
            vt_r = await vt_hash(value, conn, vt_key, user_id) if vt_key else ({"skipped":True} if vt_quota is None else quota_error("VirusTotal"))
            if not isinstance(vt_r, Exception): results["virustotal"] = vt_r
        else:
            results["note"] = f"No enrichment for type {ioc_type}"
    except Exception as e:
        results["error"] = str(e)

    final_score, reasons = calc_confidence(results, base)
    results["calculated_confidence"] = final_score
    results["confidence_reasons"]    = reasons
    results["enriched_at"]           = datetime.now(timezone.utc).isoformat()
    return results

# ── STIX ─────────────────────────────────────────────────────────────────────
def row_to_stix(row):
    pattern = PATTERNS.get(row["type"],"[artifact:mime_type = '{v}']").format(v=row["value"])
    vu = row.get("valid_until")
    return {"type":"indicator","spec_version":"2.1","id":row["id"],
            "created":row["created_at"].isoformat()+"Z","modified":row["created_at"].isoformat()+"Z",
            "name":f"{row['type']}: {row['value']}","description":row.get("description",""),
            "indicator_types":["malicious-activity"],"pattern":pattern,"pattern_type":"stix",
            "valid_from":row["created_at"].isoformat()+"Z",
            "valid_until":vu.isoformat()+"Z" if vu else None,
            "confidence":row.get("confidence",75),"labels":row.get("tags") or [],
            "object_marking_refs":[TLP_IDS.get(row.get("tlp","AMBER"),TLP_IDS["AMBER"])],
            "x_opencti_score":row.get("confidence",75),"x_opencti_main_observable_type":row["type"],
            "x_mitre_techniques":row.get("mitre_techniques") or []}

def audit(conn, action, ioc_id, ioc_value, ioc_type, user):
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO audit_log (action,ioc_id,ioc_value,ioc_type,username,user_id) VALUES (%s,%s,%s,%s,%s,%s)",
            (action,ioc_id,ioc_value,ioc_type,user.get("username","?"),user.get("id","?")))
    except Exception: pass

def record_score(conn, ioc_id, old_score, new_score, reasons, by="system"):
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO ioc_score_history (ioc_id,old_score,new_score,delta,reason,triggered_by) VALUES (%s,%s,%s,%s,%s,%s)",
            (ioc_id, old_score, new_score, new_score-old_score, " | ".join(reasons), by))
    except Exception: pass

# ═══════════════════════════════════════════════════════════════════════════════
# CVE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

PATCH_REF_TAGS = {"Patch","Vendor Advisory","Third Party Advisory","Mitigation"}

def detect_patch(references: list) -> tuple:
    """
    Find the best patch/advisory URL from NVD references.
    - Prefers HTTPS over HTTP, never returns FTP
    - Prefers official vendor/government URLs
    - Skips mailing list archives, Bugtraq, SecurityFocus etc.
    """
    SKIP_DOMAINS = ["marc.info","securityfocus.com","bugtraq","neohapsis",
                    "osvdb","openwall","secunia","vulnwatch","iss.net",
                    "packetstorm","exploit-db","xforce.ibm"]
    candidates = []
    for ref in references:
        tags = set(ref.get("tags",[]))
        url  = ref.get("url","")
        if not url: continue
        if url.startswith("ftp://"): continue          # never FTP
        if any(s in url.lower() for s in SKIP_DOMAINS): continue
        score = 0
        if tags & PATCH_REF_TAGS:                      score += 30
        if url.startswith("https://"):                 score += 20
        if any(kw in url.lower() for kw in
               ["advisory","patch","security","update","bulletin","kb"]): score += 10
        if any(d in url for d in
               ["microsoft.com","redhat.com","ubuntu.com","debian.org",
                "cisco.com","apple.com","nvd.nist.gov","cisa.gov",
                "kernel.org","github.com","oracle.com"]): score += 15
        if score > 0:
            candidates.append((score, url))
    if candidates:
        candidates.sort(reverse=True)
        return True, candidates[0][1]
    return False, None


TRUSTED_DOMAINS = [
    # Government & standards bodies
    "nvd.nist.gov","cisa.gov","cert.org","kb.cert.org","us-cert.gov","nist.gov",
    "cve.org","cve.mitre.org","mitre.org","cvedetails.com",
    "cisecurity.org","cis.org","first.org","ietf.org","w3.org",
    "rfc-editor.org","iana.org","iso.org","owasp.org",
    # Major tech vendors (advisory publishers, not threat actors)
    "microsoft.com","cisco.com","apple.com","oracle.com","google.com","google.co",
    "vmware.com","f5.com","paloaltonetworks.com","fortinet.com","juniper.net",
    "adobe.com","sap.com","ibm.com","hp.com","dell.com","lenovo.com",
    "netapp.com","citrix.com","atlassian.com","qualys.com","tenable.com",
    "broadcom.com","bmc.com","zoom.us","slack.com","salesforce.com",
    "akamai.com","cloudflare.com","fastly.com","aws.amazon.com","amazonaws.com",
    "azure.com","azure.microsoft.com","cloud.google.com","digitalocean.com",
    # Linux / open source projects
    "ubuntu.com","debian.org","redhat.com","centos.org","fedoraproject.org",
    "opensuse.org","archlinux.org","gentoo.org","kernel.org","linux.org",
    "python.org","php.net","apache.org","nginx.org","openssl.org","nodejs.org",
    "curl.se","curl.haxx.se","wordpress.org","drupal.org","joomla.org",
    "openbsd.org","freebsd.org","netbsd.org","openwrt.org",
    # Security research / databases / advisory archives
    "securityfocus.com","secunia.com","osvdb.org","openwall.com","openwall.com",
    "packetstormsecurity.com","exploit-db.com","exploitdb.com",
    "bugtraq.securityfocus.com","marc.info","archives.neohapsis.com",
    "zerodayinitiative.com","zdi.com","vulhub.org","seclists.org",
    "fulldisc.security","full-disclosure.lists.grok.org.uk",
    "iss.net","xforce.ibmcloud.com","securitytracker.com",
    "auscert.org","jvn.jp","jpcert.or.jp","cert.gov.ua","bsi.bund.de",
    "ncsc.gov.uk","ncsc.nl","cert.be","anssi.fr","enisa.europa.eu",
    # Code / issue trackers / repos
    "github.com","gitlab.com","bitbucket.org","sourceforge.net",
    "raw.githubusercontent.com","gist.github.com","gitee.com",
    "bugs.launchpad.net","bugzilla.redhat.com","bugzilla.mozilla.org",
    "issues.chromium.org","bugs.chromium.org","bugreport.apple.com",
    # CVE / vuln databases
    "vuldb.com","vulners.com","osv.dev","security.snyk.io","snyk.io",
    # Common news / research sources that appear in NVD references
    "bleepingcomputer.com","theregister.com","securityweek.com",
    "darkreading.com","threatpost.com","sans.org","sans.edu",
    "krebs on security","krebsonsecurity.com","ars technica","arstechnica.com",
    "wired.com","vice.com","techcrunch.com","zdnet.com",
    # Patch / advisory portals
    "support.microsoft.com","technet.microsoft.com","msrc.microsoft.com",
    "support.apple.com","kb.vmware.com","tools.cisco.com","sec.cloudapps.cisco.com",
    "helpx.adobe.com","www.sap.com","launchpad.support.sap.com",
    # Misc common FP sources
    "eff.org","mozilla.org","letsencrypt.org","crl.","ocsp.","pki.",
]


# Private/reserved IP ranges — never IOCs
PRIVATE_IP_PREFIXES = ("10.","192.168.","172.16.","172.17.","172.18.","172.19.",
                       "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
                       "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.",
                       "169.254.","100.64.")

def extract_iocs_from_text(text: str, include_urls: bool = False) -> list:
    """
    Extract IOCs from free text.
    - IPs: only public, routable IPs (not private/reserved ranges)
    - URLs: only if include_urls=True AND not from a trusted/advisory domain
    - Reference URLs from NVD CVE entries should NEVER be passed here
    """
    found = []

    # Extract public IPv4 addresses
    for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        parts = ip.split('.')
        if not all(0 <= int(p) <= 255 for p in parts): continue
        if ip in ('0.0.0.0','127.0.0.1','255.255.255.255','8.8.8.8','1.1.1.1'): continue
        if ip.startswith(PRIVATE_IP_PREFIXES): continue
        found.append(("IPv4", ip))

    # URLs only when explicitly requested (not for CVE references)
    if include_urls:
        for url in re.findall(r'https?://[^\s\'"<>]+', text):
            url = url.rstrip('.,)')
            if any(td in url for td in TRUSTED_DOMAINS): continue
            found.append(("URL", url))

    return found

def parse_nvd_entry(vuln: dict) -> dict:
    cve   = vuln.get("cve",{})
    cve_id = cve.get("id","")
    desc  = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")
    refs  = [{"url":r.get("url",""),"tags":r.get("tags",[])} for r in cve.get("references",[])]
    metrics = cve.get("metrics",{})
    cvss_score = None; cvss_severity = "UNKNOWN"; cvss_vector = ""
    for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
        m_list = metrics.get(key,[])
        if m_list:
            m = m_list[0].get("cvssData",{})
            cvss_score    = m.get("baseScore")
            cvss_severity = m.get("baseSeverity", m.get("accessVector","UNKNOWN"))
            cvss_vector   = m.get("vectorString","")
            break
    weaknesses = cve.get("weaknesses",[])
    cwe = ""
    if weaknesses:
        descs = weaknesses[0].get("description",[])
        cwe = next((d.get("value","") for d in descs if d.get("lang")=="en"), "")
    configs = cve.get("configurations",[])
    affected_versions = []
    for cfg in configs[:3]:
        for node in cfg.get("nodes",[]):
            for cpe_match in node.get("cpeMatch",[]):
                if cpe_match.get("vulnerable"):
                    v_start = cpe_match.get("versionStartIncluding","")
                    v_end   = cpe_match.get("versionEndExcluding","") or cpe_match.get("versionEndIncluding","")
                    if v_start or v_end:
                        affected_versions.append(f"{v_start} – {v_end}" if v_start else f"< {v_end}")
    patch_available, patch_url = detect_patch(refs)
    return {"cve_id":cve_id,"description":desc,"cvss_score":cvss_score,
            "cvss_severity":cvss_severity,"cvss_vector":cvss_vector,"cwe":cwe,
            "affected_versions":"; ".join(list(dict.fromkeys(affected_versions))[:5]),
            "published_date":cve.get("published","")[:10],"modified_date":cve.get("lastModified","")[:10],
            "references":refs,"patch_available":patch_available,"patch_url":patch_url,
            "title":f"{cve_id}: {desc[:80]}..." if len(desc)>80 else f"{cve_id}: {desc}"}

async def fetch_nvd_cves(cpe: str, days_back: int = 730) -> list:
    """
    Fetch CVEs from NVD API 2.0.
    NVD returns results sorted OLDEST FIRST by default.
    We request the last N pages to get the most recently published CVEs,
    then filter by date in Python. This avoids all NVD date format issues.
    """
    headers = {"User-Agent":"ThreatFeed-CTI/1.0"}
    if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY

    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    cutoff_str = cutoff.strftime("%Y-%m-%d")

    # Extract vendor + product from CPE for keyword fallback
    parts   = cpe.split(":")
    vendor  = parts[3].replace("_", " ") if len(parts) > 3 else ""
    product = parts[4].replace("_", " ") if len(parts) > 4 else ""
    keyword = f"{vendor} {product}".strip()

    # Strip version from CPE for broad wildcard matching
    cpe_parts = cpe.split(":")
    if len(cpe_parts) >= 6 and cpe_parts[5] not in ("*", "-", ""):
        cpe_wildcard = ":".join(cpe_parts[:5]) + ":*:" + ":".join(cpe_parts[6:])
    else:
        cpe_wildcard = cpe

    def filter_by_date(vulns):
        return [v for v in vulns
                if v.get("cve",{}).get("published","")[:10] >= cutoff_str]

    async def nvd_get(params):
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params=params, headers=headers)
        return r

    # ── Strategy 1: virtualMatchString — fetch most recent results ──────────
    # NVD returns oldest-first, so we need the last page(s) for recent CVEs.
    # Step 1: Get total count with 1 result
    # Step 2: Request last 200 results (2 pages from the end)
    try:
        r = await nvd_get({"virtualMatchString": cpe_wildcard, "resultsPerPage": 1})
        if r.status_code == 200:
            total = r.json().get("totalResults", 0)
            print(f"[nvd] virtualMatchString '{cpe_wildcard[:45]}': total={total}")
            if total > 0:
                all_vulns = []
                # Fetch up to 200 most recent CVEs (last 2 pages)
                for offset in [max(0, total-100), max(0, total-200)]:
                    if offset < 0: continue
                    r2 = await nvd_get({
                        "virtualMatchString": cpe_wildcard,
                        "resultsPerPage": 100,
                        "startIndex": offset
                    })
                    if r2.status_code == 200:
                        all_vulns.extend(r2.json().get("vulnerabilities", []))
                    elif r2.status_code == 429:
                        print("[nvd] Rate limited"); return []
                # Deduplicate and filter
                seen = set(); deduped = []
                for v in all_vulns:
                    vid = v.get("cve",{}).get("id","")
                    if vid and vid not in seen:
                        seen.add(vid); deduped.append(v)
                results = filter_by_date(deduped)
                print(f"[nvd] virtualMatchString got {len(deduped)} recent, {len(results)} within {days_back}d")
                if results:
                    return results
        elif r.status_code == 429:
            print("[nvd] Rate limited"); return []
        else:
            print(f"[nvd] virtualMatchString HTTP {r.status_code}")
    except Exception as e:
        print(f"[nvd] virtualMatchString error: {e}")

    # ── Strategy 2: keywordSearch — same approach, last 200 results ─────────
    if keyword:
        try:
            r = await nvd_get({"keywordSearch": keyword, "resultsPerPage": 1})
            if r.status_code == 200:
                total = r.json().get("totalResults", 0)
                print(f"[nvd] keywordSearch '{keyword}': total={total}")
                if total > 0:
                    all_vulns = []
                    for offset in [max(0, total-100), max(0, total-200)]:
                        r2 = await nvd_get({
                            "keywordSearch": keyword,
                            "resultsPerPage": 100,
                            "startIndex": offset
                        })
                        if r2.status_code == 200:
                            all_vulns.extend(r2.json().get("vulnerabilities", []))
                    seen = set(); deduped = []
                    for v in all_vulns:
                        vid = v.get("cve",{}).get("id","")
                        if vid and vid not in seen:
                            seen.add(vid); deduped.append(v)
                    results = filter_by_date(deduped)
                    print(f"[nvd] keywordSearch got {len(deduped)} recent, {len(results)} within {days_back}d")
                    return results
        except Exception as e:
            print(f"[nvd] keywordSearch error: {e}")

    return []
async def fetch_kev_catalog() -> dict:
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                            headers={"User-Agent":"ThreatFeed-CTI/1.0"})
        if r.status_code == 200:
            return {v["cveID"]: v.get("dateAdded","") for v in r.json().get("vulnerabilities",[])}
    except Exception as e:
        print(f"[kev] Error: {e}")
    return {}

async def fetch_epss(cve_ids: list) -> dict:
    if not cve_ids: return {}
    try:
        cve_str = ",".join(cve_ids[:100])
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"https://api.first.org/data/v1/epss?cve={cve_str}",
                            headers={"User-Agent":"ThreatFeed-CTI/1.0"})
        if r.status_code == 200:
            return {d["cve"]:{"epss":float(d.get("epss",0)),"percentile":float(d.get("percentile",0))}
                    for d in r.json().get("data",[])}
    except Exception: pass
    return {}

async def poll_cves_for_asset(asset: dict, kev_catalog: dict, conn) -> dict:
    asset_id   = asset["id"]
    asset_name = asset["name"]
    vendor     = (asset.get("vendor") or "").strip().lower().replace(" ","_")
    asset_type = asset.get("asset_type","application")
    version    = (asset.get("version") or "").strip().lstrip("vV")

    # Always rebuild CPE from KB when possible — stored CPE may be stale
    # (e.g. igor_sysoev→nginx) or have edition specifiers that limit results.
    part = "o" if asset_type == "os" else "h" if asset_type in ("hardware","firmware") else "a"
    ver  = version if version else "*"
    name_lc = asset_name.lower().strip()
    kb_hit  = None
    for key, val in PRODUCT_KB.items():
        if name_lc == key or key in name_lc or name_lc in key:
            kb_hit = val; break

    if kb_hit:
        _, _, cpe_vendor, cpe_product, _ = kb_hit
        cpe = f"cpe:2.3:{part}:{cpe_vendor}:{cpe_product}:{ver}:*:*:*:*:*:*:*"
    else:
        stored = asset.get("cpe","").strip()
        if stored:
            # Strip edition/language fields — only keep part:vendor:product:version
            sp = stored.split(":")
            cpe = ":".join(sp[:6]) + ":*:*:*:*:*:*:*" if len(sp) >= 6 else stored
        else:
            cpe_vendor  = vendor or "unknown"
            cpe_product = asset_name.strip().lower().replace(" ","_")
            cpe = f"cpe:2.3:{part}:{cpe_vendor}:{cpe_product}:{ver}:*:*:*:*:*:*:*"

    print(f"[cve-poll] '{asset_name}' → {cpe}")
    new_cves = []; new_iocs = []; patched_cves = []
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    vulns = await fetch_nvd_cves(cpe)
    if not vulns:
        print(f"[cve-poll] No CVEs found for '{asset_name}' ({cpe})")
        return {"new_cves":[],"new_iocs":[],"patched":[]}
    cve_ids = [v.get("cve",{}).get("id","") for v in vulns]
    epss_data = await fetch_epss([c for c in cve_ids if c])
    for vuln in vulns:
        parsed = parse_nvd_entry(vuln)
        cve_id = parsed["cve_id"]
        if not cve_id: continue
        epss = epss_data.get(cve_id,{})
        kev_info = kev_catalog.get(cve_id)
        cur.execute("SELECT id, patch_available FROM cve_findings WHERE cve_id = %s", (cve_id,))
        existing = cur.fetchone()
        if existing:
            if parsed["patch_available"] and not existing["patch_available"]:
                cur2 = conn.cursor()
                cur2.execute("""UPDATE cve_findings SET patch_available=TRUE,patch_url=%s,
                    patch_detected_at=NOW(),updated_at=NOW() WHERE cve_id=%s""",
                    (parsed["patch_url"], cve_id))
                patched_cves.append({"cve_id":cve_id,"patch_url":parsed["patch_url"],"asset":asset_name})
        else:
            finding_id = f"cve--{uuid.uuid4()}"
            cur2 = conn.cursor()
            cur2.execute("""INSERT INTO cve_findings
                (id,cve_id,asset_id,title,description,cvss_score,cvss_severity,cvss_vector,
                 epss_score,epss_percentile,kev_listed,kev_date,cwe,affected_versions,
                 published_date,modified_date,patch_available,patch_url,patch_detected_at,"references")
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (cve_id, asset_id) DO NOTHING""",
                (finding_id,cve_id,asset_id,parsed["title"],parsed["description"],
                 parsed["cvss_score"],parsed["cvss_severity"],parsed["cvss_vector"],
                 epss.get("epss"),epss.get("percentile"),bool(kev_info),kev_info or None,
                 parsed["cwe"],parsed["affected_versions"],parsed["published_date"],
                 parsed["modified_date"],parsed["patch_available"],parsed["patch_url"],
                 datetime.now(timezone.utc) if parsed["patch_available"] else None,
                 psycopg2.extras.Json(parsed["references"])))
            new_cves.append({"cve_id":cve_id,"severity":parsed["cvss_severity"],
                             "score":parsed["cvss_score"],"kev":bool(kev_info),
                             "asset":asset_name,"patch":parsed["patch_available"],
                             "patch_url":parsed["patch_url"]})
    conn.commit()
    return {"new_cves":new_cves,"new_iocs":new_iocs,"patched":patched_cves}

async def scheduled_cve_poll():
    print(f"[cve-poll] Starting at {datetime.now()}")
    conn = get_db_direct()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM assets WHERE active = TRUE")
    assets = cur.fetchall()
    if not assets:
        conn.close(); return
    kev_catalog = await fetch_kev_catalog()
    all_new_cves=[]; all_new_iocs=[]; all_patched=[]
    for asset in assets:
        try:
            result = await poll_cves_for_asset(dict(asset), kev_catalog, conn)
            if result:
                all_new_cves.extend(result.get("new_cves",[]))
                all_new_iocs.extend(result.get("new_iocs",[]))
                all_patched.extend(result.get("patched",[]))
        except Exception as e:
            print(f"[cve-poll] Error {asset['name']}: {e}")
    # create portal notifications
    if all_new_cves:
        critical = [c for c in all_new_cves if (c.get("score") or 0) >= 9 or c.get("kev")]
        body = f"{len(all_new_cves)} new CVE(s) detected across your assets."
        if critical:
            body += f" {len(critical)} are CRITICAL or KEV-listed."
        create_notification(conn, "cve_new",
            f"CVE Alert: {len(all_new_cves)} new CVE(s) found",
            body, "critical" if critical else "warning",
            {"new_cves": all_new_cves[:10]})
    if all_patched:
        create_notification(conn, "patch_available",
            f"Patch available for {len(all_patched)} CVE(s)",
            f"Vendor patches detected for: {', '.join(p['cve_id'] for p in all_patched)}",
            "success", {"patched": all_patched})
    # log the poll
    cur2 = conn.cursor()
    cur2.execute("""INSERT INTO cve_poll_log (assets_polled,new_cves,new_iocs,patches_detected)
        VALUES (%s,%s,%s,%s)""", (len(assets), len(all_new_cves), len(all_new_iocs), len(all_patched)))
    conn.commit(); conn.close()
    print(f"[cve-poll] Done — {len(all_new_cves)} new CVEs, {len(all_new_iocs)} IOCs, {len(all_patched)} patches")

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/login")
@limiter.limit("10/minute")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s AND active = TRUE", (form.username,))
    user = cur.fetchone()
    if not user or not pwd_ctx.verify(form.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token({"sub":user["id"],"username":user["username"],"role":user["role"]})
    return {"access_token":token,"token_type":"bearer","username":user["username"],"role":user["role"]}

@app.post("/auth/signup")
@limiter.limit("5/hour")
async def signup(request: Request, body: SignupRequest, conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id FROM users WHERE username = %s", (body.username,))
    if cur.fetchone(): raise HTTPException(status_code=400, detail="Username already taken")

    if body.invite_code:
        # Invited signup — grants whatever role the invite specifies (analyst/admin)
        cur.execute("SELECT * FROM invite_codes WHERE code = %s AND used = FALSE", (body.invite_code,))
        invite = cur.fetchone()
        if not invite: raise HTTPException(status_code=400, detail="Invalid or already used invite code")
        role = invite["role"]
    else:
        # No invite — open explorer signup. Sandboxed: full access to stateless
        # tools (CVE lookup, KQL/SPL builder, OSINT, CVE Wall, read-only Bulk
        # IOC Lookup), no access to the owner's personal IOC feed/assets/campaigns.
        role = "explorer"

    uid = f"user--{uuid.uuid4()}"
    cur2 = conn.cursor()
    cur2.execute("INSERT INTO users (id,username,password,role) VALUES (%s,%s,%s,%s)",
        (uid,body.username,pwd_ctx.hash(body.password),role))
    if body.invite_code:
        cur2.execute("UPDATE invite_codes SET used = TRUE WHERE code = %s", (body.invite_code,))
    conn.commit()
    token = create_token({"sub":uid,"username":body.username,"role":role})
    return {"access_token":token,"token_type":"bearer","username":body.username,"role":role}

@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return {"id":user["id"],"username":user["username"],"role":user["role"]}

@app.delete("/admin/purge-old-cves")
def purge_old_cves(before_year: int = 2023, admin=Depends(require_admin), conn=Depends(get_db)):
    """Remove CVEs published before a given year. Default: remove pre-2023 CVEs."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cve_findings WHERE published_date < %s", (f"{before_year}-01-01",))
    count = cur.fetchone()[0]
    cur.execute("DELETE FROM cve_ioc_links WHERE cve_id IN (SELECT cve_id FROM cve_findings WHERE published_date < %s)", (f"{before_year}-01-01",))
    cur.execute("DELETE FROM cve_findings WHERE published_date < %s", (f"{before_year}-01-01",))
    conn.commit()
    return {"removed": count, "message": f"Removed {count} CVEs published before {before_year}"}

@app.post("/admin/cleanup-advisory-iocs")
def cleanup_advisory_iocs(admin=Depends(require_admin), conn=Depends(get_db)):
    """
    Purge IOCs that were auto-extracted from CVE advisory references.
    
    Nuclear mode: delete ALL URL/Domain IOCs that were auto-added,
    regardless of what domain they point to. The old code was pulling
    NVD reference URLs (changelog links, vendor release notes, LWN articles,
    blogspot posts, etc.) and treating them as threat indicators. None of
    them are. If a real threat URL needs to be in the feed it should be
    added manually with intent.
    
    Also removes any URL/Domain matching TRUSTED_DOMAINS regardless of
    how it got in.
    
    Safe to run multiple times.
    """
    cur = conn.cursor()
    removed = 0

    # 1. Nuclear: delete ALL URLs/Domains that were auto-added by any automated path.
    #    This covers: auto-extracted (old CVE poll), auto-added (old public search),
    #    public-lookup. None of these should ever have been in the feed.
    cur.execute("""
        SELECT id FROM iocs
        WHERE type IN ('URL', 'Domain')
        AND (
            'auto-extracted' = ANY(tags) OR
            'public-lookup'  = ANY(tags) OR
            'auto-added'     = ANY(tags)
        )
    """)
    rows = cur.fetchall()
    for (ioc_id,) in rows:
        cur.execute("DELETE FROM cve_ioc_links WHERE ioc_id = %s", (ioc_id,))
        cur.execute("DELETE FROM iocs WHERE id = %s", (ioc_id,))
        removed += 1

    # 2. Any URL/Domain that matches known advisory/vendor/news domains,
    #    regardless of how it was tagged (catches ones that slipped through
    #    without the auto-extracted tag via other paths).
    cur.execute("SELECT id, value FROM iocs WHERE type IN ('URL', 'Domain')")
    for ioc_id, value in cur.fetchall():
        if any(td in (value or "").lower() for td in TRUSTED_DOMAINS):
            cur.execute("DELETE FROM cve_ioc_links WHERE ioc_id = %s", (ioc_id,))
            cur.execute("DELETE FROM iocs WHERE id = %s", (ioc_id,))
            removed += 1

    # 3. Anything with no created_by (system-generated, never manually added).
    #    These are orphan records from old automated ingestion paths.
    cur.execute("""
        SELECT id FROM iocs
        WHERE type IN ('URL', 'Domain')
        AND (created_by IS NULL OR created_by = '')
    """)
    for (ioc_id,) in cur.fetchall():
        cur.execute("DELETE FROM cve_ioc_links WHERE ioc_id = %s", (ioc_id,))
        cur.execute("DELETE FROM iocs WHERE id = %s", (ioc_id,))
        removed += 1

    conn.commit()
    return {"status": "done", "removed": removed,
            "message": (
                f"Removed {removed} false-positive IOCs from the feed. "
                f"These were reference links and advisory URLs from CVE records — "
                f"never actual threat indicators."
            )}

@app.post("/auth/change-password")
def change_password(body: PasswordChange, user=Depends(get_current_user), conn=Depends(get_db)):
    if not pwd_ctx.verify(body.current_password, user["password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = %s WHERE id = %s", (pwd_ctx.hash(body.new_password), user["id"]))
    conn.commit(); return {"status":"password updated"}

# ── USER API KEYS ─────────────────────────────────────────────────────────────

ALLOWED_SERVICES = {"virustotal","abuseipdb","shodan","hibp","groq","nvd"}
SERVICE_LABELS = {
    "virustotal": {"name":"VirusTotal",   "url":"https://www.virustotal.com/gui/my-apikey",    "placeholder":"Enter your VirusTotal API key"},
    "abuseipdb":  {"name":"AbuseIPDB",    "url":"https://www.abuseipdb.com/account/api",        "placeholder":"Enter your AbuseIPDB API key"},
    "shodan":     {"name":"Shodan",       "url":"https://account.shodan.io/",                   "placeholder":"Enter your Shodan API key"},
    "hibp":       {"name":"HaveIBeenPwned","url":"https://haveibeenpwned.com/API/Key",           "placeholder":"Enter your HIBP API key"},
    "groq":       {"name":"Groq",         "url":"https://console.groq.com/keys",                "placeholder":"gsk_xxxxxxxxxxxx"},
    "nvd":        {"name":"NVD",          "url":"https://nvd.nist.gov/developers/request-an-api-key","placeholder":"Enter your NVD API key"},
}

@app.get("/users/me/api-keys")
def get_my_api_keys(user=Depends(get_current_user), conn=Depends(get_db)):
    """Return user's saved API keys (masked) + quota status."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT service, api_key_encrypted, updated_at FROM user_api_keys WHERE user_id = %s",
                (user["id"],))
    rows = {r["service"]: r for r in cur.fetchall()}
    quota = get_all_quota_status(conn, user["id"], user["role"] == "admin")
    result = []
    for svc, label in SERVICE_LABELS.items():
        row = rows.get(svc)
        has_key = bool(row and row["api_key_encrypted"])
        result.append({
            "service":      svc,
            "name":         label["name"],
            "url":          label["url"],
            "placeholder":  label["placeholder"],
            "has_key":      has_key,
            "masked":       mask_key(decrypt_key(row["api_key_encrypted"])) if has_key else None,
            "updated_at":   row["updated_at"].isoformat() if has_key and row.get("updated_at") else None,
            **quota.get(svc, {}),
        })
    return result

@app.post("/users/me/api-keys/{service}")
def save_api_key(service: str, body: dict, user=Depends(get_current_user), conn=Depends(get_db)):
    """Save or update a personal API key for a service."""
    if service not in ALLOWED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Unknown service: {service}")
    key = body.get("api_key","").strip()
    if not key:
        raise HTTPException(status_code=400, detail="api_key cannot be empty")
    encrypted = encrypt_key(key)
    cur = conn.cursor()
    cur.execute("""INSERT INTO user_api_keys (user_id, service, api_key_encrypted, updated_at)
        VALUES (%s,%s,%s,NOW())
        ON CONFLICT (user_id, service) DO UPDATE
        SET api_key_encrypted = EXCLUDED.api_key_encrypted, updated_at = NOW()""",
        (user["id"], service, encrypted))
    conn.commit()
    return {"status":"saved","service":service,"masked":mask_key(key)}

@app.delete("/users/me/api-keys/{service}")
def delete_api_key(service: str, user=Depends(get_current_user), conn=Depends(get_db)):
    """Remove a personal API key."""
    if service not in ALLOWED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Unknown service: {service}")
    cur = conn.cursor()
    cur.execute("DELETE FROM user_api_keys WHERE user_id = %s AND service = %s", (user["id"], service))
    conn.commit(); return {"status":"deleted","service":service}

@app.get("/users/me/quota")
def get_quota(user=Depends(get_current_user), conn=Depends(get_db)):
    """Return daily quota status for current user."""
    return get_all_quota_status(conn, user["id"], user["role"] == "admin")

# ═══════════════════════════════════════════════════════════════════════════════
# USERS + INVITES
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/invites")
def create_invite(body: InviteCreate, admin=Depends(require_admin), conn=Depends(get_db)):
    code = uuid.uuid4().hex[:16].upper()
    cur  = conn.cursor()
    cur.execute("INSERT INTO invite_codes (code,role,created_by) VALUES (%s,%s,%s)", (code,body.role,admin["id"]))
    conn.commit(); return {"code":code,"role":body.role}

@app.get("/invites")
def list_invites(admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM invite_codes ORDER BY created_at DESC")
    return cur.fetchall()

@app.get("/users")
def list_users(admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,username,role,active,created_at FROM users ORDER BY created_at DESC")
    return cur.fetchall()

@app.post("/users", status_code=201)
def create_user(body: UserCreate, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id FROM users WHERE username = %s", (body.username,))
    if cur.fetchone(): raise HTTPException(status_code=400, detail="Username already exists")
    uid = f"user--{uuid.uuid4()}"
    cur.execute("INSERT INTO users (id,username,password,role) VALUES (%s,%s,%s,%s)",
        (uid,body.username,pwd_ctx.hash(body.password),body.role))
    conn.commit(); return {"id":uid,"username":body.username,"role":body.role}

@app.patch("/users/{user_id}/disable")
def disable_user(user_id: str, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE users SET active = FALSE WHERE id = %s", (user_id,)); conn.commit()
    return {"status":"disabled"}

@app.patch("/users/{user_id}/enable")
def enable_user(user_id: str, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE users SET active = TRUE WHERE id = %s", (user_id,)); conn.commit()
    return {"status":"enabled"}

# ═══════════════════════════════════════════════════════════════════════════════
# CAMPAIGNS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/campaigns")
def list_campaigns(user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT c.*, COUNT(i.id) as ioc_count FROM campaigns c
        LEFT JOIN iocs i ON i.campaign_id = c.id GROUP BY c.id ORDER BY c.created_at DESC""")
    return cur.fetchall()

@app.post("/campaigns", status_code=201)
def create_campaign(body: CampaignIn, user=Depends(require_full_access), conn=Depends(get_db)):
    cid = f"campaign--{uuid.uuid4()}"
    cur = conn.cursor()
    cur.execute("INSERT INTO campaigns (id,name,description,threat_actor,industry_targets,created_by) VALUES (%s,%s,%s,%s,%s,%s)",
        (cid,body.name,body.description,body.threat_actor,body.industry_targets,user["id"]))
    conn.commit(); return {"id":cid,"name":body.name}

@app.delete("/campaigns/{campaign_id}")
def delete_campaign(campaign_id: str, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE iocs SET campaign_id = NULL WHERE campaign_id = %s", (campaign_id,))
    cur.execute("DELETE FROM campaigns WHERE id = %s", (campaign_id,))
    conn.commit(); return {"status":"deleted"}

# ═══════════════════════════════════════════════════════════════════════════════
# IOC ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/iocs")
def list_iocs(industry: Optional[str]=None, tlp: Optional[str]=None, ioc_type: Optional[str]=None,
              include_expired: bool=False, include_fp: bool=False, campaign_id: Optional[str]=None,
              user=Depends(require_full_access), conn=Depends(get_db)):
    cur   = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    query = """SELECT i.*, u.username as author, c.name as campaign_name FROM iocs i
        LEFT JOIN users u ON i.created_by = u.id
        LEFT JOIN campaigns c ON i.campaign_id = c.id WHERE 1=1"""
    params = []
    if industry:    query += " AND i.industry = %s";    params.append(industry)
    if tlp:         query += " AND i.tlp = %s";         params.append(tlp)
    if ioc_type:    query += " AND i.type = %s";        params.append(ioc_type)
    if campaign_id: query += " AND i.campaign_id = %s"; params.append(campaign_id)
    if not include_fp:      query += " AND (i.false_positive IS NULL OR i.false_positive = FALSE)"
    if not include_expired: query += " AND (i.valid_until IS NULL OR i.valid_until > NOW())"
    query += " ORDER BY i.created_at DESC"
    cur.execute(query, params); rows = cur.fetchall()
    now = datetime.now(timezone.utc)
    for row in rows:
        row["expired"] = bool(row.get("valid_until") and row["valid_until"].replace(tzinfo=timezone.utc) < now)
    return rows

@app.get("/iocs/search")
def search_iocs(q: str, user=Depends(require_full_access), conn=Depends(get_db)):
    normalized = refang(q.strip())
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT i.*, u.username as author FROM iocs i LEFT JOIN users u ON i.created_by = u.id
        WHERE i.value ILIKE %s OR i.value_defanged ILIKE %s OR i.description ILIKE %s OR %s = ANY(i.tags)
        ORDER BY i.created_at DESC""", (f"%{normalized}%",f"%{q}%",f"%{q}%",q.lower()))
    rows = cur.fetchall()
    now = datetime.now(timezone.utc)
    for row in rows:
        row["expired"] = bool(row.get("valid_until") and row["valid_until"].replace(tzinfo=timezone.utc) < now)
    return {"query":q,"normalized":normalized,"count":len(rows),"results":rows}

@app.post("/iocs/check")
def check_duplicate(body: dict, user=Depends(require_full_access), conn=Depends(get_db)):
    value = refang(body.get("value","").strip())
    cur   = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT i.*, u.username as author FROM iocs i LEFT JOIN users u ON i.created_by = u.id WHERE i.value = %s", (value,))
    existing = cur.fetchone()
    return {"exists":bool(existing),"existing":existing}

@app.post("/iocs", status_code=201)
async def add_ioc(ioc: IOCIn, user=Depends(require_full_access), conn=Depends(get_db)):
    canonical = refang(ioc.value.strip()); defanged = defang(canonical, ioc.type)
    enrichment = await enrich(ioc.type, canonical, ioc.confidence, conn, user=user)
    final_confidence = enrichment.get("calculated_confidence", ioc.confidence)
    reasons = enrichment.get("confidence_reasons", [])
    ioc_id = f"indicator--{uuid.uuid4()}"
    valid_until = datetime.now(timezone.utc) + timedelta(days=ioc.valid_days) if ioc.valid_days else None
    cur = conn.cursor()
    cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,
        tags,created_by,enrichment,valid_until,mitre_techniques,campaign_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (ioc_id,ioc.type,canonical,defanged,ioc.industry,ioc.tlp,final_confidence,ioc.description,
         ioc.tags,user["id"],psycopg2.extras.Json(enrichment),valid_until,ioc.mitre_techniques,ioc.campaign_id))
    record_score(conn, ioc_id, ioc.confidence, final_confidence, reasons, user["username"])
    audit(conn,"ADD",ioc_id,canonical,ioc.type,user)
    conn.commit()
    return {"id":ioc_id,"status":"created","confidence":final_confidence,
            "value_canonical":canonical,"value_defanged":defanged,"enrichment":enrichment}

class BulkIOCItem(BaseModel):
    type: str
    value: str
    confidence: Optional[int] = 50
    description: Optional[str] = ""
    tags: Optional[List[str]] = []
    enrichment: Optional[dict] = None
    industry: Optional[str] = "General"
    tlp: Optional[str] = "AMBER"
    valid_days: Optional[int] = 90

class BulkIOCCreate(BaseModel):
    items: List[BulkIOCItem]

@app.post("/iocs/bulk-create", status_code=201)
async def bulk_create_iocs(body: BulkIOCCreate, user=Depends(require_full_access), conn=Depends(get_db)):
    """
    Add multiple IOCs to the feed in one call — used by Bulk Lookup's
    'Add Selected to Feed' action. Reuses enrichment data already computed
    by the lookup instead of re-querying external APIs for each item.
    """
    if len(body.items) > MAX_BULK_INDICATORS:
        raise HTTPException(status_code=400, detail=f"Max {MAX_BULK_INDICATORS} items per bulk add.")
    created, skipped = [], []
    cur = conn.cursor()
    for item in body.items:
        try:
            canonical = refang(item.value.strip())
            defanged  = defang(canonical, item.type)
            cur.execute("SELECT id FROM iocs WHERE value = %s", (canonical,))
            if cur.fetchone():
                skipped.append({"value": canonical, "reason": "already exists"})
                continue
            enrichment = item.enrichment or {}
            if "calculated_confidence" not in enrichment:
                enrichment = await enrich(item.type, canonical, item.confidence, conn, user=user)
            final_confidence = enrichment.get("calculated_confidence", item.confidence)
            ioc_id = f"indicator--{uuid.uuid4()}"
            valid_until = (datetime.now(timezone.utc) + timedelta(days=item.valid_days)
                           if item.valid_days else None)
            cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,
                description,tags,created_by,enrichment,valid_until) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (ioc_id,item.type,canonical,defanged,item.industry,item.tlp,final_confidence,
                 item.description,item.tags,user["id"],psycopg2.extras.Json(enrichment),valid_until))
            audit(conn,"ADD",ioc_id,canonical,item.type,user)
            created.append({"id": ioc_id, "value": canonical})
        except Exception as e:
            skipped.append({"value": item.value, "reason": str(e)})
    conn.commit()
    return {"created": created, "skipped": skipped,
            "created_count": len(created), "skipped_count": len(skipped)}

@app.patch("/iocs/{ioc_id}/false-positive")
def toggle_fp(ioc_id: str, body: FPUpdate, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT created_by FROM iocs WHERE id = %s", (ioc_id,))
    ioc = cur.fetchone()
    if not ioc: raise HTTPException(status_code=404, detail="IOC not found")
    if user["role"] != "admin" and ioc["created_by"] != user["id"]:
        raise HTTPException(status_code=403, detail="You can only mark your own IOCs as FP")
    cur2 = conn.cursor()
    cur2.execute("UPDATE iocs SET false_positive = %s, fp_reason = %s WHERE id = %s",
        (body.false_positive, body.reason, ioc_id))
    conn.commit(); return {"status":"updated","false_positive":body.false_positive}

@app.patch("/iocs/{ioc_id}/campaign")
def assign_campaign(ioc_id: str, body: dict, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE iocs SET campaign_id = %s WHERE id = %s", (body.get("campaign_id"), ioc_id))
    conn.commit(); return {"status":"updated"}

@app.post("/iocs/{ioc_id}/re-enrich")
async def re_enrich(ioc_id: str, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM iocs WHERE id = %s", (ioc_id,))
    ioc = cur.fetchone()
    if not ioc: raise HTTPException(status_code=404, detail="IOC not found")
    old_score = ioc["confidence"]
    enrichment = await enrich(ioc["type"],ioc["value"],ioc["confidence"],conn,force=True,existing=ioc.get("enrichment"),user=user)
    new_score = enrichment.get("calculated_confidence", old_score)
    reasons   = enrichment.get("confidence_reasons", [])
    cur2 = conn.cursor()
    cur2.execute("UPDATE iocs SET enrichment = %s, confidence = %s WHERE id = %s",
        (psycopg2.extras.Json(enrichment), new_score, ioc_id))
    record_score(conn, ioc_id, old_score, new_score, reasons, user["username"])
    conn.commit(); return {"confidence":new_score,"enrichment":enrichment}

# ── BULK IOC LOOKUP / VALIDATOR ──────────────────────────────────────────────

class BulkLookupRequest(BaseModel):
    input: str

MAX_BULK_INDICATORS = 60

async def run_bulk_lookup(raw_text: str, user: dict, conn) -> dict:
    """
    Core bulk IOC validator logic — shared by the paste-text and
    file-upload endpoints. Paste/file content of mixed IPs, domains,
    URLs, hashes, emails, or filenames — fanged or defanged — one or
    many per line. Resolves owner/org/country via batch geo lookup,
    then checks each indicator against threat intel sources.
    """
    tokens = parse_bulk_input(raw_text)
    if not tokens:
        raise HTTPException(status_code=400, detail="No indicators found in the input.")
    if len(tokens) > MAX_BULK_INDICATORS:
        raise HTTPException(status_code=400,
            detail=f"Too many indicators ({len(tokens)}). Max {MAX_BULK_INDICATORS} per lookup — split into smaller batches.")

    # ── Phase 1: classify each token ─────────────────────────────────────────
    parsed = []
    for raw in tokens:
        refanged = refang(raw)
        ioc_type = detect_type(refanged)
        parsed.append({"input": raw, "refanged": refanged, "type": ioc_type})

    # ── Phase 2: resolve Domain/URL hostnames to IP for geo lookup ───────────
    geo_ips = await asyncio.gather(*[resolve_to_ip(p["refanged"], p["type"]) for p in parsed])
    for p, ip in zip(parsed, geo_ips):
        p["geo_ip"] = ip if ip else (p["refanged"] if p["type"] in ("IPv4","IPv6") else None)

    # ── Phase 3: one batched geo/ASN/org lookup for every unique IP ──────────
    unique_ips = list({p["geo_ip"] for p in parsed if p["geo_ip"]})
    geo_data   = await geo_org_lookup_batch(unique_ips) if unique_ips else {}

    # ── Phase 4: threat-intel enrichment (concurrency-limited) ───────────────
    sem = asyncio.Semaphore(5)

    def build_geo(item):
        raw_geo = geo_data.get(item["geo_ip"]) if item["geo_ip"] else None
        if not raw_geo or raw_geo.get("status") == "fail":
            return None
        org = raw_geo.get("org") or raw_geo.get("isp") or ""
        return {
            "country":        raw_geo.get("country"),
            "country_code":   raw_geo.get("countryCode"),
            "org":             org,
            "isp":            raw_geo.get("isp"),
            "asn":            raw_geo.get("as"),
            "cloud_provider": detect_cloud_provider(org),
            "resolved_ip":    item["geo_ip"] if item["type"] in ("Domain","URL") else None,
        }

    async def process_one(item: dict) -> dict:
        async with sem:
            raw, refanged, ioc_type = item["input"], item["refanged"], item["type"]
            geo = build_geo(item)

            if ioc_type == "Unknown":
                return {"input": raw, "refanged": refanged, "defanged": refanged,
                        "type": "Unknown", "verdict": "unrecognized",
                        "reason": "Could not determine indicator type", "enrichment": {}, "geo": geo}

            if ioc_type == "CVE":
                return {"input": raw, "refanged": refanged, "defanged": refanged,
                        "type": "CVE", "verdict": "info",
                        "reason": "This is a CVE ID, not a threat indicator. Use the CVE Lookup page for vulnerability details.",
                        "enrichment": {}, "geo": None}

            if ioc_type == "Filename":
                flags = check_filename_heuristics(refanged)
                return {"input": raw, "refanged": refanged, "defanged": refanged,
                        "type": "Filename",
                        "verdict": "suspicious" if flags else "unknown",
                        "reason": "; ".join(flags) if flags else "No red flags in filename — submit the file's MD5/SHA256 hash for a real reputation check",
                        "enrichment": {"flags": flags}, "geo": None}

            # Reuse a fresh cached enrichment from an existing IOC record if one
            # exists — but never for explorer role, since that would leak
            # whether/what the owner has personally tracked on this indicator
            existing = None
            if user.get("role") != "explorer":
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute("SELECT * FROM iocs WHERE value = %s", (refanged,))
                existing = cur.fetchone()

            enrichment = await enrich(ioc_type, refanged, 50, conn,
                force=False, existing=existing.get("enrichment") if existing else None, user=user)
            verdict_info = compute_verdict(enrichment)

            return {
                "input": raw, "refanged": refanged,
                "defanged": defang(refanged, ioc_type),
                "type": ioc_type,
                "verdict": verdict_info["verdict"],
                "score": verdict_info["score"],
                "reason": verdict_info["reason"],
                "enrichment": enrichment,
                "geo": geo,
                "already_tracked": bool(existing),
                "existing_id": existing["id"] if existing else None,
            }

    results = await asyncio.gather(*[process_one(p) for p in parsed])

    summary = {
        "total":      len(results),
        "malicious":  sum(1 for r in results if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in results if r["verdict"] == "suspicious"),
        "clean":      sum(1 for r in results if r["verdict"] == "clean"),
        "unknown":    sum(1 for r in results if r["verdict"] in ("unknown","unrecognized")),
        "info":       sum(1 for r in results if r["verdict"] == "info"),
    }
    return {"results": results, "summary": summary}

@app.post("/iocs/bulk-lookup")
async def bulk_ioc_lookup(body: BulkLookupRequest, user=Depends(get_current_user), conn=Depends(get_db)):
    return await run_bulk_lookup(body.input, user, conn)

@app.post("/iocs/bulk-lookup/file")
async def bulk_ioc_lookup_file(file: UploadFile = File(...), user=Depends(get_current_user), conn=Depends(get_db)):
    """
    Same as /iocs/bulk-lookup but the indicators come from an uploaded
    file (.txt, .csv, or any plain-text list) instead of a pasted blob.
    """
    if file.size and file.size > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large — max 2MB.")
    raw_bytes = await file.read()
    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = raw_bytes.decode("latin-1")
        except Exception:
            raise HTTPException(status_code=400, detail="Could not read file — please upload a plain text or CSV file.")

    # If it's a CSV with a header row containing a recognizable column
    # (value/ioc/indicator), extract just that column; otherwise treat
    # the whole file as free text (one indicator per line/cell).
    if file.filename and file.filename.lower().endswith(".csv"):
        try:
            reader = csv.reader(io.StringIO(text))
            rows = list(reader)
            if rows:
                header = [h.strip().lower() for h in rows[0]]
                col_idx = next((i for i,h in enumerate(header)
                                if h in ("value","ioc","indicator","ip","domain","url","hash")), None)
                if col_idx is not None:
                    lines = [r[col_idx] for r in rows[1:] if len(r) > col_idx and r[col_idx].strip()]
                else:
                    # No recognizable header — flatten every cell in every row
                    lines = [cell for row in rows for cell in row if cell.strip()]
                text = "\n".join(lines)
        except Exception:
            pass  # fall through and treat as plain text

    return await run_bulk_lookup(text, user, conn)


@app.get("/iocs/{ioc_id}/score-history")
def score_history(ioc_id: str, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ioc_score_history WHERE ioc_id = %s ORDER BY created_at DESC", (ioc_id,))
    return cur.fetchall()

@app.delete("/iocs/{ioc_id}")
def delete_ioc(ioc_id: str, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT created_by, value, type FROM iocs WHERE id = %s", (ioc_id,))
    ioc = cur.fetchone()
    if not ioc: raise HTTPException(status_code=404, detail="IOC not found")
    if user["role"] != "admin" and ioc["created_by"] != user["id"]:
        raise HTTPException(status_code=403, detail="You can only delete your own IOCs")
    audit(conn,"DELETE",ioc_id,ioc["value"],ioc["type"],user)
    cur2 = conn.cursor()
    for tbl in ["ioc_notes","ioc_score_history","cve_ioc_links"]:
        try: cur2.execute(f"DELETE FROM {tbl} WHERE ioc_id = %s OR {'cve_id' if tbl=='cve_ioc_links' else 'ioc_id'} = %s", (ioc_id,ioc_id))
        except Exception: pass
    cur2.execute("DELETE FROM ioc_relationships WHERE source_id = %s OR target_id = %s", (ioc_id,ioc_id))
    cur2.execute("DELETE FROM iocs WHERE id = %s", (ioc_id,))
    conn.commit(); return {"status":"deleted"}

@app.get("/iocs/{ioc_id}/notes")
def get_notes(ioc_id: str, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ioc_notes WHERE ioc_id = %s ORDER BY created_at ASC", (ioc_id,))
    return cur.fetchall()

@app.post("/iocs/{ioc_id}/notes", status_code=201)
def add_note(ioc_id: str, body: IocNoteIn, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("INSERT INTO ioc_notes (ioc_id,note,username,user_id) VALUES (%s,%s,%s,%s)",
        (ioc_id,body.note,user["username"],user["id"]))
    conn.commit(); return {"status":"created"}

@app.delete("/iocs/{ioc_id}/notes/{note_id}")
# Named distinctly from the workspace delete_note above — same name for two
# unrelated routes is what let the NoteIn model collision hide in this file.
def delete_ioc_note(ioc_id: str, note_id: int, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT user_id FROM ioc_notes WHERE id = %s AND ioc_id = %s", (note_id,ioc_id))
    note = cur.fetchone()
    if not note: raise HTTPException(status_code=404, detail="Note not found")
    if user["role"] != "admin" and note["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Cannot delete another user's note")
    cur2 = conn.cursor()
    cur2.execute("DELETE FROM ioc_notes WHERE id = %s", (note_id,))
    conn.commit(); return {"status":"deleted"}

@app.get("/iocs/{ioc_id}/relationships")
def get_relationships(ioc_id: str, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT r.*,
        s.value as source_value, s.type as source_type, s.value_defanged as source_defanged,
        t.value as target_value, t.type as target_type, t.value_defanged as target_defanged
        FROM ioc_relationships r
        JOIN iocs s ON r.source_id = s.id JOIN iocs t ON r.target_id = t.id
        WHERE r.source_id = %s OR r.target_id = %s""", (ioc_id,ioc_id))
    return cur.fetchall()

@app.post("/iocs/{ioc_id}/relationships", status_code=201)
def add_relationship(ioc_id: str, body: RelationshipIn, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("SELECT id FROM iocs WHERE id = %s", (ioc_id,))
    if not cur.fetchone(): raise HTTPException(status_code=404, detail="Source IOC not found")
    cur.execute("SELECT id FROM iocs WHERE id = %s", (body.target_id,))
    if not cur.fetchone(): raise HTTPException(status_code=404, detail="Target IOC not found")
    cur.execute("INSERT INTO ioc_relationships (source_id,target_id,relationship_type,note,created_by) VALUES (%s,%s,%s,%s,%s)",
        (ioc_id,body.target_id,body.relationship_type,body.note,user["id"]))
    conn.commit(); return {"status":"created"}

@app.delete("/iocs/relationships/{rel_id}")
def delete_relationship(rel_id: int, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("DELETE FROM ioc_relationships WHERE id = %s", (rel_id,))
    conn.commit(); return {"status":"deleted"}

@app.get("/iocs/pivot/subnet/{ip}")
def subnet_pivot(ip: str, user=Depends(require_full_access), conn=Depends(get_db)):
    try:
        parts = ip.split(".")
        if len(parts) != 4: raise ValueError
        subnet = ".".join(parts[:3])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid IPv4 address")
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT i.*, u.username as author FROM iocs i LEFT JOIN users u ON i.created_by = u.id
        WHERE i.type = 'IPv4' AND i.value LIKE %s ORDER BY i.created_at DESC""", (f"{subnet}.%",))
    rows = cur.fetchall()
    return {"subnet":f"{subnet}.0/24","count":len(rows),"iocs":rows}

# ═══════════════════════════════════════════════════════════════════════════════
# ASSETS + CVE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/assets")
def list_assets(user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT a.*,
        COUNT(DISTINCT cf.id) as cve_count,
        SUM(CASE WHEN cf.patch_available = FALSE AND cf.cvss_score >= 9 THEN 1 ELSE 0 END) as critical_unpatched,
        SUM(CASE WHEN cf.kev_listed = TRUE AND cf.patch_available = FALSE THEN 1 ELSE 0 END) as kev_unpatched
        FROM assets a LEFT JOIN cve_findings cf ON cf.asset_id = a.id
        WHERE a.active = TRUE GROUP BY a.id ORDER BY a.created_at DESC""")
    return cur.fetchall()

@app.post("/assets", status_code=201)
async def create_asset(body: AssetIn, user=Depends(require_full_access), conn=Depends(get_db)):
    aid = f"asset--{uuid.uuid4()}"
    cpe = body.cpe or ""

    # Auto-resolve CPE from name+vendor if not provided
    if not cpe and body.name:
        try:
            headers = {"User-Agent":"ThreatFeed-CTI/1.0"}
            if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY

            name_lc   = body.name.lower().strip()
            vendor_lc = (body.vendor or "").lower().strip()

            # Build search query — NVD searches across CPE titles
            query = f"{vendor_lc} {name_lc}".strip()

            async with httpx.AsyncClient(timeout=12) as c:
                r = await c.get("https://services.nvd.nist.gov/rest/json/cpes/2.0",
                                params={"keywordSearch": query, "resultsPerPage": 20},
                                headers=headers)

            if r.status_code == 200:
                products = r.json().get("products", [])

                # Score each candidate CPE for relevance
                def score_cpe(p):
                    cpe_data  = p.get("cpe", {})
                    cpe_name  = cpe_data.get("cpeName", "").lower()
                    # get human-readable title
                    titles    = cpe_data.get("titles", [])
                    title     = next((t["title"].lower() for t in titles if t.get("lang") == "en"), "")
                    parts     = cpe_name.split(":")
                    cpe_part  = parts[2] if len(parts) > 2 else "a"  # a=app, o=os, h=hw
                    cpe_vendor= parts[3] if len(parts) > 3 else ""
                    cpe_prod  = parts[4] if len(parts) > 4 else ""
                    score = 0

                    # Vendor match
                    if vendor_lc and vendor_lc in cpe_vendor: score += 30
                    if vendor_lc and vendor_lc in title:       score += 10

                    # Product name match — split into words for partial matching
                    name_words = re.split(r'[\s_\-]+', name_lc)
                    for word in name_words:
                        if len(word) < 3: continue
                        if word in cpe_prod:  score += 20
                        if word in title:     score += 10

                    # Exact product name in CPE string
                    name_slug = re.sub(r'[\s\-]+', '_', name_lc)
                    if name_slug in cpe_prod: score += 25

                    # Asset type hints
                    if body.asset_type == "os" and cpe_part == "o":   score += 40
                    if body.asset_type == "hardware" and cpe_part == "h": score += 40
                    if body.asset_type in ("application","library","database","cloud_service") and cpe_part == "a": score += 15

                    # Penalise obviously wrong matches
                    wrong_keywords = ["media_player","office","edge","store","sdk","runtime","driver"]
                    for kw in wrong_keywords:
                        if kw in cpe_prod and kw not in name_lc: score -= 30

                    return score

                scored = sorted(products, key=score_cpe, reverse=True)
                best_product = scored[0] if scored else None

                if best_product:
                    best = best_product.get("cpe", {}).get("cpeName", "")
                    parts = best.split(":")

                    # Ensure CPE has all 13 fields (cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other)
                    while len(parts) < 13:
                        parts.append("*")

                    # Set version field
                    if body.version:
                        parts[5] = body.version   # exact installed version
                    else:
                        parts[5] = "*"            # all versions

                    # Normalise remaining fields to wildcards
                    for i in range(6, 13):
                        if parts[i] in ("", "-"): parts[i] = "*"

                    cpe = ":".join(parts[:13])
                    print(f"[cpe-autoresolve] '{query}' → {cpe} (score={score_cpe(best_product)})")

        except Exception as e:
            print(f"[cpe-autoresolve] Error: {e}")

        # Fallback: build CPE from name/vendor directly if NVD lookup failed or scored poorly
        if not cpe:
            part       = "o" if body.asset_type == "os" else "h" if body.asset_type == "hardware" else "a"
            safe_vendor = re.sub(r'[^a-z0-9]', '_', vendor_lc or name_lc).strip('_')
            safe_name   = re.sub(r'[^a-z0-9]', '_', name_lc).strip('_')
            version_part = body.version if body.version else "*"
            cpe = f"cpe:2.3:{part}:{safe_vendor}:{safe_name}:{version_part}:*:*:*:*:*:*:*"
            print(f"[cpe-autoresolve] Fallback CPE: {cpe}")

    cur = conn.cursor()
    cur.execute("""INSERT INTO assets (id,name,vendor,version,asset_type,criticality,cpe,description,created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (aid, body.name, body.vendor, body.version, body.asset_type,
         body.criticality, cpe, body.description, user["id"]))
    conn.commit()
    return {"id": aid, "name": body.name, "cpe_resolved": cpe}

# ── PRODUCT KNOWLEDGE BASE ────────────────────────────────────────────────────
# Maps common product names → (vendor, asset_type, cpe_vendor, cpe_product, notes)
PRODUCT_KB = {
    # Browsers
    "chrome":           ("Google",       "application", "google",    "chrome",           "Chromium-based"),
    "google chrome":    ("Google",       "application", "google",    "chrome",           "Chromium-based"),
    "chromium":         ("Google",       "application", "google",    "chromium",         None),
    "edge":             ("Microsoft",    "application", "microsoft", "edge",             "Chromium-based"),
    "microsoft edge":   ("Microsoft",    "application", "microsoft", "edge",             "Chromium-based"),
    "firefox":          ("Mozilla",      "application", "mozilla",   "firefox",          None),
    "safari":           ("Apple",        "application", "apple",     "safari",           None),
    "opera":            ("Opera",        "application", "opera",     "opera_browser",    "Chromium-based"),
    "brave":            ("Brave",        "application", "brave",     "brave",            "Chromium-based"),

    # Operating Systems
    "windows 11":       ("Microsoft",    "os",          "microsoft", "windows_11",       None),
    "windows 10":       ("Microsoft",    "os",          "microsoft", "windows_10",       None),
    "windows server":   ("Microsoft",    "os",          "microsoft", "windows_server",   None),
    "windows server 2022": ("Microsoft", "os",          "microsoft", "windows_server_2022", None),
    "windows server 2019": ("Microsoft", "os",          "microsoft", "windows_server_2019", None),
    "ubuntu":           ("Canonical",    "os",          "canonical", "ubuntu_linux",     None),
    "debian":           ("Debian",       "os",          "debian",    "debian_linux",     None),
    "centos":           ("Red Hat",      "os",          "centos",    "centos",           "EOL — migrate to Rocky/Alma"),
    "rhel":             ("Red Hat",      "os",          "redhat",    "enterprise_linux",  None),
    "red hat":          ("Red Hat",      "os",          "redhat",    "enterprise_linux",  None),
    "red hat linux":    ("Red Hat",      "os",          "redhat",    "enterprise_linux",  None),
    "red hat enterprise linux": ("Red Hat","os",         "redhat",    "enterprise_linux",  None),
    "macos":            ("Apple",        "os",          "apple",     "macos",            None),
    "mac os":           ("Apple",        "os",          "apple",     "macos",            None),
    "android":          ("Google",       "os",          "google",    "android",          None),
    "ios":              ("Apple",        "os",          "apple",     "iphone_os",        None),

    # Web Servers / Middleware
    "nginx":            ("Nginx",        "application", "nginx",     "nginx",            None),
    "apache":           ("Apache",       "application", "apache",    "http_server",      None),    "iis":              ("Microsoft",    "application", "microsoft", "iis",              "Internet Information Services"),
    "tomcat":           ("Apache",       "application", "apache",    "tomcat",           None),

    # Databases
    "mysql":            ("Oracle",       "database",    "mysql",     "mysql",            None),
    "postgresql":       ("PostgreSQL",   "database",    "postgresql","postgresql",       None),
    "postgres":         ("PostgreSQL",   "database",    "postgresql","postgresql",       None),
    "mongodb":          ("MongoDB",      "database",    "mongodb",   "mongodb",          None),
    "mssql":            ("Microsoft",    "database",    "microsoft", "sql_server",       None),
    "sql server":       ("Microsoft",    "database",    "microsoft", "sql_server",       None),
    "redis":            ("Redis",        "database",    "redis",     "redis",            None),
    "elasticsearch":    ("Elastic",      "database",    "elastic",   "elasticsearch",    None),

    # Network / Security
    "cisco ios":        ("Cisco",        "firmware",    "cisco",     "ios",              None),
    "cisco ios xe":     ("Cisco",        "firmware",    "cisco",     "ios_xe",           None),
    "catalyst":         ("Cisco",        "hardware",    "cisco",     "catalyst",         None),
    "catalyst wd-wan":  ("Cisco",        "hardware",    "cisco",     "catalyst_sd-wan",  None),
    "catalyst sd-wan":  ("Cisco",        "hardware",    "cisco",     "catalyst_sd-wan",  None),
    "sd-wan":           ("Cisco",        "hardware",    "cisco",     "sd-wan",           None),
    "palo alto":        ("Palo Alto Networks", "hardware", "paloaltonetworks", "pan-os", None),
    "pan-os":           ("Palo Alto Networks", "hardware", "paloaltonetworks", "pan-os", None),
    "fortios":          ("Fortinet",     "firmware",    "fortinet",  "fortios",          None),
    "fortigate":        ("Fortinet",     "hardware",    "fortinet",  "fortigate",        None),
    "openssl":          ("OpenSSL",      "library",     "openssl",   "openssl",          None),
    "openssh":          ("OpenBSD",      "application", "openbsd",   "openssh",          None),
    "vmware esxi":      ("VMware",       "firmware",    "vmware",    "esxi",             None),
    "esxi":             ("VMware",       "firmware",    "vmware",    "esxi",             None),
    "vcenter":          ("VMware",       "application", "vmware",    "vcenter_server",   None),
    "exchange":         ("Microsoft",    "application", "microsoft", "exchange_server",  None),
    "sharepoint":       ("Microsoft",    "application", "microsoft", "sharepoint_server",None),

    # Dev / Cloud
    "log4j":            ("Apache",       "library",     "apache",    "log4j",            "Log4Shell — CRITICAL"),
    "spring":           ("VMware",       "library",     "vmware",    "spring_framework",  None),
    "docker":           ("Docker",       "application", "docker",    "docker",           None),
    "kubernetes":       ("CNCF",         "application", "kubernetes","kubernetes",       None),
    "k8s":              ("CNCF",         "application", "kubernetes","kubernetes",       None),
    "jenkins":          ("Jenkins",      "application", "jenkins",   "jenkins",          None),
    "gitlab":           ("GitLab",       "application", "gitlab",    "gitlab",           None),
    "github":           ("GitHub",       "application", "github",    "github_enterprise",None),
    "jira":             ("Atlassian",    "application", "atlassian", "jira",             None),
    "confluence":       ("Atlassian",    "application", "atlassian", "confluence",       None),
}

async def get_nvd_latest_version(cpe_vendor: str, cpe_product: str) -> str:
    """Query NVD to find the latest-1 version for a product."""
    try:
        headers = {"User-Agent": "ThreatFeed-CTI/1.0"}
        if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY
        # Search CPE dictionary for this product, sorted by version
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cpes/2.0",
                params={"keywordSearch": f"{cpe_vendor} {cpe_product}", "resultsPerPage": 20},
                headers=headers)
        if r.status_code != 200:
            return ""
        products = r.json().get("products", [])
        # Extract versions from CPE names, filter out wildcards
        versions = []
        for p in products:
            cpe_name = p.get("cpe", {}).get("cpeName", "")
            parts = cpe_name.split(":")
            if len(parts) > 5:
                v = parts[5]
                if v and v not in ("*", "-", "") and any(c.isdigit() for c in v):
                    # Try to parse as version tuple for sorting
                    try:
                        versions.append(v)
                    except Exception:
                        pass
        if not versions:
            return ""
        # Sort versions — simple lexicographic works well for semver-ish
        def version_key(v):
            try:
                return tuple(int(x) for x in re.split(r'[.\-_]', v) if x.isdigit())
            except Exception:
                return (0,)
        versions.sort(key=version_key, reverse=True)
        # Return latest-1 (index 1 = second newest = "what you probably have")
        if len(versions) >= 2:
            return versions[1]
        elif versions:
            return versions[0]
    except Exception as e:
        print(f"[autofill] version lookup error: {e}")
    return ""

@app.get("/assets/autofill")
async def autofill_asset(name: str, user=Depends(get_current_user)):
    """
    Given a product name, return suggested vendor, type, version, cpe, and notes.
    Priority: local knowledge base → NVD CPE search.
    Version defaults to latest-1 if not known.
    """
    name_lc = name.lower().strip()

    # ── 1. Local knowledge base (instant, no API call) ──────────────────────
    kb_match = None
    # Try exact match first, then partial
    for key, val in PRODUCT_KB.items():
        if name_lc == key:
            kb_match = val
            break
    if not kb_match:
        for key, val in PRODUCT_KB.items():
            if key in name_lc or name_lc in key:
                kb_match = val
                break

    if kb_match:
        vendor, asset_type, cpe_vendor, cpe_product, notes = kb_match
        # Don't auto-suggest version — NVD CPE dict returns old versions
        # User should enter their actual installed version
        return {
            "found":      True,
            "source":     "knowledge_base",
            "vendor":     vendor,
            "asset_type": asset_type,
            "version":    "",
            "notes":      notes,
            "cpe_hint":   f"cpe:2.3:{'o' if asset_type=='os' else 'h' if asset_type in ('hardware','firmware') else 'a'}:{cpe_vendor}:{cpe_product}:*:*:*:*:*:*:*:*",
            "confidence": "high",
        }

    # ── 2. NVD CPE dictionary lookup ─────────────────────────────────────────
    try:
        headers = {"User-Agent": "ThreatFeed-CTI/1.0"}
        if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cpes/2.0",
                params={"keywordSearch": name, "resultsPerPage": 10},
                headers=headers)
        if r.status_code == 200 and r.json().get("products"):
            products = r.json()["products"]
            best = products[0]
            cpe_name = best.get("cpe", {}).get("cpeName", "")
            parts    = cpe_name.split(":")
            cpe_type  = parts[2] if len(parts) > 2 else "a"
            cpe_vendor= parts[3].replace("_"," ").title() if len(parts) > 3 else ""
            cpe_prod  = parts[4] if len(parts) > 4 else ""
            asset_type_map = {"o": "os", "h": "hardware", "a": "application"}
            asset_type = asset_type_map.get(cpe_type, "application")
            version = await get_nvd_latest_version(parts[3] if len(parts)>3 else "", cpe_prod)
            return {
                "found":      True,
                "source":     "nvd",
                "vendor":     cpe_vendor,
                "asset_type": asset_type,
                "version":    "",
                "notes":      None,
                "cpe_hint":   cpe_name,
                "confidence": "medium",
            }
    except Exception as e:
        print(f"[autofill] NVD lookup error: {e}")

    return {"found": False, "source": None, "vendor": "", "asset_type": "application",
            "version": "", "notes": None, "cpe_hint": "", "confidence": "none"}


# and would otherwise treat "cpe-search" as an asset_id path parameter.
@app.get("/assets/cpe-search")
async def cpe_search(q: str, user=Depends(get_current_user)):
    try:
        headers = {"User-Agent":"ThreatFeed-CTI/1.0"}
        if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cpes/2.0",
                            params={"keywordSearch":q,"resultsPerPage":10}, headers=headers)
        if r.status_code != 200: return {"results":[]}
        products = r.json().get("products",[])
        return {"results":[{"cpe":p.get("cpe",{}).get("cpeName",""),
                            "title":next((t["title"] for t in p.get("cpe",{}).get("titles",[]) if t.get("lang")=="en"),"")
                           } for p in products]}
    except Exception as e:
        return {"results":[],"error":str(e)}

@app.delete("/assets/{asset_id}")
def delete_asset(asset_id: str, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE assets SET active = FALSE WHERE id = %s", (asset_id,))
    conn.commit(); return {"status":"deactivated"}

@app.get("/cves")
def list_cves(asset_id: Optional[str]=None, patch_available: Optional[bool]=None,
              kev_only: bool=False, min_score: Optional[float]=None,
              user=Depends(require_full_access), conn=Depends(get_db)):
    cur   = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    query = """SELECT cf.*, a.name as asset_name, a.criticality as asset_criticality
        FROM cve_findings cf LEFT JOIN assets a ON cf.asset_id = a.id WHERE 1=1"""
    params = []
    if asset_id:             query += " AND cf.asset_id = %s";         params.append(asset_id)
    if patch_available is not None: query += " AND cf.patch_available = %s"; params.append(patch_available)
    if kev_only:             query += " AND cf.kev_listed = TRUE"
    if min_score:            query += " AND cf.cvss_score >= %s";       params.append(min_score)
    query += " ORDER BY cf.kev_listed DESC, cf.cvss_score DESC NULLS LAST, cf.created_at DESC"
    cur.execute(query, params); return cur.fetchall()

# NOTE: poll-now and stats/summary MUST be before /{cve_id} — specific routes first
@app.get("/admin/nvd-test")
async def nvd_test(q: str = "chrome", admin=Depends(require_admin)):
    """Diagnostic: test NVD API directly for a given keyword or CPE."""
    headers = {"User-Agent":"ThreatFeed-CTI/1.0"}
    if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY
    results = {}
    # Test 1: keyword search
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch":q,"resultsPerPage":5}, headers=headers)
        data = r.json() if r.status_code==200 else {}
        results["keyword"] = {
            "status": r.status_code,
            "total":  data.get("totalResults","N/A"),
            "sample": [v["cve"]["id"] for v in data.get("vulnerabilities",[])[:3]]
        }
    except Exception as e:
        results["keyword"] = {"error": str(e)}
    # Test 2: virtualMatchString with full CPE
    cpe = f"cpe:2.3:a:google:{q.lower()}:*:*:*:*:*:*:*:*"
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"virtualMatchString":cpe,"resultsPerPage":5}, headers=headers)
        data = r.json() if r.status_code==200 else {}
        results["virtualMatch_full"] = {
            "cpe": cpe, "status": r.status_code,
            "total": data.get("totalResults","N/A"),
            "sample": [v["cve"]["id"] for v in data.get("vulnerabilities",[])[:3]]
        }
    except Exception as e:
        results["virtualMatch_full"] = {"cpe": cpe, "error": str(e)}
    # Test 3: virtualMatchString with short CPE (no trailing wildcards)
    cpe_short = f"cpe:2.3:a:google:{q.lower()}"
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"virtualMatchString":cpe_short,"resultsPerPage":5}, headers=headers)
        data = r.json() if r.status_code==200 else {}
        results["virtualMatch_short"] = {
            "cpe": cpe_short, "status": r.status_code,
            "total": data.get("totalResults","N/A"),
            "sample": [v["cve"]["id"] for v in data.get("vulnerabilities",[])[:3]]
        }
    except Exception as e:
        results["virtualMatch_short"] = {"cpe": cpe_short, "error": str(e)}
    return results

@app.post("/cves/poll-now")
async def poll_now(admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM assets WHERE active = TRUE")
    assets = cur.fetchall()
    if not assets: return {"message":"No assets configured"}
    kev_catalog = await fetch_kev_catalog()
    all_new_cves=[]; all_new_iocs=[]; all_patched=[]
    for asset in assets:
        try:
            result = await poll_cves_for_asset(dict(asset), kev_catalog, conn)
            if result:
                all_new_cves.extend(result.get("new_cves",[]))
                all_new_iocs.extend(result.get("new_iocs",[]))
                all_patched.extend(result.get("patched",[]))
        except Exception as e:
            print(f"[poll-now] Error: {e}")
    if all_new_cves:
        critical = [c for c in all_new_cves if (c.get("score") or 0) >= 9 or c.get("kev")]
        create_notification(conn, "cve_new",
            f"CVE Poll: {len(all_new_cves)} new CVE(s) found",
            f"{len(all_new_cves)} new CVE(s) detected.{' ' + str(len(critical)) + ' are CRITICAL/KEV.' if critical else ''}",
            "critical" if critical else "warning", {"new_cves":all_new_cves[:10]})
    if all_patched:
        create_notification(conn, "patch_available",
            f"Patches available for {len(all_patched)} CVE(s)",
            f"Patches detected for: {', '.join(p['cve_id'] for p in all_patched)}",
            "success", {"patched":all_patched})
    conn.commit()
    return {"new_cves":len(all_new_cves),"new_iocs":len(all_new_iocs),
            "patches_detected":len(all_patched),"assets_polled":len(assets)}

@app.get("/cves/stats/summary")
def cve_summary(user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT COUNT(*) as total FROM cve_findings")
    total = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as c FROM cve_findings WHERE patch_available = FALSE OR patch_available IS NULL")
    unpatched = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM cve_findings WHERE patch_available = TRUE")
    patched = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM cve_findings WHERE kev_listed = TRUE AND (patch_available = FALSE OR patch_available IS NULL)")
    kev_unpatched = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM cve_findings WHERE cvss_score >= 9 AND (patch_available = FALSE OR patch_available IS NULL)")
    critical_unpatched = cur.fetchone()["c"]
    cur.execute("SELECT cvss_severity, COUNT(*) as count FROM cve_findings GROUP BY cvss_severity ORDER BY count DESC")
    by_severity = cur.fetchall()
    cur.execute("""SELECT a.name as asset_name, COUNT(cf.id) as cve_count,
        SUM(CASE WHEN cf.patch_available = FALSE OR cf.patch_available IS NULL THEN 1 ELSE 0 END) as unpatched
        FROM assets a LEFT JOIN cve_findings cf ON cf.asset_id = a.id
        WHERE a.active = TRUE GROUP BY a.name ORDER BY unpatched DESC""")
    by_asset = cur.fetchall()
    cur.execute("SELECT polled_at FROM cve_poll_log ORDER BY polled_at DESC LIMIT 1")
    last_poll = cur.fetchone()
    return {"total":total,"unpatched":unpatched,"patched":patched,"kev_unpatched":kev_unpatched,
            "critical_unpatched":critical_unpatched,"by_severity":by_severity,"by_asset":by_asset,
            "last_poll":last_poll["polled_at"].isoformat() if last_poll else None}

# NOTE: must stay ABOVE /cves/{cve_id}. FastAPI matches routes in registration
# order, so a path-parameter route declared first swallows every literal
# sibling — this endpoint was unreachable for that reason, answering
# "CVE not found" to every search including one with no parameters at all.
@app.get("/cves/search")
async def search_cves(
    q: str = "",
    severity: str = "",
    kev_only: bool = False,
    unpatched_only: bool = False,
    min_epss: float = 0,
    asset_id: str = "",
    year: int = 0,
    limit: int = 50,
    offset: int = 0,
    user=Depends(require_full_access),
    conn=Depends(get_db)
):
    """Full CVE search with filters — OpenCVE-parity search endpoint."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    where = ["1=1"]; params = []
    if q:
        where.append("(cf.cve_id ILIKE %s OR cf.title ILIKE %s OR cf.description ILIKE %s)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if severity:
        # Stored values are upper case ("CRITICAL", "HIGH") from the NVD poller,
        # so .capitalize() produced "Critical" and matched nothing — the severity
        # filter silently returned zero rows for every value.
        where.append("UPPER(cf.cvss_severity) = %s"); params.append(severity.upper())
    if kev_only:
        where.append("cf.kev_listed = TRUE")
    if unpatched_only:
        where.append("(cf.patch_available = FALSE OR cf.patch_available IS NULL)")
    if min_epss > 0:
        where.append("cf.epss_score >= %s"); params.append(min_epss)
    if asset_id:
        where.append("cf.asset_id = %s"); params.append(asset_id)
    if year:
        where.append("cf.published_date LIKE %s"); params.append(f"{year}%")
    query = f"""SELECT cf.*, a.name as asset_name, a.vendor as asset_vendor
        FROM cve_findings cf LEFT JOIN assets a ON cf.asset_id = a.id
        WHERE {' AND '.join(where)}
        ORDER BY cf.kev_listed DESC, cf.cvss_score DESC NULLS LAST, cf.published_date DESC
        LIMIT %s OFFSET %s"""
    params.extend([limit, offset])
    cur.execute(query, params)
    rows = cur.fetchall()
    # Total count
    cur.execute(f"SELECT COUNT(*) FROM cve_findings cf WHERE {' AND '.join(where)}", params[:-2])
    total = cur.fetchone()["count"]
    return {"cves": rows, "total": total, "limit": limit, "offset": offset}

@app.get("/cves/{cve_id}")
def get_cve(cve_id: str, user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT cf.*, a.name as asset_name FROM cve_findings cf
        LEFT JOIN assets a ON cf.asset_id = a.id WHERE cf.cve_id = %s""", (cve_id,))
    cve = cur.fetchone()
    if not cve: raise HTTPException(status_code=404, detail="CVE not found")
    cur.execute("""SELECT i.* FROM iocs i JOIN cve_ioc_links l ON i.id = l.ioc_id WHERE l.cve_id = %s""", (cve_id,))
    cve["linked_iocs"] = cur.fetchall()
    return cve

# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD + GEO
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/stats/geo")
def geo_stats(user=Depends(require_full_access), conn=Depends(get_db)):
    """Country breakdown of IP-type IOCs, for the Geo Map page.

    The frontend has always called this; it was never implemented, so the page
    sat on its loading state with a 404 in the console. There is no country
    column — geo lives inside the enrichment JSONB written by AbuseIPDB and
    VirusTotal, so read it from there. IOCs pulled in by the ThreatFox connector
    carry no geo at all, which is why coverage is partial rather than absent.
    """
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT code, COUNT(*)::int AS count FROM (
            SELECT COALESCE(
                       enrichment->'abuseipdb'->>'country',
                       enrichment->'abuseipdb'->>'countryCode',
                       enrichment->'virustotal'->>'country'
                   ) AS code
            FROM iocs
            WHERE type IN ('IPv4','IPv6')
              AND enrichment IS NOT NULL
              AND (false_positive IS NULL OR false_positive = FALSE)
        ) t
        WHERE code IS NOT NULL AND code <> '' AND LENGTH(code) = 2
        GROUP BY code
        ORDER BY count DESC, code ASC
    """)
    countries = [dict(r) for r in cur.fetchall()]

    cur.execute("""SELECT COUNT(*)::int AS c FROM iocs WHERE type IN ('IPv4','IPv6')
                   AND (false_positive IS NULL OR false_positive = FALSE)""")
    total_ips = cur.fetchone()["c"]
    located = sum(c["count"] for c in countries)

    return {
        "countries":   countries,
        "total_ips":   total_ips,
        "located":     located,
        # Surfaced so the page can be honest about coverage instead of implying
        # these few countries are the whole picture.
        "unlocated":   total_ips - located,
    }

@app.get("/stats/dashboard")
def dashboard(user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT COUNT(*) as total FROM iocs WHERE (valid_until IS NULL OR valid_until > NOW()) AND (false_positive IS NULL OR false_positive = FALSE)")
    total = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as expired FROM iocs WHERE valid_until IS NOT NULL AND valid_until <= NOW()")
    expired = cur.fetchone()["expired"]
    cur.execute("SELECT COUNT(*) as fp_count FROM iocs WHERE false_positive = TRUE")
    fp_count = cur.fetchone()["fp_count"]
    cur.execute("SELECT type, COUNT(*) as count FROM iocs GROUP BY type ORDER BY count DESC")
    by_type = cur.fetchall()
    cur.execute("SELECT industry, COUNT(*) as count FROM iocs GROUP BY industry ORDER BY count DESC")
    by_industry = cur.fetchall()
    cur.execute("SELECT tlp, COUNT(*) as count FROM iocs GROUP BY tlp ORDER BY count DESC")
    by_tlp = cur.fetchall()
    cur.execute("""SELECT CASE WHEN confidence >= 80 THEN 'High' WHEN confidence >= 50 THEN 'Medium' ELSE 'Low' END as band,
        COUNT(*) as count FROM iocs GROUP BY band ORDER BY band""")
    by_conf = cur.fetchall()
    cur.execute("""SELECT u.username, COUNT(*) as count FROM iocs i LEFT JOIN users u ON i.created_by = u.id
        GROUP BY u.username ORDER BY count DESC LIMIT 10""")
    top_contributors = cur.fetchall()
    cur.execute("SELECT c.name, COUNT(i.id) as count FROM campaigns c LEFT JOIN iocs i ON i.campaign_id = c.id GROUP BY c.name ORDER BY count DESC LIMIT 5")
    top_campaigns = cur.fetchall()
    api_usage = {}
    for api in ["virustotal","abuseipdb","urlhaus"]:
        cur.execute("SELECT COUNT(*) as calls FROM api_usage_log WHERE api_name = %s AND cache_hit = FALSE AND created_at >= CURRENT_DATE", (api,))
        api_usage[api] = cur.fetchone()["calls"]
    cur.execute("SELECT COUNT(*) as hits FROM api_usage_log WHERE cache_hit = TRUE AND created_at >= CURRENT_DATE")
    api_usage["cache_hits_today"] = cur.fetchone()["hits"]
    return {"total":total,"expired":expired,"fp_count":fp_count,"by_type":by_type,
            "by_industry":by_industry,"by_tlp":by_tlp,"by_confidence":by_conf,
            "top_contributors":top_contributors,"top_campaigns":top_campaigns,"api_usage":api_usage}

@app.get("/health")
def health():
    """Docker healthcheck endpoint."""
    return {"status": "ok", "service": "TFII"}

@app.get("/admin/health")
async def health_detailed(admin=Depends(require_admin), conn=Depends(get_db)):
    """
    Detailed system health check — admin only.
    Checks: DB, disk, memory, API keys, scheduler, last CVE poll, API quotas.
    """
    import shutil, time
    report = {"checked_at": datetime.now(timezone.utc).isoformat(), "checks": {}}
    overall_ok = True

    # ── 1. Database ──────────────────────────────────────────────────────────
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM iocs")
        ioc_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM assets WHERE active=TRUE")
        asset_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM cve_findings")
        cve_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users WHERE active=TRUE")
        user_count = cur.fetchone()[0]
        report["checks"]["database"] = {
            "ok": True, "status": "Connected",
            "iocs": ioc_count, "assets": asset_count,
            "cve_findings": cve_count, "active_users": user_count
        }
    except Exception as e:
        report["checks"]["database"] = {"ok": False, "status": f"ERROR: {e}"}
        overall_ok = False

    # ── 2. Last CVE poll ─────────────────────────────────────────────────────
    try:
        cur.execute("""SELECT polled_at, assets_polled, new_cves, patches_detected
            FROM cve_poll_log ORDER BY polled_at DESC LIMIT 1""")
        last_poll = cur.fetchone()
        if last_poll:
            polled_at, assets_polled, new_cves, patches = last_poll
            age_hours = (datetime.now(timezone.utc) - polled_at.replace(tzinfo=timezone.utc)).total_seconds() / 3600
            stale = age_hours > 8
            report["checks"]["cve_poll"] = {
                "ok": not stale,
                "last_poll": polled_at.isoformat(),
                "age_hours": round(age_hours, 1),
                "assets_polled": assets_polled,
                "new_cves": new_cves,
                "patches_detected": patches,
                "status": f"Last poll {round(age_hours,1)}h ago" + (" — STALE (>8h)" if stale else "")
            }
            if stale: overall_ok = False
        else:
            report["checks"]["cve_poll"] = {"ok": False, "status": "No poll has run yet"}
    except Exception as e:
        report["checks"]["cve_poll"] = {"ok": False, "status": f"ERROR: {e}"}

    # ── 3. Disk space ────────────────────────────────────────────────────────
    try:
        total, used, free = shutil.disk_usage("/")
        pct_used = round(used / total * 100, 1)
        low_disk = free < 1 * 1024**3  # warn if < 1GB free
        report["checks"]["disk"] = {
            "ok": not low_disk,
            "total_gb": round(total / 1024**3, 1),
            "used_gb":  round(used  / 1024**3, 1),
            "free_gb":  round(free  / 1024**3, 1),
            "used_pct": pct_used,
            "status": f"{pct_used}% used, {round(free/1024**3,1)}GB free" + (" — LOW DISK" if low_disk else "")
        }
        if low_disk: overall_ok = False
    except Exception as e:
        report["checks"]["disk"] = {"ok": False, "status": f"ERROR: {e}"}

    # ── 4. Memory ────────────────────────────────────────────────────────────
    try:
        with open("/proc/meminfo") as f:
            meminfo = {l.split(":")[0]: int(l.split()[1]) for l in f if ":" in l and "kB" in l}
        total_mb = meminfo.get("MemTotal", 0) // 1024
        free_mb  = (meminfo.get("MemAvailable", 0)) // 1024
        used_mb  = total_mb - free_mb
        pct_used = round(used_mb / total_mb * 100, 1) if total_mb else 0
        low_mem  = free_mb < 256  # warn if < 256MB available
        report["checks"]["memory"] = {
            "ok": not low_mem,
            "total_mb": total_mb, "used_mb": used_mb, "free_mb": free_mb,
            "used_pct": pct_used,
            "status": f"{pct_used}% used, {free_mb}MB available" + (" — LOW MEMORY" if low_mem else "")
        }
        if low_mem: overall_ok = False
    except Exception as e:
        report["checks"]["memory"] = {"ok": False, "status": f"ERROR: {e}"}

    # ── 5. API key status ────────────────────────────────────────────────────
    try:
        cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
        admin_row = cur.fetchone()
        quota = get_all_quota_status(conn, admin_row[0] if admin_row else "", True)
        key_summary = {}
        for svc, info in quota.items():
            has_key = info.get("has_personal_key") or bool(PLATFORM_KEYS.get(svc,""))
            key_summary[svc] = {
                "configured": has_key,
                "source": "personal" if info.get("has_personal_key") else ("env" if PLATFORM_KEYS.get(svc,"") else "none")
            }
        report["checks"]["api_keys"] = {"ok": True, "services": key_summary,
            "status": f"{sum(1 for v in key_summary.values() if v['configured'])}/{len(key_summary)} services configured"}
    except Exception as e:
        report["checks"]["api_keys"] = {"ok": False, "status": f"ERROR: {e}"}

    # ── 6. External connectivity (quick probe) ───────────────────────────────
    connectivity = {}
    probes = [
        ("NVD API", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"),
        ("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
        ("EPSS", "https://api.first.org/data/v1/epss?limit=1"),
    ]
    async def probe(name, url):
        try:
            async with httpx.AsyncClient(timeout=6) as c:
                r = await c.get(url)
            return name, r.status_code in (200, 206), f"HTTP {r.status_code}"
        except Exception as ex:
            return name, False, str(ex)[:60]

    probe_results = await asyncio.gather(*[probe(n,u) for n,u in probes], return_exceptions=True)
    for pr in probe_results:
        if isinstance(pr, tuple):
            name, ok, msg = pr
            connectivity[name] = {"ok": ok, "status": msg}
            if not ok: overall_ok = False
    report["checks"]["connectivity"] = connectivity

    # ── 7. Pending access requests ────────────────────────────────────────────
    try:
        cur.execute("SELECT COUNT(*) FROM access_requests WHERE status='pending'")
        pending = cur.fetchone()[0]
        report["checks"]["access_requests"] = {
            "ok": True, "pending": pending,
            "status": f"{pending} pending request(s)" if pending else "No pending requests"
        }
    except Exception as e:
        report["checks"]["access_requests"] = {"ok": True, "pending": 0, "status": "N/A"}

    report["overall"] = "ok" if overall_ok else "degraded"
    return report


@app.get("/audit")
def get_audit(limit: int=100, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT %s", (limit,))
    return cur.fetchall()

# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC SEARCH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/public/search")
async def public_search(q: str, conn=Depends(get_db)):
    """
    Public IOC lookup — no auth required. Enriches and returns results.
    Does NOT auto-add to the IOC feed. That must be an explicit user action.
    """
    canonical = refang(q.strip()); ioc_type = detect_type(canonical)
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT i.*, u.username as author FROM iocs i LEFT JOIN users u ON i.created_by = u.id
        WHERE i.value = %s OR i.value_defanged = %s LIMIT 1""", (canonical, q.strip()))
    existing = cur.fetchone()
    if existing:
        return {"source":"database","found_in_db":True,"auto_added":False,"ioc_type":existing["type"],
                "value":existing["value"],"value_defanged":existing.get("value_defanged"),
                "confidence":existing["confidence"],"tlp":existing["tlp"],"industry":existing["industry"],
                "description":existing["description"],"tags":existing["tags"],
                "last_updated":existing.get("enrichment",{}).get("enriched_at") if existing.get("enrichment") else None,
                "added_by":existing.get("author","unknown"),
                "created_at":existing["created_at"].isoformat() if existing.get("created_at") else None,
                "enrichment":existing.get("enrichment")}
    if ioc_type == "Unknown":
        return {"source":"providers","found_in_db":False,"auto_added":False,"ioc_type":"Unknown","value":canonical,"message":"Could not determine IOC type"}
    enrichment = await enrich(ioc_type, canonical, 50)
    score, reasons = calc_confidence(enrichment, 50)
    enrichment["calculated_confidence"] = score; enrichment["confidence_reasons"] = reasons
    verdict = "MALICIOUS" if score >= 80 else "SUSPICIOUS" if score >= 50 else "CLEAN"
    # Never auto-add to feed from public search.
    # User must explicitly add via the authenticated IOC feed interface.
    return {"source":"providers","found_in_db":False,"auto_added":False,"ioc_type":ioc_type,
            "value":canonical,"verdict":verdict,"confidence":score,"reasons":reasons,
            "enrichment":enrichment,"checked_at":now}


# ═══════════════════════════════════════════════════════════════════════════════
# OSINT
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/osint/lookup")
async def osint_lookup(body: OSINTRequest, user=Depends(get_current_user)):
    results = {"target":body.target,"type":body.target_type,"data":{}}
    try:
        if body.target_type in ("domain","ip"):
            dns_results = {}
            for record_type in ["A","MX","TXT","NS","CNAME"]:
                try:
                    async with httpx.AsyncClient(timeout=8) as c:
                        r = await c.get(f"https://dns.google/resolve?name={body.target}&type={record_type}",
                                        headers={"Accept":"application/json"})
                    if r.status_code == 200:
                        answers = r.json().get("Answer",[])
                        if answers: dns_results[record_type] = [a.get("data","") for a in answers]
                except Exception: pass
            results["data"]["dns"] = dns_results
            if body.target_type == "ip":
                try:
                    async with httpx.AsyncClient(timeout=8) as c:
                        r = await c.get(f"https://rdap.arin.net/registry/ip/{body.target}")
                    if r.status_code == 200:
                        d = r.json()
                        results["data"]["rdap"] = {"name":d.get("name","?"),"handle":d.get("handle","?"),
                            "country":d.get("country","?"),"start_address":d.get("startAddress","?"),
                            "end_address":d.get("endAddress","?"),
                            "entities":[e.get("handle","?") for e in d.get("entities",[])[:3]]}
                except Exception: pass
                if SHODAN_API_KEY:
                    try:
                        async with httpx.AsyncClient(timeout=10) as c:
                            r = await c.get(f"https://api.shodan.io/shodan/host/{body.target}?key={SHODAN_API_KEY}")
                        if r.status_code == 200:
                            d = r.json()
                            results["data"]["shodan"] = {"ports":d.get("ports",[]),"hostnames":d.get("hostnames",[]),
                                "country":d.get("country_name","?"),"org":d.get("org","?"),"isp":d.get("isp","?"),
                                "last_update":d.get("last_update","?"),"vulns":list(d.get("vulns",{}).keys())[:10]}
                    except Exception: pass
            else:
                try:
                    async with httpx.AsyncClient(timeout=8) as c:
                        r = await c.get(f"https://rdap.iana.org/domain/{body.target}")
                    if r.status_code == 200:
                        d = r.json()
                        results["data"]["rdap"] = {"name":d.get("ldhName","?"),"status":d.get("status",[]),
                            "nameservers":[ns.get("ldhName","?") for ns in d.get("nameservers",[])],
                            "registered":next((e.get("eventDate","?") for e in d.get("events",[]) if e.get("eventAction")=="registration"),"?"),
                            "last_changed":next((e.get("eventDate","?") for e in d.get("events",[]) if e.get("eventAction")=="last changed"),"?")}
                except Exception: pass
        elif body.target_type == "email":
            if HIBP_API_KEY:
                try:
                    async with httpx.AsyncClient(timeout=10) as c:
                        r = await c.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{body.target}",
                                        headers={"hibp-api-key":HIBP_API_KEY,"user-agent":"ThreatFeed-CTI/1.0"})
                    if r.status_code == 200:
                        breaches = r.json()
                        results["data"]["hibp"] = {"breached":True,"breach_count":len(breaches),
                            "breaches":[{"name":b.get("Name","?"),"date":b.get("BreachDate","?"),
                                         "data_classes":b.get("DataClasses",[])[:5]} for b in breaches[:10]]}
                    elif r.status_code == 404:
                        results["data"]["hibp"] = {"breached":False}
                except Exception as e:
                    results["data"]["hibp"] = {"error":str(e)}
            else:
                results["data"]["hibp"] = {"skipped":True}
            try:
                domain = body.target.split("@")[1] if "@" in body.target else None
                if domain:
                    async with httpx.AsyncClient(timeout=8) as c:
                        r = await c.get(f"https://dns.google/resolve?name={domain}&type=MX",
                                        headers={"Accept":"application/json"})
                    if r.status_code == 200:
                        results["data"]["email_domain_mx"] = [a.get("data","") for a in r.json().get("Answer",[])]
            except Exception: pass
    except Exception as e:
        results["error"] = str(e)
    results["queried_at"] = datetime.now(timezone.utc).isoformat()
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# REDIRECT TRACER
# ═══════════════════════════════════════════════════════════════════════════════
# Follows a link hop by hop and reports what happens at each step. The question
# behind a shortened or gateway-wrapped phishing link is "where does this
# actually land, and what does it do on the way" — one hop at a time is the only
# way to see cloaking, cookie drops and meta/JS bounces.
#
# SECURITY: this fetches attacker-supplied URLs from inside the server, which is
# textbook SSRF. Every hop is re-validated, not just the first — a redirect to
# 169.254.169.254 (cloud metadata) or 127.0.0.1:8000 (this very API) IS the
# attack, and validating only the submitted URL would miss all of it.

TRACE_UA = {
    "desktop": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "mobile":  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) "
               "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "bot":     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl":    "curl/8.4.0",
}

# Real web ports only. Without this the tracer doubles as a port scanner that
# runs from our IP and burns our reputation.
TRACE_PORTS = {80, 443, 8080, 8443}

# The lookahead pins this to a refresh meta tag without caring where the
# http-equiv attribute sits — kits reorder attributes, and requiring
# http-equiv before content silently misses half of them.
META_REFRESH_RE = re.compile(
    r"""<meta(?=[^>]*?http-equiv\s*=\s*['"]?refresh)[^>]*?url\s*=\s*['"]?([^'"\s>;]+)""",
    re.I)
JS_REDIRECT_RE = re.compile(
    r"""(?:window\s*\.)?location(?:\s*\.\s*href|\s*\.\s*replace\s*\(|\s*\.\s*assign\s*\(|\s*)\s*=?\s*['"]([^'"]{3,})['"]""",
    re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


async def _trace_guard(url: str):
    """Resolve and vet one URL. Returns (host, port, ips); raises ValueError if unsafe."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError(f"scheme '{p.scheme or 'none'}' not allowed (http/https only)")
    host = p.hostname
    if not host:
        raise ValueError("no host in URL")
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise ValueError("invalid port")
    if port not in TRACE_PORTS:
        raise ValueError(f"port {port} not allowed (80/443/8080/8443 only)")

    # An attacker controls this hostname, so resolve it ourselves and judge the
    # answer rather than trusting the name.
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM)
    except Exception as e:
        raise ValueError(f"DNS resolution failed: {e}")
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise ValueError("hostname did not resolve")
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"unparseable address {ip}")
        # is_link_local covers 169.254.0.0/16, i.e. the cloud metadata endpoint
        if (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_multicast or a.is_unspecified):
            raise ValueError(f"host resolves to non-public address {ip} — blocked (SSRF guard)")
    return host, port, ips


def _cookie_summary(resp):
    """Cookie names plus the flags that matter for tracking/session analysis."""
    out = []
    for raw in resp.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        flags = [f for f, present in (
            ("Secure", "secure" in low), ("HttpOnly", "httponly" in low),
            ("SameSite=None", "samesite=none" in low)) if present]
        out.append({"name": name[:64], "flags": flags})
    return out[:12]


class RedirectTraceRequest(BaseModel):
    url: str
    user_agent: Optional[str] = "desktop"
    max_hops: Optional[int] = 20
    follow_meta: Optional[bool] = True


@app.post("/tools/trace-redirects")
@limiter.limit("20/minute")
async def trace_redirects(request: Request, body: RedirectTraceRequest,
                          user=Depends(get_current_user)):
    # Analysts paste defanged URLs straight out of tickets and mail headers.
    raw = (body.url or "").strip()
    raw = re.sub(r"hxxp", "http", raw, flags=re.I)
    raw = raw.replace("[.]", ".").replace("[:]", ":").replace("(dot)", ".")
    if not raw:
        raise HTTPException(status_code=400, detail="No URL supplied")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "https://" + raw

    max_hops = max(1, min(int(body.max_hops or 20), 20))
    ua = TRACE_UA.get((body.user_agent or "desktop").lower(), TRACE_UA["desktop"])
    hdrs = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9"}

    hops, seen = [], []
    current, stop_reason = raw, "reached final destination"

    # Two clients: hostile hosts routinely have broken certificates, and refusing
    # to look at them would make the tool useless exactly when it matters. We try
    # strict first purely so we can *report* whether the cert was valid.
    async with httpx.AsyncClient(follow_redirects=False, timeout=12.0) as strict, \
               httpx.AsyncClient(follow_redirects=False, timeout=12.0, verify=False) as loose:

        for n in range(1, max_hops + 1):
            if current in seen:
                hops.append({"hop": n, "url": current, "error": "redirect loop — already visited",
                             "loop": True})
                stop_reason = "redirect loop detected"
                break
            seen.append(current)

            hop = {"hop": n, "url": current}
            try:
                host, port, ips = await _trace_guard(current)
                hop.update({"host": host, "port": port, "ips": ips})
            except ValueError as e:
                hop.update({"error": str(e), "blocked": True})
                hops.append(hop)
                stop_reason = "blocked by SSRF guard"
                break

            started = datetime.now(timezone.utc)
            resp, tls = None, "valid"
            for client, is_strict in ((strict, True), (loose, False)):
                try:
                    resp = await client.get(current, headers=hdrs)
                    if not is_strict:
                        tls = "invalid certificate"
                    break
                except Exception as e:
                    msg = str(e)
                    tls_problem = any(k in msg.upper() for k in ("SSL", "CERTIFICATE", "TLSV"))
                    if is_strict and tls_problem and current.lower().startswith("https"):
                        continue          # retry without verification, and say so
                    hop["error"] = f"{type(e).__name__}: {msg[:200]}"
                    break

            if resp is None:
                hops.append(hop)
                stop_reason = "request failed"
                break

            hop["elapsed_ms"] = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
            hop["status"] = resp.status_code
            hop["reason"] = resp.reason_phrase
            hop["tls"] = tls if current.lower().startswith("https") else "none (plaintext http)"
            hop["server"] = resp.headers.get("server", "")
            hop["content_type"] = resp.headers.get("content-type", "")
            hop["cookies"] = _cookie_summary(resp)

            # ── HTTP-level redirect ────────────────────────────────────────────
            loc = resp.headers.get("location")
            if 300 <= resp.status_code < 400 and loc:
                nxt = urljoin(current, loc.strip())
                hop["redirect_type"] = f"HTTP {resp.status_code}"
                hop["location"] = loc.strip()
                hop["next"] = nxt
                hops.append(hop)
                current = nxt
                continue

            # ── Body-level redirect (meta refresh / JS) ────────────────────────
            body_txt = ""
            if "text" in hop["content_type"] or "html" in hop["content_type"] or not hop["content_type"]:
                body_txt = resp.text[:200_000]

            title = TITLE_RE.search(body_txt)
            if title:
                hop["title"] = re.sub(r"\s+", " ", title.group(1)).strip()[:200]

            meta = META_REFRESH_RE.search(body_txt)
            js = JS_REDIRECT_RE.search(body_txt)

            if meta and body.follow_meta:
                nxt = urljoin(current, meta.group(1).strip().strip("'\""))
                hop["redirect_type"] = "meta refresh"
                hop["location"] = meta.group(1).strip()
                hop["next"] = nxt
                hops.append(hop)
                current = nxt
                continue

            # A JS redirect is reported but never followed — executing attacker
            # script server-side is a different and much worse problem. The
            # analyst sees the target and can trace it deliberately.
            if js:
                hop["redirect_type"] = "javascript (detected, not followed)"
                hop["location"] = js.group(1).strip()[:300]
                hop["js_only"] = True
                stop_reason = "stopped at a JavaScript redirect — not executed server-side"
            else:
                hop["redirect_type"] = "final"

            hops.append(hop)
            break
        else:
            stop_reason = f"hop limit ({max_hops}) reached"

    domains = []
    for h in hops:
        d = h.get("host")
        if d and d not in domains:
            domains.append(d)
    final = hops[-1] if hops else {}

    return {
        "start_url": raw,
        "final_url": final.get("url", raw),
        "final_status": final.get("status"),
        "hop_count": len(hops),
        "domains": domains,
        "crossed_domains": len(domains) > 1,
        "stop_reason": stop_reason,
        "hops": hops,
        "user_agent": ua,
        "traced_at": datetime.now(timezone.utc).isoformat(),
    }

# ═══════════════════════════════════════════════════════════════════════════════
# RULE-BASED PRE-FILL
# ═══════════════════════════════════════════════════════════════════════════════

MITRE_MAP = {
    "IPv4":   ["T1071 - Application Layer Protocol","T1041 - Exfiltration Over C2 Channel"],
    "IPv6":   ["T1071 - Application Layer Protocol"],
    "Domain": ["T1071.001 - Web Protocols","T1566.002 - Spearphishing Link","T1071.004 - DNS"],
    "URL":    ["T1566.002 - Spearphishing Link","T1105 - Ingress Tool Transfer"],
    "MD5":    ["T1027 - Obfuscated Files or Information","T1105 - Ingress Tool Transfer"],
    "SHA1":   ["T1027 - Obfuscated Files or Information","T1105 - Ingress Tool Transfer"],
    "SHA256": ["T1027 - Obfuscated Files or Information","T1105 - Ingress Tool Transfer"],
    "Email":  ["T1566 - Phishing","T1566.001 - Spearphishing Attachment"],
    "CVE":    ["T1190 - Exploit Public-Facing Application","T1203 - Exploitation for Client Execution"],
}
INDUSTRY_TAGS = {
    "Fintech":["banking-trojan","credential-theft","fraud"],
    "Medical":["ransomware","healthcare"],
    "Gaming":["infostealer","fake-update"],
    "Retail":["magecart","skimmer"],
    "Energy":["ics","scada","critical-infrastructure"],
    "Government":["espionage","apt","nation-state"],
    "Telecom":["sim-swap","telco"],
    "General":["malware","threat"],
}
TYPE_TAGS = {
    "IPv4":["ip","c2"],"IPv6":["ip","c2"],"Domain":["domain","infrastructure"],
    "URL":["url","phishing"],"MD5":["hash","malware"],"SHA1":["hash","malware"],
    "SHA256":["hash","malware"],"Email":["email","phishing"],"CVE":["vulnerability","exploit"],
}
DESC_MAP = {
    "IPv4":   "IPv4 address {v} associated with potentially malicious activity targeting {ind}.",
    "IPv6":   "IPv6 address {v} associated with suspicious activity targeting {ind}.",
    "Domain": "Domain {v} identified as potentially malicious infrastructure targeting {ind} organisations.",
    "URL":    "URL {v} associated with malicious activity — potential phishing or malware delivery targeting {ind}.",
    "MD5":    "File hash (MD5) {v} associated with a potentially malicious binary targeting {ind}.",
    "SHA1":   "File hash (SHA1) {v} associated with a potentially malicious binary targeting {ind}.",
    "SHA256": "File hash (SHA256) {v} associated with a potentially malicious binary targeting {ind}.",
    "Email":  "Email address {v} linked to phishing or BEC campaigns targeting {ind}.",
    "CVE":    "Vulnerability {v} being actively exploited against {ind} infrastructure.",
}

@app.post("/ai/pre-fill")
async def ai_pre_fill(body: AIEnrichRequest, user=Depends(get_current_user)):
    """Suggest TLP, tags and MITRE techniques for a new IOC.

    Despite the /ai/ path this calls NO language model — it is a lookup over
    TYPE_TAGS, INDUSTRY_TAGS and MITRE_MAP, which is why it kept answering in
    ~130ms while every real AI feature was down. Don't chase it when debugging
    an LLM outage. The path is kept for compatibility; the UI correctly labels
    this "Pre-fill" rather than anything AI.
    """
    high_risk = ["Government","Energy","Medical","Fintech"]
    tlp = "RED" if body.industry in high_risk else "AMBER"
    tags = list(set(TYPE_TAGS.get(body.ioc_type,["ioc"]) + INDUSTRY_TAGS.get(body.industry,["malware"])))[:5]
    return {"description": DESC_MAP.get(body.ioc_type,"Indicator associated with malicious activity.").format(v=body.value, ind=body.industry),
            "tags": tags, "confidence": 65, "tlp": tlp, "mitre_techniques": MITRE_MAP.get(body.ioc_type,[])[:2]}

# ═══════════════════════════════════════════════════════════════════════════════
# INTEL NEWS — RSS FEEDS
# ═══════════════════════════════════════════════════════════════════════════════

RSS_FEEDS = {
    "all":[
        ("https://www.cisa.gov/cybersecurity-advisories/all.xml","CISA","CVE","Critical"),
        ("https://feeds.feedburner.com/TheHackersNews","The Hacker News","Malware","High"),
        ("https://www.bleepingcomputer.com/feed/","BleepingComputer","Malware","High"),
        ("https://krebsonsecurity.com/feed/","Krebs on Security","Data Breach","High"),
        ("https://isc.sans.edu/rssfeed_full.xml","SANS ISC","Malware","Medium"),
    ],
    "cve":[
        ("https://www.cisa.gov/cybersecurity-advisories/all.xml","CISA","CVE","Critical"),
        ("https://isc.sans.edu/rssfeed_full.xml","SANS ISC","CVE","High"),
    ],
    "apt":[
        ("https://feeds.feedburner.com/TheHackersNews","The Hacker News","APT","High"),
        ("https://krebsonsecurity.com/feed/","Krebs on Security","APT","High"),
    ],
    "ransomware":[
        ("https://www.bleepingcomputer.com/feed/","BleepingComputer","Ransomware","Critical"),
        ("https://krebsonsecurity.com/feed/","Krebs on Security","Ransomware","Critical"),
    ],
    "ioc":[
        ("https://isc.sans.edu/rssfeed_full.xml","SANS ISC","Malware","High"),
        ("https://feeds.feedburner.com/TheHackersNews","The Hacker News","Malware","High"),
    ],
}

def parse_rss_date(date_str: str) -> str:
    if not date_str: return datetime.now().strftime("%Y-%m-%d")
    try: return parsedate_to_datetime(date_str).strftime("%Y-%m-%d")
    except Exception:
        try: return date_str[:10]
        except Exception: return datetime.now().strftime("%Y-%m-%d")

def clean_html(text: str) -> str:
    if not text: return ""
    # Unescape first so escaped markup becomes real tags and gets stripped,
    # rather than reaching the UI as literal &lt;a href=&quot;...
    text = _html.unescape(_html.unescape(text))
    text = re.sub(r'<[^>]+>',' ',text); text = re.sub(r'\s+',' ',text).strip()
    return text[:300] + ("..." if len(text)>300 else "")

async def fetch_rss(url: str, source: str, category: str, severity: str, limit: int=4) -> list:
    items = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True,
                                     headers={"User-Agent":"ThreatFeed-CTI/1.0"}) as c:
            r = await c.get(url)
        if r.status_code != 200: return []
        root = ET.fromstring(r.text)
        ns   = {"atom":"http://www.w3.org/2005/Atom"}
        entries = root.findall(".//item") or root.findall(".//atom:entry",ns)
        for entry in entries[:limit]:
            title_el = entry.find("title"); link_el = entry.find("link")
            desc_el  = entry.find("description") or entry.find("summary") or entry.find("atom:summary",ns)
            date_el  = entry.find("pubDate") or entry.find("updated") or entry.find("atom:updated",ns)
            title    = (title_el.text or "").strip() if title_el is not None else ""
            link     = (link_el.text or "").strip() if link_el is not None else ""
            if not link and link_el is not None: link = link_el.get("href","")
            summary  = clean_html((desc_el.text or "") if desc_el is not None else "")
            date_str = (date_el.text or "") if date_el is not None else ""
            if not title: continue
            items.append({"title":title,"summary":summary or f"Latest from {source}.",
                          "date":parse_rss_date(date_str),"category":category,
                          "severity":severity,"source":source,"url":link or None})
    except Exception as e:
        print(f"RSS fetch error {url}: {e}")
    return items

@app.post("/ai/intel-news")
async def intel_news(body: IntelNewsRequest, user=Depends(get_current_user)):
    feeds   = RSS_FEEDS.get(body.category, RSS_FEEDS["all"])
    tasks   = [fetch_rss(url,source,cat,sev) for url,source,cat,sev in feeds]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    items   = []; seen = set()
    for r in results:
        if isinstance(r, list): items.extend(r)
    unique = []
    for item in sorted(items, key=lambda x: x.get("date",""), reverse=True):
        if item["title"] not in seen:
            seen.add(item["title"]); unique.append(item)
    return {"items": unique[:16]}

# ── CVE WALL ─────────────────────────────────────────────────────────────────
# fetch_cve_rss swallows non-200s and returns [], so a dead feed degrades the
# wall silently. Four entries were removed on 2026-08-17 after each was
# confirmed dead; don't re-add without checking:
#   nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml    404 — NVD retired its RSS feeds
#   debian.org/security/dsa.en.rdf                 404 — file moved
#   cisa.gov/known-exploited-vulnerabilities.xml    404 — XML gone; the JSON
#     catalogue used by fetch_kev_catalog() is unaffected and still serves 200
#   cvedetails.com/rss/vulnerabilities.php         403 — now behind Cloudflare's
#     bot check, so it cannot be fetched server-side at all
# A further five were removed on the same day after being tested FROM THE SERVER
# rather than from a dev box — an important distinction, because two of them
# answer 200 elsewhere:
#   cisa.gov/cybersecurity-advisories/all.xml   403 Access Denied to this host's
#     IP specifically (200 from other networks) — not a User-Agent problem
#   redhat.com/en/rss/security-advisories       200 but an empty channel upstream,
#     682 bytes with zero items
#   support.apple.com/.../feed.rss              200 but now serves HTML
#   openwall.com/lists/oss-security/            an HTML list index, never a feed
#   packetstormsecurity.com/.../rss.xml         301 to an HTML page
# Replacements below were each confirmed live from the server with real items.
CVE_FEEDS = [
    # Vendor / distro security advisories
    ("https://ubuntu.com/security/notices/rss.xml",                       "Ubuntu",        "Advisory"),
    ("https://www.debian.org/security/dsa",                               "Debian",        "Advisory"),
    # Vulnerability research & 0day
    ("https://www.zerodayinitiative.com/rss/published/",                  "Zero Day",      "0day"),
    ("https://blog.talosintelligence.com/rss/",                           "Cisco Talos",   "Analysis"),
    ("https://blog.rapid7.com/rss/",                                      "Rapid7",        "Analysis"),
    ("https://securelist.com/feed/",                                      "Kaspersky",     "Analysis"),
]

async def fetch_cve_rss(url: str, source: str, category: str) -> dict:
    """Fetch one CVE feed. Returns {source, ok, items, error} rather than a bare
    list so the wall can report which feeds are failing. Returning [] for both
    "fetched nothing" and "feed is dead" is how four feeds stayed broken
    unnoticed until the 2026-08-17 audit."""
    try:
        # follow_redirects was missing here (fetch_rss has always had it), so a
        # feed that moved returned a bare 301 and counted as dead.
        async with httpx.AsyncClient(timeout=12, follow_redirects=True,
            headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/120.0.0.0 Safari/537.36"}) as c:
            r = await c.get(url)
        if r.status_code != 200:
            return {"source": source, "ok": False, "items": [],
                    "error": f"HTTP {r.status_code}"}
        content = r.text
        items = []
        # Extract titles and links
        titles = re.findall(r"<title><!\[CDATA\[(.*?)\]\]>|<title>(.*?)</title>", content, re.DOTALL)
        links  = re.findall(r"<link>(.*?)</link>|<link href=[\"'](.*?)[\"']", content, re.DOTALL)
        dates  = re.findall(r"<pubDate>(.*?)</pubDate>|<updated>(.*?)</updated>|<dc:date>(.*?)</dc:date>", content)
        descs  = re.findall(r"<description><!\[CDATA\[(.*?)\]\]>|<description>(.*?)</description>", content, re.DOTALL)
        for i, (t1,t2) in enumerate(titles[1:], 0):  # skip feed title
            title = (t1 or t2).strip()
            if not title or len(title) < 5: continue
            link  = links[i+1][0] or links[i+1][1] if i+1 < len(links) else ""
            link  = link.strip()
            raw_date = (dates[i][0] or dates[i][1] or dates[i][2]).strip() if i < len(dates) else ""
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(raw_date)
                date_str = dt.strftime("%Y-%m-%d")
            except Exception:
                date_str = raw_date[:10] if raw_date else ""
            desc = ""
            if i < len(descs):
                raw = (descs[i][0] or descs[i][1]).strip()
                # Decode entities BEFORE stripping tags, or escaped markup
                # survives to the UI verbatim — Debian's DSA feed ships its
                # links double-encoded and rendered as "&lt;a href=&quot;...".
                # Unescape twice to catch that second layer.
                raw = _html.unescape(_html.unescape(raw))
                desc = re.sub(r"<[^>]+>", " ", raw)
                desc = re.sub(r"\s+", " ", desc).strip()[:300]
            # Extract CVE IDs mentioned
            # Strip HTML tags and decode entities before extracting CVE IDs
            clean_title = re.sub(r"<[^>]+>", "", title)
            clean_desc  = re.sub(r"<[^>]+>", "", desc)
            # Decode common HTML entities
            for ent, ch in [("&amp;","&"),("&lt;","<"),("&gt;",">"),("&quot;",'"'),("&#39;","'"),("&nbsp;"," ")]:
                clean_title = clean_title.replace(ent, ch)
                clean_desc  = clean_desc.replace(ent, ch)
            cves_mentioned = list(set(re.findall(r"CVE-\d{4}-\d{4,}", clean_title + " " + clean_desc)))
            # Severity hint from title
            sev = "Medium"
            title_lc = title.lower()
            if any(w in title_lc for w in ["critical","remote code","rce","unauthenticated"]):
                sev = "Critical"
            elif any(w in title_lc for w in ["high","elevation","privilege","bypass"]):
                sev = "High"
            elif any(w in title_lc for w in ["low","informational","denial of service"]):
                sev = "Low"
            items.append({
                "title":         title,
                "source":        source,
                "category":      category,
                "severity":      sev,
                "date":          date_str,
                "url":           link,
                "description":   desc,
                "cves_mentioned": cves_mentioned[:5],
            })
            if len(items) >= 8: break
        # Reachable but yielding nothing is its own failure mode — a feed that
        # changed format parses to zero items while still returning 200.
        return {"source": source, "ok": bool(items), "items": items,
                "error": None if items else "reachable but no items parsed"}
    except Exception as e:
        print(f"[cve-wall] {source}: {e}")
        return {"source": source, "ok": False, "items": [],
                "error": f"{type(e).__name__}: {str(e)[:120]}"}

@app.get("/cve-wall")
async def cve_wall(category: str = "all", user=Depends(get_current_user)):
    """CVE-specific news wall: advisories, KEV, vendor patches, 0days."""
    feeds_to_use = CVE_FEEDS if category == "all" else [
        f for f in CVE_FEEDS if f[2].lower() == category.lower()
    ]
    tasks = [fetch_cve_rss(url, source, cat) for url, source, cat in feeds_to_use]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    items = []; seen = set(); feed_status = []
    for r, (_u, src, _c) in zip(results, feeds_to_use):
        if isinstance(r, Exception):
            feed_status.append({"source": src, "ok": False, "count": 0,
                                "error": f"{type(r).__name__}: {str(r)[:120]}"})
            continue
        items.extend(r["items"])
        feed_status.append({"source": r["source"], "ok": r["ok"],
                            "count": len(r["items"]), "error": r["error"]})
    unique = []
    for item in sorted(items, key=lambda x: x.get("date",""), reverse=True):
        k = item["title"][:60]
        if k not in seen:
            seen.add(k); unique.append(item)
    return {"items": unique[:40], "total": len(unique), "feeds": feed_status,
            "feeds_ok": sum(1 for f in feed_status if f["ok"]),
            "feeds_total": len(feed_status)}




# ═══════════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-SOURCE CVE LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

CVE_ID_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

async def lookup_nvd(cve_id: str, headers: dict) -> dict:
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                            headers=headers)
        if r.status_code != 200:
            return {"source":"NVD","status":"error","error":f"HTTP {r.status_code}"}
        vulns = r.json().get("vulnerabilities",[])
        if not vulns:
            return {"source":"NVD","status":"not_found"}
        cve = vulns[0].get("cve",{})
        desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
        metrics = cve.get("metrics",{})
        cvss = None
        for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            if metrics.get(key):
                m = metrics[key][0].get("cvssData",{})
                cvss = {"score": m.get("baseScore"), "severity": m.get("baseSeverity"),
                        "vector": m.get("vectorString"), "version": m.get("version")}
                break
        refs = [{"url":r.get("url",""),"tags":r.get("tags",[])}
                for r in cve.get("references",[]) if r.get("url")]
        cpes = []
        for cfg in cve.get("configurations",[]):
            for node in cfg.get("nodes",[]):
                for match in node.get("cpeMatch",[]):
                    if match.get("vulnerable") and match.get("criteria"):
                        cpes.append(match["criteria"])
        weaknesses = [w.get("description",[{}])[0].get("value","")
                      for w in cve.get("weaknesses",[]) if w.get("description")]
        return {
            "source":      "NVD",
            "status":      "ok",
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "description": desc,
            "published":   cve.get("published","")[:10],
            "modified":    cve.get("lastModified","")[:10],
            "cvss":        cvss,
            "references":  refs[:15],
            "affected_cpes": list(dict.fromkeys(cpes))[:10],
            "weaknesses":  weaknesses[:5],
            "status_nvd":  cve.get("vulnStatus",""),
        }
    except Exception as e:
        return {"source":"NVD","status":"error","error":str(e)}

async def lookup_cve_org(cve_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=12,
            headers={"User-Agent":"ThreatFeed-CTI/1.0"}) as c:
            r = await c.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
        if r.status_code == 404:
            return {"source":"CVE.org","status":"not_found"}
        if r.status_code != 200:
            return {"source":"CVE.org","status":"error","error":f"HTTP {r.status_code}"}
        data = r.json()
        cna = data.get("containers",{}).get("cna",{})
        desc = next((d.get("value","") for d in cna.get("descriptions",[]) if d.get("lang","").startswith("en")),"")
        refs = [{"url":r.get("url",""),"tags":r.get("tags",[])}
                for r in cna.get("references",[]) if r.get("url")]
        affected = []
        for a in cna.get("affected",[]):
            vendor  = a.get("vendor","")
            product = a.get("product","")
            versions= [v.get("version","") for v in a.get("versions",[])
                       if v.get("status") in ("affected","lessThan","lessThanOrEqual")]
            if vendor or product:
                affected.append(f"{vendor} {product}".strip() +
                                 (f" ({', '.join(versions[:3])})" if versions else ""))
        state = data.get("cveMetadata",{}).get("state","")
        return {
            "source":    "CVE.org",
            "status":    "ok",
            "url":       f"https://www.cve.org/CVERecord?id={cve_id}",
            "description": desc,
            "published": data.get("cveMetadata",{}).get("datePublished","")[:10],
            "state":     state,
            "references": refs[:15],
            "affected":  affected[:8],
        }
    except Exception as e:
        return {"source":"CVE.org","status":"error","error":str(e)}

async def lookup_osv(cve_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=12,
            headers={"User-Agent":"ThreatFeed-CTI/1.0"}) as c:
            r = await c.post("https://api.osv.dev/v1/query",
                             json={"cve_id": cve_id})
        if r.status_code != 200:
            return {"source":"OSV","status":"error","error":f"HTTP {r.status_code}"}
        vulns = r.json().get("vulns",[])
        if not vulns:
            return {"source":"OSV","status":"not_found"}
        items = []
        for v in vulns[:5]:
            pkgs = []
            for a in v.get("affected",[]):
                pkg = a.get("package",{})
                ecosystem = pkg.get("ecosystem","")
                name = pkg.get("name","")
                fix_versions = []
                for rng in a.get("ranges",[]):
                    for ev in rng.get("events",[]):
                        if "fixed" in ev:
                            fix_versions.append(ev["fixed"])
                pkgs.append({
                    "ecosystem": ecosystem,
                    "name":      name,
                    "fix":       fix_versions[0] if fix_versions else None,
                })
            refs = [r.get("url","") for r in v.get("references",[]) if r.get("url")]
            items.append({
                "id":       v.get("id",""),
                "summary":  v.get("summary","") or v.get("details","")[:200],
                "packages": pkgs[:6],
                "refs":     refs[:5],
                "modified": v.get("modified","")[:10],
            })
        return {
            "source":  "OSV",
            "status":  "ok",
            "url":     f"https://osv.dev/vulnerability/{cve_id}",
            "vulns":   items,
            "count":   len(vulns),
        }
    except Exception as e:
        return {"source":"OSV","status":"error","error":str(e)}

@app.get("/cve/lookup")
async def cve_multi_lookup(id: str, user=Depends(get_current_user)):
    """
    Aggregate CVE data from NVD, CVE.org, OSV, EPSS, and CISA KEV.
    Returns all sources in parallel with their references and affected packages.

    CVE Trends was dropped on 2026-08-17 — cvetrends.com is gone (its API 404s
    and the domain serves a parking page). It degraded gracefully, but it cost a
    request per lookup and showed the analyst a permanently empty source.
    """
    cve_id = id.upper().strip()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(status_code=400, detail=f"Invalid CVE ID format: {id}")

    nvd_headers = {"User-Agent":"ThreatFeed-CTI/1.0"}
    if NVD_API_KEY: nvd_headers["apiKey"] = NVD_API_KEY

    # Fetch all sources in parallel
    results = await asyncio.gather(
        lookup_nvd(cve_id, nvd_headers),
        lookup_cve_org(cve_id),
        lookup_osv(cve_id),
        return_exceptions=True
    )
    sources = [r if not isinstance(r, Exception) else {"source":"?","status":"error","error":str(r)}
               for r in results]

    # EPSS score
    epss_data = await fetch_epss([cve_id])
    epss = epss_data.get(cve_id)

    # CISA KEV check
    kev = await fetch_kev_catalog()
    in_kev = cve_id in kev
    kev_date = kev.get(cve_id,"") if in_kev else None

    # Deduplicate all references across sources
    all_refs = {}
    for s in sources:
        for ref in s.get("references",[]):
            url = ref.get("url","") if isinstance(ref,dict) else ref
            if url and url not in all_refs:
                tags = ref.get("tags",[]) if isinstance(ref,dict) else []
                src_name = s.get("source","")
                all_refs[url] = {"url":url,"tags":tags,"source":src_name}

    return {
        "cve_id":    cve_id,
        "sources":   sources,
        "epss":      epss,
        "in_kev":    in_kev,
        "kev_date":  kev_date,
        "all_refs":  list(all_refs.values())[:30],
    }


# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/cve/report")
async def cve_report(id: str, format: str = "email", user=Depends(get_current_user)):
    """
    Generate a professional CVE advisory report or email.
    Fetches CVE data, checks for PoC exploits, and uses Groq to structure output.
    format: "email" | "summary"
    """
    cve_id = id.upper().strip()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(status_code=400, detail=f"Invalid CVE ID: {id}")

    if not GROQ_API_KEY:
        raise HTTPException(status_code=503, detail="GROQ_API_KEY not configured.")

    year = cve_id.split("-")[1]
    nvd_headers = {"User-Agent":"ThreatFeed-CTI/1.0"}
    if NVD_API_KEY: nvd_headers["apiKey"] = NVD_API_KEY

    # ── Fetch data in parallel ───────────────────────────────────────────────
    async def get_nvd():
        try:
            async with httpx.AsyncClient(timeout=12) as c:
                r = await c.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                                headers=nvd_headers)
            if r.status_code == 200:
                vulns = r.json().get("vulnerabilities",[])
                if vulns: return vulns[0].get("cve",{})
        except Exception: pass
        return {}

    # ── Comprehensive PoC Search ─────────────────────────────────────────────
    # Quality tiers: verified > high > medium > low
    # verified = ExploitDB / Metasploit / Vulhub (battle-tested, curated)
    # high     = nomi-sec indexed with stars, NVD Exploit-tagged refs
    # medium   = GitHub search results with description + some stars
    # low      = GitHub repos with 0 stars / no description

    GH_HEADERS = {"User-Agent":"ThreatFeed-CTI/1.0",
                  "Accept":"application/vnd.github+json"}

    async def search_nomi_sec():
        """nomi-sec/PoC-in-GitHub — curated, auto-updated daily index."""
        try:
            url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"
            async with httpx.AsyncClient(timeout=8, headers=GH_HEADERS) as c:
                r = await c.get(url)
            if r.status_code != 200: return []
            results = []
            for e in r.json():
                stars = e.get("stargazers_count",0)
                results.append({
                    "url":         e.get("html_url",""),
                    "source":      "GitHub (nomi-sec index)",
                    "quality":     "high" if stars >= 5 else "medium",
                    "stars":       stars,
                    "description": (e.get("description") or "")[:120],
                    "author":      e.get("owner",{}).get("login",""),
                    "pushed_at":   e.get("pushed_at","")[:10],
                    "language":    e.get("language",""),
                })
            return sorted(results, key=lambda x: -x["stars"])
        except Exception: return []

    async def search_github_api():
        """
        GitHub Search API — search for repos mentioning this CVE.
        Quality-filtered: prefer repos with stars, recent activity, good description.
        Searches 3 query variants to maximize coverage.
        """
        queries = [
            f"{cve_id} poc exploit",
            f"{cve_id} proof-of-concept",
            f"{cve_id} vulnerability exploit",
        ]
        seen_urls = set()
        results   = []
        for q in queries:
            try:
                async with httpx.AsyncClient(timeout=10, headers=GH_HEADERS) as c:
                    r = await c.get("https://api.github.com/search/repositories",
                        params={"q": q, "sort":"stars","order":"desc","per_page":10})
                if r.status_code != 200: continue
                items = r.json().get("items",[])
                for repo in items:
                    url = repo.get("html_url","")
                    if not url or url in seen_urls: continue
                    # Quality filter: skip empty/clearly irrelevant repos
                    desc   = (repo.get("description") or "").lower()
                    name   = (repo.get("name") or "").lower()
                    stars  = repo.get("stargazers_count",0)
                    pushed = repo.get("pushed_at","")[:10]
                    cve_lc = cve_id.lower()
                    # Must mention the CVE in name, description, or topics
                    topics = [t.lower() for t in repo.get("topics",[])]
                    mentions_cve = (cve_lc in name or cve_lc in desc or
                                   any(cve_lc in t for t in topics))
                    if not mentions_cve: continue
                    # Skip archived repos with 0 stars
                    if repo.get("archived") and stars == 0: continue
                    qual = ("high"   if stars >= 10 else
                            "medium" if stars >= 2 or any(
                                kw in desc or kw in name
                                for kw in ["poc","exploit","proof","demo","rce","lpe"]) else
                            "low")
                    seen_urls.add(url)
                    results.append({
                        "url":         url,
                        "source":      "GitHub Search",
                        "quality":     qual,
                        "stars":       stars,
                        "description": (repo.get("description") or "")[:120],
                        "author":      repo.get("owner",{}).get("login",""),
                        "pushed_at":   pushed,
                        "language":    repo.get("language",""),
                    })
            except Exception: pass
        return sorted(results, key=lambda x: -x["stars"])

    async def search_metasploit():
        """Search Rapid7 Metasploit Framework for modules using this CVE."""
        try:
            async with httpx.AsyncClient(timeout=10, headers=GH_HEADERS) as c:
                r = await c.get("https://api.github.com/search/code",
                    params={"q": f"{cve_id} repo:rapid7/metasploit-framework",
                            "per_page": 5})
            if r.status_code != 200: return []
            items = r.json().get("items",[])
            results = []
            for item in items:
                path = item.get("path","")
                if path.endswith((".rb",".py")):
                    results.append({
                        "url":         item.get("html_url",""),
                        "source":      "Metasploit Framework",
                        "quality":     "verified",
                        "stars":       0,
                        "description": f"Metasploit module: {path.split('/')[-1]}",
                        "author":      "rapid7",
                        "pushed_at":   "",
                        "language":    "Ruby",
                    })
            return results
        except Exception: return []

    async def search_vulhub():
        """Vulhub — Docker-based PoC environments, highly reliable."""
        try:
            async with httpx.AsyncClient(timeout=10, headers=GH_HEADERS) as c:
                r = await c.get("https://api.github.com/search/code",
                    params={"q": f"{cve_id} repo:vulhub/vulhub",
                            "per_page": 3})
            if r.status_code != 200: return []
            items = r.json().get("items",[])
            results = []
            seen = set()
            for item in items:
                path = item.get("path","")
                folder = "/".join(path.split("/")[:2])
                if folder in seen: continue
                seen.add(folder)
                results.append({
                    "url":         f"https://github.com/vulhub/vulhub/tree/master/{folder}",
                    "source":      "Vulhub (Docker PoC)",
                    "quality":     "verified",
                    "stars":       0,
                    "description": f"Docker-based PoC environment: {folder}",
                    "author":      "vulhub",
                    "pushed_at":   "",
                    "language":    "Dockerfile",
                })
            return results
        except Exception: return []

    async def search_exploitdb():
        """ExploitDB — verified, manually curated exploit database."""
        try:
            cve_num = cve_id.replace("CVE-","")
            async with httpx.AsyncClient(timeout=8,
                headers={"User-Agent":"Mozilla/5.0 ThreatFeed-CTI/1.0",
                         "Accept":"application/json"}) as c:
                r = await c.get(f"https://www.exploit-db.com/search?cve={cve_num}")
            if r.status_code == 200:
                data = r.json()
                results = []
                for e in data.get("data",[])[:4]:
                    if e.get("id"):
                        results.append({
                            "url":         f"https://www.exploit-db.com/exploits/{e['id']}",
                            "source":      "ExploitDB",
                            "quality":     "verified",
                            "stars":       0,
                            "description": e.get("description","")[:120],
                            "author":      e.get("author",""),
                            "pushed_at":   e.get("date_published","")[:10],
                            "language":    e.get("platform",""),
                        })
                return results
        except Exception: pass
        return []

    async def search_nvd_refs_for_poc(nvd_data):
        """Deep scan NVD references for exploit/PoC URLs from known sources."""
        poc_domains = ["exploit-db.com","packetstormsecurity.com","github.com",
                       "metasploit.com","seebug.org","seclists.org","0day.today",
                       "vulhub.org","poc-in-github","offensive-security.com"]
        poc_tag_kw  = ["exploit","proof of concept","poc"]
        results = []
        for ref in nvd_data.get("references",[]):
            url  = ref.get("url","")
            tags = [t.lower() for t in ref.get("tags",[])]
            if not url: continue
            url_lc = url.lower()
            tag_match = any(kw in t for kw in poc_tag_kw for t in tags)
            dom_match = any(d in url_lc for d in poc_domains)
            kw_match  = any(kw in url_lc for kw in ["exploit","poc","proof","0day"])
            if tag_match or dom_match or kw_match:
                quality = ("verified" if "exploit-db.com" in url_lc or
                                         "packetstormsecurity.com" in url_lc else
                           "high"     if tag_match else "medium")
                results.append({
                    "url":         url,
                    "source":      "NVD Reference",
                    "quality":     quality,
                    "stars":       0,
                    "description": f"NVD-tagged: {', '.join(ref.get('tags',[]))}" if ref.get("tags") else "PoC/Exploit URL in NVD references",
                    "author":      "",
                    "pushed_at":   "",
                    "language":    "",
                })
        return results

    # Run all PoC sources in parallel
    nvd_data, nomi_pocs, gh_pocs, msf_pocs, vh_pocs, edb_pocs = await asyncio.gather(
        get_nvd(),
        search_nomi_sec(),
        search_github_api(),
        search_metasploit(),
        search_vulhub(),
        search_exploitdb(),
        return_exceptions=True
    )
    if isinstance(nvd_data,   Exception): nvd_data   = {}
    if isinstance(nomi_pocs,  Exception): nomi_pocs  = []
    if isinstance(gh_pocs,    Exception): gh_pocs    = []
    if isinstance(msf_pocs,   Exception): msf_pocs   = []
    if isinstance(vh_pocs,    Exception): vh_pocs    = []
    if isinstance(edb_pocs,   Exception): edb_pocs   = []

    nvd_ref_pocs = await search_nvd_refs_for_poc(nvd_data if nvd_data else {})

    # ── Merge, deduplicate, and rank all PoC results ─────────────────────────
    QUALITY_ORDER = {"verified": 0, "high": 1, "medium": 2, "low": 3}
    all_poc_raw = edb_pocs + msf_pocs + vh_pocs + nomi_pocs + gh_pocs + nvd_ref_pocs
    seen_urls   = set()
    all_pocs    = []
    for poc in all_poc_raw:
        url = poc.get("url","")
        if url and url not in seen_urls:
            seen_urls.add(url)
            all_pocs.append(poc)
    # Sort: quality tier first, then by stars desc
    all_pocs.sort(key=lambda x: (QUALITY_ORDER.get(x.get("quality","low"),3),
                                  -x.get("stars",0)))
    # Drop low-quality zero-star results if we already have better ones
    has_good = any(p["quality"] in ("verified","high") for p in all_pocs)
    if has_good:
        all_pocs = [p for p in all_pocs if p["quality"] != "low" or p.get("stars",0) > 0]

    has_poc  = len(all_pocs) > 0
    top_poc  = all_pocs[0] if all_pocs else None
    poc_links = [p["url"] for p in all_pocs[:6]]


    # ── Extract structured CVE data ──────────────────────────────────────────
    desc = next((d["value"] for d in nvd_data.get("descriptions",[])
                 if d.get("lang")=="en"), "")
    metrics  = nvd_data.get("metrics",{})
    cvss_v31 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [])[0:1]
    cvss_v2  = (metrics.get("cvssMetricV2") or [])[0:1]
    cvss_data = (cvss_v31 or cvss_v2 or [{}])[0].get("cvssData",{})
    score     = cvss_data.get("baseScore","N/A")
    severity  = cvss_data.get("baseSeverity","N/A")
    vector    = cvss_data.get("vectorString","")
    cwe_list  = [d["description"][0]["value"] for d in nvd_data.get("weaknesses",[])
                 if d.get("description")]
    cwe       = cwe_list[0] if cwe_list else "N/A"

    # Affected CPEs → products
    affected_cpes = []
    for cfg in nvd_data.get("configurations",[]):
        for node in cfg.get("nodes",[]):
            for m in node.get("cpeMatch",[]):
                if m.get("vulnerable") and m.get("criteria"):
                    affected_cpes.append(m["criteria"])

    # References: separate into patches vs general
    all_refs = nvd_data.get("references",[])
    patch_refs = [r["url"] for r in all_refs
                  if any(t in r.get("tags",[]) for t in ["Patch","Vendor Advisory"])]
    other_refs = [r["url"] for r in all_refs
                  if r["url"] not in patch_refs][:5]

    # Published / modified dates
    published = nvd_data.get("published","")[:10]
    modified  = nvd_data.get("lastModified","")[:10]

    # KEV
    kev_catalog = await fetch_kev_catalog()
    in_kev    = cve_id in kev_catalog
    kev_date  = kev_catalog.get(cve_id,"")

    # EPSS
    epss_data = await fetch_epss([cve_id])
    epss      = epss_data.get(cve_id,{})
    epss_pct  = f"{float(epss.get('epss',0))*100:.2f}%" if epss else "N/A"

    # ── Build prompt context ─────────────────────────────────────────────────
    poc_section = ""
    if has_poc:
        by_quality = {}
        for p in all_pocs[:6]:
            q = p.get("quality","medium")
            by_quality.setdefault(q,[]).append(p)
        poc_section = f"YES — {len(all_pocs)} PoC/exploit source(s) found across multiple platforms.\n\n"
        if by_quality.get("verified"):
            poc_section += "VERIFIED EXPLOITS (ExploitDB / Metasploit / Vulhub):\n"
            for p in by_quality["verified"]:
                poc_section += f"  • [{p['source']}] {p['url']} — {p.get('description','')}\n"
        if by_quality.get("high"):
            poc_section += "\nHIGH-QUALITY PoC (well-starred GitHub repos):\n"
            for p in by_quality["high"]:
                poc_section += f"  • ⭐{p.get('stars',0)} {p['url']} — {p.get('description','')}\n"
        if by_quality.get("medium"):
            poc_section += "\nADDITIONAL PoC REFERENCES:\n"
            for p in by_quality["medium"][:3]:
                poc_section += f"  • {p['url']} ({p['source']})\n"
    else:
        poc_section = "No public PoC identified across GitHub, ExploitDB, Metasploit, Vulhub, or NVD references at time of scan."

    context = f"""CVE ID: {cve_id}
Severity: {severity} (CVSS {score})
CVSS Vector: {vector}
CWE: {cwe}
Published: {published} | Modified: {modified}
EPSS (exploitation probability): {epss_pct}
CISA KEV: {"YES — Known Exploited" if in_kev else "No"}
{f"KEV Date Added: {kev_date}" if in_kev else ""}

DESCRIPTION:
{desc}

AFFECTED PRODUCTS (CPE):
{chr(10).join(affected_cpes[:10]) if affected_cpes else "See vendor advisory"}

PROOF OF CONCEPT:
{poc_section}

PATCH / VENDOR ADVISORY LINKS:
{chr(10).join(patch_refs[:5]) if patch_refs else "No official patch links found in NVD — check vendor website."}

OTHER REFERENCES:
{chr(10).join(other_refs[:5])}

NVD LINK: https://nvd.nist.gov/vuln/detail/{cve_id}
CVE.ORG LINK: https://www.cve.org/CVERecord?id={cve_id}
"""

    # ── LLM prompt based on format ───────────────────────────────────────────
    if format == "email":
        system = """You are a security operations engineer writing a professional vulnerability advisory email to IT and management stakeholders.
Write a clear, concise security advisory email based on the CVE data provided.

The email must contain exactly these sections with these headings:
Subject: (on first line, format: "Security Advisory: [CVE-ID] – [Short Vulnerability Title] – [Severity]")

Then the body starting with "Dear Team,"

Sections (use bold headings like **SECTION NAME**):
1. **Vulnerability Overview** — CVE ID, severity, CVSS score, EPSS probability, KEV status, one-sentence description
2. **Affected Products & Versions** — specific product names and version ranges from the CPE data
3. **Exploit Conditions** — what is required for a successful attack (network access, authentication, user interaction etc.) — derive from CVSS vector
4. **Proof of Concept (PoC) Availability** — Yes/No with links if available, or state none found
5. **Mitigation & Patch** — specific patch links if available; if no patch, workarounds
6. **References** — bulleted links: NVD, CVE.org, vendor advisories, PoC if present

Close with: "Please assess your environment for exposure and apply patches according to your organization's risk acceptance policy."

Be factual, professional, and direct. No fluff. Do not invent information not present in the data."""

        user_msg = f"Write a security advisory email for this CVE:\n\n{context}"

    else:  # summary
        system = """You are a threat intelligence analyst writing a structured CVE summary brief.
Format as a clean markdown report with these exact sections:

# [CVE-ID] — [Short Vulnerability Title]
**Severity:** [Critical/High/Medium/Low] (CVSS [score]) | **EPSS:** [%] | **KEV:** [Yes/No]

## Vulnerability Description
[Clear 2-3 sentence description of what the vulnerability is, its root cause, and impact]

## Affected Products & Versions
[Table or bullet list of affected products with specific version ranges]

## Exploit Conditions
| Metric | Value |
|--------|-------|
| Attack Vector | ... |
| Attack Complexity | ... |
| Privileges Required | ... |
| User Interaction | ... |
[Derive from CVSS vector, explain in plain English below the table]

## Proof of Concept (PoC)
**Available:** Yes/No
[If yes: links and brief description. If no: state no public PoC identified.]

## Mitigation
[Specific patch version to upgrade to, patch links, or workarounds if no patch]

## References
- [NVD link]
- [CVE.org link]
- [Vendor advisories]
- [PoC links if available]

Be factual. Use the provided data only. Do not invent version numbers or links."""

        user_msg = f"Write a CVE summary brief for:\n\n{context}"

    try:
        async with httpx.AsyncClient(timeout=45) as c:
            r = await c.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                         "Content-Type": "application/json"},
                json={
                    "model": GROQ_MODEL,
                    "messages": [{"role":"system","content":system},
                                 {"role":"user",  "content":user_msg}],
                    "temperature": 0.15,
                    "max_tokens": 1800,
                }
            )
        # Check the status before indexing the body. Without this an error
        # response (429 rate limit, 404 retired model) surfaced as a bare
        # KeyError — "LLM error: 'choices'" — which says nothing about the
        # actual cause and sent us looking in the wrong place.
        if r.status_code == 429:
            raise HTTPException(status_code=429,
                detail="AI rate limit reached on Groq. Wait a minute and retry.")
        if r.status_code != 200:
            raise HTTPException(status_code=502,
                detail=f"Groq API error: {r.status_code} {r.text[:180]}")
        content = r.json()["choices"][0]["message"]["content"]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM error: {type(e).__name__}: {e}")

    # Extract subject line for emails
    subject = ""
    body    = content
    if format == "email" and content.startswith("Subject:"):
        lines     = content.split("\n", 2)
        subject   = lines[0].replace("Subject:","").strip()
        body      = "\n".join(lines[1:]).strip()

    return {
        "cve_id":     cve_id,
        "format":     format,
        "subject":    subject,
        "content":    body,
        "poc": {
            "available": has_poc,
            "count":     len(all_pocs),
            "results":   all_pocs[:6],      # full rich objects
            "links":     poc_links,
            "top":       top_poc,
        },
        "severity":   severity,
        "score":      score,
    }

@app.get("/mitre/actor")
async def mitre_actor_lookup(name: str, user=Depends(get_current_user)):
    try:
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent":"ThreatFeed-CTI/1.0"}) as c:
            r = await c.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        if r.status_code != 200: return {"found":False,"error":f"MITRE CTI HTTP {r.status_code}"}
        objects = r.json().get("objects",[]); name_lc = name.lower(); actor = None
        for obj in objects:
            if obj.get("type") != "intrusion-set": continue
            obj_name = obj.get("name","").lower()
            aliases  = [a.lower() for a in obj.get("aliases",[])]
            if name_lc in obj_name or any(name_lc in a for a in aliases) or obj_name in name_lc:
                actor = obj; break
        if not actor: return {"found":False,"name":name}
        actor_id = actor["id"]; rel_target_ids = set()
        for obj in objects:
            if obj.get("type")=="relationship" and obj.get("relationship_type")=="uses" and obj.get("source_ref")==actor_id:
                rel_target_ids.add(obj.get("target_ref",""))
        techniques=[]; malware_used=[]; tools_used=[]
        for obj in objects:
            if obj["id"] in rel_target_ids:
                if obj.get("type")=="attack-pattern":
                    ext = obj.get("external_references",[])
                    tid = next((e.get("external_id","") for e in ext if e.get("source_name")=="mitre-attack"),"")
                    techniques.append(f"{tid} - {obj.get('name','')}" if tid else obj.get("name",""))
                elif obj.get("type")=="malware": malware_used.append(obj.get("name",""))
                elif obj.get("type")=="tool":    tools_used.append(obj.get("name",""))
        ext_refs  = actor.get("external_references",[])
        refs      = [e.get("url","") for e in ext_refs if e.get("url")]
        mitre_url = next((e.get("url","") for e in ext_refs if "mitre" in e.get("url","")),"")
        return {"found":True,"name":actor.get("name"),"also_known_as":actor.get("aliases",[]),
                "description":actor.get("description",""),"ttps":techniques[:20],
                "malware_used":malware_used[:10],"tools_used":tools_used[:10],
                "references":refs[:5],"mitre_url":mitre_url,"active_status":"Unknown","source":"MITRE ATT&CK"}
    except Exception as e:
        return {"found":False,"error":str(e)}

# ═══════════════════════════════════════════════════════════════════════════════
# STIX + TAXII EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

STIX_TYPE_MAP = {"ipv4-addr":"IPv4","ipv6-addr":"IPv6","domain-name":"Domain","url":"URL","email-addr":"Email"}

@app.post("/iocs/import/stix")
async def import_stix(body: STIXImport, user=Depends(require_full_access), conn=Depends(get_db)):
    objects = body.bundle.get("objects",[]); results = {"imported":0,"skipped":0,"errors":[]}
    cur = conn.cursor()
    for obj in objects:
        if obj.get("type") != "indicator": continue
        try:
            pattern = obj.get("pattern",""); ioc_type = None; value = None
            for stix_obj, tf_type in STIX_TYPE_MAP.items():
                m = re.search(rf"\[{stix_obj}:(?:value|hashes\.\S+) = '(.+?)'\]", pattern)
                if m: ioc_type = tf_type; value = m.group(1); break
            if not ioc_type:
                for hash_type, tf_type in [("MD5","MD5"),("SHA-1","SHA1"),("SHA-256","SHA256")]:
                    m = re.search(rf"hashes\.'{hash_type}' = '(.+?)'", pattern)
                    if m: ioc_type = tf_type; value = m.group(1); break
            if not ioc_type or not value: results["skipped"] += 1; continue
            canonical = refang(value); defanged = defang(canonical, ioc_type)
            base_conf = obj.get("confidence", obj.get("x_opencti_score",75))
            enrichment = await enrich(ioc_type, canonical, base_conf, conn)
            final_confidence = enrichment.get("calculated_confidence", base_conf)
            ioc_id = obj.get("id", f"indicator--{uuid.uuid4()}")
            tlp = "AMBER"
            for ref in obj.get("object_marking_refs",[]):
                for k,v in TLP_IDS.items():
                    if v == ref: tlp = k
            cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,created_by,enrichment)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING""",
                (ioc_id,ioc_type,canonical,defanged,"General",tlp,final_confidence,
                 obj.get("description",""),obj.get("labels",[]),user["id"],psycopg2.extras.Json(enrichment)))
            audit(conn,"ADD",ioc_id,canonical,ioc_type,user); results["imported"] += 1
        except Exception as e:
            results["errors"].append({"id":obj.get("id","?"),"error":str(e)}); results["skipped"] += 1
    conn.commit(); return results

@app.post("/iocs/import/taxii")
async def poll_taxii(body: TAXIIPoll, user=Depends(require_full_access), conn=Depends(get_db)):
    headers = {"Accept":"application/taxii+json;version=2.1"}
    if body.token:   headers["Authorization"] = f"Bearer {body.token}"
    if body.api_key: headers["x-api-key"] = body.api_key
    url = f"{body.server_url.rstrip('/')}/collections/{body.collection_id}/objects/?match[type]=indicator"
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(url, headers=headers)
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"TAXII server returned HTTP {r.status_code}")
    objects = r.json().get("objects",[])
    result = await import_stix(STIXImport(bundle={"objects":objects}), user=user, conn=conn)
    return {"taxii_url":url,"objects_received":len(objects),**result}

@app.post("/iocs/import/misp")
async def misp_pull(body: MISPPull, user=Depends(require_full_access), conn=Depends(get_db)):
    headers = {"Authorization":body.misp_key,"Accept":"application/json","Content-Type":"application/json"}
    url = f"{body.misp_url.rstrip('/')}/attributes/restSearch"
    payload = {"returnFormat":"json","limit":body.limit,"type":["ip-dst","ip-src","domain","url","md5","sha1","sha256"]}
    async with httpx.AsyncClient(timeout=30, verify=False) as c:
        r = await c.post(url, headers=headers, json=payload)
    if r.status_code != 200: raise HTTPException(status_code=502, detail=f"MISP returned HTTP {r.status_code}")
    attrs = r.json().get("response",{}).get("Attribute",[])
    MISP_TYPE_MAP = {"ip-dst":"IPv4","ip-src":"IPv4","domain":"Domain","url":"URL","md5":"MD5","sha1":"SHA1","sha256":"SHA256"}
    results = {"imported":0,"skipped":0,"errors":[]}; cur = conn.cursor()
    for attr in attrs:
        try:
            misp_type = attr.get("type",""); value = refang(attr.get("value","").strip())
            ioc_type = MISP_TYPE_MAP.get(misp_type)
            if not ioc_type or not value: results["skipped"] += 1; continue
            defanged = defang(value, ioc_type)
            enrichment = await enrich(ioc_type, value, 70, conn)
            final_confidence = enrichment.get("calculated_confidence", 70)
            ioc_id = f"indicator--{uuid.uuid4()}"
            cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,created_by,enrichment)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (ioc_id,ioc_type,value,defanged,"General","AMBER",final_confidence,
                 f"MISP: {attr.get('comment','')}",
                 [attr.get("category","misp")],user["id"],psycopg2.extras.Json(enrichment)))
            results["imported"] += 1
        except Exception as e:
            results["errors"].append({"error":str(e)}); results["skipped"] += 1
    conn.commit(); return results

@app.post("/iocs/import/csv")
async def import_csv(file: UploadFile = File(...), user=Depends(require_full_access), conn=Depends(get_db)):
    content = await file.read()
    reader  = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    results = {"imported":0,"skipped":0,"errors":[]}; cur = conn.cursor()
    for i, row in enumerate(reader):
        try:
            ioc_type = row.get("type","").strip(); value = refang(row.get("value","").strip())
            if not ioc_type or not value: results["skipped"] += 1; continue
            defanged = defang(value, ioc_type); base_conf = int(row.get("confidence","75") or 75)
            enrichment = await enrich(ioc_type, value, base_conf, conn)
            final_confidence = enrichment.get("calculated_confidence", base_conf)
            ioc_id = f"indicator--{uuid.uuid4()}"
            tags = [t.strip() for t in row.get("tags","").split(",") if t.strip()]
            valid_days = int(row.get("valid_days","90") or 90)
            valid_until = datetime.now(timezone.utc) + timedelta(days=valid_days)
            cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,created_by,enrichment,valid_until)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING""",
                (ioc_id,ioc_type,value,defanged,row.get("industry","General"),row.get("tlp","AMBER"),
                 final_confidence,row.get("description",""),tags,user["id"],psycopg2.extras.Json(enrichment),valid_until))
            audit(conn,"ADD",ioc_id,value,ioc_type,user); results["imported"] += 1
        except Exception as e:
            results["errors"].append({"row":i+2,"error":str(e)}); results["skipped"] += 1
    conn.commit(); return results

@app.get("/stix/bundle")
def stix_bundle(industry: Optional[str]=None, include_expired: bool=False,
                user=Depends(require_full_access), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    q = "SELECT * FROM iocs WHERE (false_positive IS NULL OR false_positive = FALSE)"; params = []
    if industry: q += " AND industry = %s"; params.append(industry)
    if not include_expired: q += " AND (valid_until IS NULL OR valid_until > NOW())"
    cur.execute(q, params); rows = cur.fetchall()
    return {"type":"bundle","id":f"bundle--{uuid.uuid4()}","spec_version":"2.1",
            "created":datetime.now(timezone.utc).isoformat(),"objects":[row_to_stix(r) for r in rows]}

@app.get("/taxii/")
def taxii_discovery(user=Depends(require_full_access)):
    return JSONResponse(content={"title":"ThreatFeed Intelligence Platform",
        "description":"Industry-vertical IOC intelligence","contact":"ti@your-domain.com",
        "default":f"{SERVER_URL}/","api_roots":[f"{SERVER_URL}/"]},
        media_type="application/taxii+json;version=2.1")

@app.get("/collections/")
def taxii_collections(user=Depends(get_current_user)):
    industries = ["Fintech","Medical","Gaming","Retail","Energy","Government","Telecom"]
    return JSONResponse(content={"collections":[{"id":f"{COLLECTION_ID[:-1]}{i}",
        "title":f"{ind} Threat Intelligence","description":f"IOC feed for the {ind} sector",
        "can_read":True,"can_write":False,"media_types":["application/stix+json;version=2.1"]}
        for i,ind in enumerate(industries)]},media_type="application/taxii+json;version=2.1")

@app.get("/collections/{collection_id}/objects/")
def taxii_objects(collection_id: str, user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM iocs WHERE (valid_until IS NULL OR valid_until > NOW()) AND (false_positive IS NULL OR false_positive = FALSE) ORDER BY created_at DESC")
    rows = cur.fetchall()
    return JSONResponse(content={"more":False,"next":None,"objects":[row_to_stix(r) for r in rows]},
        media_type="application/taxii+json;version=2.1")

# ═══════════════════════════════════════════════════════════════════════════════
# QUERY BUILDER & EXPLAINER — powered by Groq (see GROQ_MODEL)
# ═══════════════════════════════════════════════════════════════════════════════

class QueryGenRequest(BaseModel):
    use_case:    str
    query_type:  str            # "kql" | "spl"
    context:     Optional[str] = ""
    tactic_hint: Optional[str] = ""  # optional MITRE tactic hint

class QueryExplainRequest(BaseModel):
    query:      str
    query_type: str  # "kql" | "spl"

SENTINEL_TABLES = """
MICROSOFT SENTINEL / DEFENDER TABLES (use these, know their key fields):
-- Identity & Auth --
SecurityEvent           EventID,Account,Computer,LogonType,IpAddress,SubjectUserName
SigninLogs              UserPrincipalName,IPAddress,AppDisplayName,ResultType,ConditionalAccessStatus,RiskLevelDuringSignIn
AADNonInteractiveUserSignInLogs  same schema as SigninLogs
AuditLogs               OperationName,InitiatedBy,TargetResources,Result
IdentityLogonEvents     AccountName,DeviceName,Protocol,LogonType,FailureReason
IdentityQueryEvents     QueryType,QueryTarget,AccountName  (Kerberos/LDAP)
IdentityDirectoryEvents AccountName,ActionType,TargetAccountName

-- Endpoint (MDE) --
DeviceProcessEvents     DeviceName,FileName,FolderPath,ProcessCommandLine,InitiatingProcessFileName,InitiatingProcessCommandLine,AccountName,SHA256
DeviceNetworkEvents     DeviceName,RemoteIP,RemotePort,RemoteUrl,InitiatingProcessFileName,InitiatingProcessCommandLine,ActionType
DeviceFileEvents        DeviceName,FileName,FolderPath,SHA256,InitiatingProcessFileName,ActionType
DeviceRegistryEvents    DeviceName,RegistryKey,RegistryValueName,RegistryValueData,ActionType,InitiatingProcessFileName
DeviceLogonEvents       DeviceName,AccountName,LogonType,RemoteIP,Protocol,ActionType
DeviceImageLoadEvents   DeviceName,FileName,SHA256,IsSigned,IsAzureADJoined,InitiatingProcessFileName
DeviceAlertEvents       AlertId,Title,Severity,Category,MitreTechniques,DeviceName

-- Network & Cloud --
CommonSecurityLog       DeviceVendor,DeviceProduct,SourceIP,DestinationIP,DestinationPort,RequestURL,Activity,DeviceAction,BytesSent,BytesReceived
DnsEvents               Name,QueryType,QueryResults,ClientIP,Computer
AzureActivity           OperationName,Caller,CallerIpAddress,ResourceGroup,Properties,Level
AzureDiagnostics        ResourceType,OperationName,ResultType
StorageBlobLogs         OperationName,CallerIpAddress,Uri,StatusCode
KeyVaultLogs            OperationName,CallerIPAddress,ResultType,Id

-- O365 --
OfficeActivity          UserId,Operation,ClientIP,UserType,RecordType,ObjectId,Parameters
EmailEvents             NetworkMessageId,SenderFromAddress,RecipientEmailAddress,Subject,DeliveryAction,ThreatTypes
EmailUrlInfo            NetworkMessageId,Url,UrlDomain
"""

SPLUNK_SOURCETYPES = """
COMMON SPLUNK SOURCETYPES & INDEXES (use these, know their key fields):
index=windows  sourcetype=WinEventLog:Security   EventCode,Account_Name,Computer,Logon_Type,IpAddress
index=windows  sourcetype=WinEventLog:System      EventCode,ComputerName,Message
index=endpoint sourcetype=crowdstrike:events      aid,aip,CommandLine,FileName,SHA256,UserName,LocalIP
index=network  sourcetype=cisco:asa               src_ip,dest_ip,dest_port,action,bytes
index=network  sourcetype=pan:traffic             src_ip,dest_ip,dest_port,action,bytes,app
index=network  sourcetype=stream:dns              query,query_type,src_ip,answer
index=proxy    sourcetype=bluecoat:proxysg:access  cs-uri-stem,cs-host,c-ip,sc-status,cs-bytes,sc-bytes
index=o365     sourcetype=o365:management:activity Operation,UserId,ClientIP,ObjectId
index=azure    sourcetype=azure:audit             operationName,caller,callerIpAddress,resultType
index=endpoint sourcetype=sysmon                  EventCode,Image,CommandLine,ParentImage,ParentCommandLine
"""

KQL_BEST_PRACTICES = """
KQL BEST PRACTICES (follow these strictly for production quality):
1. Always use 'let' statements at the top for tunable parameters (lookback, thresholds, allowlist)
2. Filter EARLY — where clauses before join/summarize for performance
3. Use has/has_any for substring matching on indexed fields (NOT contains)
4. Use in~ for case-insensitive list lookups
5. Use startswith for prefix matching (faster than contains)
6. Comment every major section with // Description
7. Use extend to add computed fields (risk scores, enrichment)
8. Use project at the end to select only necessary columns
9. For aggregation detections: summarize → where count > threshold
10. For time-series: bin() + summarize for beaconing/periodic detection
11. Always include entity columns needed for Sentinel incidents: AccountName/UPN, DeviceName/Computer, IPAddress
12. Use tostring(), toint() for type safety on dynamic fields
13. For joins: use leftsemi/leftanti for inclusion/exclusion checks
14. Avoid cross-joins; always join on a specific key
15. For hunting: add | sort by timestamp desc | take 1000 at the end
"""

SYSTEM_PROMPT_KQL_BUILDER = f"""You are a senior detection engineer who has written production KQL queries for Fortune 500 SOC teams for 10+ years. Your queries are deployed in real Microsoft Sentinel environments. They are used by Tier 1-3 analysts and must actually work.

{SENTINEL_TABLES}
{KQL_BEST_PRACTICES}

MISSION: Write 3 KQL query variants for the described detection use case:
1. HIGH FIDELITY — Precise detection, very low false positives, may miss edge cases. Uses tight filters, specific field values, correlated with additional signals.
2. BALANCED — Good detection rate, manageable FP rate. Suitable for production scheduling.
3. THREAT HUNTING — Wide net, expect noise, designed for analyst-driven hunts. Include anomaly/statistical approaches where appropriate.

Each query MUST:
- Have let statements for all tunable parameters
- Be fully commented
- Be immediately deployable (no placeholders like YOUR_DOMAIN)
- Include realistic detection logic (not just a basic where clause)
- For HIGH FIDELITY: correlate at least 2 signals or add behavioral context
- For HUNTING: use summarize/arg_max or statistical outlier detection where relevant

RESPOND WITH VALID JSON ONLY (no markdown, no backticks around JSON):
{{
  "queries": [
    {{
      "label": "High Fidelity",
      "description": "What makes this precise",
      "query": "the full kql query as a single string with \\n for newlines",
      "severity": "High",
      "confidence": 85,
      "schedule": "Every 5 minutes, lookback 1h"
    }},
    {{
      "label": "Balanced",
      "description": "...",
      "query": "...",
      "severity": "Medium",
      "confidence": 70,
      "schedule": "Every 15 minutes, lookback 4h"
    }},
    {{
      "label": "Threat Hunting",
      "description": "...",
      "query": "...",
      "severity": "Low",
      "confidence": 50,
      "schedule": "On-demand / weekly hunt"
    }}
  ],
  "mitre": {{
    "tactic": "Credential Access",
    "technique": "T1003.001",
    "technique_name": "OS Credential Dumping: LSASS Memory",
    "url": "https://attack.mitre.org/techniques/T1003/001/"
  }},
  "required_tables": ["DeviceProcessEvents"],
  "required_connectors": ["Microsoft Defender for Endpoint"],
  "false_positives": ["Security tools like Process Monitor", "AV software performing scans"],
  "tuning_tips": ["Whitelist known security tool hashes", "Add parent process validation"],
  "performance": "Medium — DeviceProcessEvents is large; time-bound with has() filters recommended"
}}"""

SYSTEM_PROMPT_SPL_BUILDER = f"""You are a senior detection engineer who has written production Splunk SPL searches for Fortune 500 SOC teams for 10+ years. Your searches are deployed in real Splunk SIEM environments with ES (Enterprise Security) and are used by analysts who will actually run them.

{SPLUNK_SOURCETYPES}

MISSION: Write 3 SPL search variants:
1. HIGH FIDELITY — Tight filters, correlated signals, low FP. Use eval+case for risk scoring, stats for aggregation.
2. BALANCED — Good detection/FP balance. Production-ready.
3. THREAT HUNTING — Wide net. Use outlier detection, rare(), eventstats, or machine-learning SPL commands.

Each search MUST:
- Start with the most restrictive index/sourcetype filters
- Use earliest/latest time modifiers as macros or variables
- Include | eval risk_score statements for risk-based alerting
- Be commented with | `comment("...")` or inline notes
- For HIGH FIDELITY: correlate 2+ event types via subsearch or lookup
- For HUNTING: use stats/eventstats/streamstats for behavioral baselining

RESPOND WITH VALID JSON ONLY (no markdown, no backticks around JSON):
{{
  "queries": [
    {{
      "label": "High Fidelity",
      "description": "...",
      "query": "the full spl as single string with \\n",
      "severity": "High",
      "confidence": 85,
      "schedule": "Cron: */5 * * * *, Earliest: -1h"
    }},
    {{"label":"Balanced","description":"...","query":"...","severity":"Medium","confidence":70,"schedule":"*/15 * * * *, Earliest: -4h"}},
    {{"label":"Threat Hunting","description":"...","query":"...","severity":"Low","confidence":50,"schedule":"On-demand"}}
  ],
  "mitre": {{"tactic":"...","technique":"T1XXX","technique_name":"...","url":"https://attack.mitre.org/techniques/T1XXX/"}},
  "required_indexes": ["windows","endpoint"],
  "required_sourcetypes": ["WinEventLog:Security"],
  "false_positives": ["..."],
  "tuning_tips": ["..."],
  "performance": "..."
}}"""

SYSTEM_PROMPT_KQL_EXPLAIN = """You are a KQL detection query expert and security educator. Your job is to explain KQL queries to security analysts — both those who wrote the query and those seeing it for the first time.

When given a KQL or SPL query, return a structured explanation that covers:
- What threat/attack scenario this detects
- What each line/clause does in plain English
- MITRE ATT&CK mapping
- What it will catch vs. what it will miss
- Common false positive scenarios
- Specific improvement suggestions (not generic advice)

RESPOND WITH VALID JSON ONLY (no markdown, no backticks around JSON):
{
  "summary": "One sentence: what attack/behavior does this detect?",
  "threat_description": "2-3 sentences describing the threat this targets and why it matters",
  "severity": "Critical|High|Medium|Low",
  "line_by_line": [
    {"code": "let lookback = 1d;", "explanation": "Defines a 1-day lookback window. Change to 7d for weekly hunts."},
    {"code": "DeviceProcessEvents", "explanation": "Queries the MDE process creation table — logs every process launched on enrolled endpoints."},
    ...
  ],
  "mitre": {
    "tactic": "Credential Access",
    "technique": "T1003.001",
    "technique_name": "OS Credential Dumping: LSASS Memory",
    "url": "https://attack.mitre.org/techniques/T1003/001/"
  },
  "what_it_catches": [
    "Direct lsass.exe memory access via OpenProcess",
    "Task Manager dump of lsass"
  ],
  "what_it_misses": [
    "Kernel-level dumps (PPLDump, Nt* syscalls)",
    "Comsvcs.dll MiniDump technique if DLL name is renamed"
  ],
  "false_positives": [
    "SentinelOne/CrowdStrike agents access lsass legitimately",
    "Windows Defender scheduled scans"
  ],
  "improvements": [
    {"issue": "No parent process validation", "fix": "Add | where InitiatingProcessFileName !in~ ('svchost.exe','MsMpEng.exe') to reduce FPs"},
    {"issue": "Missing allowlist for known security tools", "fix": "Add let allowlisted_tools = dynamic(['MsMpEng.exe','SentinelAgent.exe']); and filter with !has_any(allowlisted_tools)"}
  ],
  "data_sources": ["DeviceProcessEvents (MDE required)"],
  "estimated_fidelity": "Medium — catches common techniques, misses advanced evasion"
}"""

async def call_groq(system: str, user: str, max_tokens: int = 2500) -> str:
    async with httpx.AsyncClient(timeout=45) as c:
        r = await c.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [{"role":"system","content":system},{"role":"user","content":user}],
                "temperature": 0.2,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
            }
        )
    # 429 is the common failure on the free tier and needs to read as a rate
    # limit, not a generic upstream fault. 404 almost always means the model
    # in GROQ_MODEL has been retired.
    if r.status_code == 429:
        raise HTTPException(status_code=429,
            detail="AI rate limit reached on Groq. Wait a minute and retry.")
    if r.status_code == 404:
        raise HTTPException(status_code=502,
            detail=f"Groq rejected model '{GROQ_MODEL}' (404). It may have been retired — "
                   f"check https://api.groq.com/openai/v1/models and set GROQ_MODEL.")
    if r.status_code != 200:
        raise HTTPException(status_code=502,
            detail=f"Groq API error: {r.status_code} {r.text[:180]}")
    return r.json()["choices"][0]["message"]["content"]

# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT ADVISORY BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

# Malware families actively targeting GCC / South Asia fintech sector
FINTECH_FAMILIES = {
    # Banking trojans / stealers
    "remcos","agentesla","agent_tesla","agent tesla",
    "formbook","form_book","form book",
    "snakekeylogger","snake_keylogger","snake keylogger",
    "asyncrat","async_rat","async rat",
    "lokibot","loki_bot","loki bot",
    "guloader","gup_loader","guloader",
    "njrat","nj_rat","nj rat",
    "dcrat","dc_rat","dc rat",
    "nanocore","nano_core","nano core",
    "warzone","warzoner",
    "redline","redline_stealer","redline stealer",
    "raccoon","raccoon_stealer","raccoon stealer",
    "vidar","vidar_stealer",
    "stealc","lumma","lummac2",
    # Banking-specific
    "qakbot","qbot","quakbot",
    "icedid","iced_id",
    "trickbot","trick_bot",
    "dridex","emotet",
    "grandoreiro","xenomorph","sova","anubis","cerberus","flubot",
    # RATs / backdoors common in GCC targeted attacks
    "cobalt_strike","cobalt strike","cobaltstrike",
    "systembc","system_bc",
    "netsupport","netsupportrat",
    "ave_maria","avemaria",
    "buer","buerloader",
    "darkcomet","dark_comet",
}

# Vendors/products that matter to most organisations — used to filter CISA KEV
COMMON_TECH_KEYWORDS = [
    # Microsoft ecosystem
    "microsoft","windows","azure","office","exchange","sharepoint","defender",
    "edge","teams","iis","ntlm","outlook","active directory","hyper-v",
    # Linux
    "linux","kernel","ubuntu","debian","red hat","rhel","centos","fedora",
    # Web servers / infrastructure
    "apache","nginx","iis","http",
    # Scripting / runtimes
    "node.js","nodejs","php","python","perl","ruby",
    # Java
    "java","openjdk","tomcat","spring","log4",
    # Databases
    "mysql","postgresql","mongodb","redis","mssql","sql server","oracle database",
    # Cloud / containers
    "kubernetes","docker","vmware","esxi","vsphere","aws","amazon","azure",
    # Security / networking
    "cisco","fortinet","palo alto","juniper","sonicwall","f5","netscaler","citrix","ivanti",
    # Browsers
    "chrome","chromium","firefox","webkit","safari",
    # CMS / productivity
    "wordpress","drupal","joomla","confluence","jira","gitlab","jenkins","git",
    # Common enterprise
    "openssl","openssh","curl","libcurl","weblogic","websphere","sharepoint",
    # Mobile / IoT
    "android","ios","iphone",
    # Vendors known for fintech-relevant flaws
    "splunk","elastic","kibana","grafana",
]

@app.get("/advisory/suggested-cves")
async def suggested_cves(limit: int = 15, days: int = 30, user=Depends(get_current_user)):
    """
    Surface the most relevant CVEs for a client advisory:
    1. Fetch CISA KEV (confirmed actively exploited) — filtered for commonly-used tech
    2. Enrich each with EPSS exploitation probability
    3. Sort by priority: KEV + EPSS score + CVSS severity
    Returns the top {limit} most actionable CVEs.
    """
    results = []

    async with httpx.AsyncClient(timeout=15) as c:
        # Pull full CISA KEV catalog
        kev_r = await c.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")

    if kev_r.status_code != 200:
        raise HTTPException(status_code=502, detail="Could not fetch CISA KEV catalog")

    vulns = kev_r.json().get("vulnerabilities", [])
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")

    # Filter: recent KEV additions + commonly-used tech
    relevant = []
    for v in vulns:
        date_added = v.get("dateAdded", "")
        vendor  = (v.get("vendorProject") or "").lower()
        product = (v.get("product") or "").lower()
        combined = f"{vendor} {product}"

        if date_added < cutoff:
            continue

        if any(kw in combined for kw in COMMON_TECH_KEYWORDS):
            relevant.append(v)

    # If fewer than limit results in the window, extend the search
    if len(relevant) < limit:
        for v in vulns:
            if v in relevant:
                continue
            vendor  = (v.get("vendorProject") or "").lower()
            product = (v.get("product") or "").lower()
            combined = f"{vendor} {product}"
            if any(kw in combined for kw in COMMON_TECH_KEYWORDS):
                relevant.append(v)
            if len(relevant) >= limit * 3:
                break

    # Sort by date added (newest first)
    relevant.sort(key=lambda x: x.get("dateAdded",""), reverse=True)

    # Enrich top candidates with EPSS
    top_candidates = relevant[:limit * 2]
    cve_ids = [v["cveID"] for v in top_candidates if v.get("cveID")]

    epss_map = {}
    if cve_ids:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                epss_r = await c.get("https://api.first.org/data/v1/epss",
                    params={"cve": ",".join(cve_ids[:50]), "limit": 100})
            if epss_r.status_code == 200:
                for item in epss_r.json().get("data", []):
                    epss_map[item["cve"]] = {
                        "epss": round(float(item.get("epss", 0)) * 100, 1),
                        "percentile": round(float(item.get("percentile", 0)) * 100, 1),
                    }
        except Exception:
            pass

    # Fetch NVD CVSS for top candidates in parallel
    async def fetch_nvd_cvss(cve_id: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                r = await c.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
            if r.status_code == 200:
                items = r.json().get("vulnerabilities", [])
                if items:
                    cve = items[0]["cve"]
                    metrics = cve.get("metrics", {})
                    cvss = (
                        metrics.get("cvssMetricV31", [{}])[0].get("cvssData") or
                        metrics.get("cvssMetricV30", [{}])[0].get("cvssData") or
                        metrics.get("cvssMetricV2", [{}])[0].get("cvssData") or {}
                    )
                    return {
                        "cvss_score": cvss.get("baseScore"),
                        "severity":   cvss.get("baseSeverity", ""),
                    }
        except Exception:
            pass
        return {}

    # Batch NVD calls (throttled — don't hammer NVD)
    nvd_map = {}
    for i in range(0, min(len(cve_ids), limit * 2), 5):
        batch = cve_ids[i:i+5]
        batch_results = await asyncio.gather(*[fetch_nvd_cvss(c) for c in batch],
                                              return_exceptions=True)
        for cve_id, res in zip(batch, batch_results):
            if not isinstance(res, Exception):
                nvd_map[cve_id] = res
        if i + 5 < len(cve_ids):
            await asyncio.sleep(0.5)  # gentle rate limit for NVD

    # Build final result list with priority scoring
    for v in top_candidates:
        cve_id  = v.get("cveID", "")
        epss    = epss_map.get(cve_id, {})
        nvd     = nvd_map.get(cve_id, {})
        severity = nvd.get("severity", "").upper()
        cvss     = nvd.get("cvss_score")

        # Priority score: EPSS percentile + severity boost
        priority = epss.get("percentile", 0)
        if severity == "CRITICAL": priority += 40
        elif severity == "HIGH":   priority += 20
        kev_days_ago = max(0, (datetime.now(timezone.utc) -
            datetime.strptime(v.get("dateAdded","2000-01-01"), "%Y-%m-%d")
            .replace(tzinfo=timezone.utc)).days) if v.get("dateAdded") else 999
        priority += max(0, 30 - kev_days_ago)  # boost for very recent KEV additions

        results.append({
            "id":              cve_id,
            "vendor":          v.get("vendorProject", ""),
            "product":         v.get("product", ""),
            "name":            v.get("vulnerabilityName", ""),
            "description":     v.get("shortDescription", ""),
            "kev_date":        v.get("dateAdded", ""),
            "due_date":        v.get("dueDate", ""),
            "ransomware":      v.get("knownRansomwareCampaignUse", "Unknown") == "Known",
            "cvss_score":      cvss,
            "severity":        severity or "UNKNOWN",
            "epss_pct":        epss.get("percentile"),
            "epss_score":      epss.get("epss"),
            "priority":        priority,
        })

    results.sort(key=lambda x: x["priority"], reverse=True)
    return results[:limit]


@app.get("/advisory/iocs")
def advisory_ioc_pool(
    family: str = "",
    ioc_type: str = "",
    sector: str = "fintech",
    limit: int = 50,
    user=Depends(get_current_user),
    conn=Depends(get_db)
):
    """
    Return IOCs from connector feeds suitable for a client advisory.
    Defaults to fintech-relevant malware families for GCC/South Asia.
    """
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if sector == "fintech" and not family:
        # Build a filter for known fintech-targeting families
        family_conditions = []
        params = []
        for fam in FINTECH_FAMILIES:
            family_conditions.append("EXISTS (SELECT 1 FROM unnest(tags) t WHERE t ILIKE %s)")
            params.append(f"%{fam}%")
        fintech_filter = f"AND ({' OR '.join(family_conditions)})" if family_conditions else ""
        # Also include 'fintech' tagged items
        query = f"""
            SELECT id,type,value,value_defanged,confidence,tlp,tags,enrichment,created_at
            FROM iocs
            WHERE ('connector'=ANY(tags) OR 'threatfox'=ANY(tags) OR 'malwarebazaar'=ANY(tags))
            {'AND verdict != false_positive' if False else ''}
            AND (false_positive IS NULL OR false_positive = FALSE)
            {fintech_filter}
            ORDER BY created_at DESC LIMIT %s
        """
        cur.execute(query, params + [limit])
    else:
        fam_filter = ""
        params = []
        if family:
            fam_filter = "AND EXISTS (SELECT 1 FROM unnest(tags) t WHERE t ILIKE %s)"
            params.append(f"%{family}%")
        type_filter = "AND type = %s" if ioc_type else ""
        if ioc_type: params.append(ioc_type)
        cur.execute(f"""
            SELECT id,type,value,value_defanged,confidence,tlp,tags,enrichment,created_at
            FROM iocs
            WHERE ('connector'=ANY(tags) OR 'threatfox'=ANY(tags) OR 'malwarebazaar'=ANY(tags))
            AND (false_positive IS NULL OR false_positive = FALSE)
            {fam_filter} {type_filter}
            ORDER BY confidence DESC, created_at DESC LIMIT %s
        """, params + [limit])

    rows = cur.fetchall()
    result = []
    for r in rows:
        enr = r.get("enrichment") or {}
        malware_family = (enr.get("malware_family") or "")
        # extract the most relevant tag for display
        tags = r.get("tags") or []
        family_tag = malware_family or next(
            (t for t in tags if t not in ("connector","threatfox","malwarebazaar","urlhaus","malware-hash","malware-url")), ""
        )
        result.append({
            "id":           r["id"],
            "type":         r["type"],
            "value":        r.get("value_defanged") or r["value"],
            "value_raw":    r["value"],
            "confidence":   r["confidence"],
            "tlp":          r["tlp"],
            "family":       family_tag,
            "tags":         tags,
            "source":       "ThreatFox" if "threatfox" in tags else "MalwareBazaar" if "malwarebazaar" in tags else "URLhaus" if "urlhaus" in tags else "Feed",
        })
    return result

class AdvisoryRequest(BaseModel):
    ioc_ids:     List[str]
    cve_ids:     List[str]
    client_name: str
    analyst_name: Optional[str] = "TFII Analyst"
    sector:      Optional[str] = "Financial Services / Fintech"
    tlp:         Optional[str] = "AMBER"
    custom_note: Optional[str] = ""

@app.post("/advisory/generate")
async def generate_advisory(body: AdvisoryRequest, user=Depends(get_current_user), conn=Depends(get_db)):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=503, detail="GROQ_API_KEY not configured.")
    if not body.ioc_ids and not body.cve_ids:
        raise HTTPException(status_code=400, detail="Select at least one IOC or CVE.")

    # ── Fetch selected IOCs ───────────────────────────────────────────────────
    iocs = []
    if body.ioc_ids:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM iocs WHERE id = ANY(%s)", (body.ioc_ids,))
        for r in cur.fetchall():
            enr = r.get("enrichment") or {}
            iocs.append({
                "type":     r["type"],
                "value":    r.get("value_defanged") or r["value"],
                "family":   enr.get("malware_family") or next(
                    (t for t in (r.get("tags") or []) if t not in ("connector","threatfox","malwarebazaar")), "Unknown"),
                "confidence": r["confidence"],
                "source":   "ThreatFox" if "threatfox" in (r.get("tags") or []) else
                            "MalwareBazaar" if "malwarebazaar" in (r.get("tags") or []) else "URLhaus",
            })

    # ── Fetch selected CVEs ───────────────────────────────────────────────────
    cves = []
    for cve_id in body.cve_ids[:3]:
        try:
            async with httpx.AsyncClient(timeout=12) as c:
                r = await c.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}")
            if r.status_code == 200:
                items = r.json().get("vulnerabilities", [])
                if items:
                    vuln = items[0]["cve"]
                    desc = next(
                        (d["value"] for d in vuln.get("descriptions",[]) if d["lang"]=="en"), "")
                    metrics = vuln.get("metrics",{})
                    cvss_data = (
                        metrics.get("cvssMetricV31",[{}])[0].get("cvssData") or
                        metrics.get("cvssMetricV30",[{}])[0].get("cvssData") or
                        metrics.get("cvssMetricV2",[{}])[0].get("cvssData") or {}
                    )
                    cves.append({
                        "id": cve_id.upper(),
                        "description": desc[:600],
                        "cvss_score": cvss_data.get("baseScore","N/A"),
                        "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                        "vector": cvss_data.get("vectorString",""),
                    })
        except Exception:
            cves.append({"id": cve_id.upper(), "description": "Could not fetch details.", "cvss_score":"N/A","severity":"UNKNOWN","vector":""})

    today = datetime.now(timezone.utc).strftime("%d %B %Y")

    system_prompt = """You are a senior threat intelligence analyst writing a formal advisory for a fintech client.
Generate a professional HTML email advisory. Return ONLY valid JSON with this exact structure:
{"subject": "...", "html": "...", "plain_text": "..."}

The HTML must:
- Use inline CSS only (email client compatible — Outlook, Gmail)
- Dark navy/professional colour scheme (#0f2744 header, #ffffff body)
- Include a TLP classification banner at the top
- Have clearly structured sections with subtle dividers
- Be formatted for a C-suite or security team audience
- Not include any placeholder text — everything must be fully written

Never say "I generated this" or reference AI."""

    ioc_block = "\n".join([
        f"- {i['type']}: {i['value']} | Family: {i['family']} | Confidence: {i['confidence']}% | Source: {i['source']}"
        for i in iocs
    ]) or "None selected"

    cve_block = "\n".join([
        f"- {c['id']} | CVSS {c['cvss_score']} ({c['severity']}) | {c['description'][:300]}"
        for c in cves
    ]) or "None selected"

    user_msg = f"""Generate a threat advisory email with these details:

Date: {today}
Client: {body.client_name}
Sector: {body.sector}
TLP: TLP:{body.tlp}
Analyst: {body.analyst_name}
{"Additional context: " + body.custom_note if body.custom_note else ""}

ACTIVE THREAT INDICATORS ({len(iocs)} IOCs):
{ioc_block}

CVE ADVISORIES ({len(cves)} CVEs):
{cve_block}

Structure:
1. TLP:{body.tlp} banner (coloured — RED=#dc2626, AMBER=#d97706, GREEN=#16a34a, WHITE=#374151)
2. Header: "Threat Intelligence Advisory — {body.client_name}" with date
3. Executive Summary (2-3 sentences — threat landscape context for fintech/GCC sector)
4. Section: "Active Threat Indicators" — HTML table with columns: Type, Indicator (defanged), Malware Family, Source, Confidence
5. Section: "Vulnerability Advisories" — for each CVE: ID badge, severity, description, recommended action
6. Section: "Recommended Actions" — 4-5 specific, actionable steps relevant to these specific threats
7. Footer: Analyst name, date, TLP reminder, "This advisory is for authorised recipients only"

Return as JSON: {{"subject": "TLP:{body.tlp} // Threat Advisory — {body.client_name} // {today}", "html": "<full html>", "plain_text": "<plain text version>"}}"""

    try:
        raw = await call_groq(system_prompt, user_msg, max_tokens=4000)
        import json as _j
        # strip markdown fences if present
        clean = raw.strip()
        if clean.startswith("```"): clean = re.sub(r"^```[a-z]*\n?","",clean).rstrip("`").strip()
        data = _j.loads(clean)
        return {
            "subject":    data.get("subject",""),
            "html":       data.get("html",""),
            "plain_text": data.get("plain_text",""),
            "iocs":       iocs,
            "cves":       cves,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Advisory generation failed: {e}")


    async with httpx.AsyncClient(timeout=45) as c:
        r = await c.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [{"role":"system","content":system},{"role":"user","content":user}],
                "temperature": 0.2,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
            }
        )
    # 429 is the common failure on the free tier and needs to read as a rate
    # limit, not a generic upstream fault. 404 almost always means the model
    # in GROQ_MODEL has been retired.
    if r.status_code == 429:
        raise HTTPException(status_code=429,
            detail="AI rate limit reached on Groq. Wait a minute and retry.")
    if r.status_code == 404:
        raise HTTPException(status_code=502,
            detail=f"Groq rejected model '{GROQ_MODEL}' (404). It may have been retired — "
                   f"check https://api.groq.com/openai/v1/models and set GROQ_MODEL.")
    if r.status_code != 200:
        raise HTTPException(status_code=502,
            detail=f"Groq API error: {r.status_code} {r.text[:180]}")
    return r.json()["choices"][0]["message"]["content"]

@app.post("/query-gen/generate")
async def generate_query(body: QueryGenRequest, user=Depends(get_current_user)):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=503, detail="GROQ_API_KEY not configured. Add it to .env and restart.")

    system = SYSTEM_PROMPT_KQL_BUILDER if body.query_type == "kql" else SYSTEM_PROMPT_SPL_BUILDER
    user_msg = body.use_case
    if body.tactic_hint:
        user_msg += f"\n\nMITRE Tactic hint: {body.tactic_hint}"
    if body.context:
        user_msg += f"\n\nEnvironment context: {body.context}"

    try:
        raw = await call_groq(system, user_msg, max_tokens=3000)
        import json as _json
        data = _json.loads(raw)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse response: {str(e)}")

@app.post("/query-gen/explain")
async def explain_query(body: QueryExplainRequest, user=Depends(get_current_user)):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=503, detail="GROQ_API_KEY not configured. Add it to .env and restart.")

    user_msg = f"Explain this {'KQL' if body.query_type == 'kql' else 'SPL'} query:\n\n{body.query}"
    try:
        raw = await call_groq(SYSTEM_PROMPT_KQL_EXPLAIN, user_msg, max_tokens=2500)
        import json as _json
        return _json.loads(raw)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse response: {str(e)}")

# ═══════════════════════════════════════════════════════════════════════════════
# FILE STORE
# ═══════════════════════════════════════════════════════════════════════════════
# Restricted to the single named owner account (see require_root_admin), not to
# the admin role generally.
#
# The dangerous part of any file store is serving what was uploaded. This API and
# the UI share an origin and the session JWT lives in localStorage, so an
# uploaded .html or .svg served inline would run in the app's origin and could
# read that token. Every download — public or authenticated — is therefore forced
# to application/octet-stream + Content-Disposition: attachment + nosniff. The
# browser never renders these files, so an uploaded page cannot become stored XSS.
#
# Files land on disk under a generated UUID and the original name is kept only as
# a database column, which makes path traversal via the filename impossible
# rather than merely filtered.

UPLOAD_DIR      = os.path.abspath(os.getenv("UPLOAD_DIR", "uploads"))
MAX_FILE_BYTES  = int(os.getenv("MAX_FILE_MB", "100")) * 1024 * 1024
MAX_TOTAL_BYTES = int(os.getenv("MAX_STORE_GB", "5")) * 1024 * 1024 * 1024
CHUNK           = 1024 * 1024


def _safe_display_name(name: str) -> str:
    """Keep a human-readable name that is safe in a header and on a listing."""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\r\n\t\x00-\x1f\x7f]", "", name).strip()
    name = name.lstrip(".") or "unnamed"
    return name[:200]


def _content_disposition(filename: str) -> str:
    # RFC 5987. ASCII fallback plus a UTF-8 form so non-Latin names survive.
    from urllib.parse import quote
    ascii_name = re.sub(r'[^\x20-\x7e]', "_", filename).replace('"', "'")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"


DOWNLOAD_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Cache-Control": "private, no-store",
}


def _store_usage(cur) -> int:
    cur.execute("SELECT COALESCE(SUM(size_bytes),0) AS total FROM stored_files")
    row = cur.fetchone()
    return int(row["total"] if isinstance(row, dict) else row[0])


class FileUpdate(BaseModel):
    filename: Optional[str] = None
    shared: Optional[bool] = None


@app.post("/files/upload")
@limiter.limit("30/hour")
async def upload_file(request: Request, file: UploadFile = File(...),
                      user=Depends(require_root_admin), conn=Depends(get_db)):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    used = _store_usage(cur)
    if used >= MAX_TOTAL_BYTES:
        raise HTTPException(status_code=507,
            detail=f"Store full ({used // (1024*1024)}MB used of "
                   f"{MAX_TOTAL_BYTES // (1024*1024*1024)}GB).")

    display = _safe_display_name(file.filename)
    stored_name = uuid.uuid4().hex
    dest = os.path.join(UPLOAD_DIR, stored_name)

    # Stream to disk. Content-Length is attacker-controlled and this host has
    # under 1GB of RAM, so the limit is enforced as bytes actually arrive and
    # nothing is buffered whole.
    sha = hashlib.sha256()
    size = 0
    try:
        with open(dest, "wb") as out:
            while True:
                chunk = await file.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise HTTPException(status_code=413,
                        detail=f"File exceeds {MAX_FILE_BYTES // (1024*1024)}MB limit")
                if used + size > MAX_TOTAL_BYTES:
                    raise HTTPException(status_code=507, detail="Upload would exceed store quota")
                sha.update(chunk)
                out.write(chunk)
    except HTTPException:
        if os.path.exists(dest):
            os.remove(dest)
        raise
    except Exception as e:
        if os.path.exists(dest):
            os.remove(dest)
        raise HTTPException(status_code=500, detail=f"Upload failed: {e}")

    if size == 0:
        os.remove(dest)
        raise HTTPException(status_code=400, detail="Empty file")

    fid = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO stored_files (id, filename, stored_name, size_bytes,
               content_type, sha256, uploaded_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
        (fid, display, stored_name, size, file.content_type or "application/octet-stream",
         sha.hexdigest(), user["username"]))
    row = cur.fetchone()
    conn.commit()
    return dict(row)


@app.get("/files")
async def list_files(user=Depends(require_root_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM stored_files ORDER BY created_at DESC")
    files = [dict(r) for r in cur.fetchall()]
    return {
        "files": files,
        "used_bytes": _store_usage(cur),
        "quota_bytes": MAX_TOTAL_BYTES,
        "max_file_bytes": MAX_FILE_BYTES,
    }


@app.patch("/files/{file_id}")
async def update_file(file_id: str, body: FileUpdate,
                      user=Depends(require_root_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM stored_files WHERE id = %s", (file_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="File not found")

    if body.filename is not None:
        new_name = _safe_display_name(body.filename)
        if not new_name:
            raise HTTPException(status_code=400, detail="Invalid filename")
        cur.execute("UPDATE stored_files SET filename = %s WHERE id = %s", (new_name, file_id))

    if body.shared is not None:
        # Revoking and re-sharing mints a fresh token, so an old link that leaked
        # stays dead rather than springing back to life.
        token = secrets.token_urlsafe(24) if body.shared else None
        cur.execute("UPDATE stored_files SET share_token = %s WHERE id = %s", (token, file_id))

    cur.execute("SELECT * FROM stored_files WHERE id = %s", (file_id,))
    out = dict(cur.fetchone())
    conn.commit()
    return out


@app.delete("/files/{file_id}")
async def delete_file(file_id: str, user=Depends(require_root_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM stored_files WHERE id = %s", (file_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="File not found")

    path = os.path.join(UPLOAD_DIR, row["stored_name"])
    # Remove the row regardless — a missing blob should not leave an
    # undeletable ghost entry in the listing.
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass
    cur.execute("DELETE FROM stored_files WHERE id = %s", (file_id,))
    conn.commit()
    return {"deleted": file_id}


def _serve(row):
    path = os.path.join(UPLOAD_DIR, row["stored_name"])
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File data missing on disk")
    headers = dict(DOWNLOAD_HEADERS)
    headers["Content-Disposition"] = _content_disposition(row["filename"])
    # Always octet-stream: never hand the browser a type it would render.
    return FileResponse(path, media_type="application/octet-stream", headers=headers)


@app.get("/files/{file_id}/download")
async def download_file(file_id: str, user=Depends(require_root_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM stored_files WHERE id = %s", (file_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    return _serve(row)


@app.get("/f/{token}")
@limiter.limit("120/minute")
async def public_download(request: Request, token: str, conn=Depends(get_db)):
    """Unauthenticated download of an explicitly shared file."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # Length check first so this cannot be used to probe with trivial tokens.
    if not token or len(token) < 20:
        raise HTTPException(status_code=404, detail="Not found")
    cur.execute("SELECT * FROM stored_files WHERE share_token = %s", (token,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    cur.execute("UPDATE stored_files SET download_count = download_count + 1 WHERE id = %s",
                (row["id"],))
    conn.commit()
    return _serve(row)


# ═══════════════════════════════════════════════════════════════════════════════
# DIFF EXPLANATION
# ═══════════════════════════════════════════════════════════════════════════════
# The diff checker itself is entirely client-side. This endpoint is opt-in: it
# only runs when the analyst presses the button, because using it means the diff
# leaves the browser and goes to Groq. The client sends a context-limited diff
# rather than both documents in full, so unchanged bulk never leaves the machine.

SYSTEM_PROMPT_DIFF_EXPLAIN = """You are a security analyst reviewing a change between two versions of a file. The audience is a threat intelligence analyst who wants to know what changed and whether it matters — not a line-by-line restatement of the diff they are already looking at.

The content could be anything: detection rules (Suricata/Sigma/YARA), IOC lists, firewall or server configuration, a phishing kit's source, an advisory draft, or ordinary prose. Work out what it is from the content and adapt.

Prioritise, in this order:
1. Changes with a security consequence — a controls weakened, authentication or TLS altered, a rule's scope narrowed so it now misses things, an IOC added or removed, a new outbound destination, a widened CIDR, a raised timeout, a disabled check.
2. Changes in behaviour that are not obviously security related but alter what the system does.
3. Cosmetic changes — grouped and summarised in one line, never enumerated.

Be specific and concrete. "The C2 IP changed from 185.220.101.45 to 185.220.101.99, so any blocklist built from the old value is now stale" is useful. "An IP address was modified" is not. Reference actual values from the diff.

If a change looks risky, say so plainly. If the change set is benign, say that too — do not manufacture concern. If the content is truncated or you cannot determine intent, say so rather than guessing.

RESPOND WITH VALID JSON ONLY (no markdown, no backticks around JSON):
{
  "summary": "2-3 sentences: what changed overall and the practical effect. Plain English.",
  "content_type": "What this file appears to be, e.g. 'Suricata IDS rules' or 'nginx configuration'",
  "risk": "none|low|medium|high",
  "risk_reason": "One sentence justifying the risk level. If 'none', say why the changes are safe.",
  "changes": [
    {
      "what": "Concrete description citing real values from the diff",
      "impact": "Why it matters operationally, or 'No functional impact' when cosmetic",
      "severity": "info|low|medium|high"
    }
  ],
  "watch_for": [
    "Specific follow-up actions, e.g. 'Update blocklists still referencing 185.220.101.45'"
  ]
}

Keep "changes" to the 8 most significant entries. Leave "watch_for" as an empty array when there is genuinely nothing to follow up."""


class DiffExplainRequest(BaseModel):
    diff: str
    context: Optional[str] = ""
    stats: Optional[str] = ""


@app.post("/diff/explain")
@limiter.limit("15/minute")
async def explain_diff(request: Request, body: DiffExplainRequest,
                       user=Depends(get_current_user)):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=503,
            detail="GROQ_API_KEY not configured. Add it in Settings → API Keys.")

    diff = (body.diff or "").strip()
    if not diff:
        raise HTTPException(status_code=400, detail="No diff supplied")
    if diff.count("\n") < 1 and len(diff) < 8:
        raise HTTPException(status_code=400, detail="Diff too small to explain")

    # Hard cap regardless of what the client sent. Groq has a context limit and
    # an analyst pasting a 5MB log should get a truncation notice, not a 502.
    MAX = 48_000
    truncated = len(diff) > MAX
    if truncated:
        diff = diff[:MAX]

    user_msg = ""
    if body.context:
        user_msg += f"Analyst-supplied context: {body.context[:500]}\n\n"
    if body.stats:
        user_msg += f"Change counts: {body.stats[:200]}\n\n"
    if truncated:
        user_msg += ("NOTE: this diff was truncated at 48000 characters. Say so in your "
                     "summary and scope your conclusions to what you can see.\n\n")
    user_msg += f"Unified diff (- removed, + added):\n\n{diff}"

    try:
        raw = await call_groq(SYSTEM_PROMPT_DIFF_EXPLAIN, user_msg, max_tokens=2500)
        import json as _json
        data = _json.loads(raw)
        data["truncated"] = truncated
        return data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse response: {str(e)}")

