import os, uuid, httpx, asyncio, base64, csv, io, re, json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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
    services = ["virustotal","abuseipdb","shodan","hibp","groq","nvd"]
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

def detect_type(val: str) -> str:
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val): return "IPv4"
    if re.match(r'^[0-9a-fA-F]{32}$', val): return "MD5"
    if re.match(r'^[0-9a-fA-F]{40}$', val): return "SHA1"
    if re.match(r'^[0-9a-fA-F]{64}$', val): return "SHA256"
    if re.match(r'^https?://', val, re.IGNORECASE): return "URL"
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', val): return "Domain"
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', val): return "Email"
    if re.match(r'^CVE-\d{4}-\d+$', val, re.IGNORECASE): return "CVE"
    return "Unknown"

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
            active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW())""",
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
        scheduler = AsyncIOScheduler()
        scheduler.add_job(scheduled_cve_poll, IntervalTrigger(hours=6),
                          id="cve_poll", replace_existing=True, misfire_grace_time=300)
        scheduler.start()
        print("[scheduler] CVE poll scheduled every 6 hours")
    except ImportError:
        print("[scheduler] apscheduler not installed — run: pip install apscheduler")

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
    username: str; password: str; invite_code: str

class PasswordChange(BaseModel):
    current_password: str; new_password: str

class InviteCreate(BaseModel):
    role: Optional[str] = "analyst"

class CampaignIn(BaseModel):
    name: str; description: Optional[str] = ""
    threat_actor: Optional[str] = ""; industry_targets: Optional[List[str]] = []

class NoteIn(BaseModel):
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
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey":k})
    if r.status_code == 404: return {"source":"VirusTotal","found":False,"vt_score":0}
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

async def urlhaus_url_lookup(url_val, conn=None, user_id: str = None):
    if conn: log_api_call(conn,"urlhaus",url_val,False,user_id)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url":url_val})
    if r.status_code != 200: return {"source":"URLhaus","error":f"HTTP {r.status_code}"}
    d = r.json()
    if d.get("query_status") == "no_results": return {"source":"URLhaus","found":False}
    return {"source":"URLhaus","found":True,"threat":d.get("threat","?"),
            "url_status":d.get("url_status","?"),"link":d.get("urlhaus_reference","")}

async def urlhaus_host_lookup(domain, conn=None, user_id: str = None):
    if conn: log_api_call(conn,"urlhaus",domain,False,user_id)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host":domain})
    if r.status_code != 200: return {"source":"URLhaus","error":f"HTTP {r.status_code}"}
    d = r.json()
    if d.get("query_status") == "no_results": return {"source":"URLhaus","found":False}
    return {"source":"URLhaus","found":True,"urls_count":len(d.get("urls",[])),"link":d.get("urlhaus_reference","")}

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
            vt_r = await vt_ip(value, conn, vt_key, user_id) if vt_key else ({"skipped":True} if vt_quota is None else quota_error("VirusTotal"))
            ab_r = await abuseipdb_lookup(value, conn, ab_key, user_id) if ab_key else ({"skipped":True} if ab_quota is None else quota_error("AbuseIPDB"))
            if not isinstance(vt_r, Exception): results["virustotal"] = vt_r
            if not isinstance(ab_r, Exception): results["abuseipdb"] = ab_r
        elif ioc_type == "Domain":
            vt_key, vt_quota = get_key("virustotal")
            vt_r = await vt_domain(value, conn, vt_key, user_id) if vt_key else ({"skipped":True} if vt_quota is None else quota_error("VirusTotal"))
            uh_r = await urlhaus_host_lookup(value, conn, user_id)
            if not isinstance(vt_r, Exception): results["virustotal"] = vt_r
            if not isinstance(uh_r, Exception): results["urlhaus"] = uh_r
        elif ioc_type == "URL":
            vt_key, vt_quota = get_key("virustotal")
            vt_r = await vt_url_lookup(value, conn, vt_key, user_id) if vt_key else ({"skipped":True} if vt_quota is None else quota_error("VirusTotal"))
            uh_r = await urlhaus_url_lookup(value, conn, user_id)
            if not isinstance(vt_r, Exception): results["virustotal"] = vt_r
            if not isinstance(uh_r, Exception): results["urlhaus"] = uh_r
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
    # Government & standards
    "nvd.nist.gov","cisa.gov","cert.org","kb.cert.org","us-cert.gov","nist.gov",
    # Vendors
    "microsoft.com","cisco.com","apple.com","support.apple.com","oracle.com",
    "vmware.com","f5.com","paloaltonetworks.com","fortinet.com","juniper.net",
    "adobe.com","sap.com","ibm.com","hp.com","dell.com","lenovo.com",
    # Linux / open source
    "ubuntu.com","debian.org","redhat.com","centos.org","fedoraproject.org",
    "opensuse.org","archlinux.org","gentoo.org","kernel.org",
    # Security research / advisory archives — the ones in the screenshot
    "securityfocus.com","secunia.com","osvdb.org","openwall.com",
    "marc.info","archives.neohapsis.com","packetstormsecurity.com",
    "exploit-db.com","full-disclosure","bugtraq","vulnwatch",
    "iss.net","secnet.com","auscert.org","xforce.ibmcloud.com",
    "calderasystems.com","linux-mandrake.com","linuxsecurity.com",
    "novell.com","openbsd.org","freebsd.org","netbsd.org",
    "secunia.com","vupen.com","zerodayinitiative.com",
    # Code / issue trackers
    "github.com","gitlab.com","bitbucket.org","sourceforge.net",
    # CVE / vuln databases
    "cve.org","cvedetails.com","cve.mitre.org","mitre.org",
    # Misc common false positives
    "w3.org","ietf.org","rfc-editor.org","iana.org",
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

def auto_add_iocs_from_cve(conn, cve_id: str, cve_desc: str, refs: list, asset_name: str) -> list:
    """
    Extract genuine IOCs from CVE description text only.
    Never extract from reference URLs — those are advisory links, not IOCs.
    Only extracts IPs from description; URL extraction from CVE text is disabled
    because CVE descriptions rarely contain malicious URLs worth tracking.
    """
    # Only use description text — refs are vendor/advisory links, not IOCs
    candidates = extract_iocs_from_text(cve_desc, include_urls=False)
    if not candidates:
        return []

    added = []; cur = conn.cursor()
    for ioc_type, value in candidates:
        if any(td in value for td in TRUSTED_DOMAINS): continue
        cur.execute("SELECT id FROM iocs WHERE value = %s", (value,))
        existing = cur.fetchone()
        if existing:
            try: cur.execute("INSERT INTO cve_ioc_links (cve_id,ioc_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                             (cve_id, existing[0]))
            except Exception: pass
            continue
        ioc_id = f"indicator--{uuid.uuid4()}"
        defanged = defang(value, ioc_type)
        try:
            cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,enrichment)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (ioc_id, ioc_type, value, defanged, "General", "AMBER", 60,
                 f"Auto-extracted from {cve_id} — {asset_name}",
                 [cve_id.lower(), "auto-extracted", "cve"],
                 psycopg2.extras.Json({"note": f"Auto-extracted from {cve_id}",
                                       "enriched_at": datetime.now(timezone.utc).isoformat()})))
            cur.execute("INSERT INTO cve_ioc_links (cve_id,ioc_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                        (cve_id, ioc_id))
            added.append(value)
        except Exception: pass
    return added
    added = []; cur = conn.cursor()
    for ioc_type, value in candidates:
        if any(td in value for td in TRUSTED_DOMAINS): continue
        cur.execute("SELECT id FROM iocs WHERE value = %s", (value,))
        existing = cur.fetchone()
        if existing:
            try: cur.execute("INSERT INTO cve_ioc_links (cve_id,ioc_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                             (cve_id, existing[0]))
            except Exception: pass
            continue
        ioc_id = f"indicator--{uuid.uuid4()}"
        defanged = defang(value, ioc_type)
        try:
            cur.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,enrichment)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (ioc_id, ioc_type, value, defanged, "General", "AMBER", 60,
                 f"Auto-extracted from {cve_id} — {asset_name}",
                 [cve_id.lower(), "auto-extracted", "cve"],
                 psycopg2.extras.Json({"note": f"Auto-extracted from {cve_id}",
                                       "enriched_at": datetime.now(timezone.utc).isoformat()})))
            cur.execute("INSERT INTO cve_ioc_links (cve_id,ioc_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                        (cve_id, ioc_id))
            added.append(value)
        except Exception: pass
    return added

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
            extracted = extract_iocs_from_text(parsed["description"], include_urls=False)
            ioc_values = []
            # NOTE: IOC auto-extraction from CVEs disabled
            # CVE descriptions contain version numbers and bug tracker IDs
            # that match IP patterns but are not threat indicators.
            # Legitimate IOCs come from threat intel feeds, not CVE descriptions.
            # if extracted: ...  (disabled)
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
    if all_new_iocs:
        create_notification(conn, "ioc_auto",
            f"{len(all_new_iocs)} IOC(s) auto-extracted from CVEs",
            f"The following IOCs were automatically added to your feed: {', '.join(i['value'] for i in all_new_iocs[:5])}",
            "info", {"iocs": all_new_iocs[:10]})
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
    cur.execute("SELECT * FROM invite_codes WHERE code = %s AND used = FALSE", (body.invite_code,))
    invite = cur.fetchone()
    if not invite: raise HTTPException(status_code=400, detail="Invalid or already used invite code")
    cur.execute("SELECT id FROM users WHERE username = %s", (body.username,))
    if cur.fetchone(): raise HTTPException(status_code=400, detail="Username already taken")
    uid = f"user--{uuid.uuid4()}"
    cur2 = conn.cursor()
    cur2.execute("INSERT INTO users (id,username,password,role) VALUES (%s,%s,%s,%s)",
        (uid,body.username,pwd_ctx.hash(body.password),invite["role"]))
    cur2.execute("UPDATE invite_codes SET used = TRUE WHERE code = %s", (body.invite_code,))
    conn.commit()
    token = create_token({"sub":uid,"username":body.username,"role":invite["role"]})
    return {"access_token":token,"token_type":"bearer","username":body.username,"role":invite["role"]}

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
    """Remove IOCs that were incorrectly extracted from CVE reference URLs (advisory/vendor links)."""
    cur = conn.cursor()
    # Find IOCs tagged 'auto-extracted' that are advisory/vendor domains
    cur.execute("SELECT id, value FROM iocs WHERE 'auto-extracted' = ANY(tags) AND type = 'URL'")
    rows = cur.fetchall()
    removed = 0
    for ioc_id, value in rows:
        if any(td in (value or "") for td in TRUSTED_DOMAINS):
            cur.execute("DELETE FROM cve_ioc_links WHERE ioc_id = %s", (ioc_id,))
            cur.execute("DELETE FROM iocs WHERE id = %s", (ioc_id,))
            removed += 1
    # Also clean up Bugtraq, SecurityFocus, mailing list archive URLs
    advisory_patterns = ["bugtraq","securityfocus","marc.info","neohapsis","vulnwatch",
                         "iss.net","linuxsecurity","calderasystems","linux-mandrake",
                         "openwall","secunia","osvdb","auscert","secnet","xforce"]
    cur.execute("SELECT id, value FROM iocs WHERE 'auto-extracted' = ANY(tags) AND type = 'URL'")
    rows = cur.fetchall()
    for ioc_id, value in rows:
        if any(p in (value or "").lower() for p in advisory_patterns):
            cur.execute("DELETE FROM cve_ioc_links WHERE ioc_id = %s", (ioc_id,))
            cur.execute("DELETE FROM iocs WHERE id = %s", (ioc_id,))
            removed += 1
    conn.commit()
    return {"status": "done", "removed": removed,
            "message": f"Removed {removed} advisory URLs that were incorrectly tagged as IOCs"}

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
def list_campaigns(user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT c.*, COUNT(i.id) as ioc_count FROM campaigns c
        LEFT JOIN iocs i ON i.campaign_id = c.id GROUP BY c.id ORDER BY c.created_at DESC""")
    return cur.fetchall()

@app.post("/campaigns", status_code=201)
def create_campaign(body: CampaignIn, user=Depends(get_current_user), conn=Depends(get_db)):
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
              user=Depends(get_current_user), conn=Depends(get_db)):
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
def search_iocs(q: str, user=Depends(get_current_user), conn=Depends(get_db)):
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
def check_duplicate(body: dict, user=Depends(get_current_user), conn=Depends(get_db)):
    value = refang(body.get("value","").strip())
    cur   = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT i.*, u.username as author FROM iocs i LEFT JOIN users u ON i.created_by = u.id WHERE i.value = %s", (value,))
    existing = cur.fetchone()
    return {"exists":bool(existing),"existing":existing}

@app.post("/iocs", status_code=201)
async def add_ioc(ioc: IOCIn, user=Depends(get_current_user), conn=Depends(get_db)):
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

@app.patch("/iocs/{ioc_id}/false-positive")
def toggle_fp(ioc_id: str, body: FPUpdate, user=Depends(get_current_user), conn=Depends(get_db)):
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
def assign_campaign(ioc_id: str, body: dict, user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE iocs SET campaign_id = %s WHERE id = %s", (body.get("campaign_id"), ioc_id))
    conn.commit(); return {"status":"updated"}

@app.post("/iocs/{ioc_id}/re-enrich")
async def re_enrich(ioc_id: str, user=Depends(get_current_user), conn=Depends(get_db)):
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

@app.get("/iocs/{ioc_id}/score-history")
def score_history(ioc_id: str, user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ioc_score_history WHERE ioc_id = %s ORDER BY created_at DESC", (ioc_id,))
    return cur.fetchall()

@app.delete("/iocs/{ioc_id}")
def delete_ioc(ioc_id: str, user=Depends(get_current_user), conn=Depends(get_db)):
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
def get_notes(ioc_id: str, user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ioc_notes WHERE ioc_id = %s ORDER BY created_at ASC", (ioc_id,))
    return cur.fetchall()

@app.post("/iocs/{ioc_id}/notes", status_code=201)
def add_note(ioc_id: str, body: NoteIn, user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("INSERT INTO ioc_notes (ioc_id,note,username,user_id) VALUES (%s,%s,%s,%s)",
        (ioc_id,body.note,user["username"],user["id"]))
    conn.commit(); return {"status":"created"}

@app.delete("/iocs/{ioc_id}/notes/{note_id}")
def delete_note(ioc_id: str, note_id: int, user=Depends(get_current_user), conn=Depends(get_db)):
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
def get_relationships(ioc_id: str, user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT r.*,
        s.value as source_value, s.type as source_type, s.value_defanged as source_defanged,
        t.value as target_value, t.type as target_type, t.value_defanged as target_defanged
        FROM ioc_relationships r
        JOIN iocs s ON r.source_id = s.id JOIN iocs t ON r.target_id = t.id
        WHERE r.source_id = %s OR r.target_id = %s""", (ioc_id,ioc_id))
    return cur.fetchall()

@app.post("/iocs/{ioc_id}/relationships", status_code=201)
def add_relationship(ioc_id: str, body: RelationshipIn, user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("SELECT id FROM iocs WHERE id = %s", (ioc_id,))
    if not cur.fetchone(): raise HTTPException(status_code=404, detail="Source IOC not found")
    cur.execute("SELECT id FROM iocs WHERE id = %s", (body.target_id,))
    if not cur.fetchone(): raise HTTPException(status_code=404, detail="Target IOC not found")
    cur.execute("INSERT INTO ioc_relationships (source_id,target_id,relationship_type,note,created_by) VALUES (%s,%s,%s,%s,%s)",
        (ioc_id,body.target_id,body.relationship_type,body.note,user["id"]))
    conn.commit(); return {"status":"created"}

@app.delete("/iocs/relationships/{rel_id}")
def delete_relationship(rel_id: int, user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("DELETE FROM ioc_relationships WHERE id = %s", (rel_id,))
    conn.commit(); return {"status":"deleted"}

@app.get("/iocs/pivot/subnet/{ip}")
def subnet_pivot(ip: str, user=Depends(get_current_user), conn=Depends(get_db)):
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
def list_assets(user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT a.*,
        COUNT(DISTINCT cf.id) as cve_count,
        SUM(CASE WHEN cf.patch_available = FALSE AND cf.cvss_score >= 9 THEN 1 ELSE 0 END) as critical_unpatched,
        SUM(CASE WHEN cf.kev_listed = TRUE AND cf.patch_available = FALSE THEN 1 ELSE 0 END) as kev_unpatched
        FROM assets a LEFT JOIN cve_findings cf ON cf.asset_id = a.id
        WHERE a.active = TRUE GROUP BY a.id ORDER BY a.created_at DESC""")
    return cur.fetchall()

@app.post("/assets", status_code=201)
async def create_asset(body: AssetIn, user=Depends(get_current_user), conn=Depends(get_db)):
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
              user=Depends(get_current_user), conn=Depends(get_db)):
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
    if all_new_iocs:
        create_notification(conn, "ioc_auto",
            f"{len(all_new_iocs)} IOC(s) auto-extracted from CVEs",
            f"Auto-added: {', '.join(i['value'] for i in all_new_iocs[:5])}",
            "info", {"iocs":all_new_iocs[:10]})
    if all_patched:
        create_notification(conn, "patch_available",
            f"Patches available for {len(all_patched)} CVE(s)",
            f"Patches detected for: {', '.join(p['cve_id'] for p in all_patched)}",
            "success", {"patched":all_patched})
    conn.commit()
    return {"new_cves":len(all_new_cves),"new_iocs":len(all_new_iocs),
            "patches_detected":len(all_patched),"assets_polled":len(assets)}

@app.get("/cves/stats/summary")
def cve_summary(user=Depends(get_current_user), conn=Depends(get_db)):
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

@app.get("/cves/{cve_id}")
def get_cve(cve_id: str, user=Depends(get_current_user), conn=Depends(get_db)):
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

@app.get("/stats/dashboard")
def dashboard(user=Depends(get_current_user), conn=Depends(get_db)):
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

@app.get("/stats/geo")
def geo_stats(user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT enrichment FROM iocs WHERE type IN ('IPv4','IPv6') AND enrichment IS NOT NULL")
    rows = cur.fetchall(); country_counts = {}
    for row in rows:
        e = row.get("enrichment") or {}
        # AbuseIPDB uses 'country' (2-letter code), VT uses 'country'
        # Try all possible field locations
        country = (
            e.get("abuseipdb",{}).get("country") or
            e.get("abuseipdb",{}).get("countryCode") or
            e.get("virustotal",{}).get("country") or
            e.get("country")
        )
        if country and country not in ("?", "Unknown", ""):
            # Normalise to uppercase 2-letter code
            country = str(country).strip().upper()[:2]
            if len(country) == 2:
                country_counts[country] = country_counts.get(country,0) + 1
    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
    return {"countries":[{"code":k,"count":v} for k,v in sorted_countries[:30]]}

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
    auto_added = False; verdict = "MALICIOUS" if score >= 80 else "SUSPICIOUS" if score >= 50 else "CLEAN"
    if score >= 50:
        try:
            ioc_id = f"indicator--{uuid.uuid4()}"; defanged = defang(canonical, ioc_type)
            valid_until = datetime.now(timezone.utc) + timedelta(days=90)
            cur2 = conn.cursor()
            cur2.execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,enrichment,valid_until)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (ioc_id,ioc_type,canonical,defanged,"General","RED" if score>=80 else "AMBER",score,
                 f"Auto-added via public lookup. Verdict: {verdict}.",
                 ["auto-added","public-lookup"],psycopg2.extras.Json(enrichment),valid_until))
            conn.commit(); auto_added = True
        except Exception: pass
    return {"source":"providers","found_in_db":False,"auto_added":auto_added,"ioc_type":ioc_type,
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
CVE_FEEDS = [
    # CISA Advisories
    ("https://www.cisa.gov/cybersecurity-advisories/all.xml",             "CISA",          "Advisory"),
    ("https://www.cisa.gov/known-exploited-vulnerabilities.xml",          "CISA KEV",      "KEV"),
    # Vendor Security Advisories
    ("https://www.redhat.com/en/rss/security-advisories",                 "Red Hat",       "Advisory"),
    ("https://support.apple.com/en-us/100100/rss/feed.rss",              "Apple",         "Advisory"),
    ("https://www.debian.org/security/dsa.en.rdf",                        "Debian",        "Advisory"),
    ("https://ubuntu.com/security/notices/rss.xml",                       "Ubuntu",        "Advisory"),
    ("https://www.openwall.com/lists/oss-security/",                      "OSS Security",  "Vulnerability"),
    # CVE-focused news
    ("https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",             "NVD",           "CVE"),
    ("https://www.cvedetails.com/rss/vulnerabilities.php",               "CVE Details",   "CVE"),
    ("https://securelist.com/feed/",                                      "Kaspersky",     "Analysis"),
    ("https://www.zerodayinitiative.com/rss/published/",                  "Zero Day",      "0day"),
    ("https://packetstormsecurity.com/files/tags/advisory/rss.xml",      "PacketStorm",   "Advisory"),
]

async def fetch_cve_rss(url: str, source: str, category: str) -> list:
    try:
        async with httpx.AsyncClient(timeout=8,
            headers={"User-Agent":"Mozilla/5.0 ThreatFeed-CTI/1.0"}) as c:
            r = await c.get(url)
        if r.status_code != 200: return []
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
                desc = re.sub(r"<[^>]+>","",raw).strip()[:300]
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
        return items
    except Exception as e:
        print(f"[cve-wall] {source}: {e}")
        return []

@app.get("/cve-wall")
async def cve_wall(category: str = "all", user=Depends(get_current_user)):
    """CVE-specific news wall: advisories, KEV, vendor patches, 0days."""
    feeds_to_use = CVE_FEEDS if category == "all" else [
        f for f in CVE_FEEDS if f[2].lower() == category.lower()
    ]
    tasks = [fetch_cve_rss(url, source, cat) for url, source, cat in feeds_to_use]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    items = []; seen = set()
    for r in results:
        if isinstance(r, list): items.extend(r)
    unique = []
    for item in sorted(items, key=lambda x: x.get("date",""), reverse=True):
        k = item["title"][:60]
        if k not in seen:
            seen.add(k); unique.append(item)
    return {"items": unique[:40], "total": len(unique)}

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
    user=Depends(get_current_user),
    conn=Depends(get_db)
):
    """Full CVE search with filters — OpenCVE-parity search endpoint."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    where = ["1=1"]; params = []
    if q:
        where.append("(cf.cve_id ILIKE %s OR cf.title ILIKE %s OR cf.description ILIKE %s)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if severity:
        where.append("cf.cvss_severity = %s"); params.append(severity.capitalize())
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

async def lookup_cve_trends(cve_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8,
            headers={"User-Agent":"ThreatFeed-CTI/1.0"}) as c:
            r = await c.get(f"https://cvetrends.com/api/cve/{cve_id}")
        if r.status_code == 404:
            return {"source":"CVE Trends","status":"not_found"}
        if r.status_code != 200:
            return {"source":"CVE Trends","status":"error","error":f"HTTP {r.status_code}"}
        data = r.json()
        return {
            "source":   "CVE Trends",
            "status":   "ok",
            "url":      f"https://cvetrends.com/cve/{cve_id}",
            "tweets":   data.get("tweets",[])[:5],
            "trending": data.get("trending", False),
            "count_24h": data.get("tweet_count_24h", 0),
        }
    except Exception:
        return {"source":"CVE Trends","status":"not_found"}

@app.get("/cve/lookup")
async def cve_multi_lookup(id: str, user=Depends(get_current_user)):
    """
    Aggregate CVE data from NVD, CVE.org, OSV, CVE Trends, EPSS, and CISA KEV.
    Returns all sources in parallel with their references and affected packages.
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
        lookup_cve_trends(cve_id),
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

    async def check_poc_github():
        """Check nomi-sec/PoC-in-GitHub database — free, comprehensive."""
        pocs = []
        try:
            url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"
            async with httpx.AsyncClient(timeout=8,
                headers={"User-Agent":"ThreatFeed-CTI/1.0"}) as c:
                r = await c.get(url)
            if r.status_code == 200:
                entries = r.json()
                for entry in entries[:5]:
                    pocs.append({
                        "url":         entry.get("html_url",""),
                        "author":      entry.get("owner",{}).get("login",""),
                        "stars":       entry.get("stargazers_count",0),
                        "description": entry.get("description",""),
                        "created_at":  entry.get("created_at","")[:10],
                    })
        except Exception: pass
        return pocs

    async def check_poc_refs(nvd_data):
        """Check NVD references for Exploit/PoC tags."""
        refs = nvd_data.get("references",[])
        poc_refs = []
        for ref in refs:
            tags = ref.get("tags",[])
            url  = ref.get("url","")
            if any(t in tags for t in ["Exploit","Proof of Concept","PoC"]):
                poc_refs.append(url)
            elif any(kw in url.lower() for kw in ["exploit","poc","proof","metasploit",
                                                    "packetstorm","exploit-db"]):
                poc_refs.append(url)
        return poc_refs

    async def check_exploitdb():
        """Check ExploitDB for this CVE."""
        try:
            cve_num = cve_id.replace("CVE-","")
            async with httpx.AsyncClient(timeout=8,
                headers={"User-Agent":"Mozilla/5.0 ThreatFeed-CTI/1.0"}) as c:
                r = await c.get(f"https://www.exploit-db.com/search?cve={cve_num}",
                               headers={"Accept":"application/json, text/javascript"})
            if r.status_code == 200:
                try:
                    data = r.json()
                    results = data.get("data",[])
                    if results:
                        return [f"https://www.exploit-db.com/exploits/{e.get('id','')}"
                                for e in results[:3] if e.get("id")]
                except Exception: pass
        except Exception: pass
        return []

    # Run all lookups in parallel
    nvd_data, poc_github, edb_pocs = await asyncio.gather(
        get_nvd(), check_poc_github(), check_exploitdb(),
        return_exceptions=True
    )
    if isinstance(nvd_data, Exception):   nvd_data   = {}
    if isinstance(poc_github, Exception): poc_github = []
    if isinstance(edb_pocs,   Exception): edb_pocs   = []

    poc_ref_urls = await check_poc_refs(nvd_data if nvd_data else {})

    # ── Compile PoC status ───────────────────────────────────────────────────
    has_poc       = bool(poc_github or poc_ref_urls or edb_pocs)
    poc_links     = ([p["url"] for p in poc_github if p.get("url")] +
                     poc_ref_urls + edb_pocs)[:5]
    top_poc       = poc_github[0] if poc_github else None

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
        poc_section = f"YES — PoC exploits are publicly available.\n"
        if top_poc:
            poc_section += f"Most notable: {top_poc.get('url','')} (⭐ {top_poc.get('stars',0)} stars)\n"
        if poc_links:
            poc_section += "Links:\n" + "\n".join(f"- {u}" for u in poc_links[:4])
    else:
        poc_section = "No public PoC identified in GitHub, ExploitDB, or NVD references at time of scan."

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
        raw = await call_groq(system, user_msg, max_tokens=1800)
        # call_groq uses json_object mode — but for reports we want plain text
        # Re-call without json mode
        async with httpx.AsyncClient(timeout=45) as c:
            r = await c.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                         "Content-Type": "application/json"},
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [{"role":"system","content":system},
                                 {"role":"user",  "content":user_msg}],
                    "temperature": 0.15,
                    "max_tokens": 1800,
                }
            )
        content = r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM error: {str(e)}")

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
            "links":     poc_links,
            "github":    poc_github[:3],
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
async def import_stix(body: STIXImport, user=Depends(get_current_user), conn=Depends(get_db)):
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
async def poll_taxii(body: TAXIIPoll, user=Depends(get_current_user), conn=Depends(get_db)):
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
async def misp_pull(body: MISPPull, user=Depends(get_current_user), conn=Depends(get_db)):
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
async def import_csv(file: UploadFile = File(...), user=Depends(get_current_user), conn=Depends(get_db)):
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
                user=Depends(get_current_user), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    q = "SELECT * FROM iocs WHERE (false_positive IS NULL OR false_positive = FALSE)"; params = []
    if industry: q += " AND industry = %s"; params.append(industry)
    if not include_expired: q += " AND (valid_until IS NULL OR valid_until > NOW())"
    cur.execute(q, params); rows = cur.fetchall()
    return {"type":"bundle","id":f"bundle--{uuid.uuid4()}","spec_version":"2.1",
            "created":datetime.now(timezone.utc).isoformat(),"objects":[row_to_stix(r) for r in rows]}

@app.get("/taxii/")
def taxii_discovery(user=Depends(get_current_user)):
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
# QUERY BUILDER & EXPLAINER — powered by Groq (llama-3.3-70b)
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
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role":"system","content":system},{"role":"user","content":user}],
                "temperature": 0.2,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
            }
        )
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Groq API error: {r.status_code}")
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

