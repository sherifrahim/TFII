import os, uuid, httpx, asyncio, base64, csv, io, re, json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

import psycopg2, psycopg2.extras
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import JWTError, jwt

load_dotenv()

SECRET_KEY         = os.getenv("SECRET_KEY", "changeme")
ALGORITHM          = "HS256"
TOKEN_EXPIRE       = 480
ADMIN_DEFAULT_USER = "admin"
ADMIN_DEFAULT_PASS = "TFeed@99"
VT_API_KEY         = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
HIBP_API_KEY       = os.getenv("HIBP_API_KEY", "")
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY", "")
NVD_API_KEY        = os.getenv("NVD_API_KEY", "")
GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "")
CACHE_HOURS        = 24

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2  = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="ThreatFeed Intelligence Platform")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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
        """CREATE TABLE IF NOT EXISTS assets (
            id VARCHAR(100) PRIMARY KEY, name VARCHAR(200) NOT NULL,
            vendor VARCHAR(200), version VARCHAR(100),
            asset_type VARCHAR(50) DEFAULT 'application',
            criticality VARCHAR(20) DEFAULT 'high',
            cpe TEXT, description TEXT, created_by VARCHAR(100),
            active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW())""",
        """CREATE TABLE IF NOT EXISTS cve_findings (
            id VARCHAR(100) PRIMARY KEY, cve_id VARCHAR(50) UNIQUE NOT NULL,
            asset_id VARCHAR(100), title TEXT, description TEXT,
            cvss_score FLOAT, cvss_severity VARCHAR(20), cvss_vector TEXT,
            epss_score FLOAT, epss_percentile FLOAT,
            kev_listed BOOLEAN DEFAULT FALSE, kev_date TEXT,
            cwe TEXT, affected_versions TEXT,
            published_date TEXT, modified_date TEXT,
            patch_available BOOLEAN DEFAULT FALSE, patch_url TEXT,
            patch_detected_at TIMESTAMP,
            references JSONB, iocs_extracted TEXT[],
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
def log_api_call(conn, api_name: str, ioc_value: str, cache_hit: bool):
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO api_usage_log (api_name,ioc_value,cache_hit) VALUES (%s,%s,%s)",
                    (api_name, ioc_value, cache_hit))
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
async def vt_ip(ip, conn=None):
    if not VT_API_KEY: return {"source":"VirusTotal","skipped":True}
    if conn: log_api_call(conn,"virustotal",ip,False)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey":VT_API_KEY})
    if r.status_code != 200: return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    attrs = r.json().get("data",{}).get("attributes",{})
    stats = attrs.get("last_analysis_stats",{})
    mal = stats.get("malicious",0); total = sum(stats.values()) or 1
    return {"source":"VirusTotal","malicious":mal,"total":total,"vt_score":round((mal/total)*100),
            "country":attrs.get("country","?"),"asn":str(attrs.get("asn","?")),
            "link":f"https://www.virustotal.com/gui/ip-address/{ip}"}

async def vt_domain(domain, conn=None):
    if not VT_API_KEY: return {"source":"VirusTotal","skipped":True}
    if conn: log_api_call(conn,"virustotal",domain,False)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey":VT_API_KEY})
    if r.status_code != 200: return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    attrs = r.json().get("data",{}).get("attributes",{})
    stats = attrs.get("last_analysis_stats",{})
    mal = stats.get("malicious",0); total = sum(stats.values()) or 1
    return {"source":"VirusTotal","malicious":mal,"total":total,"vt_score":round((mal/total)*100),
            "country":attrs.get("country","?"),"link":f"https://www.virustotal.com/gui/domain/{domain}"}

async def vt_hash(h, conn=None):
    if not VT_API_KEY: return {"source":"VirusTotal","skipped":True}
    if conn: log_api_call(conn,"virustotal",h,False)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={"x-apikey":VT_API_KEY})
    if r.status_code == 404: return {"source":"VirusTotal","found":False,"vt_score":0}
    if r.status_code != 200: return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    attrs = r.json().get("data",{}).get("attributes",{})
    stats = attrs.get("last_analysis_stats",{})
    mal = stats.get("malicious",0); total = sum(stats.values()) or 1
    return {"source":"VirusTotal","found":True,"malicious":mal,"total":total,
            "file_name":attrs.get("meaningful_name","unknown"),
            "vt_score":round((mal/total)*100),"link":f"https://www.virustotal.com/gui/file/{h}"}

async def vt_url_lookup(url_val, conn=None):
    if not VT_API_KEY: return {"source":"VirusTotal","skipped":True}
    if conn: log_api_call(conn,"virustotal",url_val,False)
    url_id = base64.urlsafe_b64encode(url_val.encode()).decode().rstrip("=")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey":VT_API_KEY})
    if r.status_code == 404: return {"source":"VirusTotal","found":False,"vt_score":0}
    if r.status_code != 200: return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    mal = stats.get("malicious",0); total = sum(stats.values()) or 1
    return {"source":"VirusTotal","malicious":mal,"total":total,
            "vt_score":round((mal/total)*100),"link":f"https://www.virustotal.com/gui/url/{url_id}"}

async def abuseipdb_lookup(ip, conn=None):
    if not ABUSEIPDB_API_KEY: return {"source":"AbuseIPDB","skipped":True}
    if conn: log_api_call(conn,"abuseipdb",ip,False)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get("https://api.abuseipdb.com/api/v2/check",
            headers={"Key":ABUSEIPDB_API_KEY,"Accept":"application/json"},
            params={"ipAddress":ip,"maxAgeInDays":90})
    if r.status_code != 200: return {"source":"AbuseIPDB","error":f"HTTP {r.status_code}"}
    d = r.json().get("data",{})
    return {"source":"AbuseIPDB","abuse_score":d.get("abuseConfidenceScore",0),
            "total_reports":d.get("totalReports",0),"country":d.get("countryCode","?"),
            "isp":d.get("isp","?"),"link":f"https://www.abuseipdb.com/check/{ip}"}

async def urlhaus_url_lookup(url_val, conn=None):
    if conn: log_api_call(conn,"urlhaus",url_val,False)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url":url_val})
    if r.status_code != 200: return {"source":"URLhaus","error":f"HTTP {r.status_code}"}
    d = r.json()
    if d.get("query_status") == "no_results": return {"source":"URLhaus","found":False}
    return {"source":"URLhaus","found":True,"threat":d.get("threat","?"),
            "url_status":d.get("url_status","?"),"link":d.get("urlhaus_reference","")}

async def urlhaus_host_lookup(domain, conn=None):
    if conn: log_api_call(conn,"urlhaus",domain,False)
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

async def enrich(ioc_type: str, value: str, base: int, conn=None, force: bool=False, existing: dict=None) -> dict:
    if not force and existing and is_cache_fresh(existing):
        if conn: log_api_call(conn,"cache",value,True)
        return existing
    results = {}
    try:
        if ioc_type in ("IPv4","IPv6"):
            vt_r, ab_r = await asyncio.gather(vt_ip(value,conn), abuseipdb_lookup(value,conn), return_exceptions=True)
            results["virustotal"] = vt_r if not isinstance(vt_r,Exception) else {"error":str(vt_r)}
            results["abuseipdb"]  = ab_r if not isinstance(ab_r,Exception) else {"error":str(ab_r)}
        elif ioc_type == "Domain":
            vt_r, uh_r = await asyncio.gather(vt_domain(value,conn), urlhaus_host_lookup(value,conn), return_exceptions=True)
            results["virustotal"] = vt_r if not isinstance(vt_r,Exception) else {"error":str(vt_r)}
            results["urlhaus"]    = uh_r if not isinstance(uh_r,Exception) else {"error":str(uh_r)}
        elif ioc_type == "URL":
            vt_r, uh_r = await asyncio.gather(vt_url_lookup(value,conn), urlhaus_url_lookup(value,conn), return_exceptions=True)
            results["virustotal"] = vt_r if not isinstance(vt_r,Exception) else {"error":str(vt_r)}
            results["urlhaus"]    = uh_r if not isinstance(uh_r,Exception) else {"error":str(uh_r)}
        elif ioc_type in ("MD5","SHA1","SHA256"):
            vt_r = await vt_hash(value,conn)
            results["virustotal"] = vt_r if not isinstance(vt_r,Exception) else {"error":str(vt_r)}
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
TRUSTED_DOMAINS = ["nvd.nist.gov","cisa.gov","microsoft.com","cisco.com","ubuntu.com",
                   "debian.org","redhat.com","github.com","kb.cert.org","support.apple.com",
                   "oracle.com","vmware.com","f5.com","paloaltonetworks.com"]

def detect_patch(references: list) -> tuple:
    for ref in references:
        tags = set(ref.get("tags",[]))
        url  = ref.get("url","")
        if tags & PATCH_REF_TAGS:
            return True, url
        if any(kw in url.lower() for kw in ["advisory","security","patch","update","bulletin","kb"]):
            return True, url
    return False, None

def extract_iocs_from_text(text: str) -> list:
    found = []
    for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts) and ip not in ('0.0.0.0','127.0.0.1','255.255.255.255'):
            found.append(("IPv4", ip))
    for url in re.findall(r'https?://[^\s\'"<>]+', text):
        found.append(("URL", url.rstrip('.,)')))
    return found

def auto_add_iocs_from_cve(conn, cve_id: str, cve_desc: str, refs: list, asset_name: str) -> list:
    all_text = cve_desc + " " + " ".join(r.get("url","") for r in refs)
    candidates = extract_iocs_from_text(all_text)
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

async def fetch_nvd_cves(cpe: str, days_back: int = 90) -> list:
    headers = {"User-Agent":"ThreatFeed-CTI/1.0"}
    if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY
    end = datetime.now(timezone.utc); start = end - timedelta(days=days_back)
    params = {"cpeName":cpe,"pubStartDate":start.strftime("%Y-%m-%dT%H:%M:%S.000"),
              "pubEndDate":end.strftime("%Y-%m-%dT%H:%M:%S.000"),"resultsPerPage":50}
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params=params, headers=headers)
        if r.status_code == 200: return r.json().get("vulnerabilities",[])
    except Exception as e:
        print(f"[nvd] Error for {cpe}: {e}")
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
    cpe = asset.get("cpe","")
    if not cpe: return {"new_cves":[],"new_iocs":[],"patched":[]}
    asset_id = asset["id"]; asset_name = asset["name"]
    new_cves = []; new_iocs = []; patched_cves = []
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    vulns = await fetch_nvd_cves(cpe)
    if not vulns: return {"new_cves":[],"new_iocs":[],"patched":[]}
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
                 published_date,modified_date,patch_available,patch_url,patch_detected_at,references)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (cve_id) DO NOTHING""",
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
            extracted = extract_iocs_from_text(parsed["description"] + " ".join(r.get("url","") for r in parsed["references"]))
            ioc_values = []
            for ioc_type, value in extracted:
                if any(td in value for td in TRUSTED_DOMAINS): continue
                cur.execute("SELECT id FROM iocs WHERE value = %s", (value,))
                ex = cur.fetchone()
                if not ex:
                    ioc_id = f"indicator--{uuid.uuid4()}"
                    defanged = defang(value, ioc_type)
                    try:
                        conn.cursor().execute("""INSERT INTO iocs (id,type,value,value_defanged,industry,tlp,confidence,description,tags,enrichment)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                            (ioc_id,ioc_type,value,defanged,"General","AMBER",60,
                             f"Auto-extracted from {cve_id}",
                             [cve_id.lower(),"auto-extracted","cve"],
                             psycopg2.extras.Json({"note":f"Auto-extracted from {cve_id}",
                                                   "enriched_at":datetime.now(timezone.utc).isoformat()})))
                        conn.cursor().execute("INSERT INTO cve_ioc_links (cve_id,ioc_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",(cve_id,ioc_id))
                        ioc_values.append(value)
                    except Exception: pass
            if ioc_values:
                new_iocs.extend([{"value":v,"cve_id":cve_id} for v in ioc_values])
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
def login(form: OAuth2PasswordRequestForm = Depends(), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s AND active = TRUE", (form.username,))
    user = cur.fetchone()
    if not user or not pwd_ctx.verify(form.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token({"sub":user["id"],"username":user["username"],"role":user["role"]})
    return {"access_token":token,"token_type":"bearer","username":user["username"],"role":user["role"]}

@app.post("/auth/signup")
def signup(body: SignupRequest, conn=Depends(get_db)):
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

@app.post("/auth/change-password")
def change_password(body: PasswordChange, user=Depends(get_current_user), conn=Depends(get_db)):
    if not pwd_ctx.verify(body.current_password, user["password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = %s WHERE id = %s", (pwd_ctx.hash(body.new_password), user["id"]))
    conn.commit(); return {"status":"password updated"}

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
    enrichment = await enrich(ioc.type, canonical, ioc.confidence, conn)
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
    enrichment = await enrich(ioc["type"],ioc["value"],ioc["confidence"],conn,force=True,existing=ioc.get("enrichment"))
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
def create_asset(body: AssetIn, user=Depends(get_current_user), conn=Depends(get_db)):
    aid = f"asset--{uuid.uuid4()}"
    cur = conn.cursor()
    cur.execute("""INSERT INTO assets (id,name,vendor,version,asset_type,criticality,cpe,description,created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (aid,body.name,body.vendor,body.version,body.asset_type,body.criticality,body.cpe,body.description,user["id"]))
    conn.commit(); return {"id":aid,"name":body.name}

@app.delete("/assets/{asset_id}")
def delete_asset(asset_id: str, admin=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("UPDATE assets SET active = FALSE WHERE id = %s", (asset_id,))
    conn.commit(); return {"status":"deactivated"}

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
        country = e.get("abuseipdb",{}).get("country") or e.get("virustotal",{}).get("country")
        if country and country != "?":
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

# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK ACTOR LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

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
# SPL / KQL GENERATOR — powered by Groq (free, llama3-70b)
# ═══════════════════════════════════════════════════════════════════════════════

class QueryGenRequest(BaseModel):
    use_case: str
    query_type: str      # "spl" | "kql"
    context: Optional[str] = ""   # optional: log source, product, field names

SYSTEM_PROMPT_SPL = """You are a security engineer expert in Splunk SPL (Search Processing Language).
The user will describe a detection use case or investigation need.
You will respond with:
1. A ready-to-use SPL query
2. A brief explanation of what each clause does
3. Any important notes about tuning or prerequisites (index names, sourcetypes etc.)

Format your response exactly like this:
QUERY:
```spl
<the query here>
```
EXPLANATION:
<line by line explanation>
NOTES:
<tuning tips, required sourcetypes/indexes, field dependencies>"""

SYSTEM_PROMPT_KQL = """You are a security engineer expert in KQL (Kusto Query Language) for Microsoft Sentinel and Defender.
The user will describe a detection use case or investigation need.
You will respond with:
1. A ready-to-use KQL query
2. A brief explanation of what each clause does
3. Any important notes about tuning or prerequisites (tables, connectors needed etc.)

Format your response exactly like this:
QUERY:
```kql
<the query here>
```
EXPLANATION:
<line by line explanation>
NOTES:
<tuning tips, required tables/connectors, field dependencies>"""

@app.post("/query-gen/generate")
async def generate_query(body: QueryGenRequest, user=Depends(get_current_user)):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=503,
            detail="GROQ_API_KEY not configured. Add it to .env and restart the backend.")

    system_prompt = SYSTEM_PROMPT_KQL if body.query_type == "kql" else SYSTEM_PROMPT_SPL

    user_message = body.use_case
    if body.context:
        user_message += f"\n\nAdditional context: {body.context}"

    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "llama3-70b-8192",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": user_message},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 1500,
                },
            )
        if r.status_code != 200:
            raise HTTPException(status_code=502,
                detail=f"Groq API error: {r.status_code} — {r.text[:200]}")

        content = r.json()["choices"][0]["message"]["content"]

        # Parse the structured response
        query    = ""
        explanation = ""
        notes    = ""

        if "QUERY:" in content:
            after_query = content.split("QUERY:", 1)[1]
            code_match = re.search(r"```(?:spl|kql)?\n(.*?)```", after_query, re.DOTALL)
            if code_match:
                query = code_match.group(1).strip()

        if "EXPLANATION:" in content:
            after_exp = content.split("EXPLANATION:", 1)[1]
            notes_split = after_exp.split("NOTES:", 1)
            explanation = notes_split[0].strip()
            if len(notes_split) > 1:
                notes = notes_split[1].strip()

        if not query:
            # fallback — return raw if parsing failed
            return {"raw": content, "query": "", "explanation": content, "notes": ""}

        return {
            "query":       query,
            "explanation": explanation,
            "notes":       notes,
            "query_type":  body.query_type,
            "raw":         content,
        }

    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Groq API timed out. Try again.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
