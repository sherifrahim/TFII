# TFII — Backlog & TODO

> Items postponed, deferred, or noted during development.
> Mark as done when implemented and merged.

---

## 🔴 High Priority

- [ ] **Mode switcher** — IOC / CVE mode toggle in sidebar, nav changes per mode *(in progress)*
- [ ] **NVD API key** — Add free key at nvd.nist.gov/developers/request-an-api-key to increase rate limit from 5→50 req/30s
- [ ] **HIBP API key** — Add to .env to enable email breach lookups in OSINT (haveibeenpwned.com/API/Key)

---

## 🟡 Features Deferred to Later

### Notifications
- [ ] **Email notifications** — Deferred in favour of in-app portal notifications. When ready: support Gmail SMTP App Password or SendGrid free tier (100/day). Env vars: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `ADMIN_EMAIL`

### ThreatLens Extension Integration
- [ ] **ThreatLens browser extension** — Friend's project (github.com/muraleekrishnan4/threatlens). Plan: add `/lookup?ioc=VALUE` public read-only endpoint (no auth, rate-limited by IP). Extension points at this endpoint to highlight IOCs on any webpage the user browses. Awaiting extension options.html field names to know how to configure it.

### IOC Features
- [ ] **YARA rule export** — Generate YARA rules from hash IOCs and string/URL IOCs
- [ ] **Snort/Suricata rule export** — `alert tcp $HOME_NET any -> <ip> any` rules for IP/domain IOCs
- [ ] **Webhook / Slack notification** — POST to Slack/Teams webhook when TLP:RED or high-confidence IOC added
- [ ] **IOC relationship graph improvements** — Currently force-directed SVG. Could add: relationship type labels clickable, zoom/pan, export as PNG

### CVE Features
- [ ] **Patch notes / SLA tracking** — Deferred. Was discussed but removed from scope. Future: add patch_notes text field, SLA deadline per severity (Critical=7d, High=30d), RAG status indicator
- [ ] **PoC / exploit tracker** — For each CVE, check Exploit-DB and GitHub for public PoC existence. Show "PoC Available" badge and date published relative to CVE disclosure
- [ ] **Vendor-specific RSS feeds** — Microsoft MSRC, Cisco Talos, Palo Alto Unit42, VMware advisories. Add to Intel Wall CVE filter category
- [ ] **EPSS score change alerts** — Notify when a CVE's EPSS exploitation probability jumps significantly (e.g. +20% in one poll cycle)
- [ ] **Asset risk heat map** — Grid view: assets vs CVE count, coloured by highest severity unpatched
- [ ] **Compliance mapping** — Map CVEs to CIS Controls or NIST 800-53 for audit reporting

### Intel Wall
- [ ] **More feed sources** — Exploit-DB RSS, PacketStorm, GitHub Security Advisories, OSV (open source vulnerabilities). Currently: CISA, The Hacker News, BleepingComputer, Krebs, SANS ISC
- [ ] **Full article view** — Clicking a card currently opens external link. Consider embedded article reader

### OSINT
- [ ] **Automated multi-source OSINT** — User inputs email/domain/IP, system crawls multiple sources automatically. Currently requires manual selection of target type. Social media crawling intentionally excluded (ToS/ethics)
- [ ] **Shodan integration** — Already supported if `SHODAN_API_KEY` set in .env. Free account: shodan.io

### Threat Actors
- [ ] **Threat actor profile page improvements** — MITRE ATT&CK free dataset covers ~140 groups. For actors not in MITRE (LockBit, BlackCat, cybercriminal groups), data currently unavailable without Anthropic key. Future: maintain a local JSON file with additional actor profiles

---

## 🟢 Completed

- [x] JWT auth, invite codes, role-based access (admin/analyst)
- [x] IOC CRUD with defang/refang normalization
- [x] Enrichment: VT + AbuseIPDB + URLhaus with 24h cache
- [x] Confidence scoring with reasons
- [x] STIX 2.1 export + TAXII 2.1 server
- [x] STIX import, TAXII poll, MISP pull, CSV upload
- [x] IOC relationships (force-directed graph)
- [x] IOC notes per indicator
- [x] IOC score history with explanation
- [x] False positive flagging (excluded from STIX/TAXII exports)
- [x] MITRE ATT&CK technique tagging per IOC
- [x] Campaign clusters
- [x] Subnet pivot (/24 search)
- [x] Global search (fanged + defanged)
- [x] Duplicate check before submit
- [x] AI pre-fill (rule-based, no API key)
- [x] Geo map (country origin of IP IOCs)
- [x] Public lookup (DB-first, auto-add if malicious)
- [x] OSINT tool (DNS, RDAP, Shodan optional, HIBP optional)
- [x] Intel Wall (RSS: CISA, THN, BleepingComputer, Krebs, SANS ISC)
- [x] Threat actor profiles (MITRE ATT&CK free JSON)
- [x] CVE monitor: asset registry with CPE search
- [x] CVE monitor: NVD polling every 6h via APScheduler
- [x] CVE monitor: KEV cross-reference (CISA free JSON)
- [x] CVE monitor: EPSS scoring (FIRST.org free API)
- [x] CVE monitor: patch detection from NVD reference tags
- [x] CVE monitor: auto-extract IOCs from CVE descriptions
- [x] CVE monitor: CVE ↔ IOC linking
- [x] In-app notification system (admin portal bell)
- [x] API usage tracking + cache hit counter
- [x] Audit log (admin only, inside Settings)
- [x] 3 themes: Operator (dark), Nebula (purple glow), Light
- [x] Inter font for Nebula/Light, Space Mono for Operator
- [x] CI/CD: GitHub Actions → SSH → server auto-deploy
- [x] Tab title: TFII — ThreatFeed Intelligence

---

## ❌ Cancelled / Out of Scope

- **Email digest** — Weekly summary email to all users. Cancelled in favour of in-app notifications
- **MISP push** — Only pull implemented. Push deferred indefinitely
- **Social media crawling** — Against platform ToS; excluded from OSINT feature
- **CVE patch status / SLA workflow** — Removed from scope to keep CVE page clean. Only patch available/not available indicator kept
- **Webhook notifications** — Deferred; in-app notifications used instead

---

## 🔧 Infrastructure Notes

- **Server**: Oracle Cloud Free Tier ARM VM, Ubuntu 22.04, IP: YOUR_SERVER_IP
- **Domain**: YOUR_DOMAIN
- **Stack**: FastAPI + PostgreSQL + Nginx + Certbot + React (CRA)
- **Venv**: /home/ubuntu/threatfeed/venv
- **Backend service**: threatfeed.service (systemd)
- **Frontend build**: /home/ubuntu/threatfeed-ui/build/
- **Nginx serves**: /ui/ → static build, / → FastAPI :8000

---

## 📋 Setup Checklist (New Server)

```bash
# Python deps
pip install fastapi uvicorn psycopg2-binary python-dotenv \
  python-jose[cryptography] passlib[bcrypt] python-multipart \
  httpx apscheduler bcrypt==4.0.1

# .env required keys
DB_HOST, DB_NAME, DB_USER, DB_PASS, SECRET_KEY

# .env optional keys (features degrade gracefully without these)
VT_API_KEY          # virustotal.com
ABUSEIPDB_API_KEY   # abuseipdb.com
NVD_API_KEY         # nvd.nist.gov/developers (free, improves rate limit)
HIBP_API_KEY        # haveibeenpwned.com/API/Key
SHODAN_API_KEY      # shodan.io
```
