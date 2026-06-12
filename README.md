# TFII — ThreatFeed Intelligence Platform

> Production-grade threat intelligence portal. Self-hosted, open source, $0/month infrastructure.

**IOC management · CVE monitoring · Detection engineering · OSINT · CVE Wall · KQL/SPL builder**

---

## Quick Start

Two paths — pick one:

### 🐳 Docker (recommended — 5 minutes)

```bash
git clone https://github.com/sherifrahim/TFII.git && cd TFII
chmod +x scripts/docker-setup.sh && ./scripts/docker-setup.sh
```

The script creates your `.env`, generates secrets, builds the containers, and opens the platform. Choose HTTP (local/dev) or HTTPS (production — auto Let's Encrypt via Caddy).

### 🔧 Manual (bare metal / existing server)

See [Manual Deployment Guide](#manual-deployment) below.

---

## Features

| Module | What it does |
|--------|-------------|
| **IOC Management** | Add, enrich, track indicators. VirusTotal + AbuseIPDB + URLhaus enrichment. STIX 2.1 export, TAXII 2.1 server |
| **CVE Monitor** | Track your software stack. NVD polling every 6h. CISA KEV cross-reference, EPSS scoring, patch detection |
| **CVE Intelligence** | Multi-source lookup: NVD, CVE.org, OSV, CVE Trends, EPSS, CISA KEV. Visual CVSS breakdown. PoC search (GitHub, Metasploit, Vulhub, ExploitDB) |
| **CVE Report** | Generate professional advisory emails or summary briefs with one click |
| **Detection Builder** | KQL/SPL query builder (3 production variants per use case). KQL Explainer — paste any query, get line-by-line analysis |
| **Intel Wall** | Live RSS from CISA, SANS ISC, BleepingComputer, Krebs, and more |
| **CVE Wall** | Vulnerability-specific advisories from 12 sources. Filterable by severity, time, source |
| **OSINT** | DNS, WHOIS, Shodan, HaveIBeenPwned, MX in one tabbed view |
| **Threat Actors** | MITRE ATT&CK integration — actor profiles, TTPs, malware, tools |

---

## Infrastructure (all free)

| Component | Free tier |
|-----------|-----------|
| Compute | Oracle Cloud ARM VM — 4 OCPU, 24GB RAM, permanent free |
| NVD | CVE database API — free with registration |
| CISA KEV | Known exploited vulnerabilities — free JSON feed |
| EPSS | Exploitation probability — free API from FIRST.org |
| MITRE ATT&CK | Threat actor data — free open-source CTI dataset |
| Groq (LLaMA 3.3 70B) | KQL/SPL generation — 14,400 free requests/day |
| URLhaus | Abuse.ch IOC feeds — free API |

**Monthly cost: $0**

---

## Docker Deployment

### Prerequisites
- Docker Engine 24+ and Docker Compose v2
- A domain pointing to your server (for HTTPS)
- Ports 80/443 open (HTTPS) or just 80 (HTTP)

### One-command setup
```bash
./scripts/docker-setup.sh
```

### Manual Docker steps
```bash
# 1. Copy and configure environment
cp .env.example .env
nano .env          # Set DOMAIN, DB_PASS, and generate SECRET_KEY

# 2. Build and start (HTTP)
docker compose up -d --build

# 3. With auto-HTTPS (requires domain → server)
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d --build
```

### Common Docker commands
```bash
docker compose logs -f backend      # Backend logs
docker compose ps                   # Service status
docker compose down                 # Stop
docker compose pull && docker compose up -d   # Update
docker compose exec postgres psql -U threatfeed threatfeeddb   # DB access
```

---

## Manual Deployment

Tested on Ubuntu 22.04. Requires: Python 3.10+, Node.js 20+, PostgreSQL 15+, Nginx.

### 1. System setup
```bash
sudo apt update && sudo apt install -y python3-pip python3-venv nodejs npm nginx certbot python3-certbot-nginx postgresql
```

### 2. Database
```bash
sudo -u postgres psql -c "CREATE USER threatfeed WITH PASSWORD 'your_password';"
sudo -u postgres psql -c "CREATE DATABASE threatfeeddb OWNER threatfeed;"
```

### 3. Backend
```bash
git clone https://github.com/sherifrahim/TFII.git /opt/tfii
cd /opt/tfii
python3 -m venv venv && source venv/bin/activate
pip install -r backend/requirements.txt

cp .env.example .env
nano .env    # Fill in all values

# systemd service
sudo cp scripts/threatfeed.service /etc/systemd/system/
sudo systemctl enable --now threatfeed
```

### 4. Frontend
```bash
cd /opt/tfii/frontend-ui    # or wherever your CRA project lives
# Substitute domain into App.js
sed "s|YOUR_DOMAIN|your-domain.com|g" /opt/tfii/frontend/src/App.js > src/App.js
npm install && npm run build
```

### 5. Nginx + HTTPS
```bash
sudo certbot --nginx -d your-domain.com
# Configure nginx to serve /ui/ from the React build and proxy / to port 8000
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DOMAIN` | ✓ | Your domain (e.g. `tfii.example.com`) |
| `DB_HOST` | ✓ | `postgres` (Docker) or `localhost` (manual) |
| `DB_NAME` | ✓ | Database name (default: `threatfeeddb`) |
| `DB_USER` | ✓ | Database user |
| `DB_PASS` | ✓ | Database password |
| `SECRET_KEY` | ✓ | JWT signing key — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ALLOWED_ORIGINS` | ✓ | `https://your-domain.com` |
| `ENCRYPTION_KEY` | ✓ | Fernet key for stored API keys |
| `GROQ_API_KEY` | Optional | KQL/SPL query builder ([console.groq.com](https://console.groq.com)) |
| `VT_API_KEY` | Optional | VirusTotal enrichment |
| `ABUSEIPDB_API_KEY` | Optional | AbuseIPDB enrichment |
| `NVD_API_KEY` | Optional | Higher NVD rate limits ([nvd.nist.gov/developers](https://nvd.nist.gov/developers)) |
| `SHODAN_API_KEY` | Optional | Shodan OSINT |
| `HIBP_API_KEY` | Optional | HaveIBeenPwned email lookup |

---

## Default Credentials

| | |
|-|-|
| Username | `admin` |
| Password | `TFeed@99` |

**Change the password immediately** — Settings → Change Password.

New users require an invite code generated by an admin (Settings → Invites).

---

## Security Notes

- Signup is invite-only — admins generate codes, no open registration
- CORS locked to `ALLOWED_ORIGINS` — no wildcard in production
- Rate limiting: login 10/min, signup 5/hr
- Per-user API keys encrypted at rest (Fernet)
- Port 8000 (backend) not exposed externally — Nginx/Caddy proxies everything
- Scrub your deployment of any secrets before sharing: `git-filter-repo --replace-text replacements.txt`

---

## Contributing

Issues and PRs welcome. If you find a bug or have a feature idea, open an issue.

---

## License

MIT
