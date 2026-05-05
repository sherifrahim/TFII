# TFII — ThreatFeed Intelligence Platform

IOC + CVE intelligence portal with automated enrichment, STIX/TAXII, CVE monitoring, and threat actor profiling.

## Repository Structure

```
tfii/
├── .github/
│   └── workflows/
│       └── deploy.yml          ← Auto-deploy on push to main
├── backend/
│   ├── main.py                 ← FastAPI backend (full platform)
│   └── requirements.txt        ← Python dependencies
├── frontend/
│   ├── src/
│   │   └── App.js              ← React frontend (single file)
│   └── public/
│       └── index.html          ← Tab title etc.
├── scripts/
│   └── server_setup.sh         ← Run once on server to init CI/CD
└── README.md
```

## First-Time CI/CD Setup

### 1. Create the GitHub repo
```bash
gh repo create tfii --private
```

### 2. Push this structure
```bash
git init
git remote add origin https://github.com/YOURNAME/tfii.git
git add .
git commit -m "initial"
git push -u origin main
```

### 3. Run setup script on server (once)
```bash
ssh ubuntu@YOUR_SERVER_IP
bash <(curl -s https://raw.githubusercontent.com/YOURNAME/tfii/main/scripts/server_setup.sh) https://github.com/YOURNAME/tfii.git
```
This will print the SSH private key to add as a GitHub Actions secret.

### 4. Add GitHub Actions secrets
Go to: `https://github.com/YOURNAME/tfii/settings/secrets/actions`

| Secret | Value |
|--------|-------|
| `SERVER_HOST` | `YOUR_SERVER_IP` |
| `SERVER_USER` | `ubuntu` |
| `SERVER_SSH_KEY` | Private key from step 3 |

### 5. Done
Every `git push` to `main` will automatically:
- Copy `backend/main.py` → server → `systemctl restart threatfeed`
- Copy `frontend/src/App.js` → server → `npm run build`
- Only rebuilds what actually changed

## Giving Claude Direct Push Access

To let Claude push code changes directly without you copy-pasting files:

1. Create a GitHub Personal Access Token:
   - GitHub → Settings → Developer Settings → Personal Access Tokens → Tokens (classic)
   - Scopes: `repo` (full)
   - Copy the token

2. In your next Claude conversation, share:
   - Repo URL: `https://github.com/YOURNAME/tfii.git`
   - Token: `ghp_xxxxx...`

Claude will use `bash_tool` to clone, edit, commit, and push directly.
The CI/CD pipeline then auto-deploys to your server within ~60 seconds.

## Environment Variables (.env on server)

```env
DB_HOST=localhost
DB_NAME=threatfeed
DB_USER=threatfeed
DB_PASS=your-db-password
SECRET_KEY=your-secret-key

VT_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
NVD_API_KEY=your-nvd-key         # free at nvd.nist.gov/developers

# Optional
HIBP_API_KEY=your-hibp-key
SHODAN_API_KEY=your-shodan-key
```

## Stack

- **Backend**: FastAPI + PostgreSQL + APScheduler
- **Frontend**: React (single-file, Create React App)
- **Server**: Oracle Cloud Free Tier ARM, Ubuntu 22.04
- **Web**: Nginx + Certbot (HTTPS)
- **CI/CD**: GitHub Actions + SSH deploy
