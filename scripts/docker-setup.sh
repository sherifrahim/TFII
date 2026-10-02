#!/usr/bin/env bash
# TFII Docker Setup Script
# Guides you through first-time configuration and starts the platform

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   TFII — ThreatFeed Intelligence Platform    ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── Check dependencies ────────────────────────────────────────────────────────
echo -e "${BOLD}Checking dependencies...${NC}"
for cmd in docker python3; do
    if ! command -v $cmd &>/dev/null; then
        echo -e "${RED}✗ $cmd is not installed${NC}"
        exit 1
    fi
done
if ! docker compose version &>/dev/null; then
    echo -e "${RED}✗ Docker Compose v2 not found. Install Docker Desktop or 'docker-compose-plugin'${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker and Docker Compose found${NC}"
echo ""

# ── Create .env if it doesn't exist ──────────────────────────────────────────
if [ ! -f .env ]; then
    echo -e "${YELLOW}No .env file found. Creating from template...${NC}"
    cp .env.example .env

    # Generate secrets automatically
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    DB_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    # A Fernet key is 32 random bytes, URL-safe base64 encoded. Built from the standard library so it does not
    # depend on the host having the `cryptography` package installed.
    ENCRYPTION_KEY=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
    ADMIN_PW=$(python3 -c "import secrets; print(secrets.token_urlsafe(14))")

    sed -i "s|replace_with_64_char_hex_string|${SECRET_KEY}|g" .env
    sed -i "s|change_this_strong_password|${DB_PASS}|g" .env
    sed -i "s|^ADMIN_INITIAL_PASSWORD=.*|ADMIN_INITIAL_PASSWORD=${ADMIN_PW}|" .env
    sed -i "s|replace_with_fernet_key|${ENCRYPTION_KEY}|g" .env

    echo -e "${GREEN}✓ .env created with auto-generated secrets${NC}"
    echo ""
    echo -e "${YELLOW}⚠ You must set your DOMAIN in .env before starting:${NC}"
    echo "   nano .env"
    echo ""
    read -p "Press Enter when you've set DOMAIN in .env, or Ctrl+C to exit..."
    echo ""
fi

# A placeholder left in .env (for example from an older run of this script) would be used as a real secret.
if grep -q -E "replace_with_|change_this_strong_password" .env; then
    echo -e "${RED}✗ .env still contains a placeholder (replace_with_… or change_this_strong_password).${NC}"
    echo "  Fill it in, or delete .env and run this script again to generate fresh secrets."
    exit 1
fi

# ── Read DOMAIN from .env ─────────────────────────────────────────────────────
DOMAIN=$(grep "^DOMAIN=" .env | cut -d= -f2)
if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "your-domain.com" ]; then
    echo -e "${RED}✗ DOMAIN is not set in .env. Please edit .env and set your domain.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Domain: ${DOMAIN}${NC}"

# ── Choose HTTP or HTTPS ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Deployment mode:${NC}"
echo "  1) HTTP only        (for local/testing — http://localhost)"
echo "  2) HTTPS via Caddy  (for production — auto Let's Encrypt)"
echo ""
read -p "Choose [1/2]: " MODE

if [ "$MODE" = "2" ]; then
    echo ""
    echo -e "${YELLOW}Note: HTTPS requires:${NC}"
    echo "  - Your domain (${DOMAIN}) pointing to this server's IP"
    echo "  - Ports 80 and 443 open in your firewall"
    echo ""
    COMPOSE_FILES="-f docker-compose.yml -f docker-compose.https.yml"
    echo -e "${GREEN}✓ HTTPS mode selected${NC}"
else
    COMPOSE_FILES="-f docker-compose.yml"
    echo -e "${GREEN}✓ HTTP mode selected${NC}"
fi

# ── Build and start ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Building and starting TFII...${NC}"
echo "(First build takes 3-5 minutes — subsequent starts are fast)"
echo ""

docker compose $COMPOSE_FILES build
docker compose $COMPOSE_FILES up -d

# ── Wait for backend to be ready ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}Waiting for services to start...${NC}"
for i in {1..30}; do
    if docker compose exec -T backend python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" &>/dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend ready${NC}"
        break
    fi
    sleep 2
    echo -n "."
done
echo ""

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║                TFII is running!              ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
if [ "$MODE" = "2" ]; then
    echo -e "  🌐 Open: ${BOLD}https://${DOMAIN}/ui/${NC}"
else
    echo -e "  🌐 Open: ${BOLD}http://localhost/ui/${NC}"
fi
echo ""
ADMIN_PW=$(grep "^ADMIN_INITIAL_PASSWORD=" .env | cut -d= -f2-)
echo -e "  👤 First admin login:"
echo -e "     Username: ${BOLD}admin${NC}"
if [ -n "$ADMIN_PW" ]; then
    echo -e "     Password: ${BOLD}${ADMIN_PW}${NC}   (generated for you; it is also in .env)"
else
    echo -e "     Password: printed once in the backend log:  ${BOLD}docker compose logs backend | grep 'First-run admin'${NC}"
fi
echo ""
echo -e "${YELLOW}  ⚠ Change the admin password on first login (Settings → Change Password).${NC}"
echo -e "    The password only applies on the first start; later edits to .env do not change it."
echo ""
echo -e "  Useful commands:"
echo -e "     ${BOLD}docker compose logs -f backend${NC}   — view logs"
echo -e "     ${BOLD}docker compose ps${NC}                — service status"
echo -e "     ${BOLD}docker compose down${NC}              — stop everything"
echo -e "     ${BOLD}docker compose pull && docker compose up -d${NC} — update"
echo ""
