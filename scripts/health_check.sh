#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TFII Health Check Script
# Run manually:  bash /home/ubuntu/threatfeed-repo/scripts/health_check.sh
# Or via cron:   0 * * * * /home/ubuntu/threatfeed-repo/scripts/health_check.sh >> /var/log/tfii-health.log 2>&1
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
DOMAIN="${DOMAIN:-threatintel.mooo.com}"
TFII_SERVICE="threatfeed"
DB_NAME="${DB_NAME:-threatfeeddb}"
DB_USER="${DB_USER:-threatfeed}"
ENV_FILE="/home/ubuntu/threatfeed/.env"
LOG_FILE="/var/log/tfii-health.log"

# Load .env if present (gives us DB_PASS etc)
[ -f "$ENV_FILE" ] && set -o allexport && source "$ENV_FILE" && set +o allexport 2>/dev/null || true

PASS=0; WARN=0; FAIL=0
check_result() {
    local label="$1" status="$2" detail="$3"
    if   [ "$status" = "ok"   ]; then echo -e " ${GREEN}✓${NC} $label${detail:+ — $detail}"; ((PASS++))
    elif [ "$status" = "warn" ]; then echo -e " ${YELLOW}⚠${NC} $label${detail:+ — $detail}"; ((WARN++))
    else                              echo -e " ${RED}✗${NC} $label${detail:+ — $detail}"; ((FAIL++)); fi
}

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  TFII Health Check  —  $(date '+%Y-%m-%d %H:%M:%S %Z')${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"

# ── 1. systemd service ────────────────────────────────────────────────────────
echo -e "\n${BOLD}[ System ]${NC}"
if systemctl is-active --quiet "$TFII_SERVICE" 2>/dev/null; then
    UPTIME=$(systemctl show "$TFII_SERVICE" --property=ActiveEnterTimestamp --value 2>/dev/null | xargs -I{} date -d {} '+%Y-%m-%d %H:%M' 2>/dev/null || echo "unknown")
    check_result "TFII service ($TFII_SERVICE)" "ok" "running since $UPTIME"
else
    check_result "TFII service ($TFII_SERVICE)" "fail" "NOT RUNNING — sudo systemctl start $TFII_SERVICE"
fi

# ── 2. Backend HTTP ────────────────────────────────────────────────────────────
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000/health" --max-time 5 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    check_result "Backend HTTP (localhost:8000)" "ok" "HTTP $HTTP_CODE"
else
    check_result "Backend HTTP (localhost:8000)" "fail" "HTTP $HTTP_CODE — backend not responding"
fi

# ── 3. Public HTTPS ───────────────────────────────────────────────────────────
HTTPS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN/health" --max-time 8 2>/dev/null || echo "000")
if [ "$HTTPS_CODE" = "200" ]; then
    check_result "Public HTTPS ($DOMAIN)" "ok" "HTTP $HTTPS_CODE"
elif [ "$HTTPS_CODE" = "000" ]; then
    check_result "Public HTTPS ($DOMAIN)" "fail" "No response — nginx or cert issue?"
else
    check_result "Public HTTPS ($DOMAIN)" "warn" "HTTP $HTTPS_CODE"
fi

# ── 4. SSL certificate ───────────────────────────────────────────────────────
CERT_EXPIRY=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
if [ -n "$CERT_EXPIRY" ]; then
    EXPIRY_TS=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null || echo 0)
    NOW_TS=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_TS - NOW_TS) / 86400 ))
    if   [ "$DAYS_LEFT" -gt 14 ]; then check_result "SSL certificate" "ok"   "expires in ${DAYS_LEFT}d"
    elif [ "$DAYS_LEFT" -gt 0  ]; then check_result "SSL certificate" "warn" "expires in ${DAYS_LEFT}d — renew soon"
    else                               check_result "SSL certificate" "fail" "EXPIRED"
    fi
else
    check_result "SSL certificate" "warn" "could not check"
fi

# ── 5. Nginx ──────────────────────────────────────────────────────────────────
if systemctl is-active --quiet nginx 2>/dev/null; then
    check_result "Nginx" "ok" "running"
else
    check_result "Nginx" "fail" "NOT RUNNING"
fi

# ── 6. PostgreSQL ─────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[ Database ]${NC}"
if systemctl is-active --quiet postgresql 2>/dev/null; then
    check_result "PostgreSQL service" "ok" "running"
    # Quick connection test
    if PGPASSWORD="${DB_PASS:-}" psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" -q --no-align -t 2>/dev/null | grep -q "1"; then
        IOC_COUNT=$(PGPASSWORD="${DB_PASS:-}" psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT COUNT(*) FROM iocs" -q --no-align -t 2>/dev/null || echo "?")
        CVE_COUNT=$(PGPASSWORD="${DB_PASS:-}" psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT COUNT(*) FROM cve_findings" -q --no-align -t 2>/dev/null || echo "?")
        ASSET_COUNT=$(PGPASSWORD="${DB_PASS:-}" psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT COUNT(*) FROM assets WHERE active=TRUE" -q --no-align -t 2>/dev/null || echo "?")
        check_result "PostgreSQL connection" "ok" "${IOC_COUNT} IOCs  ${CVE_COUNT} CVE findings  ${ASSET_COUNT} active assets"
    else
        check_result "PostgreSQL connection" "fail" "cannot connect to $DB_NAME as $DB_USER"
    fi
else
    check_result "PostgreSQL service" "fail" "NOT RUNNING"
fi

# ── 7. Last CVE poll ─────────────────────────────────────────────────────────
echo -e "\n${BOLD}[ CVE Monitor ]${NC}"
LAST_POLL=$(PGPASSWORD="${DB_PASS:-}" psql -U "$DB_USER" -d "$DB_NAME" \
    -c "SELECT polled_at, assets_polled, new_cves FROM cve_poll_log ORDER BY polled_at DESC LIMIT 1" \
    -q --no-align -t 2>/dev/null || echo "")
if [ -n "$LAST_POLL" ]; then
    POLL_AT=$(echo "$LAST_POLL" | cut -d'|' -f1)
    ASSETS=$(echo "$LAST_POLL" | cut -d'|' -f2)
    NEW_CVES=$(echo "$LAST_POLL" | cut -d'|' -f3)
    POLL_TS=$(date -d "$POLL_AT" +%s 2>/dev/null || echo 0)
    HOURS_AGO=$(( ($(date +%s) - POLL_TS) / 3600 ))
    if [ "$HOURS_AGO" -lt 8 ]; then
        check_result "Last CVE poll" "ok" "${HOURS_AGO}h ago | ${ASSETS} assets | ${NEW_CVES} new CVEs"
    else
        check_result "Last CVE poll" "warn" "${HOURS_AGO}h ago — STALE (scheduler may not be running)"
    fi
else
    check_result "Last CVE poll" "warn" "No poll has run yet"
fi

# ── 8. Disk ───────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[ Resources ]${NC}"
DISK_INFO=$(df -h / | tail -1)
DISK_PCT=$(echo "$DISK_INFO" | awk '{print $5}' | tr -d '%')
DISK_FREE=$(echo "$DISK_INFO" | awk '{print $4}')
if   [ "$DISK_PCT" -lt 80 ]; then check_result "Disk (/)" "ok"   "${DISK_PCT}% used, ${DISK_FREE} free"
elif [ "$DISK_PCT" -lt 90 ]; then check_result "Disk (/)" "warn" "${DISK_PCT}% used, ${DISK_FREE} free — getting full"
else                               check_result "Disk (/)" "fail" "${DISK_PCT}% used — CRITICAL"
fi

# ── 9. Memory ────────────────────────────────────────────────────────────────
MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
MEM_AVAIL=$(free -m | awk '/^Mem:/{print $7}')
MEM_USED=$((MEM_TOTAL - MEM_AVAIL))
MEM_PCT=$((MEM_USED * 100 / MEM_TOTAL))
if   [ "$MEM_PCT" -lt 80 ]; then check_result "Memory" "ok"   "${MEM_PCT}% used, ${MEM_AVAIL}MB available"
elif [ "$MEM_PCT" -lt 90 ]; then check_result "Memory" "warn" "${MEM_PCT}% used — getting low"
else                              check_result "Memory" "fail" "${MEM_PCT}% used — CRITICAL"
fi

# ── 10. External APIs ─────────────────────────────────────────────────────────
echo -e "\n${BOLD}[ External APIs ]${NC}"
check_api() {
    local name="$1" url="$2"
    local code=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 6 2>/dev/null || echo "000")
    if [[ "$code" =~ ^(200|201|206|400|401|403)$ ]]; then
        check_result "$name" "ok" "reachable (HTTP $code)"
    else
        check_result "$name" "warn" "unreachable (HTTP $code)"
    fi
}
check_api "NVD API"   "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
check_api "CISA KEV"  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
check_api "EPSS"      "https://api.first.org/data/v1/epss?limit=1"
check_api "URLhaus"   "https://urlhaus-api.abuse.ch/v1/info/"
check_api "ip-api"    "http://ip-api.com/json/8.8.8.8"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
TOTAL=$((PASS + WARN + FAIL))
echo -e "  ${GREEN}✓ $PASS passed${NC}  ${YELLOW}⚠ $WARN warnings${NC}  ${RED}✗ $FAIL failed${NC}  (${TOTAL} checks)"
if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}${BOLD}OVERALL: DEGRADED${NC}"
elif [ "$WARN" -gt 0 ]; then
    echo -e "  ${YELLOW}${BOLD}OVERALL: WARNING${NC}"
else
    echo -e "  ${GREEN}${BOLD}OVERALL: HEALTHY${NC}"
fi
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Exit with non-zero if failures (useful for cron/alerting)
[ "$FAIL" -eq 0 ]
