#!/usr/bin/env bash
# scan-trackers.sh — detect analytics, advertising, and tracking SDKs in frontend code
#
# Checks whether each tracker found is wrapped in a consent gate.
# Exits 1 if any tracker loads unconditionally (without consent check).
#
# Usage:
#   ./scripts/scan-trackers.sh [directory]
#   ./scripts/scan-trackers.sh src/
#   ./scripts/scan-trackers.sh --dir frontend/src --format json

set -euo pipefail

SCAN_DIR="."
FORMAT="text"
FOUND=0

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--dir)    SCAN_DIR="$2"; shift 2 ;;
    -f|--format) FORMAT="$2"; shift 2 ;;
    *) SCAN_DIR="$1"; shift ;;
  esac
done

# ── Tracker signatures ────────────────────────────────────────────────────────
# Format: "TRACKER_NAME|CATEGORY|PATTERN"
declare -a TRACKERS=(
  # Analytics
  "Google Analytics (gtag)|analytics|gtag\(|GoogleAnalyticsObject|UA-[0-9]+-[0-9]+|G-[A-Z0-9]+"
  "Google Tag Manager|analytics|googletagmanager\.com|GTM-[A-Z0-9]+"
  "Mixpanel|analytics|mixpanel\.(init|track|identify)|mixpanel\.com"
  "Amplitude|analytics|amplitude\.(init|track|identify|logEvent)|amplitude\.com"
  "Segment|analytics|analytics\.(load|identify|track|page)\(|cdn\.segment\.com"
  "Heap|analytics|heap\.(init|track|identify)|heap\.io"
  "Hotjar|analytics|hj\(|hotjar\.com|hjid|hjsv"
  "FullStory|analytics|FS\.(init|identify)|fullstory\.com"
  "Posthog|analytics|posthog\.(init|capture|identify)|posthog\.com"
  "Plausible|analytics|plausible\.io"
  "Matomo/Piwik|analytics|_paq\.push|matomo\.org|piwik\.js"
  "Intercom|analytics|Intercom\(|intercom\.com|intercomSettings"
  "Crisp|analytics|CRISP_WEBSITE_ID|crisp\.chat"
  "Drift|analytics|drift\.com|window\.drift"
  # Advertising
  "Facebook Pixel|advertising|fbq\(|connect\.facebook\.net|_fbp\b"
  "Google Ads|advertising|google_conversion|googleadservices\.com"
  "LinkedIn Insight|advertising|linkedin\.com/analytics|_linkedin_data_partner"
  "Twitter/X Pixel|advertising|twq\(|analytics\.twitter\.com|twitter_site_id"
  "TikTok Pixel|advertising|ttq\.(load|track)|analytics\.tiktok\.com"
  "Pinterest Tag|advertising|pintrk\(|ct\.pinterest\.com"
  "Snapchat Pixel|advertising|snaptr\(|tr\.snapchat\.com"
  # Error tracking (may capture PII in stack traces)
  "Sentry|error-tracking|Sentry\.(init|captureException|setUser)|@sentry/"
  "Datadog RUM|error-tracking|datadogrumconfig|browser-agent\.datadoghq"
  "Bugsnag|error-tracking|Bugsnag\.(start|notify)|app\.bugsnag\.com"
  "Rollbar|error-tracking|rollbar\.(init|error)|api\.rollbar\.com"
  "LogRocket|error-tracking|LogRocket\.(init|identify)|logrocket\.com"
  # Session replay (high privacy risk)
  "Microsoft Clarity|session-replay|clarity\(|clarity\.ms"
  "Mouseflow|session-replay|mouseflow\.com|_mfq"
  "Lucky Orange|session-replay|luckyorange\.com|__lo_uid"
)

# ── Consent gate patterns ─────────────────────────────────────────────────────
# If any of these appear in the same file as a tracker, it's likely gated
CONSENT_PATTERNS=(
  "consent" "cookie.*accept" "cookieConsent" "CookieConsent" "gdprConsent"
  "hasConsent" "analyticsEnabled" "trackingEnabled" "allowAnalytics"
  "consentGiven" "userConsent" "cookieYes" "cookiebot" "onetrust"
  "osano" "didomi" "axeptio" "tarteaucitron"
)

# ── scan ──────────────────────────────────────────────────────────────────────
declare -A RESULTS  # tracker -> "file|gated"

INCLUDE_FLAGS=(
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx"
  --include="*.html" --include="*.vue" --include="*.svelte"
)

EXCLUDE_FLAGS=(
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.next
  --exclude-dir=.nuxt --exclude-dir=build --exclude-dir=.git
)

if [ "$FORMAT" = "text" ] && [ -t 1 ]; then
  echo -e "${BOLD}Privacy Tracker Scanner${RESET}"
  echo -e "Scanning: ${CYAN}${SCAN_DIR}${RESET}"
  echo "────���─────────────────────────────────────────────────"
  echo ""
fi

for entry in "${TRACKERS[@]}"; do
  IFS='|' read -r name category pattern <<< "$entry"

  matches=$(grep -rPln "${INCLUDE_FLAGS[@]}" "${EXCLUDE_FLAGS[@]}" \
    "$pattern" "$SCAN_DIR" 2>/dev/null || true)

  [ -z "$matches" ] && continue

  # Check each file for consent gating
  while IFS= read -r file; do
    gated=false
    for cp in "${CONSENT_PATTERNS[@]}"; do
      if grep -qiP "$cp" "$file" 2>/dev/null; then
        gated=true
        break
      fi
    done

    if [ "$FORMAT" = "text" ]; then
      if $gated; then
        echo -e "${GREEN}[GATED]${RESET}   ${BOLD}${name}${RESET} (${category})"
        echo -e "          ${file}"
        echo -e "          ${GREEN}✓ Consent check detected in file${RESET}"
      else
        echo -e "${RED}[UNGATED]${RESET} ${BOLD}${name}${RESET} (${category})"
        echo -e "          ${file}"
        echo -e "          ${RED}✗ No consent gate detected — loads unconditionally${RESET}"
        FOUND=1
      fi
      echo ""
    else
      echo "{\"tracker\":\"${name}\",\"category\":\"${category}\",\"file\":\"${file}\",\"gated\":${gated}}"
    fi
  done <<< "$matches"
done

if [ "$FORMAT" = "text" ]; then
  echo "─────────────��────────────────────────────────────────"
  if [ "$FOUND" -eq 0 ]; then
    echo -e "${GREEN}✓ All detected trackers appear to be consent-gated.${RESET}"
  else
    echo -e "${RED}✗ Ungated trackers detected — these load before user consent.${RESET}"
    echo ""
    echo "This violates:"
    echo "  • GDPR Art. 6(1)(a) — consent required before non-essential cookies"
    echo "  • LGPD Art. 8 — consent must be specific and prior to processing"
    echo "  • ePrivacy Directive — prior consent for analytics cookies"
    echo ""
    echo "See: cookbook/analytics-consent-gating.md for remediation patterns"
  fi
fi

exit $FOUND
