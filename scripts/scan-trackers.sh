#!/usr/bin/env bash
# scan-trackers.sh — detect analytics, advertising, and tracking SDKs in frontend code
#
# Checks whether each tracker call is preceded by a consent guard within
# CONSENT_WINDOW lines. File-level co-occurrence is NOT sufficient — a
# consent variable defined at the top of a file does not gate a tracker
# call at the bottom. This script inspects the lines immediately before
# each tracker match.
#
# NOTE: Line-proximity analysis is a heuristic. It does not parse the AST.
# A result of [GATED] means a consent guard was found within CONSENT_WINDOW
# lines above the tracker call — verify manually that the guard is actually
# conditional (e.g. inside an if block, a .then() callback, or an event handler).
# A result of [UNGATED] means no guard was found in that window — it may
# still be gated at a higher scope; investigate before treating as a violation.
#
# Exits 1 if any tracker appears ungated.
#
# Usage:
#   ./scripts/scan-trackers.sh [directory]
#   ./scripts/scan-trackers.sh src/
#   ./scripts/scan-trackers.sh --dir frontend/src --format json
#   ./scripts/scan-trackers.sh --dir src/ --window 40   # larger window for deep component trees

set -euo pipefail

SCAN_DIR="."
FORMAT="text"
FOUND=0
CONSENT_WINDOW=20  # default: lines above tracker call to search for a consent guard

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
    -w|--window) CONSENT_WINDOW="$2"; shift 2 ;;
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

# ── Consent guard patterns ────────────────────────────────────────────────────
# These are matched against the CONSENT_WINDOW lines immediately preceding
# each tracker call. They indicate a conditional guard — not just the presence
# of a consent library in the same file.
CONSENT_GUARD_PATTERNS=(
  # Conditional checks
  "if\s*\(.*consent"
  "if\s*\(.*cookie"
  "if\s*\(.*tracking"
  "if\s*\(.*analytics"
  "if\s*\(.*hasConsent"
  "if\s*\(.*analyticsEnabled"
  "if\s*\(.*trackingEnabled"
  "if\s*\(.*allowAnalytics"
  # Promise / callback patterns
  "\.then\s*\(.*consent"
  "onAccept\s*[=({]"
  "OnConsentChanged\s*[=({]"
  "onConsentChanged\s*[=({]"
  # CMP-specific callbacks (OneTrust, Cookiebot, Didomi, Osano, etc.)
  "OptanonWrapper"
  "Cookiebot\.onaccept"
  "cookiebot.*onaccept"
  "didomi\.on\s*\("
  "Osano\.cm\.on\s*\("
  "axeptio.*completed"
  "tarteaucitron.*job"
  # Google Consent Mode v2
  "consent_update"
  "update.*consent"
  # React / hook patterns
  "useConsent\s*\("
  "consentGiven\s*===?\s*true"
  "consent\s*===?\s*true"
  "analyticsConsent\s*&&"
  "trackingConsent\s*&&"
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

  # Get files containing this tracker
  match_files=$(grep -rPln "${INCLUDE_FLAGS[@]}" "${EXCLUDE_FLAGS[@]}" \
    "$pattern" "$SCAN_DIR" 2>/dev/null || true)

  [ -z "$match_files" ] && continue

  while IFS= read -r file; do
    # Get line numbers of every tracker call in this file
    tracker_lines=$(grep -nP "$pattern" "$file" 2>/dev/null | cut -d: -f1 || true)
    [ -z "$tracker_lines" ] && continue

    gated=false
    matched_guard=""
    matched_line=""

    while IFS= read -r lnum; do
      # Extract CONSENT_WINDOW lines ending at (and including) the tracker line
      start=$(( lnum > CONSENT_WINDOW ? lnum - CONSENT_WINDOW : 1 ))
      context=$(sed -n "${start},${lnum}p" "$file" 2>/dev/null || true)

      for cp in "${CONSENT_GUARD_PATTERNS[@]}"; do
        guard_hit=$(echo "$context" | grep -iP "$cp" 2>/dev/null | tail -1 || true)
        if [ -n "$guard_hit" ]; then
          gated=true
          matched_guard="$cp"
          matched_line=$(echo "$guard_hit" | sed 's/^[[:space:]]*//')
          break 2
        fi
      done
    done <<< "$tracker_lines"

    if [ "$FORMAT" = "text" ]; then
      if $gated; then
        echo -e "${GREEN}[GATED]${RESET}   ${BOLD}${name}${RESET} (${category})"
        echo -e "          ${file}"
        echo -e "          ${GREEN}✓ Consent guard found within ${CONSENT_WINDOW} lines of tracker call${RESET}"
        echo -e "          ${GREEN}  Guard: $(echo "$matched_line" | cut -c1-80)${RESET}"
        echo -e "          ${YELLOW}  ↳ Verify manually: guard must be conditional, not just declared${RESET}"
      else
        echo -e "${RED}[UNGATED]${RESET} ${BOLD}${name}${RESET} (${category})"
        echo -e "          ${file}"
        echo -e "          ${RED}✗ No consent guard found in ${CONSENT_WINDOW} lines before tracker call${RESET}"
        FOUND=1
      fi
      echo ""
    else
      echo "{\"tracker\":\"${name}\",\"category\":\"${category}\",\"file\":\"${file}\",\"gated\":${gated},\"guard\":\"$(echo "${matched_line}" | sed 's/"/\\"/g' | head -c 120)\"}"
    fi
  done <<< "$match_files"
done

if [ "$FORMAT" = "text" ]; then
  echo "──────────────────────────────────────────────────────"
  if [ "$FOUND" -eq 0 ]; then
    echo -e "${GREEN}✓ All detected trackers have a consent guard in the preceding ${CONSENT_WINDOW} lines.${RESET}"
    echo -e "${YELLOW}  Reminder: [GATED] is a heuristic. Verify each marked result is truly conditional.${RESET}"
  else
    echo -e "${RED}✗ Ungated trackers detected — no consent guard found before tracker call.${RESET}"
    echo ""
    echo "This may violate:"
    echo "  • GDPR Art. 6(1)(a) — consent required before non-essential cookies"
    echo "  • LGPD Art. 8 — consent must be specific and prior to processing"
    echo "  • ePrivacy Directive — prior consent for analytics cookies"
    echo ""
    echo "See: cookbook/analytics-consent-gating.md for remediation patterns"
    echo ""
    echo -e "${YELLOW}Note: [UNGATED] means no consent guard was found within ${CONSENT_WINDOW} lines.${RESET}"
    echo -e "${YELLOW}The tracker may still be gated at a higher scope — investigate before filing a finding.${RESET}"
  fi
fi

exit $FOUND
