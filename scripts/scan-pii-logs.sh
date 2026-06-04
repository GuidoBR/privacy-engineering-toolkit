#!/usr/bin/env bash
# scan-pii-logs.sh — detect PII in log/print statements across a codebase
#
# Usage:
#   ./scripts/scan-pii-logs.sh [options] [directory]
#
# Options:
#   -d, --dir DIR        Directory to scan (default: current directory)
#   -f, --format FORMAT  Output format: text (default), json, sarif
#   -s, --strict         Also flag medium-confidence patterns (usernames, IDs)
#   -q, --quiet          Only print findings, no headers
#   -h, --help           Show this help
#
# Exit codes:
#   0  No findings
#   1  Findings detected
#   2  Script error

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
SCAN_DIR="."
FORMAT="text"
STRICT=false
QUIET=false
FOUND=0
TOTAL_MATCHES=0

# ── colours (disabled when not a terminal) ──────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

# ── argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--dir)   SCAN_DIR="$2"; shift 2 ;;
    -f|--format) FORMAT="$2"; shift 2 ;;
    -s|--strict) STRICT=true; shift ;;
    -q|--quiet)  QUIET=true; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) SCAN_DIR="$1"; shift ;;
  esac
done

if [ ! -d "$SCAN_DIR" ]; then
  echo "Error: directory '$SCAN_DIR' not found" >&2
  exit 2
fi

# ── pattern definitions ───────────────────────────────────────────────────────
# Each entry: "LABEL|SEVERITY|EXTENSIONS|GREP_PATTERN"
# SEVERITY: CRITICAL | HIGH | MEDIUM
declare -a PATTERNS=(

  # ── Python (loguru / stdlib logging) ────────────────────────────────────────
  "Email in Python log|CRITICAL|py|logger\.(debug|info|warning|error|exception|critical)\(.*\{[^}]*\bemail\b[^}]*\}"
  "Password in Python log|CRITICAL|py|logger\.(debug|info|warning|error|exception|critical)\(.*\{[^}]*\bpassword\b[^}]*\}"
  "Phone in Python log|HIGH|py|logger\.(debug|info|warning|error|exception|critical)\(.*\{[^}]*\bphone\b[^}]*\}"
  "SSN/CPF in Python log|CRITICAL|py|logger\.(debug|info|warning|error|exception|critical)\(.*\{[^}]*(ssn|cpf|tax_id|sin)\b[^}]*\}"
  "Raw token in Python log|HIGH|py|logger\.(debug|info|warning|error|exception|critical)\(.*\{[^}]*\btoken\b[^}]*\}(?!.*hash|.*ref|.*id)"
  "Address in Python log|HIGH|py|logger\.(debug|info|warning|error|exception|critical)\(.*\{[^}]*(address|street|postal|zipcode|zip_code)\b[^}]*\}"
  "Request body in Python log|CRITICAL|py|(logger|print)\(.*\b(request\.body|request\.data|req\.data|payload)\b"
  "Email in Python print|HIGH|py|print\(.*\{[^}]*\bemail\b[^}]*\}"

  # ── JavaScript / TypeScript ──────────────────────────────────────────────────
  "Email in JS console|CRITICAL|ts,tsx,js,jsx|console\.(log|error|warn|info|debug)\(.*\\\$\{[^}]*\bemail\b[^}]*\}"
  "Password in JS console|CRITICAL|ts,tsx,js,jsx|console\.(log|error|warn|info|debug)\(.*\\\$\{[^}]*\bpassword\b[^}]*\}"
  "Token in JS console|HIGH|ts,tsx,js,jsx|console\.(log|error|warn|info|debug)\(.*\\\$\{[^}]*\btoken\b[^}]*\}"
  "Phone in JS console|HIGH|ts,tsx,js,jsx|console\.(log|error|warn|info|debug)\(.*\\\$\{[^}]*(phone|mobile)\b[^}]*\}"
  "SSN in JS console|CRITICAL|ts,tsx,js,jsx|console\.(log|error|warn|info|debug)\(.*\\\$\{[^}]*(ssn|cpf|tax_id)\b[^}]*\}"
  "Request body in JS log|CRITICAL|ts,tsx,js,jsx|(console\.(log|error)|logger\.(info|error))\(.*\b(req\.body|request\.body)\b"

  # ── Go ──────────────────────────────────────────────────────────────────────
  "Email in Go log|CRITICAL|go|log\.(Print|Fatal|Panic|Error|Warn|Info|Debug).*[^_]\bemail\b"
  "Password in Go log|CRITICAL|go|log\.(Print|Fatal|Panic|Error|Warn|Info|Debug).*\bpassword\b"
  "Token in Go log|HIGH|go|log\.(Print|Fatal|Panic|Error|Warn|Info|Debug).*\btoken\b"

  # ── Java / Kotlin ────────────────────────────────────────────────────────────
  "Email in Java log|CRITICAL|java,kt|log(ger)?\.(debug|info|warn|error)\(.*\bemail\b"
  "Password in Java log|CRITICAL|java,kt|log(ger)?\.(debug|info|warn|error)\(.*\bpassword\b"

  # ── Ruby ─────────────────────────────────────────────────────────────────────
  "Email in Ruby log|CRITICAL|rb|Rails\.logger\.(debug|info|warn|error|fatal).*\bemail\b"
  "Password in Ruby log|CRITICAL|rb|Rails\.logger\.(debug|info|warn|error|fatal).*\bpassword\b"

  # ── Structured loggers — Python ───────────────────────────────────────────────
  # loguru: logger.bind(email=x, phone=x).info(...)
  "PII in loguru bind()|CRITICAL|py|logger\.bind\([^)]*\b(email|phone|password|ssn|cpf|address|token)\b"
  # structlog / stdlib extra={}: log.info("msg", email=x) or logging.info("msg", extra={"email": x})
  "PII in structlog keyword arg|CRITICAL|py|(logger|log)\.(info|debug|warning|error|exception)\([^,)]+,\s*(email|phone|password|ssn|cpf|address)\s*="
  "PII in logging extra dict|HIGH|py|logging\.(info|debug|warning|error)\(.*extra\s*=.*\b(email|phone|password|ssn|cpf)\b"
  # Exception message forwarded directly to logger — may contain PII strings
  "Exception str() forwarded to log|HIGH|py|logger\.(exception|error|warning)\(\s*str\s*\(\s*(e|exc|err|error|exception)\s*\)"
  "f-string exception in log|HIGH|py|logger\.(exception|error|warning)\(f['\"].*\{(e|exc|err)\b"
  # Django DB query logging at DEBUG — logs full SQL including parameter values
  "Django DB query logging enabled|HIGH|py|django\.db\.backends.*['\"]LEVEL['\"]\s*:\s*['\"]DEBUG['\"]|logging\.getLogger\(['\"]django\.db"

  # ── Structured loggers — Go (zap / zerolog) ───────────────────────────────────
  # zap.String("email", x), zap.Any("password", x)
  "PII field in zap log|CRITICAL|go|zap\.(String|Any|Reflect|Stringer|Binary)\s*\(\s*\"(email|phone|password|ssn|token|address|cpf)\""
  # zerolog: log.Str("email", x).Msg() or log.With().Str("email", x)
  "PII field in zerolog|CRITICAL|go|\.(Str|String|Interface|Any)\s*\(\s*\"(email|phone|password|ssn|token|address|cpf)\""

  # ── Structured loggers — Node.js (pino) ──────────────────────────────────────
  # pino child({ email }): creates a child logger with PII bound to every line
  "PII in pino child logger|CRITICAL|ts,tsx,js,jsx|(logger|log)\.child\s*\(\s*\{[^}]*(email|phone|password|token|address|ssn)"
  # pino without redact: passing object with PII field directly
  "PII object passed to pino|HIGH|ts,tsx,js,jsx|(logger|log)\.(info|debug|warn|error|trace)\(\s*\{[^}]*(email|phone|password|token)\b"
)

# ── strict-only patterns (medium confidence) ─────────────────────────────────
declare -a STRICT_PATTERNS=(
  "Username in Python log|MEDIUM|py|logger\.(debug|info|warning|error)\(.*\{[^}]*\busername\b[^}]*\}"
  "Full name in Python log|MEDIUM|py|logger\.(debug|info|warning|error)\(.*\{[^}]*(full_name|first_name|last_name)\b[^}]*\}"
  "IP address in Python log|MEDIUM|py|logger\.(debug|info|warning|error)\(.*\{[^}]*(ip_address|client_ip|remote_addr)\b[^}]*\}"
  "Credit card in any log|CRITICAL|py,ts,js,rb,go|log.*\b(card_number|cc_number|credit_card|cvv|cvc)\b"
  # ORM / framework query logging — logs full SQL with bound parameters
  "SQLAlchemy echo mode enabled|MEDIUM|py|create_engine\(.*echo\s*=\s*True"
  "Django DB logging in settings|MEDIUM|py|'django\.db\.backends'|\"django\.db\.backends\""
  # Sentry / error tracker with PII context attached
  "Sentry setUser with PII|MEDIUM|py,ts,tsx,js|Sentry\.(setUser|setExtra|setContext)\s*\(\s*\{[^}]*(email|name|username|phone|ip_address)"
  "Sentry captureException with extra|MEDIUM|py,ts,tsx,js|Sentry\.captureException\(.*extra\s*=\s*\{[^}]*(email|phone|password|address)"
  # pino serializers not redacting known PII fields
  "pino missing req serializer redact|MEDIUM|ts,tsx,js|pino\s*\([^)]*(?!redact)"
  # Winston format without PII scrubber
  "Winston without PII scrubber|MEDIUM|ts,tsx,js|createLogger\s*\([^)]*(?!scrub|redact|pii)"
)

# ── JSON output helpers ─���─────────────────────────────────────────────────────
JSON_FINDINGS="[]"

add_json_finding() {
  local label="$1" severity="$2" file="$3" line="$4" match="$5"
  local escaped_match
  escaped_match=$(echo "$match" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n')
  JSON_FINDINGS=$(echo "$JSON_FINDINGS" | python3 -c "
import json, sys
findings = json.load(sys.stdin)
findings.append({'label': '$label', 'severity': '$severity', 'file': '$file', 'line': $line, 'match': '$escaped_match'})
print(json.dumps(findings, indent=2))
" 2>/dev/null || echo "$JSON_FINDINGS")
}

# ── SARIF output builder ─────��────────────────────────────────────────────────
SARIF_RESULTS="[]"

# ── scan function ────────────────────────────���────────────────────────────────
run_pattern() {
  local label="$1" severity="$2" extensions="$3" pattern="$4"

  # Build --include flags from comma-separated extensions
  local include_flags=()
  IFS=',' read -ra exts <<< "$extensions"
  for ext in "${exts[@]}"; do
    include_flags+=("--include=*.${ext}")
  done

  local matches
  matches=$(grep -rPn "${include_flags[@]}" \
    --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv \
    --exclude-dir=dist --exclude-dir=build --exclude-dir=.git \
    --exclude-dir=__pycache__ --exclude-dir=vendor --exclude-dir=.next \
    --exclude-dir=test --exclude-dir=tests --exclude-dir=spec \
    --exclude-dir=specs --exclude-dir=__tests__ --exclude-dir=fixtures \
    --exclude='*.test.py'  --exclude='*.spec.py' \
    --exclude='*.test.ts'  --exclude='*.spec.ts' \
    --exclude='*.test.js'  --exclude='*.spec.js' \
    --exclude='*.test.tsx' --exclude='*.spec.tsx' \
    --exclude='*_test.go'  --exclude='*_spec.rb' \
    "$pattern" "$SCAN_DIR" 2>/dev/null || true)

  if [ -z "$matches" ]; then
    return
  fi

  FOUND=1

  while IFS= read -r match_line; do
    [ -z "$match_line" ] && continue
    TOTAL_MATCHES=$((TOTAL_MATCHES + 1))

    local file line_no code
    file=$(echo "$match_line" | cut -d: -f1)
    line_no=$(echo "$match_line" | cut -d: -f2)
    code=$(echo "$match_line" | cut -d: -f3-)

    case "$FORMAT" in
      text)
        local color="$RED"
        [ "$severity" = "HIGH" ] && color="$YELLOW"
        [ "$severity" = "MEDIUM" ] && color="$CYAN"
        echo -e "${color}[${severity}]${RESET} ${BOLD}${label}${RESET}"
        echo -e "  ${file}:${line_no}"
        echo -e "  ${CYAN}${code}${RESET}"
        echo ""
        ;;
      json)
        add_json_finding "$label" "$severity" "$file" "$line_no" "$code"
        ;;
      sarif)
        # Minimal SARIF — collected at the end
        SARIF_RESULTS="${SARIF_RESULTS}|${severity}|${label}|${file}|${line_no}|${code}"
        ;;
    esac
  done <<< "$matches"
}

# ── header ─────��──────────────────────────────────────────────────────────────
if [ "$QUIET" = false ] && [ "$FORMAT" = "text" ]; then
  echo -e "${BOLD}Privacy PII Log Scanner${RESET}"
  echo -e "Scanning: ${CYAN}${SCAN_DIR}${RESET}"
  echo -e "Patterns: standard$([ "$STRICT" = true ] && echo " + strict" || echo "")"
  echo "──���───────────────────────────────────────────────────"
  echo ""
fi

# ── run all patterns ─────��────────────────────────────���───────────────────────
for entry in "${PATTERNS[@]}"; do
  IFS='|' read -r label severity extensions pattern <<< "$entry"
  run_pattern "$label" "$severity" "$extensions" "$pattern"
done

if [ "$STRICT" = true ]; then
  for entry in "${STRICT_PATTERNS[@]}"; do
    IFS='|' read -r label severity extensions pattern <<< "$entry"
    run_pattern "$label" "$severity" "$extensions" "$pattern"
  done
fi

# ── output final report ─────��─────────────────────────────────────────────────
case "$FORMAT" in
  text)
    echo "──────────────────────────────────────────────────────"
    if [ "$FOUND" -eq 0 ]; then
      echo -e "${GREEN}✓ No PII patterns detected in log statements.${RESET}"
    else
      echo -e "${RED}✗ ${TOTAL_MATCHES} finding(s) detected.${RESET}"
      echo ""
      echo "Remediation:"
      echo "  1. Remove the PII from the log call (use IDs, not values)"
      echo "  2. Add a log-scrubbing filter (see cookbook/pii-scrubber-logging.md)"
      echo "  3. Add this script to your pre-commit hooks and CI"
      echo "  See: https://github.com/guidopercu/privacy-engineering-toolkit"
    fi
    ;;
  json)
    echo "$JSON_FINDINGS"
    ;;
  sarif)
    # Emit minimal SARIF 2.1.0
    python3 - "$SARIF_RESULTS" <<'PYEOF'
import sys, json
raw = sys.argv[1]
results = []
if raw != "[]":
    for entry in raw.split("|")[1:]:  # skip leading empty
        parts = entry.split("|", 4)
        if len(parts) == 5:
            sev, label, file, line, text = parts
            results.append({
                "ruleId": label.replace(" ", "_").lower(),
                "level": "error" if sev == "CRITICAL" else "warning",
                "message": {"text": f"{label}: {text.strip()}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": int(line) if line.isdigit() else 1}
                }}]
            })
sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "scan-pii-logs", "version": "1.0.0",
        "rules": []}}, "results": results}]
}
print(json.dumps(sarif, indent=2))
PYEOF
    ;;
esac

exit $FOUND
