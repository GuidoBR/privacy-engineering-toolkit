#!/usr/bin/env bash
# init-secret-scanning.sh — bootstrap secret detection in a repository
#
# Installs gitleaks and detect-secrets, scans git history, generates a
# baseline, and patches .pre-commit-config.yaml to run on future commits.
#
# Usage:
#   ./scripts/init-secret-scanning.sh [--skip-history] [--skip-precommit]

set -euo pipefail

SKIP_HISTORY=false
SKIP_PRECOMMIT=false
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

for arg in "$@"; do
  case $arg in
    --skip-history)   SKIP_HISTORY=true ;;
    --skip-precommit) SKIP_PRECOMMIT=true ;;
  esac
done

step() { echo -e "\n${BOLD}${CYAN}▶ $1${RESET}"; }
ok()   { echo -e "${GREEN}  ✓ $1${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $1${RESET}"; }
fail() { echo -e "${RED}  ✗ $1${RESET}"; }

echo -e "${BOLD}Secret Scanning Initializer${RESET}"
echo -e "Repository: ${CYAN}${REPO_ROOT}${RESET}"

# ── 1. Install gitleaks ───────────────��───────────────────────────────────────
step "Installing gitleaks"
if command -v gitleaks &>/dev/null; then
  ok "gitleaks already installed ($(gitleaks version 2>/dev/null || echo 'version unknown'))"
else
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  if [ "$OS" = "Darwin" ] && command -v brew &>/dev/null; then
    brew install gitleaks
    ok "gitleaks installed via Homebrew"
  elif [ "$OS" = "Linux" ]; then
    GITLEAKS_VERSION="8.18.4"
    ARCH_SUFFIX="x64"
    [ "$ARCH" = "aarch64" ] && ARCH_SUFFIX="arm64"
    URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH_SUFFIX}.tar.gz"
    tmpdir=$(mktemp -d)
    curl -sSL "$URL" | tar -xz -C "$tmpdir"
    sudo mv "$tmpdir/gitleaks" /usr/local/bin/gitleaks
    rm -rf "$tmpdir"
    ok "gitleaks ${GITLEAKS_VERSION} installed to /usr/local/bin"
  else
    warn "Could not auto-install gitleaks. Install manually: https://github.com/gitleaks/gitleaks#installing"
  fi
fi

# ── 2. Install detect-secrets ─────────────��───────────────────────────────────
step "Installing detect-secrets"
if command -v detect-secrets &>/dev/null; then
  ok "detect-secrets already installed ($(detect-secrets --version 2>/dev/null || echo 'version unknown'))"
elif command -v pip3 &>/dev/null; then
  pip3 install detect-secrets --quiet
  ok "detect-secrets installed via pip3"
elif command -v pip &>/dev/null; then
  pip install detect-secrets --quiet
  ok "detect-secrets installed via pip"
else
  warn "pip not found. Install detect-secrets manually: pip install detect-secrets"
fi

# ── 3. Scan git history with gitleaks ────────────────────────────────────────
if [ "$SKIP_HISTORY" = false ] && command -v gitleaks &>/dev/null; then
  step "Scanning git history with gitleaks"
  cd "$REPO_ROOT"
  GITLEAKS_REPORT="gitleaks-report.json"
  if gitleaks detect --source . --report-path "$GITLEAKS_REPORT" --report-format json 2>/dev/null; then
    ok "No secrets detected in git history"
    rm -f "$GITLEAKS_REPORT"
  else
    fail "Secrets detected in git history! Review ${GITLEAKS_REPORT}"
    echo ""
    echo "  To view findings:"
    echo "    cat ${GITLEAKS_REPORT} | python3 -m json.tool"
    echo ""
    echo "  If these are false positives, add rules to .gitleaks.toml:"
    echo "    [[allowlists]]"
    echo "    regexes = ['your-false-positive-pattern']"
    echo ""
    echo "  To remove a secret from git history (destructive — coordinate with team):"
    echo "    git filter-repo --path-glob '*.env' --invert-paths"
  fi
fi

# ── 4. Generate detect-secrets baseline ────��─────────────────────────────────
if command -v detect-secrets &>/dev/null; then
  step "Generating detect-secrets baseline"
  cd "$REPO_ROOT"
  BASELINE=".secrets.baseline"
  if [ -f "$BASELINE" ]; then
    warn "${BASELINE} already exists — updating"
    detect-secrets scan --baseline "$BASELINE" > /dev/null
    ok "Baseline updated: ${BASELINE}"
  else
    detect-secrets scan \
      --exclude-files '\.git/.*' \
      --exclude-files 'node_modules/.*' \
      --exclude-files '\.venv/.*' \
      --exclude-files 'package-lock\.json' \
      --exclude-files 'yarn\.lock' \
      --exclude-files '\.secrets\.baseline' \
      > "$BASELINE"
    ok "Baseline created: ${BASELINE}"
    echo ""
    warn "Review the baseline before committing:"
    echo "    detect-secrets audit .secrets.baseline"
    echo "  Mark each finding as real or false positive."
  fi
fi

# ── 5. Patch .pre-commit-config.yaml ─────────────────────────────────────────
if [ "$SKIP_PRECOMMIT" = false ]; then
  step "Configuring pre-commit hooks"
  cd "$REPO_ROOT"
  PRECOMMIT_CONFIG=".pre-commit-config.yaml"

  GITLEAKS_HOOK='
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks'

  DETECT_SECRETS_HOOK='
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]'

  if [ ! -f "$PRECOMMIT_CONFIG" ]; then
    # Create a new pre-commit config
    cat > "$PRECOMMIT_CONFIG" <<'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]
EOF
    ok "Created ${PRECOMMIT_CONFIG} with gitleaks and detect-secrets"
  else
    # Patch existing config
    PATCHED=false
    if ! grep -q 'gitleaks' "$PRECOMMIT_CONFIG"; then
      echo "$GITLEAKS_HOOK" >> "$PRECOMMIT_CONFIG"
      ok "Added gitleaks to ${PRECOMMIT_CONFIG}"
      PATCHED=true
    else
      ok "gitleaks already in ${PRECOMMIT_CONFIG}"
    fi
    if ! grep -q 'detect-secrets' "$PRECOMMIT_CONFIG"; then
      echo "$DETECT_SECRETS_HOOK" >> "$PRECOMMIT_CONFIG"
      ok "Added detect-secrets to ${PRECOMMIT_CONFIG}"
      PATCHED=true
    else
      ok "detect-secrets already in ${PRECOMMIT_CONFIG}"
    fi
  fi

  # Install pre-commit if available
  if command -v pre-commit &>/dev/null; then
    pre-commit install --quiet
    ok "pre-commit hooks installed (git hook registered)"
  else
    warn "pre-commit not installed. Run: pip install pre-commit && pre-commit install"
  fi
fi

# ── 6. Summary ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Setup complete.${RESET}"
echo ""
echo "Next steps:"
echo "  1. Review the baseline:  detect-secrets audit .secrets.baseline"
echo "  2. Commit the baseline:  git add .secrets.baseline .pre-commit-config.yaml"
echo "  3. Verify hooks work:    pre-commit run --all-files"
echo ""
echo "Add to CI (GitHub Actions example — see .github/workflows/security.yml):"
echo "  - uses: gitleaks/gitleaks-action@v2"
