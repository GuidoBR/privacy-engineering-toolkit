# Privacy Engineering Toolkit

A comprehensive, open-source toolkit for privacy engineering: a Claude Code skill for automated privacy audits, standalone scanning scripts, documentation templates, law references, and cookbook recipes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What's Included

| Directory | Contents |
|---|---|
| `.claude/skills/privacy-audit/` | Claude Code `/privacy-audit` skill — automated multi-layer audit |
| `scripts/` | Standalone shell/Python scripts for CI/CD integration |
| `templates/` | DPIA, RoPA, DSAR response, breach notification, vendor assessment |
| `laws/` | Quick-reference summaries of major privacy laws |
| `cookbook/` | Implementation recipes for common privacy engineering patterns |
| `.github/workflows/` | Ready-to-use GitHub Actions security workflow |

---

## The `/privacy-audit` Claude Code Skill

A Claude Code skill that performs a comprehensive, multi-layer privacy audit on any software repository. Run it with a single slash command: `/privacy-audit`.

### Installation

```bash
# Clone into your home Claude skills directory
git clone https://github.com/guidopercu/privacy-engineering-toolkit.git \
  ~/.claude/skills/privacy-engineering-toolkit

# Or copy just the skill
mkdir -p ~/.claude/skills/privacy-audit
cp -r .claude/skills/privacy-audit/SKILL.md ~/.claude/skills/privacy-audit/
```

Then in any Claude Code session, run:
```
/privacy-audit
```

### Layers Audited

| Layer | What's Checked |
|---|---|
| **Database / ORM** | Every table and field classified by sensitivity; encryption at rest; retention policies |
| **Backend logs** | Grep patterns detect emails, phone numbers, tokens, and passwords in log calls |
| **Infrastructure (CDK / Terraform / Pulumi / CloudFormation)** | Encryption, public access, IAM least-privilege, log retention, KMS, MFA, secrets management |
| **Backend API** | Auth, authorization, rate limiting, soft-delete PII gaps, bulk export risks |
| **Frontend** | Cookie consent, analytics/pixel gating, localStorage PII, Sentry scrubbing, privacy policy |
| **CI/CD & pre-commit** | Hardcoded secrets in workflows, SAST presence, dependency scanning |

### Legal Compliance Matrix

The audit generates a per-article compliance table for:

- **GDPR** (EU — Regulation 2016/679)
- **LGPD** (Brazil — Lei 13.709/2018), including CPF/CNPJ handling and ANPD requirements
- **CCPA / CPRA** (California)
- **PIPEDA** (Canada)
- **PDPA** (Thailand 2019 / Singapore 2012, amended 2020)
- **POPIA** (South Africa — Act 4 of 2013)

### Sample Output

```
## Privacy Audit — MyApp

### Data Inventory
| Table            | Field           | Sensitivity | PII Category       | Basis      |
|------------------|-----------------|-------------|-------------------|------------|
| users            | email           | HIGH        | Contact identifier | Contract   |
| users            | date_of_birth   | HIGH        | Demographic        | Contract   |
| audit_logs       | before_state    | CRITICAL    | Full entity JSON   | Legal obli.|
| signatures       | signature_image | CRITICAL    | Biometric (Art. 9) | Consent    |

### Log Violations Found (8 files, 38 statements)
[CRITICAL] src/api/v1/public.py:103 — email + IP logged on public endpoint
[HIGH]     src/emails/ses_client.py:83 — to_email in every send/fail log

### Infrastructure Gaps
❌ Cognito — MFA not enforced (auth-stack.ts:32)
❌ DynamoDB — no encryption at rest (lambda-stack.ts:458)
❌ ECS LogGroup — no retention period → infinite PII storage (ecs-stack.ts:375)

### Regulation Violations
| Article       | Violation                          | Severity |
|---------------|------------------------------------|----------|
| GDPR Art. 5(c)| Email logged when ID suffices      | HIGH     |
| GDPR Art. 9   | Biometric data (signature_image)   | CRITICAL |
| LGPD Art. 46  | No encryption on DynamoDB          | HIGH     |
```

---

## Standalone Scripts

### `scripts/scan-pii-logs.sh` — PII in Log Statements

Detects emails, passwords, phone numbers, SSNs/CPFs, and tokens logged in plaintext across Python, TypeScript, JavaScript, Go, Java/Kotlin, and Ruby.

```bash
# Text output (default)
./scripts/scan-pii-logs.sh src/

# JSON output (for tooling)
./scripts/scan-pii-logs.sh --format json src/

# SARIF output (for GitHub Code Scanning)
./scripts/scan-pii-logs.sh --format sarif src/ > results.sarif

# Also flag medium-confidence patterns (usernames, IPs)
./scripts/scan-pii-logs.sh --strict src/
```

**Exit code:** `0` = clean, `1` = findings detected.

Example output:
```
[CRITICAL] Email in JS console
  src/auth/login.ts:47
  console.log(`Login failed for ${user.email}`)

[HIGH] Token in Python log
  src/api/auth.py:112
  logger.info(f"Token issued: {token[:8]}")
```

### `scripts/scan-trackers.sh` — Analytics Consent Gating

Detects analytics, advertising, and tracking SDKs (GA4, GTM, Mixpanel, Facebook Pixel, TikTok, Sentry, etc.) and checks whether each is wrapped in a consent gate.

```bash
./scripts/scan-trackers.sh src/
./scripts/scan-trackers.sh --dir frontend/src --format json
```

Example output:
```
[UNGATED]  Facebook Pixel (advertising)
           src/app/layout.tsx
           ✗ No consent gate detected — loads unconditionally

[GATED]    Google Analytics (analytics)
           src/components/Analytics.tsx
           ✓ Consent check detected in file
```

### `scripts/generate-data-inventory.py` — ORM Data Inventory

Parses your ORM models and generates a data inventory with sensitivity classification.

```bash
# Markdown table
python3 scripts/generate-data-inventory.py --dir backend/src --format markdown

# CSV (for spreadsheets)
python3 scripts/generate-data-inventory.py --dir . --format csv --output inventory.csv
```

Supports: **SQLAlchemy**, **Django ORM**, **Prisma**, **TypeORM**, **ActiveRecord**.

Example output:
```markdown
| Table    | Field           | Sensitivity | PII Category      | Legal Basis | Encrypt? | Retention    |
|----------|-----------------|-------------|-------------------|-------------|----------|--------------|
| users    | email           | HIGH        | Contact           | Contract    | At rest  | Account life |
| users    | ssn_encrypted   | CRITICAL    | Government ID     | Legal obli. | Required | 7 years      |
| orders   | shipping_address| HIGH        | Physical location | Contract    | At rest  | 5 years      |
```

### `scripts/init-secret-scanning.sh` — Bootstrap Secret Scanning

Installs gitleaks and detect-secrets, scans git history, generates a baseline, and patches `.pre-commit-config.yaml`.

```bash
./scripts/init-secret-scanning.sh

# Skip git history scan (faster for large repos)
./scripts/init-secret-scanning.sh --skip-history

# Skip pre-commit hook setup
./scripts/init-secret-scanning.sh --skip-precommit
```

---

## Templates

| Template | Purpose |
|---|---|
| [`templates/dpia-gdpr.md`](templates/dpia-gdpr.md) | GDPR Art. 35 Data Protection Impact Assessment |
| [`templates/dpia-lgpd-ripd.md`](templates/dpia-lgpd-ripd.md) | LGPD Art. 38 Relatório de Impacto à Proteção de Dados |
| [`templates/ropa.md`](templates/ropa.md) | GDPR Art. 30 Record of Processing Activities |
| [`templates/dsar-response.md`](templates/dsar-response.md) | Response letters for access, erasure, portability, opt-out |
| [`templates/breach-notification.md`](templates/breach-notification.md) | Breach notification to supervisory authority and data subjects |
| [`templates/processor-assessment.md`](templates/processor-assessment.md) | Vendor/processor due diligence questionnaire (Art. 28) |
| [`templates/feature-privacy-checklist.md`](templates/feature-privacy-checklist.md) | PR checklist for features touching personal data |

---

## Law References

Quick-reference summaries for major privacy laws. Not legal advice — consult a privacy lawyer for compliance decisions.

| File | Law | Jurisdiction |
|---|---|---|
| [`laws/gdpr.md`](laws/gdpr.md) | GDPR — General Data Protection Regulation | EU/EEA |
| [`laws/lgpd.md`](laws/lgpd.md) | LGPD — Lei Geral de Proteção de Dados | Brazil |
| [`laws/ccpa.md`](laws/ccpa.md) | CCPA/CPRA — California Consumer Privacy Act | California, USA |
| [`laws/pipeda.md`](laws/pipeda.md) | PIPEDA + Quebec Law 25 | Canada |
| [`laws/pdpa.md`](laws/pdpa.md) | PDPA — Thailand & Singapore | Thailand / Singapore |
| [`laws/popia.md`](laws/popia.md) | POPIA — Protection of Personal Information Act | South Africa |

---

## Cookbook

Implementation recipes for common privacy engineering patterns:

| Recipe | Description |
|---|---|
| [`cookbook/pii-scrubber-logging.md`](cookbook/pii-scrubber-logging.md) | PII scrubbing filters for loguru, stdlib logging, pino, winston, slog |
| [`cookbook/analytics-consent-gating.md`](cookbook/analytics-consent-gating.md) | Consent-gating GA4, GTM, Mixpanel, Facebook Pixel, Segment, Sentry |
| [`cookbook/right-to-erasure.md`](cookbook/right-to-erasure.md) | Database deletion patterns, retention holds, external processor cleanup |
| [`cookbook/anonymization-vs-pseudonymization.md`](cookbook/anonymization-vs-pseudonymization.md) | k-anonymity, differential privacy, tokenisation, FPE |
| [`cookbook/dsar-endpoints.md`](cookbook/dsar-endpoints.md) | FastAPI + Express DSAR endpoints (export, erasure, correction, restriction) |

---

## GitHub Actions Security Workflow

Drop `.github/workflows/security.yml` into your repository for automated privacy and security scanning on every PR:

| Job | Tool | What It Checks |
|---|---|---|
| PII log scan | `scan-pii-logs.sh` | Emails/tokens/SSNs in log statements |
| Tracker audit | `scan-trackers.sh` | Ungated analytics/ad trackers |
| Secret scanning | gitleaks | Secrets in git history and staged files |
| Secret baseline | detect-secrets | New secrets vs. approved baseline |
| Python SAST | bandit | Insecure Python patterns |
| Multi-language SAST | semgrep | OWASP Top 10, secrets, security rules |
| IaC scanning | checkov | Terraform/CDK/CloudFormation misconfigurations |
| Dependency vulns | trivy | CVEs in dependencies and container images |
| Data inventory | `generate-data-inventory.py` | Weekly ORM model audit artifact |

All jobs upload SARIF results to **GitHub Code Scanning** (visible in the Security tab).

---

## Recommended SAST Tools

| Tool | Language / Target | Install |
|---|---|---|
| [bandit](https://github.com/PyCQA/bandit) | Python | `pip install bandit` |
| [semgrep](https://semgrep.dev) | Multi-language | `pip install semgrep` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets / git history | `brew install gitleaks` |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Secrets / pre-commit | `pip install detect-secrets` |
| [checkov](https://www.checkov.io) | Terraform / CDK / CF | `pip install checkov` |
| [tfsec](https://aquasecurity.github.io/tfsec) | Terraform | `brew install tfsec` |
| [cdk-nag](https://github.com/cdklabs/cdk-nag) | AWS CDK | `npm install cdk-nag` |
| [trivy](https://trivy.dev) | Containers / deps / IaC | `brew install trivy` |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secrets / git | `brew install trufflesecurity/trufflehog/trufflehog` |
| [safety](https://pyup.io/safety/) | Python deps (CVEs) | `pip install safety` |
| [npm audit](https://docs.npmjs.com/cli/commands/npm-audit) | Node.js deps | Built into npm |

---

## Remediation Quick Reference

### Remove PII from a log statement (Python)

```python
# BEFORE — logs email to CloudWatch
logger.info(f"Email sent to {to_email}: {message_id}")

# AFTER — logs only the opaque message ID
logger.info(f"Email sent: {message_id}")
```

### Hash a token before logging

```python
import hashlib
token_ref = hashlib.sha256(token.encode()).hexdigest()[:8]
logger.warning(f"Invalid token ref={token_ref}")
```

### Add a loguru PII scrubber (defence-in-depth)

```python
import re, sys
from loguru import logger

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

def _scrub_pii(record: dict) -> bool:
    record["message"] = _EMAIL_RE.sub("[REDACTED_EMAIL]", record["message"])
    return True

logger.remove()
logger.add(sys.stderr, filter=_scrub_pii)
```

See [`cookbook/pii-scrubber-logging.md`](cookbook/pii-scrubber-logging.md) for Node.js, Go, and Java patterns.

---

## Contributing

Contributions welcome. Please:

1. Fork the repository
2. Add your script, template, or recipe
3. Test any scripts against at least one real codebase
4. Open a pull request with a description of what you added and why

For law summaries: cite sources. For scripts: add usage examples and exit codes. For cookbook recipes: include at least one test pattern.

---

## Disclaimer

This toolkit is provided for informational and educational purposes. It is **not legal advice**. Consult a qualified privacy lawyer for compliance decisions. Privacy law varies by jurisdiction and is updated frequently — law summaries may not reflect the latest amendments.

---

## License

MIT — see [LICENSE](LICENSE).
