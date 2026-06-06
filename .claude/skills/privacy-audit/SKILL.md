---
name: privacy-audit
description: Run a full privacy engineering audit on the current repository. Checks CDK/Terraform infrastructure, database schemas, backend logs, API endpoints, frontend code, CI/CD pipelines, and pre-commit hooks for PII leaks, insecure data handling, and violations of GDPR, CCPA, LGPD (Brazil), PIPEDA (Canada), PDPA (Thailand/Singapore), POPIA (South Africa), and other major privacy laws. Produces a structured audit report with findings, a data inventory, a data classification map, deletion policy analysis, DPIA/DSAR gap assessment, cookie/consent review, and prioritized remediations across every layer of the stack. Use when asked to audit privacy, check for GDPR/LGPD compliance, review PII handling, or run a privacy review.
---

# Privacy Engineering Audit Skill

Perform a full-stack privacy audit and produce a structured findings report. This skill is tech-stack agnostic — it works for any combination of Python/Node/Go/Java backends, React/Vue/Angular frontends, PostgreSQL/MySQL/MongoDB/DynamoDB databases, AWS/GCP/Azure infrastructure written in CDK/Terraform/Pulumi, and any CI/CD system.

---

## How to Run This Skill

You will execute the audit in **seven phases**. Start with Phase 0 (scoping) and Phase 1 (discovery) before running anything else — scoping determines which compliance matrices are relevant, and discovery determines which scripts to run.

**Output:** `docs/privacy-audit-YYYY-MM-DD.md` (today's date). Use `docs/plans/` if that directory exists. Never overwrite a previous report — the dated filename is the audit history. Add `docs/privacy-audit-*.md` to `.gitignore`.

---

## Phase 0 — Jurisdictional Scoping (do this before everything else)

Before running any scans, determine which privacy laws actually apply. Assessing six legal frameworks for a company with no EU users wastes audit time and creates false confidence from "compliant" checkboxes on inapplicable laws.

**Ask the user (or infer from the codebase):**

```
1. Where are your users located?
   (EU/EEA · UK · USA · Brazil · Canada · Thailand · Singapore · South Africa · Other)

2. What is your approximate user count or revenue?
   (Affects CCPA threshold: $25M+ revenue OR 100k+ consumers)

3. Do you process any of these categories? (check all that apply)
   ☐ Health / medical data
   ☐ Payment card data (even via Stripe — check what's stored)
   ☐ Children's data (users under 13 or under 16 for EU)
   ☐ Employee / HR data
   ☐ Brazilian users (CPF, Pix transactions, KYC)
   ☐ US consumers in California

4. Does the company have a legal entity or data centre in any of these regions?
```

**Infer from the codebase if the user cannot answer:**

```bash
# Currency / locale hints at user base
grep -rP 'BRL|R\$|CPF|CNPJ|brazili' . --include="*.py" --include="*.ts" --include="*.json" 2>/dev/null | head -10
grep -rP 'EUR|GDPR|gdpr|dsgvo|supervisory.authority' . --include="*.py" --include="*.ts" 2>/dev/null | head -10
grep -rP 'CAD|\bCPPA\b|\bPIPEDA\b' . --include="*.py" --include="*.ts" 2>/dev/null | head -10
grep -rP 'ZAR|POPIA|information.regulator' . --include="*.py" --include="*.ts" 2>/dev/null | head -10

# Payment / fintech scope
grep -rPl 'stripe|pix|boleto|nubank|pagamento|payment' . 2>/dev/null | head -10

# Children's data scope
grep -rP '\bCOPPA\b|under.13|children|parental.consent|age.verif' . --include="*.py" --include="*.ts" 2>/dev/null | head -10
```

**Output of Phase 0 — Jurisdiction Decision:**

Based on the answers above, decide which laws to assess and record this in the report header. Only fill in compliance matrices for applicable laws. Skip the rest entirely.

| Law | Applies? | Reason |
|---|---|---|
| GDPR | Yes / No / Uncertain | EU/EEA users or EU establishment |
| UK GDPR | Yes / No / Uncertain | UK users or UK establishment (post-Brexit) |
| LGPD | Yes / No / Uncertain | Brazilian users (any volume) |
| CCPA/CPRA | Yes / No / Uncertain | CA users + meets revenue/volume threshold |
| PIPEDA / QC Law 25 | Yes / No / Uncertain | Canadian users or Canadian entity |
| PDPA (Thailand) | Yes / No / Uncertain | Thai users or Thai entity |
| PDPA (Singapore) | Yes / No / Uncertain | Singapore users or Singapore entity |
| POPIA | Yes / No / Uncertain | South African users or SA entity |
| HIPAA | Yes / No / Uncertain | US health data |
| COPPA | Yes / No / Uncertain | Users under 13 |
| PCI DSS | Yes / No / Uncertain | Payment card data stored or transmitted |

> **If a law is marked "No" or "Uncertain" and you have low confidence**, mark it "Not assessed — [reason]" in the report rather than filling in the matrix. A blank "Uncertain" matrix entry is less dangerous than a confidently wrong "Compliant."

---

## Phase 1 — Stack Discovery (do this first, in parallel)

Before auditing anything, understand what you're working with. Run these shell commands to map the repository:

```bash
# Identify languages and frameworks
find . -maxdepth 3 \( -name "package.json" -o -name "pyproject.toml" -o -name "go.mod" \
  -o -name "pom.xml" -o -name "build.gradle" -o -name "Gemfile" \) \
  ! -path "*/node_modules/*" ! -path "*/.venv/*" 2>/dev/null

# Identify infrastructure-as-code
find . -maxdepth 4 \( -name "*.tf" -o -name "cdk.json" -o -name "pulumi.yaml" \
  -o -name "serverless.yml" -o -name "template.yaml" \) \
  ! -path "*/node_modules/*" 2>/dev/null | head -30

# Identify database migration files
find . -maxdepth 5 \( -name "*.sql" -o -path "*/migrations/*" -o -path "*/alembic/*" \
  -o -path "*/flyway/*" -o -path "*/liquibase/*" \) \
  ! -path "*/node_modules/*" ! -path "*/.venv/*" 2>/dev/null | head -40

# Identify ORM model files
find . -maxdepth 5 \( -name "models.py" -o -name "database.py" -o -name "schema.py" \
  -o -name "entities.ts" -o -name "*.entity.ts" -o -name "*.model.ts" \
  -o -name "schema.rb" -o -name "*.go" \) \
  ! -path "*/node_modules/*" ! -path "*/.venv/*" ! -path "*/test*" 2>/dev/null | head -40

# Identify CI/CD
find . -maxdepth 4 \( -path "*/.github/workflows/*.yml" -o -name "Jenkinsfile" \
  -o -name ".gitlab-ci.yml" -o -name "bitbucket-pipelines.yml" \
  -o -path "*/.circleci/config.yml" \) 2>/dev/null

# Identify frontend entry points
find . -maxdepth 5 \( -name "index.html" -o -name "App.tsx" -o -name "App.vue" \
  -o -name "_app.tsx" -o -name "layout.tsx" \) \
  ! -path "*/node_modules/*" ! -path "*/dist/*" ! -path "*/.next/*" 2>/dev/null | head -20

# Check for existing privacy/compliance docs
find . -maxdepth 5 \( -iname "privacy*" -o -iname "gdpr*" -o -iname "lgpd*" \
  -o -iname "dpa*" -o -iname "dpia*" -o -iname "compliance*" \) \
  ! -path "*/node_modules/*" 2>/dev/null

# Check for pre-commit hooks
find . -maxdepth 4 \( -name ".pre-commit-config.yaml" -o -path "*/.husky/*" \
  -o -path "*/.git/hooks/*" \) 2>/dev/null
```

Launch **3 Explore agents in parallel** covering:
1. **Data layer**: Read all database model files, migration files, and ORM schemas found above. Build a complete column-by-column inventory.
2. **Infrastructure**: Read all CDK/Terraform/IaC files. Focus on RDS/databases, S3/storage, CloudWatch/logging, Cognito/auth, KMS/encryption, IAM/access policies, network config.
3. **Application + frontend**: Read all logger/logging/log calls in backend source, and read frontend code for analytics integrations, cookies, localStorage/sessionStorage usage, and any privacy policy or consent UI.

---

## Phase 2 — Audit Execution

### 2A. Data Inventory & Classification

For every table/collection/model found, build this inventory. Classify every field:

| Field | Table | Type | Classification | PII Category | Legal Basis Needed | Encrypted? | Retention Policy |
|---|---|---|---|---|---|---|---|

**Data classification levels** (CISSP five-tier commercial model — reference: [AWS Data Classification whitepaper](https://docs.aws.amazon.com/whitepapers/latest/data-classification/data-classification-models-and-schemes.html)):

| Tier | Description | Typical examples in a commercial system |
|---|---|---|
| `Sensitive` | Most limited access; highest integrity requirement; greatest organizational and regulatory damage if disclosed | SSN/TIN/CPF, payment card data (PCI), biometric data, health/medical records, passport/government ID numbers, passwords and hashes, GDPR Art. 9 / LGPD Art. 11 special categories (racial origin, religion, political opinion, sexual orientation) |
| `Confidential` | Less restrictive within the company but causes damage to individuals or the organization if disclosed externally | Full name, email address, phone number, full postal address, IP address, device fingerprint, precise geolocation, signature images |
| `Private` | Compartmental data that may not damage the company but must be kept private for legal, contractual, or ethical reasons | HR and employee records, purchase history, behavioral/activity data, session tokens, opaque internal user IDs, children's data (any tier where COPPA/Art. 8 applies) |
| `Proprietary` | Data disclosed externally only on a limited basis; exposure reduces competitive advantage | Business logic, pricing rules, internal algorithms, API keys and secrets, technical specifications, non-public financial projections |
| `Public` | Least sensitive; least harm if disclosed | Marketing content, published documentation, aggregate/anonymised statistics, company headcount, CNPJ (Brazil business ID) |

**PII categories under major laws:**
- GDPR Art. 4(1): any information relating to an identified or identifiable natural person
- GDPR Art. 9: special categories (health, biometric, racial origin, political opinion, religion, sexual orientation, trade union membership)
- LGPD Art. 5(I): any information relating to identified or identifiable natural person
- LGPD Art. 11 (sensitive data): racial/ethnic origin, religious belief, political opinion, health/sex life, genetic/biometric data
- CCPA §1798.140: identifiers, commercial info, internet activity, geolocation, biometric, professional/employment, education, inferences
- CCPA §1798.121 (sensitive PI): SSN, driver's license, financial account, precise geolocation, racial/ethnic, religious, union membership, health, sex life, biometric, children's data

**Third-party data flows to identify:**
- Email providers (SES, SendGrid, Mailgun, Mailchimp)
- Analytics (Google Analytics/GTM, Mixpanel, Segment, Amplitude, Heap, Hotjar, FullStory)
- Error tracking (Sentry, Datadog, Rollbar, Bugsnag) — these often capture PII in stack traces
- Payment processors (Stripe, PayPal, Braintree, Adyen)
- CRM (Salesforce, HubSpot)
- Advertising (Facebook Pixel, Google Ads, LinkedIn Insight)
- CDN/WAF (Cloudflare, Fastly) — log IP addresses and request data
- Authentication (Auth0, Cognito, Okta, Firebase Auth)
- Cloud AI/ML (OpenAI, AWS Bedrock, Google Vertex) — may train on customer data

---

### 2B. Logging Audit

Run the dedicated script. It handles test-path exclusion, multi-language patterns, and SARIF output — do not substitute ad-hoc greps, which will produce false positives from test fixtures and miss structured-logger patterns.

```bash
# Standard mode — Python, JS/TS, Go, Java, Ruby
scripts/scan-pii-logs.sh --dir . --format json > /tmp/pii-log-findings.json

# Strict mode adds medium-confidence patterns (usernames, IPs, full names)
scripts/scan-pii-logs.sh --dir . --format json --strict >> /tmp/pii-log-findings.json

# For SARIF upload to GitHub Code Scanning:
scripts/scan-pii-logs.sh --dir . --format sarif > pii-logs.sarif
```

Interpret `/tmp/pii-log-findings.json`: for each finding, report the file, line, severity, and the log call that leaked PII. Group by severity. Add to the Findings section of the report.

**Checks for log infrastructure** (these require reading IaC files — see Phase 2C which runs `scan-iac.py`):
- CloudWatch/Datadog/ELK log groups configured with a retention period (GDPR Art. 5(1)(e))
- Logs encrypted at rest (GDPR Art. 32)
- Is there a scrubbing/redaction layer before logs are written? — grep for `PIIScrubberFilter`, `redact`, `scrub`, `pino.redact`, `serializers` in logger config files.

---

### 2C. Infrastructure Audit

Run the dedicated script. It parses Terraform (.tf), CloudFormation (.yml/.json), and CDK TypeScript and evaluates binary flags deterministically — encryption, public access, log retention, key rotation, PITR, autovacuum, security group rules, IAM wildcards. Do not substitute ad-hoc grep; the script handles nesting, multi-resource relationships (e.g. S3 bucket + public-access-block), and outputs structured findings.

```bash
# Scan the entire repo for IaC files
python3 scripts/scan-iac.py . --format json > /tmp/iac-findings.json

# Text output for interactive review
python3 scripts/scan-iac.py . --format text

# SARIF for GitHub Code Scanning upload
python3 scripts/scan-iac.py . --format sarif > iac.sarif
```

Interpret `/tmp/iac-findings.json`: for each finding, record severity, rule_id, title, detail, file, line, and the regulation it violates. Add CRITICAL and HIGH findings to the report's Findings section. Group MEDIUM findings under "Infrastructure — Recommended Improvements."

**What `scan-iac.py` checks (by resource type):**

| Resource | Checks |
|---|---|
| RDS / Aurora | Encryption at rest, publicly_accessible, backup retention, deletion protection |
| RDS parameter group | autovacuum_enabled not disabled (MVCC dead-tuple risk) |
| S3 bucket | aws_s3_bucket_public_access_block present with all 4 flags true; encryption config present |
| CloudWatch LogGroup | retention_in_days set and non-zero; kms_key_id set |
| KMS Key | enable_key_rotation true |
| SQS Queue | kms_master_key_id or sqs_managed_sse_enabled set |
| DynamoDB | server_side_encryption enabled; point_in_time_recovery enabled |
| Security Group | No 0.0.0.0/0 on DB ports (5432, 3306, 1433, 27017, 6379) |
| IAM Policy | No wildcard Action: "*" |
| CDK constructs | Same checks via proximity search in TypeScript CDK files |
| CI/CD YAML | Hardcoded secrets; checkov --soft-fail; trivy exit-code: 0 |

**Checks `scan-iac.py` does NOT cover** (require LLM judgment or manual review):
- Credentials in secrets manager vs hardcoded in application config files — grep for `os.environ` / `process.env` alongside `password`, `secret` in non-IaC files
- SSL enforcement in transit (application-level TLS config varies by framework)
- WAF presence and configuration
- Cognito user attributes collected (requires reading user pool definition and assessing PII scope)
- CloudTrail enabled (check AWS console or use AWS CLI: `aws cloudtrail get-trail-status`)
- IAM roles with MFA required (requires full IAM policy evaluation)

**PostgreSQL MVCC note** (for LLM synthesis — `scan-iac.py` checks autovacuum_enabled in parameter groups):

PostgreSQL's MVCC mechanism means a DELETE does not immediately remove the tuple from disk. Dead tuples persist until AUTOVACUUM reclaims them. On high-write PII tables this means:
- Physical data remains on disk after logical deletion
- WAL archives retain pre-deletion row versions beyond the deletion date

After any bulk erasure, the team should run: `VACUUM (VERBOSE, ANALYZE) users;` and verify with: `SELECT n_dead_tup, last_autovacuum FROM pg_stat_user_tables WHERE relname = 'users';`

---

### 2D. Backend API Audit

Run the dedicated deletion-layer script first. It covers soft-delete gaps, orphaned FK references, ORM cascade bypass, event sourcing, and warehouse propagation — all deterministically, with test-path exclusions already applied.

```bash
scripts/scan-soft-deletes.sh --dir . --format json > /tmp/soft-delete-findings.json
```

Interpret `/tmp/soft-delete-findings.json`: severity HIGH = violation to report; MEDIUM = gap to remediate; LOW = verify manually. Add findings to the Findings section of the report. The script checks:

| Check | Severity if gap found |
|---|---|
| Soft-delete (deleted_at / is_deleted) without companion anonymization | HIGH |
| user_id / owner_id columns without FK constraint | MEDIUM |
| Django `on_delete=DO_NOTHING` (no cascade at all) | HIGH |
| Django/Rails app-layer cascade with no DB-level FK | MEDIUM |
| Event sourcing (Kafka/Kinesis) without crypto shredding | HIGH |
| Data warehouse (BigQuery/Redshift/dbt) without deletion propagation | HIGH |
| Deletion code exists but no deletion_registry table | MEDIUM |

**Additional API checks** (run these greps — they are not covered by a script):

```bash
# Find rate-limiting on sensitive endpoints
grep -rPn --include="*.py" --include="*.ts" \
  'rate.?limit|RateLimiter|throttle|slowDown' \
  . 2>/dev/null

# Check for data export / bulk download endpoints (HIGH DSAR risk if unprotected)
grep -rPn --include="*.py" --include="*.ts" \
  'export|download.*csv|download.*excel|bulk.*export' \
  . 2>/dev/null

# Check for raw SQL with string formatting (SQL injection / PII in query logs)
grep -rPn --include="*.py" \
  'execute\(.*%s|execute\(.*\.format\(' \
  . 2>/dev/null

# Check for microservice / multi-service DB access (ORM cascade bypass risk)
grep -rPn --include="*.py" --include="*.ts" --include="*.go" \
  'engine\s*=|createConnection|knex\b|db\.connect|sql\.Open' \
  . 2>/dev/null | grep -vP 'test|spec|migration' | head -20
```

**Check for:**
- Authentication on all non-public endpoints
- Authorization checks (users can only access their own data)
- Input validation on PII fields (email format, phone format)
- Rate limiting on auth, password reset, and email lookup endpoints
- **Soft delete without real erasure (HIGH):** `deleted_at`/`is_deleted` flags that leave PII in place are **not** erasure under GDPR Art. 17 / LGPD Art. 18(VI) — they are concealment (ocultação). A companion anonymisation query or scheduled purge job is required. Raise as HIGH if absent.
- **Orphaned data without FK constraints (MEDIUM):** `user_id`-type columns with no `REFERENCES` constraint or ORM `ForeignKey` declaration accumulate orphan PII silently after user deletion. List every instance found.
- **ORM cascade bypass risk (MEDIUM):** Django `on_delete` and Rails `dependent:` operate at the application layer only. Any service that accesses the database directly (a microservice, a data pipeline, a script) will bypass this logic and leave orphan rows. Raise as MEDIUM in any multi-service architecture. The fix is to also define a `ON DELETE CASCADE` / `ON DELETE SET NULL` constraint at the database level.
- **Event sourcing without crypto shredding (HIGH):** Kafka, Kinesis, DynamoDB Streams, or any append-only event log is architecturally incompatible with deletion. The only compliant strategy is **crypto shredding**: encrypt PII fields with a per-user key derived from the user ID; "deletion" means destroying that key via KMS. Raise as HIGH if an event sourcing pattern is detected with no crypto shredding implementation.
- **Data warehouse with no deletion propagation (HIGH):** BigQuery, Redshift, Snowflake, and dbt pipelines do not automatically receive deletions from the production database. A deletion in the main DB leaves the data intact in the warehouse unless the pipeline was explicitly designed to propagate it. Raise as HIGH if a warehouse integration is found with no corresponding deletion sync.
- Response bodies — do error messages leak PII from other users?
- Bulk export endpoints — are they admin-only?

---

### 2E. Frontend Audit

**Cookie and consent:**
```bash
# Find cookie usage
grep -rPn --include="*.ts" --include="*.tsx" --include="*.js" \
  'document\.cookie\|setCookie\|js-cookie\|universal-cookie\|cookie-consent\|CookieConsent' \
  src/ 2>/dev/null

# Find localStorage/sessionStorage with PII
grep -rPn --include="*.ts" --include="*.tsx" --include="*.js" \
  'localStorage\.setItem.*\(.*[email|token|user|name|address|phone]' \
  src/ 2>/dev/null

# Find analytics integrations
grep -rPn --include="*.ts" --include="*.tsx" --include="*.js" --include="*.html" \
  'gtag\|_ga\|mixpanel\|amplitude\|segment\|analytics\|hotjar\|fullstory\|intercom\|heap' \
  src/ 2>/dev/null

# Find Facebook/LinkedIn/Google pixels
grep -rPn --include="*.ts" --include="*.tsx" --include="*.html" \
  'fbq\|_fbp\|fbevents\|linkedin.*insight\|google.*ads\|googletagmanager' \
  src/ 2>/dev/null

# Find sentry/error trackers in frontend
grep -rPn --include="*.ts" --include="*.tsx" --include="*.js" \
  'Sentry\.init\|Sentry\.setUser\|@sentry\|bugsnag\|rollbar\|datadog' \
  src/ 2>/dev/null

# Check for privacy policy and terms pages
find . -maxdepth 6 \( -iname "privacy*" -o -iname "terms*" -o -iname "cookies*" \
  -o -iname "consent*" \) \
  ! -path "*/node_modules/*" 2>/dev/null
```

**Frontend checks:**
```
☐ Cookie consent banner present and implemented correctly
    - Consent obtained BEFORE non-essential cookies are set (GDPR Art. 6(1)(a); LGPD Art. 8)
    - Granular consent per category (analytics, marketing, functional)
    - Consent recorded and timestamp stored (GDPR Art. 7(1) — demonstrate consent)
    - Easy opt-out / withdraw consent mechanism
    - Cookie policy linked from consent banner
☐ Privacy policy page exists and is linked from footer
    - Lists all data collected and purpose
    - Lists all third-party processors
    - Explains retention periods
    - Explains user rights (access, correction, deletion, portability)
    - Contact info for DPO or privacy team
    - Date of last update
    - Available in all supported languages (LGPD requires Portuguese for Brazilian users)
☐ Sensitive data not stored in localStorage (tokens OK if short-lived; PII never)
☐ Analytics disabled until consent obtained
☐ Facebook/ad pixels disabled until consent obtained
☐ Error tracker (Sentry) configured to scrub PII before sending
☐ No PII in URL query parameters (visible in server logs, referrer headers, analytics)
☐ HTTPS enforced — no mixed content
☐ CSP header set (prevents data exfiltration by injected scripts)
☐ Form fields with PII use autocomplete="off" for sensitive fields (passwords, SSN)
```

---

### 2F. CI/CD and Pre-commit Hooks Audit

```bash
# Check CI for hardcoded secrets
grep -rn 'password\|secret\|api_key\|access_key\|private_key' \
  .github/workflows/ .gitlab-ci.yml bitbucket-pipelines.yml Jenkinsfile 2>/dev/null \
  | grep -v '#' | grep -v 'secrets\.' | grep -v 'env\.' | head -20

# Check for secret scanning in CI
grep -rn 'gitleaks\|trufflehog\|detect-secrets\|git-secrets\|semgrep\|bandit\|gosec\|snyk' \
  .github/ .gitlab-ci.yml 2>/dev/null

# Check for SAST in CI
grep -rn 'bandit\|semgrep\|sonar\|checkmarx\|veracode\|codeql\|snyk' \
  .github/ .gitlab-ci.yml 2>/dev/null

# Check for dependency vulnerability scanning
grep -rn 'safety\|pip-audit\|npm audit\|yarn audit\|trivy\|grype\|dependabot' \
  .github/ .gitlab-ci.yml 2>/dev/null

# Check pre-commit hooks
cat .pre-commit-config.yaml 2>/dev/null
ls .husky/ 2>/dev/null
```

**CI/CD checks:**
```
☐ No hardcoded secrets in CI workflow files
☐ Secrets injected via CI secret store (GitHub Secrets, GitLab CI variables)
☐ No PII in CI environment variable names or values visible in logs
☐ SAST tool runs on every PR (bandit for Python, ESLint security plugin, CodeQL, Semgrep)
☐ Secret scanning runs on every commit (gitleaks, trufflehog, detect-secrets)
☐ Dependency vulnerability scan runs on every PR (pip-audit/safety, npm audit, Dependabot)
☐ Container image scanning for CVEs (Trivy, Grype, Snyk)
☐ PII-in-logs check runs as a lint step
☐ Production deployments require approvals (not auto-deploy from any branch)
☐ Least-privilege cloud credentials in CI (OIDC, not long-lived keys)
```

**Pre-commit hook checks:**
```
☐ detect-secrets or gitleaks prevents secrets being committed
☐ PII-in-logger pattern check (grep for email/password/token in log calls)
☐ Ruff/ESLint security rules enabled
☐ Pre-commit hooks documented in CONTRIBUTING.md
```

---

## Phase 3 — Legal Compliance Matrix

**Only assess laws marked "Yes" or "Uncertain" in the Phase 0 jurisdiction table.** Do not fill in matrices for laws that do not apply — a completed matrix for an inapplicable law creates false audit scope and misleads reviewers. For laws marked "No", write one line: `Not applicable — [reason from Phase 0].`

### GDPR (EU — Regulation 2016/679)

| Article | Requirement | Status | Finding |
|---|---|---|---|
| Art. 5(1)(a) | Lawful basis for every processing activity | ? | |
| Art. 5(1)(b) | Purpose limitation (data used only for stated purpose) | ? | |
| Art. 5(1)(c) | Data minimisation (collect only what's necessary) | ? | |
| Art. 5(1)(d) | Accuracy (mechanisms to keep data up to date) | ? | |
| Art. 5(1)(e) | Storage limitation (retention periods defined and enforced) | ? | |
| Art. 5(1)(f) | Integrity & confidentiality (encryption, access controls) | ? | |
| Art. 6 | Legal basis documented for each processing activity | ? | |
| Art. 7 | Consent: granular, freely given, withdrawable, recorded | ? | |
| Art. 9 | Special category data: explicit consent + DPA if applicable | ? | |
| Art. 12-14 | Transparency: privacy notice provided at collection time | ? | |
| Art. 15 | Right of access (DSAR endpoint or process exists) | ? | |
| Art. 16 | Right to rectification (users can update their data) | ? | |
| Art. 17 | Right to erasure — actual deletion, not just soft-delete flag | ? | |
| Art. 18 | Right to restriction of processing | ? | |
| Art. 20 | Right to data portability (machine-readable export) | ? | |
| Art. 21 | Right to object to processing | ? | |
| Art. 22 | Automated decision-making / profiling | ? | |
| Art. 25 | Privacy by design and by default | ? | |
| Art. 28 | Data Processing Agreements with all processors | ? | |
| Art. 30 | Record of Processing Activities (ROPA) maintained | ? | |
| Art. 32 | Technical & organisational security measures | ? | |
| Art. 33 | 72-hour breach notification procedure to supervisory authority | ? | |
| Art. 34 | Breach notification to affected data subjects | ? | |
| Art. 35 | DPIA conducted for high-risk processing | ? | |
| Art. 37 | DPO appointed if required | ? | |

**GDPR Lawful bases (Art. 6) — assess which applies to each processing activity:**
- Consent (6(1)(a)) — must be freely given, specific, informed, unambiguous
- Contract (6(1)(b)) — processing necessary for contract performance
- Legal obligation (6(1)(c)) — required by law (tax records, W-9, etc.)
- Vital interests (6(1)(d)) — rarely applicable
- Public task (6(1)(e)) — for public authorities
- Legitimate interest (6(1)(f)) — requires balancing test (LIA); cannot override individual rights

---

### LGPD (Brazil — Lei 13.709/2018)

| Article | Requirement | Status | Finding |
|---|---|---|---|
| Art. 6 | Legal bases for processing (10 bases — consent, contract, legitimate interest, legal obligation, etc.) | ? | |
| Art. 8 | Consent: specific, prominent, unambiguous; cannot be bundled | ? | |
| Art. 11 | Sensitive data: explicit, specific consent required | ? | |
| Art. 15 | End of processing: upon purpose achieved, legal period expired, or revocation | ? | |
| Art. 16 | Retention after deletion request permitted only for: legal/regulatory obligation, exercise of rights in judicial/administrative proceedings, or credit protection — each retained category must have a documented legal basis | ? | |
| Art. 18 | Data subject rights: access, correction, deletion, anonymization, portability, information on sharing, right to object, revoke consent | ? | |
| Art. 20 | Automated decision-making: data subject can request review by human | ? | |
| Art. 37 | Record of processing activities maintained (RIPD — Relatório de Impacto) | ? | |
| Art. 38 | DPA (RIPD/DPIA) for high-risk processing | ? | |
| Art. 41 | DPO (Encarregado) appointed and publicly identified | ? | |
| Art. 46 | Security measures: technical and administrative | ? | |
| Art. 48 | Incident notification to ANPD and data subjects within reasonable time (ANPD guidelines suggest 2 business days for critical, 72h in practice) | ? | |
| Art. 49 | Systems built with privacy by design | ? | |

**LGPD-specific notes:**
- Applies to any processing of Brazilian residents' data, regardless of where the company is located
- Supervisory authority: ANPD (Autoridade Nacional de Proteção de Dados)
- Fines: up to 2% of Brazil revenue, capped at R$50 million per violation
- Sensitive data (Art. 11) requires explicit consent OR legal/regulatory compliance OR shared data for exercise of rights
- CPF (individual taxpayer ID) is highly regulated — classify as **Sensitive**; CNPJ is a business identifier — classify as **Public**
- Privacy policy must be available in Portuguese

**Brazilian sectoral retention rules (override LGPD Art. 18 deletion rights):**

These regulations require data to be retained even after a deletion request. For each retained category, the company must document the legal basis and expected retention end date in its deletion response.

| Sector | Regulation | Data Retained | Retention Period |
|---|---|---|---|
| Payments / Pix / banking | Resolução BCB nº 522/2025 (supersedes CMN 4.893/2021) | Transaction records, Pix logs, payment metadata | 5 years |
| Anti-money-laundering (KYC) | Lei 9.613/1998 | KYC documents, identity verification, transaction history | 10 years after end of customer relationship |
| Tax / accounting | Código Tributário Nacional (CTN) Art. 173 | Invoices, revenue records, tax-relevant transactions | 5 years |
| Credit operations | Resolução CMN 4.557/2017 / BCB rules | Credit risk records, loan contracts | Duration of contract + 5 years |
| Children's content | ECA Digital (Lei 13.431 and related) | Any data involving minors requires heightened protection; deletion may require parental/guardian confirmation | Special rules — assess per product |
| Healthcare | CFM regulations + LGPD Art. 11 | Medical records | 20 years (medical council rules) |

**Audit action:** If the codebase shows any fintech (Pix, credit, KYC), healthcare, or tax features, cross-reference all retained data categories against the table above. Any deletion response that simply says "all data deleted" without addressing these retention obligations is a compliance gap — the correct output is a structured document per Art. 16 (see DSAR section).

---

### CCPA / CPRA (California — Civil Code §1798)

| Requirement | Status | Finding |
|---|---|---|
| Privacy notice at collection (§1798.100) | ? | |
| Do Not Sell or Share My Personal Information link | ? | |
| Right to know / access (DSAR within 45 days) | ? | |
| Right to delete (within 45 days) | ? | |
| Right to correct | ? | |
| Right to opt-out of sale/sharing | ? | |
| Right to limit use of sensitive PI | ? | |
| No discrimination for exercising rights | ? | |
| Reasonable security measures | ? | |
| Annual privacy policy with "last updated" date | ? | |
| Data minimisation (CPRA addition) | ? | |
| Sensitive PI categories identified and disclosed | ? | |

---

### PIPEDA (Canada — Personal Information Protection and Electronic Documents Act)

| Principle | Status | Finding |
|---|---|---|
| Accountability: DPO or privacy officer appointed | ? | |
| Identifying purposes before or at collection | ? | |
| Consent (meaningful, informed) | ? | |
| Limiting collection to necessary data | ? | |
| Limiting use, disclosure, and retention | ? | |
| Accuracy: data kept up to date | ? | |
| Safeguards: appropriate security | ? | |
| Openness: privacy policies publicly available | ? | |
| Individual access: respond within 30 days | ? | |
| Challenging compliance: complaint process exists | ? | |
| Breach notification to OPC within reasonable time | ? | |

---

### PDPA (Thailand — 2019 / Singapore — 2012, amended 2020)

| Requirement | Status | Finding |
|---|---|---|
| Consent or other lawful basis for collection | ? | |
| Purpose limitation | ? | |
| Retention limits (no longer than necessary) | ? | |
| Data subject rights (access, correction, deletion, portability) | ? | |
| Cross-border transfer restrictions (adequacy or contractual safeguards) | ? | |
| Security measures | ? | |
| Data breach notification (Thailand: 72hr to PDPC; Singapore: 3 days for significant breach) | ? | |
| DPO requirement (Thailand: mandatory for certain controllers; Singapore: DPO recommended) | ? | |

---

### POPIA (South Africa — Act 4 of 2013)

| Condition | Status | Finding |
|---|---|---|
| Accountability | ? | |
| Processing limitation (lawful basis) | ? | |
| Purpose specification | ? | |
| Further processing limitation | ? | |
| Information quality (accuracy) | ? | |
| Openness (notification at collection) | ? | |
| Security safeguards | ? | |
| Data subject participation (access, correction, deletion) | ? | |

---

### Additional Laws to Flag if Relevant

- **HIPAA (US)** — if any health/medical data is processed
- **COPPA (US)** — if any users may be under 13
- **FERPA (US)** — if any student educational records
- **PCI DSS** — if payment card data is handled (even via Stripe, check what's stored)
- **SOC 2** — if SaaS with enterprise customers (security, availability, confidentiality)
- **ePrivacy Directive (EU Cookie Law)** — cookies and electronic communications
- **UK GDPR** — post-Brexit UK data (same as GDPR but UK ICO oversight)
- **Australia Privacy Act** — if Australian users

---

## Phase 4 — DPIA and DSAR Assessment

### DPIA (Data Protection Impact Assessment)

A DPIA is **mandatory** under GDPR Art. 35 if processing is "likely to result in a high risk." Assess each of these triggers:

```
DPIA required if ANY of the following apply:
☐ Systematic, extensive profiling with automated decision-making affecting individuals
☐ Large-scale processing of special category data (health, biometric, racial, religion, sexual orientation)
☐ Systematic monitoring of publicly accessible areas (CCTV, location tracking)
☐ Large-scale processing of children's data
☐ New technologies with unknown privacy implications
☐ Combining datasets from different sources
☐ Processing biometric or genetic data (e.g., signature images ARE biometric)
☐ Processing data of vulnerable individuals

DPIA is recommended (not mandatory) for:
☐ Financial data of individuals
☐ Location data
☐ Data from employees or customers processed at scale
☐ Any novel use of an existing dataset
```

**DPIA document should include:**
1. Description of processing and its purposes
2. Assessment of necessity and proportionality
3. Risks to individuals' rights and freedoms
4. Measures to address risks (mitigations)
5. Consultation with DPO
6. For residual high risks: prior consultation with supervisory authority

**LGPD equivalent: RIPD (Relatório de Impacto à Proteção de Dados Pessoais)**
- Required for high-risk processing (sensitive data, large scale, automated profiling)
- ANPD may require disclosure of RIPD

### DSAR (Data Subject Access Request) Process

Check for the existence and completeness of:

```
☐ Mechanism for users to submit a DSAR (email, form, or in-app)
☐ Identity verification before releasing data (prevent unauthorized access)
☐ Response time SLA defined:
    - GDPR: 1 month (extendable to 3 for complex requests)
    - LGPD: 15 days
    - CCPA: 45 calendar days
    - PIPEDA: 30 days
    - PDPA Thailand: 30 days
☐ Scope of response covers all systems (DB, logs, backups, third-party processors)
☐ Machine-readable export format available (CSV/JSON) for portability right
☐ Deletion process removes PII from: DB, backups, logs, CDN caches, third-party processors
☐ Third-party processors notified of deletion (ShipStation, QuickBooks, etc.)
☐ Deletion audit trail maintained (what was deleted, when, by whom) — using opaque reference (hashed user ID), never the user's email
☐ **Structured deletion response document produced** (see below — required for regulated industries)
☐ Process documented in runbook
☐ Process tested end-to-end at least annually

**Structured deletion response document (HIGH gap if absent in regulated contexts):**

For companies subject to sectoral retention rules (fintech, healthcare, KYC/AML), a simple "your account was deleted" response is insufficient and potentially misleading. The correct output is an auditable document delivered to the user that covers:

```
1. What was deleted:
   - User profile fields (name, email, phone, address) — anonymised on [date]
   - Session tokens — revoked on [date]
   - Profile photo — removed from storage on [date]

2. What was retained and why:
   - Transaction records: retained for 5 years per Resolução BCB 522/2025
     (last transaction: [date], retention expires: [date])
   - KYC documents: retained for 10 years per Lei 9.613/1998
     (relationship ended: [date], retention expires: [date])
   - Audit logs: event records retained with opaque reference (no PII) per legal obligation

3. Third-party processors notified:
   - [Processor name]: deletion request sent on [date], confirmation received on [date]

4. Reference number: [opaque ID for follow-up]
5. Contact for questions: [DPO / privacy team email]
```

Check whether `templates/dsar-response.md` covers this structure. Raise as HIGH finding if the system only returns a success HTTP status with no auditability, or if the deletion response doesn't distinguish retained vs deleted data with legal bases.
```

**API checks for DSAR support:**
```bash
# Look for export/download endpoints
grep -rPn --include="*.py" --include="*.ts" \
  'privacy.*export\|dsar\|data.*request\|account.*delete\|right.*erasure' \
  src/ 2>/dev/null

# Look for account deletion
grep -rPn --include="*.py" --include="*.ts" \
  'delete.*account\|deactivate.*user\|gdpr.*delete\|erasure' \
  src/ 2>/dev/null
```

---

## Phase 5 — SAST and Security Tool Recommendations

Recommend the following tools based on the tech stack found:

### Secret Detection (run on every commit and in CI)

```bash
# Gitleaks — fast, language-agnostic
brew install gitleaks  # or apt install / docker pull
gitleaks detect --source . --verbose

# Detect-secrets (Yelp) — integrates with pre-commit
pip install detect-secrets
detect-secrets scan > .secrets.baseline
detect-secrets audit .secrets.baseline

# TruffleHog — scans git history
trufflehog git file://. --only-verified
```

**Pre-commit config snippet:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

### SAST by Language

**Python:**
```bash
# Bandit — Python security linter
pip install bandit
bandit -r src/ -ll -f json -o bandit-report.json
# Key checks: B105 (hardcoded passwords), B106, B107, B108, B324 (weak hash), B501 (SSL disabled)

# Semgrep — multi-language, excellent Python rules
semgrep --config=p/python --config=p/django --config=p/flask src/
semgrep --config=p/secrets src/

# pip-audit / safety — dependency vulnerabilities
pip-audit
safety check
```

**JavaScript/TypeScript:**
```bash
# ESLint security plugins
npm install --save-dev eslint-plugin-security eslint-plugin-no-secrets
# Add to .eslintrc:
# "plugins": ["security", "no-secrets"]
# "extends": ["plugin:security/recommended"]

# npm audit
npm audit --audit-level=moderate

# Semgrep
semgrep --config=p/typescript --config=p/react --config=p/nodejs src/

# Snyk
snyk test
snyk code test
```

**Go:**
```bash
gosec ./...
semgrep --config=p/golang .
govulncheck ./...
```

**Infrastructure (Terraform/CDK):**
```bash
# tfsec — Terraform security scanner
tfsec .

# Checkov — multi-IaC scanner (Terraform, CDK, CloudFormation, Kubernetes)
checkov -d infrastructure/
checkov -d .

# KICS — broad IaC security scanner
kics scan -p infrastructure/

# CDK-nag — AWS CDK specific compliance rules
# Add to CDK app: Aspects.of(app).add(new AwsSolutionsChecks())
# npm install cdk-nag
```

**Container/Dependency scanning:**
```bash
# Trivy — comprehensive (OS, deps, secrets, IaC, container)
trivy fs .
trivy image your-image:tag

# Grype — container and filesystem vulnerability scanner
grype .
grype docker:your-image:tag
```

### Recommended CI/CD Integration (GitHub Actions example)

```yaml
# Add to .github/workflows/security.yml
name: Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  secret-scan:
    name: Secret Detection
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  sast-python:
    name: Python SAST
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install bandit pip-audit
      - run: bandit -r backend/src/ -ll
      - run: pip-audit -r backend/requirements.txt

  sast-iac:
    name: IaC Security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bridgecrewio/checkov-action@master
        with:
          directory: infrastructure/
          framework: terraform,cloudformation
          output_format: sarif
          output_file_path: checkov.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov.sarif

  dependency-scan:
    name: Dependency Vulnerabilities
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          severity: HIGH,CRITICAL
```

---

## Phase 5B — Deletion Verification

This phase answers the question every data subject should be able to ask: *"How can I be sure my data was actually deleted?"* Run these checks against the codebase and (where possible) a staging environment.

### 5B-1. Static verification — does deletion logic cover all layers?

```bash
# Find the deletion/erasure endpoint or service method
grep -rPn --include="*.py" --include="*.ts" --include="*.rb" --include="*.go" \
  'delete.*account\|erasure\|right.*forget\|gdpr.*delete\|dsar.*delete\|anonymis\|anonymiz' \
  src/ app/ . 2>/dev/null | grep -v test | grep -v spec

# Check whether each of the following stores is addressed in the deletion path:
# 1. Primary DB — look for UPDATE...NULL or DELETE FROM users
grep -rPn --include="*.py" --include="*.ts" --include="*.sql" \
  'UPDATE.*users.*SET.*NULL\|DELETE FROM users\|prisma\.user\.delete\|User\.objects\.filter.*delete' \
  . 2>/dev/null

# 2. Cache / Redis — session and user cache invalidation
grep -rPn --include="*.py" --include="*.ts" \
  'redis.*delete\|cache.*delete\|invalidate.*session\|revoke.*token\|Session.*delete\|logout.*all' \
  . 2>/dev/null

# 3. Search indices — Elasticsearch, Algolia, Typesense
grep -rPn --include="*.py" --include="*.ts" \
  'es\.delete\|client\.delete\|algolia.*delete\|index\.delete\|typesense.*delete' \
  . 2>/dev/null

# 4. Object storage — S3, GCS blobs (profile photos, documents)
grep -rPn --include="*.py" --include="*.ts" \
  's3.*delete\|delete_object\|storage\.delete\|bucket.*delete\|blob.*delete' \
  . 2>/dev/null

# 5. Message queues — in-flight PII messages
grep -rPn --include="*.py" --include="*.ts" \
  'purge.*queue\|delete.*message\|cancel.*task\|revoke.*task\|celery.*revoke' \
  . 2>/dev/null

# 6. Audit log — confirm it uses opaque reference, not email
grep -rPn --include="*.py" --include="*.ts" \
  'audit_log\|AuditLog\|audit\.create\|log_event' \
  . 2>/dev/null | grep -i 'delet\|erasure\|removal'

# 7. Deletion registry — required for backup reconciliation
grep -rPn --include="*.py" --include="*.ts" --include="*.sql" \
  'deletion_registry\|deletion_log\|erasure_registry\|DeletionRecord' \
  . 2>/dev/null
```

### 5B-2. Deletion completeness checklist

```
For each layer below, mark: ✓ covered | ✗ missing | N/A not applicable

Primary database
☐ PII fields are NULL'd or anonymised (email → deleted+{id}@redacted.invalid, name → "Deleted")
☐ Hard delete OR anonymisation + scheduled purge — NOT a bare soft-delete flag alone
☐ Cascades or explicit child-table cleanup documented and tested
☐ Foreign key orphan risk assessed (see Phase 2D)
☐ For PostgreSQL: VACUUM scheduled after bulk erasure; dead tuple count monitored

Session / cache layer
☐ All session tokens revoked (DB sessions table, Redis, JWT blocklist)
☐ In-memory user object cache cleared (Redis, Memcached)

Search indices
☐ Elasticsearch / OpenSearch document deleted
☐ Algolia / Typesense record deleted

Object storage
☐ Profile photos, avatars removed from S3/GCS
☐ User-uploaded documents removed or handed to legal hold if retained
☐ Pre-signed URLs for deleted objects expire or are invalidated

Message queues / async tasks
☐ Queued tasks referencing this user ID cancelled (Celery revoke, SQS purge)
☐ Outbox / event log checked for unprocessed events with user PII

Analytics and third-party processors
☐ Mixpanel / Amplitude / Segment deletion API called
☐ CRM (HubSpot, Salesforce) contact deleted
☐ Email service provider (SendGrid, Mailchimp) contact and suppression list cleared
☐ Error tracking (Sentry) user data scrubbed

Event sourcing / append-only logs
☐ If Kafka/Kinesis/event store detected: crypto shredding key destroyed via KMS
☐ Destruction of key documented and timestamped in deletion registry

Data warehouses / BI pipelines
☐ BigQuery / Redshift / Snowflake user rows deleted or anonymised
☐ dbt / Fivetran / Airbyte deletion propagation pipeline exists and is tested

Backups
☐ Deletion registry updated with user_id hash + deletion date
☐ Backup restoration runbook includes step: re-run deletion registry reconciliation
☐ Backup retention period is the minimum required (not indefinite)

Audit trail
☐ Deletion event recorded in audit log using opaque reference (SHA-256 of user_id), not email
☐ Timestamp and acting user (admin / self-service) recorded
☐ Deletion response document generated and deliverable to data subject on request
```

### 5B-3. Raise findings for any unchecked row

| Layer uncovered | Severity |
|---|---|
| Primary DB — bare soft-delete with no anonymisation or purge | HIGH |
| Event sourcing with no crypto shredding | HIGH |
| Data warehouse with no deletion propagation | HIGH |
| Cache / session tokens not revoked | HIGH |
| Search index not cleared | MEDIUM |
| S3 objects not deleted | MEDIUM |
| Analytics processor not notified | MEDIUM |
| No deletion registry for backup reconciliation | MEDIUM |
| Audit log uses email instead of opaque reference | MEDIUM |
| No structured deletion response document | MEDIUM (HIGH for fintech/healthcare) |
| Postgres VACUUM not scheduled after bulk erasure | LOW |

---

## Phase 5C — Consent Management Platform Assessment

This phase has two parts: **audit** what exists, then **design** what is missing.

### 5C-1. Audit existing consent infrastructure

```bash
# Find consent-related tables in DB models/migrations
grep -rPn --include="*.py" --include="*.rb" --include="*.ts" --include="*.sql" \
  'consent\|privacy_polic\|terms.*version\|policy.*version\|cookie.*consent' \
  . 2>/dev/null | grep -v node_modules | grep -v '.venv'

# Find consent recording in backend
grep -rPn --include="*.py" --include="*.ts" --include="*.go" \
  'record.*consent\|save.*consent\|consent.*record\|consent.*grant\|accept.*terms\|accept.*policy' \
  src/ app/ . 2>/dev/null | grep -v test | grep -v spec

# Find consent withdrawal / revocation
grep -rPn --include="*.py" --include="*.ts" --include="*.go" \
  'withdraw.*consent\|revoke.*consent\|opt.*out\|unsubscribe\|delete.*consent' \
  src/ app/ . 2>/dev/null | grep -v test | grep -v spec

# Find consent-gated analytics or feature flags
grep -rPn --include="*.ts" --include="*.tsx" --include="*.js" \
  'consent.*analytic\|analytic.*consent\|if.*consent\|hasConsent\|consentGiven' \
  src/ 2>/dev/null

# Find privacy policy / terms pages and versioning
grep -rPn --include="*.py" --include="*.ts" --include="*.html" \
  'privacy.policy\|terms.of.service\|policy.*version\|policy.*effective\|is_current' \
  src/ app/ . 2>/dev/null | grep -v node_modules

# Find re-consent / policy-update flows
grep -rPn --include="*.py" --include="*.ts" \
  're.consent\|reconsent\|policy.*update\|terms.*update\|consent.*expired\|new.*policy' \
  src/ app/ . 2>/dev/null | grep -v test
```

**Consent audit checklist:**

```
☐ consent_records table (or equivalent) exists with: user_id, purpose, granted bool,
    granted_at timestamp, ip_address, user_agent, withdrawn_at nullable
☐ privacy_policies table (or equivalent) exists with: version/id, content hash,
    effective_date, is_current flag
☐ Consent purposes are enumerated (TERMS_OF_SERVICE, PRIVACY_POLICY, MARKETING,
    ANALYTICS, COOKIE_FUNCTIONAL — or equivalent)
☐ Consent is recorded at initial registration (explicit opt-in, not pre-ticked)
☐ Re-consent flow exists: triggered when a new policy version becomes effective
☐ Consent withdrawal path exists for non-essential purposes (marketing, analytics)
    — withdrawal of TERMS_OF_SERVICE = account closure, not just a toggle
☐ Consent is recorded BEFORE analytics/tracking scripts load (GDPR Art. 7; LGPD Art. 8)
☐ Timestamps stored in UTC with timezone
☐ IP address and user-agent stored with consent record (GDPR Art. 7(1) — burden of proof)
☐ Admin endpoint to view any user's consent history (for regulatory audits)
☐ Consent records are NOT deleted when a user requests erasure
    (Art. 17(3)(b) GDPR — retention needed to demonstrate legal basis; raise HIGH if deleted)
☐ Frontend consent banner shown when no consent on record — not only on first visit
☐ Privacy settings page exists so users can review and withdraw consent at any time
```

**Raise findings for any unchecked row:**

| Gap | Severity |
|---|---|
| No consent records stored (no proof of consent) | HIGH |
| Consent not obtained before analytics/tracking loads | HIGH |
| No re-consent flow when policy is updated | HIGH |
| Pre-ticked consent checkboxes | HIGH |
| Consent records deleted on erasure (destroys proof of lawful basis) | HIGH |
| No withdrawal mechanism for non-essential purposes | MEDIUM |
| IP / user-agent not captured with consent record | MEDIUM |
| No versioned privacy policy table | MEDIUM |
| No admin consent audit endpoint | LOW |

---

### 5C-2. Design recommendation (produce if gaps are found)

If the audit reveals a missing or incomplete consent management platform, include the following design in the report under **Consent Management Platform Design**.

**DB schema:**

```sql
-- Versioned policy documents
CREATE TABLE privacy_policies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose       TEXT NOT NULL,           -- e.g. 'PRIVACY_POLICY', 'TERMS_OF_SERVICE'
    version       TEXT NOT NULL,           -- semver or date string, e.g. '2024-06-01'
    content_hash  TEXT NOT NULL,           -- SHA-256 of policy text (tamper evidence)
    effective_at  TIMESTAMPTZ NOT NULL,
    is_current    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (purpose, version)
);

-- Only one current policy per purpose
CREATE UNIQUE INDEX idx_privacy_policies_current
    ON privacy_policies (purpose) WHERE is_current = TRUE;

-- Per-user consent records (append-only — never update, only insert)
--
-- ON DELETE RESTRICT is intentional and must NOT be changed to CASCADE.
--
-- Why: consent records are the legal proof that processing was lawful
-- (GDPR Art. 7(1) — burden of proof; LGPD Art. 8 §5). Deleting them when
-- a user account is erased destroys that proof and is itself a compliance
-- violation (GDPR Art. 17(3)(b) exempts records needed to defend legal claims).
--
-- How this works with the erasure flow (see Phase 5B):
-- The deletion flow ANONYMISES the users row (email → deleted+id@deleted.invalid,
-- name → 'DELETED') rather than DELETEing it. The row still exists, so
-- RESTRICT is never triggered. Consent records remain intact and queryable
-- by opaque user_id for regulatory audits. Do NOT change this to CASCADE.
CREATE TABLE consent_records (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    policy_id     UUID NOT NULL REFERENCES privacy_policies(id),
    purpose       TEXT NOT NULL,
    granted       BOOLEAN NOT NULL,        -- TRUE = consent given, FALSE = withdrawn
    ip_address    INET,
    user_agent    TEXT,
    granted_at    TIMESTAMPTZ,             -- populated when granted = TRUE
    withdrawn_at  TIMESTAMPTZ,             -- populated when granted = FALSE
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_consent_user_purpose ON consent_records (user_id, purpose, created_at DESC);
```

**Consent purposes enum:**

```
TERMS_OF_SERVICE    — required for account creation; withdrawal = account closure
PRIVACY_POLICY      — required; must be re-obtained when policy changes materially
MARKETING           — optional; email/SMS marketing
ANALYTICS           — optional; behavioural analytics (Mixpanel, Amplitude, etc.)
COOKIE_FUNCTIONAL   — optional; non-essential cookies
```

**API endpoints:**

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/privacy/policies` | public | List all current policy versions |
| `GET` | `/v1/privacy/policies/:id` | public | Get full policy text by ID |
| `POST` | `/v1/privacy/consent` | user | Record consent grant or withdrawal |
| `GET` | `/v1/privacy/consent` | user | Get authenticated user's current consent per purpose |
| `DELETE` | `/v1/privacy/consent/:purpose` | user | Withdraw consent for a non-essential purpose |
| `GET` | `/v1/admin/privacy/consent/:user_id` | admin | View full consent history for a user |

**Consent flows to implement:**

1. **Initial registration** — show explicit opt-in checkbox per purpose; submit records a `consent_records` row for each. Checkboxes for TERMS_OF_SERVICE and PRIVACY_POLICY must not be pre-ticked.

2. **Policy update re-consent** — when a new policy version's `effective_at` is reached, set `is_current = TRUE` on the new row and `FALSE` on the old. On the user's next login, intercept with a re-consent modal before granting access. Record a new `consent_records` row; do not update the old one.

3. **Consent withdrawal** — available in account settings for MARKETING, ANALYTICS, COOKIE_FUNCTIONAL. Insert a `consent_records` row with `granted = FALSE, withdrawn_at = NOW()`. TERMS_OF_SERVICE / PRIVACY_POLICY withdrawal triggers the account deletion flow instead.

**Frontend components needed:**

```
☐ Consent banner — shown on first visit AND any time the user has no current consent
    record for PRIVACY_POLICY or COOKIE_FUNCTIONAL. Must not set non-essential cookies
    before the banner is dismissed with affirmative consent.
☐ Privacy settings page — shows current consent status per purpose with
    grant/withdrawal timestamps. Allows toggling MARKETING, ANALYTICS, COOKIE_FUNCTIONAL.
☐ Consent hook / context — e.g. useConsent('ANALYTICS') → boolean. Gates all
    analytics calls (Mixpanel.track, gtag, etc.) so they are no-ops until consent is given.
☐ Re-consent modal — blocks access after login when a new policy version is detected.
    Must present the diff or full new policy text; must not auto-accept on dismiss.
```

**Remediation code snippets:**

```python
# Backend: record consent (Python/FastAPI example)
@router.post("/v1/privacy/consent")
async def record_consent(
    body: ConsentRequest,
    current_user = Depends(get_current_user),
    request: Request = None,
    db = Depends(get_db),
):
    policy = db.query(PrivacyPolicy).filter_by(purpose=body.purpose, is_current=True).first()
    if not policy:
        raise HTTPException(404, "No current policy found for this purpose")
    record = ConsentRecord(
        user_id=current_user.id,
        policy_id=policy.id,
        purpose=body.purpose,
        granted=body.granted,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
        granted_at=datetime.utcnow() if body.granted else None,
        withdrawn_at=datetime.utcnow() if not body.granted else None,
    )
    db.add(record)
    db.commit()
    return {"status": "recorded"}
```

```typescript
// Frontend: consent hook that gates analytics
// hooks/useConsent.ts
import { useContext } from 'react';
import { ConsentContext } from '../context/ConsentContext';

export function useConsent(purpose: ConsentPurpose): boolean {
  const { consents } = useContext(ConsentContext);
  return consents[purpose]?.granted === true;
}

// Usage in analytics initialisation:
const analyticsConsent = useConsent('ANALYTICS');
useEffect(() => {
  if (analyticsConsent) {
    analytics.init(ANALYTICS_KEY);
  }
}, [analyticsConsent]);
```

---

## Phase 6 — Report Generation

> **Security warning — read before writing the report.**
> The audit report will contain a complete inventory of every PII field in the
> database, all security findings (unencrypted fields, missing auth, public
> buckets), third-party processor relationships, and known gaps in the deletion
> pipeline. **This document is a roadmap for attackers if it leaks.**
>
> Before writing the report:
> 1. Add `docs/privacy-audit-*.md` to `.gitignore` so reports are never
>    committed to the repository.
> 2. Consider writing outside the working tree entirely:
>    `~/privacy-audit-$(date +%Y-%m-%d).md`
> 3. Store in a private, access-controlled location (encrypted drive, internal
>    wiki with ACLs, secrets manager document store) — never in a public repo,
>    a shared Google Doc with broad access, or a CI artifact with public visibility.
> 4. Treat under the same access controls as production credentials.

Write the full audit report to `docs/privacy-audit-YYYY-MM-DD.md` using today's date (or `docs/plans/privacy-audit-YYYY-MM-DD.md` if that directory exists). **Never overwrite a previous report — the dated filename is the audit history.** Remind the user to add `docs/privacy-audit-*.md` to `.gitignore`.

**Tracking progress across runs:** To compare two audit reports, run:
```bash
diff docs/privacy-audit-2026-01-15.md docs/privacy-audit-2026-06-01.md | grep '^[<>]' | grep -E 'CRITICAL|HIGH|MEDIUM'
```
A finding that appears in `<` (old) but not `>` (new) has been remediated. A finding in `>` but not `<` is newly introduced. The run ID in each report header makes this unambiguous.

The report must follow this structure:

```markdown
# Privacy Engineering Audit Report

**Run ID:** <repo-slug>-<YYYY-MM-DD> (e.g. `myapp-2026-06-06`)
**Date:** <today>
**Previous run:** <filename of last report, or "first run">
**Repository:** <repo name>
**Tech Stack:** <detected stack>
**Jurisdictions assessed:** <from Phase 0 — only laws marked Yes/Uncertain>
**Laws Assessed:** <only applicable laws from Phase 0>

---

## Executive Summary

[3-5 sentences: overall posture, number of critical/high/medium/low findings, top 3 risks]

---

## Findings

### CRITICAL (fix before next release)
[Each finding: Description | File:Line | Regulation violated | Remediation]

### HIGH (fix within 1 sprint)
[...]

### MEDIUM (fix within 1 quarter)
[...]

### LOW / INFORMATIONAL
[...]

---

## Data Inventory

[Full table of all PII/sensitive fields found]

---

## Data Classification Map

[Diagram or table showing data sensitivity by system component]

---

## Third-Party Data Flows

[Table: service | data shared | legal basis | DPA in place? | data retention at processor]

---

## Deletion Policy Analysis

[For each data category: is there a deletion mechanism? does soft-delete leave PII (if so, HIGH finding)? are backups purged? is a deletion registry maintained?]

[Table columns: Data category | Primary DB strategy | Cascade/orphan risk | Cache cleared | Warehouse propagation | Sectoral retention rule | Legal basis for retention | Notes]

## Event Sourcing / Append-Only Architecture

[If Kafka, Kinesis, DynamoDB Streams, or event sourcing detected: document whether crypto shredding is implemented. If not, raise as HIGH. Include which PII fields are written to the event log and which KMS key would need to be destroyed per-user.]

---

## DPIA Assessment

[Is a DPIA required? Has it been conducted? Gaps?]

---

## DSAR Process Assessment

[Does a process exist? Is it complete? What's missing?]

---

## Cookie & Consent Analysis

[Findings from frontend audit — cookie categories set before consent, missing banner, tracking pixels loaded unconditionally, etc.]

---

## Consent Management Platform Assessment

[Audit findings from Phase 5C-1. For each gap found, include severity and regulation violated.]

[If CMP is absent or materially incomplete, include the full design from Phase 5C-2 here:
- DB schema: privacy_policies + consent_records tables
- Consent purposes enum
- API endpoint table
- Consent flows: initial registration, policy-update re-consent, withdrawal
- Frontend components needed: consent banner, privacy settings page, consent hook, re-consent modal]

---

## Legal Compliance Matrix

[Full matrix from Phase 3 with actual statuses filled in]

---

## Remediation Roadmap

### Immediate (this week)
[...]

### Short-term (1 month)
[...]

### Medium-term (1 quarter)
[...]

### Long-term / Ongoing
[...]

---

## SAST and Tooling Recommendations

[Recommended tools with install commands for this specific stack]

---

## Architecture Recommendations

[Privacy-by-design changes: data minimisation, anonymisation, pseudonymisation, separate PII store, etc.]
```

---

## Severity Classification

Use these rules to classify each finding:

| Severity | Definition | Example |
|---|---|---|
| **CRITICAL** | Active PII exposure or data breach risk; law requires immediate action | Email in logs, unencrypted SSN at rest, public S3 bucket with user data, no auth on user data endpoint |
| **HIGH** | Significant compliance gap; likely regulatory violation | No cookie consent, no DSAR process, MFA not available, no log retention, soft-delete doesn't purge PII |
| **MEDIUM** | Compliance gap that increases risk or violates good practice | No DPA with processor, no DPIA for biometric data, partial token in logs, weak password policy |
| **LOW** | Process gap or informational; no immediate exposure | No ROPA documented, DPO not publicly listed, privacy policy missing last-updated date |

---

## Quick Reference: PII by Regulation

Classification tiers follow the CISSP five-tier commercial model — reference: [AWS Data Classification whitepaper](https://docs.aws.amazon.com/whitepapers/latest/data-classification/data-classification-models-and-schemes.html).

| Data Type | Classification | GDPR | LGPD | CCPA | Notes |
|---|---|---|---|---|---|
| Name | Confidential | Art. 4(1) PII | Art. 5(I) | §1798.140 | Standard PII |
| Email | Confidential | Art. 4(1) PII | Art. 5(I) | §1798.140 | Standard PII |
| Phone | Confidential | Art. 4(1) PII | Art. 5(I) | §1798.140 | Standard PII |
| Full address | Confidential | Art. 4(1) PII | Art. 5(I) | §1798.140 | Standard PII |
| IP address | Confidential | Art. 4(1) PII | Art. 5(I) | §1798.140 | Pseudonymous |
| Device fingerprint | Confidential | Art. 4(1) PII | Art. 5(I) | §1798.140 | Pseudonymous |
| User-agent string | Confidential | Art. 4(1) PII | Art. 5(I) | §1798.140 | Pseudonymous |
| Geolocation (precise) | Confidential | Art. 4(1) PII | Art. 5(I) | §1798.121 SPI | Sensitive in CCPA |
| Health data | **Sensitive** | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection; DPIA required |
| Biometric (fingerprint, signature, face) | **Sensitive** | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection; DPIA required |
| Racial / ethnic origin | **Sensitive** | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| Religious belief | **Sensitive** | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| Political opinion | **Sensitive** | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| Sexual orientation / sex life | **Sensitive** | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| SSN / CPF / TIN | **Sensitive** | Art. 4(1) PII | Art. 5(I) + Art. 11 | §1798.121 SPI | Government ID; highest regulatory exposure |
| Payment card data | **Sensitive** | Art. 4(1) PII + PCI DSS | Art. 5(I) | §1798.121 SPI | PCI DSS also applies |
| Passwords / hashes | **Sensitive** | Art. 32 security | Art. 46 | Security | Never log; bcrypt/argon2 only |
| Auth tokens | Private | Art. 32 security | Art. 46 | Security | Hash before logging |
| Purchase / transaction history | Private | Art. 4(1) PII | Art. 5(I) | §1798.140 | Behavioral; sectoral retention rules may apply |
| Behavioral / activity data | Private | Art. 4(1) PII | Art. 5(I) | §1798.140 | Profiling risk |
| Children's data (<13/<16) | **Sensitive** | Art. 8 GDPR | Art. 14 LGPD | COPPA | Parental consent required regardless of other tier |
| Employee / HR data | Private | Art. 4(1) PII | Art. 5(I) | §1798.140 | Employment law also applies |
| CPF (Brazil) | **Sensitive** | Art. 4(1) PII | National ID — Art. 5(I) + strict ANPD rules | - | Treat with same care as SSN |
| CNPJ (Brazil) | Public | Lower risk | Business ID only | - | Not personal data |
| City / country alone | Public | Art. 4(1) if linkable | Art. 5(I) if linkable | §1798.140 if linkable | Re-identification risk when combined |
| Aggregate / anonymised stats | Public | Not PII if truly anonymous | Not PII if truly anonymous | Not PI if truly anonymous | Verify k-anonymity / differential privacy |

---

## Remediations Quick Reference

### PII in logs → fix
```python
# Python/loguru — remove PII, keep context
# Before: logger.info(f"Sent email to {user.email}: {msg_id}")
# After:  logger.info(f"Sent email: msg_id={msg_id}")

# Add scrubbing filter in app entrypoint
import re, sys
from loguru import logger
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
def _scrub_pii(record):
    record["message"] = _EMAIL_RE.sub("[REDACTED]", record["message"])
    return True
logger.remove()
logger.add(sys.stderr, filter=_scrub_pii)
```

### Soft-delete doesn't erase PII → fix
```sql
-- Right to erasure: anonymise, don't just flag
-- A bare soft-delete (deleted_at = NOW()) is ocultação, not erasure.
UPDATE users
SET email = CONCAT('deleted_', id, '@deleted.invalid'),
    name = 'DELETED',
    phone = NULL,
    address_line1 = NULL,
    address_line2 = NULL,
    city = NULL,
    zip = NULL,
    deleted_at = NOW()
WHERE id = $1;
-- Keep the row for referential integrity but PII is gone

-- Also insert into the deletion registry for backup reconciliation:
INSERT INTO deletion_registry (user_id_hash, deleted_at, reason)
VALUES (encode(sha256($1::bytea), 'hex'), NOW(), 'user_request');

-- After bulk erasure, reclaim disk space (PostgreSQL MVCC leaves dead tuples):
-- VACUUM (VERBOSE, ANALYZE) users;
-- Monitor: SELECT n_dead_tup FROM pg_stat_user_tables WHERE relname = 'users';
```

### Orphaned data (missing FK constraint) → fix
```sql
-- If user_id columns exist without a FK, add the constraint and clean up:

-- 1. Clean up orphans already present:
DELETE FROM messages WHERE user_id NOT IN (SELECT id FROM users);
DELETE FROM activity_logs WHERE user_id NOT IN (SELECT id FROM users);

-- 2. Add the FK so future deletes stay consistent:
ALTER TABLE messages
  ADD CONSTRAINT fk_messages_user
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Note: ON DELETE SET NULL is safer when you need to preserve the row
-- but remove the user association (e.g. audit logs, orders).
ALTER TABLE orders
  ADD CONSTRAINT fk_orders_user
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
```

### Event sourcing / append-only log → crypto shredding
```python
# Crypto shredding pattern: encrypt PII fields with a per-user key.
# "Deletion" = destroy the key. Events remain in the log but are unreadable.

import boto3
import base64
import json
from cryptography.fernet import Fernet

kms = boto3.client('kms')
KEY_ALIAS = 'alias/user-pii-{user_id}'

def get_or_create_user_key(user_id: str) -> bytes:
    """Return a data key encrypted under the user's KMS key."""
    key_id = KEY_ALIAS.format(user_id=user_id)
    response = kms.generate_data_key(KeyId=key_id, KeySpec='AES_256')
    return response['Plaintext']  # use in memory only; store CiphertextBlob in event

def encrypt_pii_for_event(user_id: str, payload: dict) -> dict:
    """Wrap PII fields so they can be crypto-shredded later."""
    plaintext_key = get_or_create_user_key(user_id)
    f = Fernet(base64.urlsafe_b64encode(plaintext_key[:32]))
    encrypted = f.encrypt(json.dumps(payload).encode())
    return {'user_id': user_id, 'pii_encrypted': base64.b64encode(encrypted).decode()}

def shred_user(user_id: str):
    """
    Crypto-shredding: schedule deletion of the KMS key.
    After PendingDeletion window (min 7 days), all encrypted payloads
    for this user become permanently unreadable.
    """
    key_id = KEY_ALIAS.format(user_id=user_id)
    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    # Log the shredding event using opaque reference only:
    import hashlib
    ref = hashlib.sha256(user_id.encode()).hexdigest()[:12]
    audit_log(action='crypto_shred_scheduled', subject_ref=ref)
```

### Data warehouse deletion propagation → fix
```python
# Option 1: propagate hard deletes via your existing pipeline
# In dbt: add a macro that filters deleted users from all models
# macros/exclude_deleted_users.sql:
#   {% macro exclude_deleted_users(user_id_col='user_id') %}
#     {{ user_id_col }} NOT IN (SELECT user_id_hash FROM deletion_registry)
#   {% endmacro %}

# Option 2: direct deletion in BigQuery after erasure request
from google.cloud import bigquery

def propagate_deletion_to_warehouse(user_id: str):
    client = bigquery.Client()
    tables_with_user_data = [
        'project.dataset.events',
        'project.dataset.sessions',
        'project.dataset.purchases',
    ]
    for table in tables_with_user_data:
        query = f"DELETE FROM `{table}` WHERE user_id = @user_id"
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("user_id", "STRING", user_id)]
        )
        client.query(query, job_config=job_config).result()
```

### No cookie consent → add
```typescript
// Use a consent management platform or library
// Options: Cookiebot, OneTrust, Osano, react-cookie-consent, vanilla-cookieconsent
// Key requirement: analytics/tracking scripts MUST NOT load until consent obtained
// Wrong:
import Analytics from './analytics'; // loads unconditionally
// Right:
if (cookieConsent.analytics) {
  import('./analytics').then(m => m.init());
}
```

### No DSAR endpoint → add
```python
# Minimum viable DSAR implementation
@router.get("/v1/privacy/export", dependencies=[Depends(get_current_user)])
async def export_my_data(current_user = Depends(get_current_user), db = Depends(get_db)):
    """Returns all data held about the authenticated user (GDPR Art. 15 / LGPD Art. 18)."""
    return {
        "profile": ...,
        "purchases": ...,
        "shipments": ...,
        "audit_log": ...,
        "exported_at": datetime.utcnow().isoformat(),
    }

@router.delete("/v1/privacy/account", dependencies=[Depends(get_current_user)])
async def delete_my_account(current_user = Depends(get_current_user), db = Depends(get_db)):
    """Anonymises all PII for the authenticated user (GDPR Art. 17 / LGPD Art. 18(IV))."""
    ...
```

### CDK — add encryption and retention
```typescript
// DynamoDB
new dynamodb.Table(this, 'UserTable', {
  encryption: dynamodb.TableEncryption.AWS_MANAGED,
  pointInTimeRecoveryEnabled: true,
});

// SQS
new sqs.Queue(this, 'Queue', {
  encryption: sqs.QueueEncryption.KMS_MANAGED,
});

// CloudWatch log retention
new logs.LogGroup(this, 'AppLogs', {
  retention: logs.RetentionDays.THREE_MONTHS,
  encryptionKey: kmsKey,
});

// Cognito MFA
new cognito.UserPool(this, 'UserPool', {
  mfa: cognito.Mfa.REQUIRED,
  mfaSecondFactor: { sms: false, otp: true }, // TOTP only (no SIM-swap risk)
  passwordPolicy: {
    minLength: 12,
    requireSymbols: true,
    requireDigits: true,
    requireUppercase: true,
    requireLowercase: true,
  },
});
```

### Terraform equivalents
```hcl
# RDS encryption
resource "aws_db_instance" "main" {
  storage_encrypted = true
  publicly_accessible = false
}

# S3 block public access
resource "aws_s3_bucket_public_access_block" "main" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudWatch log retention
resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/production"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn
}
```
