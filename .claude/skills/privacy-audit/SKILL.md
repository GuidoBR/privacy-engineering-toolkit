---
name: privacy-audit
description: Run a full privacy engineering audit on the current repository. Checks CDK/Terraform infrastructure, database schemas, backend logs, API endpoints, frontend code, CI/CD pipelines, and pre-commit hooks for PII leaks, insecure data handling, and violations of GDPR, CCPA, LGPD (Brazil), PIPEDA (Canada), PDPA (Thailand/Singapore), POPIA (South Africa), and other major privacy laws. Produces a structured audit report with findings, a data inventory, a data classification map, deletion policy analysis, DPIA/DSAR gap assessment, cookie/consent review, and prioritized remediations across every layer of the stack. Use when asked to audit privacy, check for GDPR/LGPD compliance, review PII handling, or run a privacy review.
---

# Privacy Engineering Audit Skill

Perform a full-stack privacy audit and produce a structured findings report. This skill is tech-stack agnostic — it works for any combination of Python/Node/Go/Java backends, React/Vue/Angular frontends, PostgreSQL/MySQL/MongoDB/DynamoDB databases, AWS/GCP/Azure infrastructure written in CDK/Terraform/Pulumi, and any CI/CD system.

---

## How to Run This Skill

You will execute the audit in **five phases**. Launch Explore sub-agents in parallel for discovery, synthesize findings yourself, then write the report.

**Output location:** Write the final report to `docs/privacy-audit.md` (create the path if it doesn't exist). If the repo already has a `docs/plans/` directory, write to `docs/plans/privacy-audit.md` instead.

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

| Field | Table | Type | Sensitivity | PII Category | Legal Basis Needed | Encrypted? | Retention Policy |
|---|---|---|---|---|---|---|---|

**Sensitivity levels:**
- `CRITICAL` — SSN/TIN, payment card data (PCI), biometric data, health data, passport/ID numbers, passwords/hashes
- `HIGH` — full name, email, phone, full address, IP address, device fingerprint, signature image, geolocation
- `MEDIUM` — city/state/country alone, username, opaque user ID, purchase history, behavioral data
- `LOW` — non-identifying operational data

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

Run these grep patterns against all backend source files. Each match is a potential GDPR Art. 32 / LGPD Art. 46 violation:

```bash
# Find PII in logger calls (Python — loguru/logging)
grep -rPn --include="*.py" \
  'log(ger)?\.(debug|info|warning|error|exception|critical)\(.*\{[^}]*(email|phone|password|token(?!_id|_ref|_hash)|ssn|cpf|cnpj|address|name|ip_addr)[^}]*\}' \
  src/ 2>/dev/null

# Find PII in logger calls (JavaScript/TypeScript)
grep -rPn --include="*.ts" --include="*.js" --include="*.tsx" \
  'console\.(log|error|warn|info|debug).*\$\{[^}]*(email|phone|password|token(?!Id|Ref|Hash)|address|name)\}' \
  src/ 2>/dev/null

# Find PII in logger calls (Go)
grep -rPn --include="*.go" \
  'log\.(Print|Fatal|Panic|Error|Warn|Info|Debug).*[^_](email|phone|password|address|name)' \
  . 2>/dev/null

# Find HTTP request body logging (any language) — extremely dangerous
grep -rPn --include="*.py" --include="*.ts" --include="*.js" --include="*.go" \
  'log.*request\.body\|log.*req\.body\|log.*request\.data\|log.*payload' \
  . 2>/dev/null

# Find password/secret logging
grep -rPn --include="*.py" --include="*.ts" --include="*.js" \
  'log.*password\|print.*password\|console.*password' \
  . 2>/dev/null

# Find raw token logging (not hashed)
grep -rPn --include="*.py" \
  'log.*\btoken\b.*[:=].*[a-zA-Z0-9+/=]\{20,\}' \
  . 2>/dev/null

# Check if Sentry/error trackers capture PII
grep -rPn --include="*.py" --include="*.ts" --include="*.js" \
  'sentry.*capture\|Sentry\.setUser\|Sentry\.setExtra' \
  . 2>/dev/null

# Check for structured logging that might include user objects
grep -rPn --include="*.py" \
  'logger\.\(info\|debug\|error\).*\buser\b.*=' \
  . 2>/dev/null
```

**Checks for log infrastructure:**
- Are CloudWatch/Datadog/ELK log groups configured with a retention period? (GDPR Art. 5(1)(e) — storage limitation)
- Are logs encrypted at rest? (GDPR Art. 32)
- Who has access to production logs? (GDPR Art. 32 — access controls)
- Is there a scrubbing/redaction layer before logs are written?

---

### 2C. Infrastructure Audit

For each IaC file found, check:

**Database (RDS/Aurora/Cloud SQL/DocumentDB):**
```
☐ encryption at rest enabled (storageEncrypted / disk_encryption)
☐ encryption in transit enforced (ssl_enforcement_enabled / require_ssl)
☐ not publicly accessible (publiclyAccessible: false / publicly_accessible = false)
☐ inside private VPC/subnet
☐ credentials in secrets manager (not hardcoded, not in env vars)
☐ automated backups enabled with retention period documented
☐ deletion protection enabled in production
☐ data classification tag present
☐ point-in-time recovery enabled (for GDPR Art. 32 / LGPD Art. 46 breach recovery)
```

**Object storage (S3/GCS/Azure Blob):**
```
☐ block all public access enabled
☐ encryption at rest (SSE-S3, SSE-KMS, or CMEK)
☐ enforce SSL / deny HTTP requests
☐ versioning enabled (for audit trail / right-to-erasure verification)
☐ lifecycle rules set with documented retention periods
☐ access logging enabled
☐ bucket policy restricts access (no wildcard Principal)
☐ W-9/identity documents bucket separate from general assets
☐ data classification tag present
```

**Authentication service (Cognito/Auth0/Firebase):**
```
☐ MFA available or enforced
☐ password policy meets NIST SP 800-63B (12+ chars, symbols, no common passwords)
☐ account recovery is secure (email only, not SMS — SIM-swap risk)
☐ JWT token expiry is short (access: ≤1hr, refresh: ≤30d)
☐ audit logging enabled for auth events
☐ what user attributes are collected? (each is PII under GDPR Art. 4(1))
```

**Key Management:**
```
☐ KMS/Cloud KMS used for encryption keys (not hardcoded Fernet/AES keys)
☐ key rotation enabled
☐ encryption key access restricted to necessary principals only
☐ FERNET_KEY / ENCRYPTION_KEY not in .env.example, CI env, or git history
```

**Network:**
```
☐ database only reachable from within VPC
☐ no public IPs on application servers (only load balancer)
☐ security groups follow least-privilege (not 0.0.0.0/0 on database ports)
☐ TLS 1.2+ enforced everywhere (TLS 1.0/1.1 disabled)
☐ WAF in place for public endpoints
```

**CloudWatch / Logging infrastructure:**
```
☐ log group retention periods set for ALL log groups
☐ log groups encrypted (KMS key)
☐ no PII in log group names or metric filter patterns
☐ CloudTrail enabled for API call auditing
☐ log access IAM policy is least-privilege
```

**SQS/Pub/Sub/Kinesis (message queues):**
```
☐ encryption at rest (KMS)
☐ dead-letter queue has same encryption
☐ messages containing PII? → document retention and purge policy
```

**DynamoDB / NoSQL:**
```
☐ encryption at rest (KMS-managed preferred over AWS-owned)
☐ point-in-time recovery enabled
☐ tables containing PII tagged accordingly
```

**IAM / Access Control:**
```
☐ no wildcard actions (*) on sensitive resources (S3 PII buckets, KMS, Cognito)
☐ principle of least privilege: scope resource ARNs, not "*"
☐ no inline policies attached directly to users
☐ MFA required for privileged IAM roles
☐ no long-lived IAM access keys in CI/CD (use OIDC/Workload Identity)
```

---

### 2D. Backend API Audit

```bash
# Find endpoints that accept and store user data without apparent validation
grep -rPn --include="*.py" --include="*.ts" --include="*.go" \
  '@(app|router)\.(post|put|patch).*\/(users|profile|account|signup|register)' \
  . 2>/dev/null

# Check for raw SQL queries that might not sanitize PII
grep -rPn --include="*.py" \
  'execute\(.*%s\|execute\(.*format\(' \
  . 2>/dev/null

# Find rate-limiting on sensitive endpoints
grep -rPn --include="*.py" --include="*.ts" \
  'rate.limit\|RateLimiter\|throttle\|slowDown' \
  . 2>/dev/null

# Check for data export endpoints (high DSAR risk if unprotected)
grep -rPn --include="*.py" --include="*.ts" \
  'export\|download.*csv\|download.*excel\|bulk.*export' \
  . 2>/dev/null

# Check if deleted_at soft-delete is used (right to erasure gap)
grep -rPn --include="*.py" \
  'deleted_at\|soft.delete\|is_deleted\|archived_at' \
  . 2>/dev/null
```

**Check for:**
- Authentication on all non-public endpoints
- Authorization checks (users can only access their own data)
- Input validation on PII fields (email format, phone format)
- Rate limiting on auth, password reset, and email lookup endpoints
- Whether "soft delete" actually removes PII or just sets a flag (GDPR Art. 17 violation if PII persists)
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

For each law, assess compliance based on findings above.

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
- CPF (individual taxpayer ID) and CNPJ are highly regulated — treat as CRITICAL
- Privacy policy must be available in Portuguese

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
☐ Deletion audit trail maintained (what was deleted, when, by whom)
☐ Process documented in runbook
☐ Process tested end-to-end at least annually
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

## Phase 6 — Report Generation

Write the full audit report to `docs/privacy-audit.md` (or `docs/plans/privacy-audit.md` if that directory exists). The report must follow this structure:

```markdown
# Privacy Engineering Audit Report

**Date:** <today>
**Repository:** <repo name>
**Tech Stack:** <detected stack>
**Laws Assessed:** GDPR · LGPD · CCPA · PIPEDA · [others detected as relevant]

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

[For each data category: is there a deletion mechanism? does soft-delete leave PII? are backups purged?]

---

## DPIA Assessment

[Is a DPIA required? Has it been conducted? Gaps?]

---

## DSAR Process Assessment

[Does a process exist? Is it complete? What's missing?]

---

## Cookie & Consent Analysis

[Findings from frontend audit]

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

| Data Type | GDPR | LGPD | CCPA | Notes |
|---|---|---|---|---|
| Name | Art. 4(1) PII | Art. 5(I) | §1798.140 | Standard PII |
| Email | Art. 4(1) PII | Art. 5(I) | §1798.140 | Standard PII |
| Phone | Art. 4(1) PII | Art. 5(I) | §1798.140 | Standard PII |
| Full address | Art. 4(1) PII | Art. 5(I) | §1798.140 | Standard PII |
| IP address | Art. 4(1) PII | Art. 5(I) | §1798.140 | Pseudonymous |
| Device fingerprint | Art. 4(1) PII | Art. 5(I) | §1798.140 | Pseudonymous |
| User-agent string | Art. 4(1) PII | Art. 5(I) | §1798.140 | Pseudonymous |
| Geolocation (precise) | Art. 4(1) PII | Art. 5(I) | §1798.121 SPI | Sensitive in CCPA |
| Health data | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| Biometric (fingerprint, signature, face) | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | DPIA required |
| Racial / ethnic origin | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| Religious belief | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| Political opinion | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| Sexual orientation / sex life | **Art. 9 Special** | **Art. 11 Sensitive** | §1798.121 SPI | Highest protection |
| SSN / CPF / TIN | Art. 4(1) PII | Art. 5(I) + Art. 11 | §1798.121 SPI | CRITICAL |
| Payment card data | Art. 4(1) PII + PCI DSS | Art. 5(I) | §1798.121 SPI | PCI DSS applies |
| Passwords / hashes | Art. 32 security | Art. 46 | Security | Never log; bcrypt/argon2 only |
| Auth tokens | Art. 32 security | Art. 46 | Security | Hash before logging |
| Children's data (<13/<16) | Art. 8 GDPR | Art. 14 LGPD | COPPA | Parental consent required |
| Employee data | Art. 4(1) PII | Art. 5(I) | §1798.140 | Employment law also applies |
| CPF (Brazil) | Art. 4(1) PII | **National ID — CRITICAL** | - | Strict Brazilian rules |
| CNPJ (Brazil) | Lower risk | Business ID | - | Not personal data |

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
