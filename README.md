# privacy-audit — Claude Code Skill

A [Claude Code](https://claude.ai/code) skill that performs a comprehensive, multi-layer privacy engineering audit on any software repository. Run it with a single slash command: `/privacy-audit`.

---

## What it does

The skill guides Claude through a structured, six-phase audit and writes a full findings report to `docs/privacy-audit.md` in your project. It is **tech-stack agnostic** — it works on any combination of languages, frameworks, and cloud providers.

### Layers audited

| Layer | What's checked |
|---|---|
| **Database / ORM** | Every table and field inventoried and classified by sensitivity; encryption at rest; retention policies |
| **Backend logs** | Grep patterns detect emails, phone numbers, tokens, and passwords in `logger.*` / `console.log` calls |
| **Infrastructure (CDK / Terraform / Pulumi / CloudFormation)** | Encryption, public access, IAM least-privilege, log retention, KMS, MFA, secrets management |
| **Backend API** | Auth, authorization, rate limiting, soft-delete PII gaps, bulk export risks |
| **Frontend** | Cookie consent correctness, analytics/pixel gating, localStorage PII, Sentry scrubbing, privacy policy |
| **CI/CD & pre-commit hooks** | Hardcoded secrets in workflows, SAST presence, dependency scanning |

### Legal compliance matrix

The audit generates a per-article compliance table for:

- **GDPR** (EU — Regulation 2016/679)
- **LGPD** (Brazil — Lei 13.709/2018), including CPF/CNPJ handling and ANPD requirements
- **CCPA / CPRA** (California)
- **PIPEDA** (Canada)
- **PDPA** (Thailand 2019 / Singapore 2012, amended 2020)
- **POPIA** (South Africa — Act 4 of 2013)
- Flags when **HIPAA**, **COPPA**, **FERPA**, **PCI DSS**, or **ePrivacy Directive** may apply

### Report sections

1. Executive summary with critical/high/medium/low finding counts
2. Complete **data inventory** — every PII field, its sensitivity level, legal basis needed, encryption status, and retention policy
3. **Data classification map** across system components
4. **Third-party data flow** table (SES, Stripe, Sentry, analytics, CRM, etc.)
5. **Deletion policy analysis** — does soft-delete actually erase PII? Are backups purged?
6. **DPIA assessment** — is one required? Has it been conducted? LGPD RIPD equivalent
7. **DSAR process assessment** — with per-law response SLAs (GDPR 1 month, LGPD 15 days, CCPA 45 days)
8. **Cookie & consent analysis**
9. Prioritized **remediation roadmap** by layer
10. **SAST and tooling recommendations** with ready-to-paste install commands and a GitHub Actions security workflow

---

## Installation

Copy the skill into your global Claude Code skills directory:

```bash
mkdir -p ~/.claude/skills/privacy-audit
cp .claude/skills/privacy-audit/SKILL.md ~/.claude/skills/privacy-audit/SKILL.md
```

Or clone directly to the right location:

```bash
git clone https://github.com/guidopercu/privacy-audit-skill ~/.claude/skills/privacy-audit-skill
mkdir -p ~/.claude/skills/privacy-audit
cp ~/.claude/skills/privacy-audit-skill/.claude/skills/privacy-audit/SKILL.md ~/.claude/skills/privacy-audit/SKILL.md
```

### Per-project installation

To make the skill available only within a specific project:

```bash
cd your-project
mkdir -p .claude/skills/privacy-audit
cp /path/to/SKILL.md .claude/skills/privacy-audit/SKILL.md
```

Claude Code discovers skills automatically from both `~/.claude/skills/` (global) and `.claude/skills/` (project-local).

---

## Usage

Open Claude Code inside any repository and run:

```
/privacy-audit
```

Claude will:
1. Detect your tech stack automatically
2. Launch parallel Explore agents to scan infrastructure, data models, and application code simultaneously
3. Analyze findings against all applicable privacy laws
4. Write a structured audit report to `docs/privacy-audit.md`

No configuration required.

---

## Example output

```
docs/privacy-audit.md
├── Executive Summary
│   └── 3 critical · 7 high · 12 medium · 4 low findings
├── Findings
│   ├── CRITICAL: Email addresses in CloudWatch logs (GDPR Art. 32 / LGPD Art. 46)
│   ├── CRITICAL: DynamoDB tables without encryption at rest
│   ├── HIGH: No cookie consent banner — analytics load unconditionally
│   ├── HIGH: Soft-delete does not anonymise PII (GDPR Art. 17 violation)
│   └── ...
├── Data Inventory (47 fields across 12 tables)
├── Legal Compliance Matrix
│   ├── GDPR: 8 gaps found
│   ├── LGPD: 6 gaps found
│   └── CCPA: 4 gaps found
├── DPIA Assessment: Required (biometric signature data) — not conducted
├── DSAR Process: Missing — no export or deletion endpoints
└── Remediation Roadmap
    ├── Immediate (this week): 3 items
    ├── Short-term (1 month): 8 items
    └── Medium-term (1 quarter): 9 items
```

---

## Remediations included

The skill includes ready-to-use code snippets for the most common fixes:

- **PII in logs** → loguru scrubbing filter, per-call fixes for Python, TypeScript, Go
- **Soft-delete PII gap** → SQL anonymisation pattern that preserves referential integrity
- **No cookie consent** → implementation pattern with analytics gating
- **No DSAR endpoints** → minimum viable `/v1/privacy/export` and `/v1/privacy/account` (DELETE) in FastAPI
- **CDK** → encryption snippets for DynamoDB, SQS, CloudWatch, Cognito MFA
- **Terraform** → equivalent HCL for RDS, S3, CloudWatch log groups
- **CI/CD** → complete GitHub Actions `security.yml` workflow with gitleaks, bandit, checkov, and trivy
- **Pre-commit** → `.pre-commit-config.yaml` with gitleaks and detect-secrets

---

## PII classification reference

The skill includes a full quick-reference table mapping data types to their classification under each law:

| Data type | GDPR | LGPD | CCPA |
|---|---|---|---|
| Name, email, phone, address | Art. 4(1) PII | Art. 5(I) | §1798.140 |
| IP address, device fingerprint | Art. 4(1) pseudonymous | Art. 5(I) | §1798.140 |
| Biometric data (incl. signature images) | **Art. 9 Special Category** | **Art. 11 Sensitive** | §1798.121 SPI |
| Health data | **Art. 9 Special Category** | **Art. 11 Sensitive** | §1798.121 SPI |
| SSN / CPF / TIN | Art. 4(1) PII | **National ID — CRITICAL** | §1798.121 SPI |
| Racial / ethnic / religious / political | **Art. 9 Special Category** | **Art. 11 Sensitive** | §1798.121 SPI |
| Children's data | Art. 8 (parental consent) | Art. 14 | COPPA applies |

---

## SAST tools recommended

The skill recommends tools based on detected stack. Examples:

| Tool | Purpose | Language/target |
|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection | Any |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Secret detection + pre-commit | Any |
| [bandit](https://bandit.readthedocs.io/) | SAST | Python |
| [semgrep](https://semgrep.dev/) | SAST (rules for Django, Flask, Node, React, Go) | Multi |
| [pip-audit](https://pypi.org/project/pip-audit/) | Dependency CVEs | Python |
| [tfsec](https://github.com/aquasecurity/tfsec) | IaC security | Terraform |
| [checkov](https://github.com/bridgecrewio/checkov) | IaC security | Terraform, CDK, CloudFormation, K8s |
| [cdk-nag](https://github.com/cdklabs/cdk-nag) | AWS CDK compliance rules | AWS CDK |
| [trivy](https://github.com/aquasecurity/trivy) | Container + filesystem + IaC | Any |

---

## Requirements

- [Claude Code](https://claude.ai/code) — the skill is a set of instructions for Claude; no additional runtime required
- The skill works on any repository Claude Code can read

---

## Contributing

Contributions welcome. The skill file is a single Markdown document at `.claude/skills/privacy-audit/SKILL.md`. Areas where additions would be most valuable:

- Additional law coverage (India DPDP Act, Japan APPI, South Korea PIPA, Australia Privacy Act)
- Framework-specific patterns (Django ORM, Prisma, Rails ActiveRecord, Hibernate)
- Additional grep patterns for less common logging libraries
- Language-specific SAST tool recommendations (Ruby, Java, Rust, PHP)
- Cloud-provider-specific checks for GCP and Azure

---

## License

MIT
