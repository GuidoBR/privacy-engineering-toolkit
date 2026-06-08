# Data Breach Notification Templates

Templates for notifying the supervisory authority and affected data subjects after a personal data breach.

> **GDPR timelines:**
> - Supervisory authority: within **72 hours** of becoming aware (Art. 33)
> - Data subjects: "without undue delay" when breach is likely to result in **high risk** (Art. 34)
>
> **LGPD timelines:**
> - ANPD and data subjects: within a **reasonable timeframe** (LGPD Art. 48) — ANPD guidance suggests 2 working days for initial notice, 30 days for full report.
>
> **CCPA:** No direct breach notification in CCPA itself; California Civil Code §1798.82 applies (72 hours for businesses).

> **⚠ When does the 72-hour clock start? (Common source of late-notification penalties)**
>
> Regulators (ICO, CNIL, DPC — EDPB Guidelines 01/2021 on breach notification) interpret **"became aware"** as the point when the controller has **reasonable grounds to believe** a personal data breach has occurred. This is **not** when the forensic investigation is complete or the full scope of affected individuals is confirmed.
>
> - Clock starts when your security team discovers evidence of unauthorised access, even if scope is unknown.
> - A processor's breach affecting your data subjects: the processor's notification to *you* starts *your* clock.
> - GDPR Art. 33(4) explicitly permits filing an **initial notification with incomplete information** and supplementing within 30 days. File early with what you know; do not wait for confirmation of full scope.
> - Delaying until forensic investigation is complete, when that takes more than 72 hours, is the most common cause of late-notification enforcement actions.
>
> → Fill in `72-hour Clock Started` below as soon as you have reasonable grounds. Do not leave it blank pending investigation completion.

---

## Part 1 — Internal Incident Log (complete immediately)

| Field | Value |
|---|---|
| **Incident ID** | INC-[YYYY-MM-DD]-[seq] |
| **Date/Time Discovered** | |
| **Discovered By** | |
| **Date/Time Contained** | |
| **Incident Lead** | |
| **DPO Notified At** | |
| **Legal Notified At** | |
| **72-hour Clock Started** | |
| **72-hour Deadline** | |
| **Status** | Investigating / Contained / Resolved |

### What Happened (internal summary)

> _________________

### Data Affected

| Category | Fields | Number of Records | Systems |
|---|---|---|---|
| | | | |

### Root Cause

> _________________

### Immediate Actions Taken

1.
2.
3.

---

## Part 2 — Supervisory Authority Notification

### GDPR — Article 33 Notice

*Send to the Lead Supervisory Authority (LSA) within 72 hours. Use the authority's online form where available. This template covers the minimum required content.*

---

**To:** [Supervisory Authority Name]
**Re:** Personal Data Breach Notification — [Organisation Name]
**Date:** [Date]
**Reference (if existing):** [Case number if follow-up]

#### 1. Controller Details

| Field | Value |
|---|---|
| Organisation | |
| Address | |
| DPO Name | |
| DPO Contact | |
| Representative (if applicable) | |

#### 2. Nature of the Breach

| Question | Answer |
|---|---|
| **Type of breach** | Confidentiality / Integrity / Availability |
| **How it occurred** | (e.g., unauthorised access, ransomware, accidental disclosure, lost device) |
| **Date/time of breach** | |
| **Date/time discovered** | |
| **Is the breach ongoing?** | Yes / No |

#### 3. Categories and Approximate Number of Data Subjects

| Category of Data Subject | Approximate Number |
|---|---|
| | |

#### 4. Categories and Approximate Volume of Records

| Category of Personal Data | Volume | Includes Special Categories? |
|---|---|---|
| | | Yes / No |

#### 5. Likely Consequences

Describe the likely consequences of the breach for data subjects:

> _________________

**Risk level assessment:**
- [ ] Low risk — no notification to data subjects required
- [ ] High risk — data subject notification required (Art. 34)

#### 6. Measures Taken or Proposed

Describe measures taken to address and mitigate the breach:

> _________________

#### 7. Can All Information Be Provided Now?

- [ ] Yes — this is a complete notification
- [ ] No — information is being gathered; follow-up will be provided by [date]

*(GDPR Art. 33(4) permits phased notification where full information is not available within 72 hours)*

---

### LGPD — Comunicado à ANPD (Art. 48)

**Para:** Autoridade Nacional de Proteção de Dados (ANPD)
**De:** [Nome da Organização]
**Data:** [Data]

#### Dados do Controlador

| Campo | Valor |
|---|---|
| Razão Social | |
| CNPJ | |
| Encarregado (DPO) | |
| E-mail do Encarregado | |

#### Descrição do Incidente

| Pergunta | Resposta |
|---|---|
| **Tipo de incidente** | Acesso não autorizado / Divulgação acidental / Perda / Ransomware |
| **Data/hora do incidente** | |
| **Data/hora da descoberta** | |
| **Incidente ainda ativo?** | Sim / Não |

#### Dados Pessoais Afetados

| Categoria de Titular | Quantidade Aproximada |
|---|---|
| | |

| Categoria de Dado Pessoal | Volume | Dado Sensível (Art. 11)? |
|---|---|---|
| | | Sim / Não |

#### Consequências Prováveis

> _________________

#### Medidas Adotadas

> _________________

---

## Part 3 — Data Subject Notification

*Required under GDPR Art. 34 when breach is likely to result in high risk to rights and freedoms. Send "without undue delay."*

---

**Subject: Important Security Notice — [Your Organisation Name]**

Dear [Name / "Valued Customer" if name unknown],

We are writing to inform you of a security incident that may have affected your personal information.

### What Happened

On [date], we discovered that [brief, plain-language description of the breach — avoid technical jargon].

### What Information Was Involved

The following types of personal information may have been accessed:

- [Data type 1 — e.g., name and email address]
- [Data type 2 — e.g., encrypted password]
- [Data type 3 — e.g., delivery address]

**[Special sensitivity notice if applicable]:**
*We regret to inform you that [sensitive data type] may also have been involved. We understand the seriousness of this and have taken the following additional steps: [steps].*

### What We Have Done

We have:
1. [Action 1 — e.g., secured the affected systems]
2. [Action 2 — e.g., reset affected credentials]
3. [Action 3 — e.g., engaged a cybersecurity firm]
4. Notified [Supervisory Authority] as required by law.

### What You Should Do

We recommend you take the following steps to protect yourself:

- [ ] **Change your password** for [Service] and any other accounts where you use the same password.
- [ ] **Enable two-factor authentication** on your accounts.
- [ ] **Monitor your accounts** for unusual activity.
- [ ] **Be alert for phishing emails** that may attempt to use your information.
- [ ] [If financial data involved]: **Contact your bank** and monitor your statements.
- [ ] [If ID/SSN involved]: **Consider a credit freeze** with the major credit bureaus.

### Contact Us

If you have questions or concerns, please contact our Data Protection Officer:

- **Email:** [DPO email]
- **Phone:** [Number]
- **Address:** [Address]

You also have the right to lodge a complaint with [Supervisory Authority name] at [contact].

We sincerely apologise for this incident and the concern it may cause.

Sincerely,

[CEO/DPO Name]
[Organisation Name]

---

## Part 4 — Post-Incident Review Template

Complete within 30 days of containment.

| Section | Detail |
|---|---|
| **Timeline** | Detection → Containment → Notification |
| **Root Cause (confirmed)** | |
| **Contributing Factors** | |
| **Data Subjects Notified** | Number + method |
| **Authority Response** | Any instructions received |
| **Legal/Financial Impact** | Fines, litigation, cost |
| **Lessons Learned** | |
| **Remediation Actions** | Owner + deadline |
| **Controls Added/Improved** | |
| **Next Review Date** | |
