# LGPD — Lei Geral de Proteção de Dados Pessoais
*Lei 13.709/2018 — Effective 18 September 2020; Enforcement from 1 August 2021*

> **Last verified:** June 2026
>
> **Known pending changes and active risks:**
> - **ANPD enforcement active:** The ANPD began formal enforcement proceedings in 2023. First administrative sanction (warning + corrective measure order) issued in 2023. Monetary fines (up to 2% Brazil revenue, capped R$50M per violation) are now being applied. The ANPD has prioritised health data, children's data, and security incident cases.
> - **Resolução BCB nº 522/2025:** Updated Banco Central regulation supersedes CMN 4.893/2021 for payment/Pix transaction record retention (5 years). Verify current version at bcb.gov.br before citing in deletion responses.
> - **International transfer rules:** ANPD is still developing its adequacy framework. Standard contractual clauses and BCRs are the primary mechanisms pending formal adequacy decisions.
> - **DPO (Encarregado) requirement:** Unlike GDPR, LGPD requires ALL controllers (not just those meeting a threshold) to appoint an encarregado and publicly disclose their contact. This is commonly missed by international companies with Brazilian users.
> - **Transparency effectiveness (Art. 6, VI) — active ANPD enforcement posture (2026):** In a 2026 enforcement action against a data bureau (birô de dados), the ANPD required **objective evidence that transparency mechanisms are effective**, not merely that a privacy notice exists and contains the legally required information. The ANPD requested: usability studies, accessibility assessments, legibility analysis (reading level, font, contrast), UX research, and informational comprehension tests demonstrating that data subjects can **locate and understand** privacy information without technical expertise. This aligns with WP29 Guidelines on Transparency (WP260 rev.01) where user testing with participants representing the average data subject is the "gold standard" for verifying intelligibility. The ANPD framed this as proportional to processing complexity and risk level — a data bureau processing large-scale data with significant impact on individuals warrants higher accountability than a simple service provider. **Practical implication:** Controllers engaged in high-risk or complex processing should maintain documentary evidence of transparency effectiveness — reading level scores, click-depth to the notice, usability test results, comprehension metrics — not just a compliant privacy notice. See `templates/transparency-effectiveness.md` for an evidence-gathering template.

## Overview

Brazil's primary data protection law, inspired by the GDPR but with Brazilian-specific provisions. Applies to any processing of personal data of individuals located in Brazil, regardless of the processor's location.

**Enforcement:** ANPD — Autoridade Nacional de Proteção de Dados (National Data Protection Authority).

**Penalties:** Up to R$50 million per violation or 2% of the legal entity's revenue in Brazil in the last fiscal year (whichever is lower). Additional sanctions include: daily fines, public notice of violation, blocking or deletion of personal data, suspension of processing activity.

---

## Scope (Art. 3)

Applies when:
- Processing is carried out **in Brazil**, or
- The purpose of processing is to offer goods or services to individuals **located in Brazil**, or
- Data of individuals **located in Brazil** was collected

**Exclusions (Art. 4):** purely personal/non-economic purposes; journalistic, artistic or academic research; national security, defence, public safety, or criminal investigation activities.

---

## Key Definitions (Art. 5)

| Term | Brazilian Term | Definition |
|---|---|---|
| **Personal data** | Dado pessoal | Information relating to an identified or identifiable natural person |
| **Sensitive personal data** | Dado pessoal sensível | Special category — see Art. 11 |
| **Processing** | Tratamento | Any operation with personal data |
| **Controller** | Controlador | Entity that determines purposes and means of processing |
| **Operator** | Operador | Entity that processes data on behalf of the controller (= processor) |
| **Officer (DPO)** | Encarregado | Person designated to act as channel between controller, data subjects, and ANPD |
| **Consent** | Consentimento | Free, informed, and unambiguous consent |
| **Anonymisation** | Anonimização | Process that cannot be reversed |
| **Pseudonymisation** | Pseudonimização | Data that can be re-identified with additional information |

---

## Principles (Art. 6)

| Principle | Brazilian Term | Requirement |
|---|---|---|
| Purpose | Finalidade | Specific, explicit, and legitimate purposes |
| Adequacy | Adequação | Compatible with declared purposes |
| Necessity | Necessidade | Limited to minimum necessary |
| Free access | Livre acesso | Guaranteed access to data, free of charge |
| Quality | Qualidade dos dados | Accuracy, clarity, relevance, up-to-date |
| Transparency | Transparência | Clear and accessible information |
| Security | Segurança | Technical and administrative measures |
| Prevention | Prevenção | Prevent damage before processing begins |
| Non-discrimination | Não discriminação | No discriminatory, illegal, or abusive processing |
| Accountability | Responsabilização | Demonstrate adoption of measures |

---

## Legal Bases for Processing (Art. 7)

| Basis | Description |
|---|---|
| **I — Consentimento** | Consent of the data subject |
| **II — Obrigação legal** | Compliance with legal or regulatory obligation of the controller |
| **III — Políticas públicas** | Execution of public policies by public administration |
| **IV — Estudos de pesquisa** | Research by research bodies (guaranteed anonymisation where possible) |
| **V — Execução de contrato** | Necessary for a contract or preliminary steps at the data subject's request |
| **VI — Exercício regular de direitos** | Exercise of rights in judicial, administrative or arbitral proceedings |
| **VII — Proteção da vida** | Protection of the life or physical safety of the data subject or third party |
| **VIII — Tutela da saúde** | Health care by health professionals or services |
| **IX — Interesses legítimos** | Legitimate interests of the controller or third parties (when they do not override the data subject's fundamental rights and freedoms) |
| **X — Proteção do crédito** | Credit protection |

**For sensitive data (Art. 11):** only consent (specific and highlighted), or Art. 11(2) exceptions (legal obligation, public policy, scientific research, exercise of rights, protection of life, health care, fraud prevention, data subject made public, guarantee of identity).

---

## Sensitive Personal Data (Art. 5, II and Art. 11)

Processing is more restricted for:
- Racial or ethnic origin
- Religious conviction
- Political opinion
- Trade union or religious/philosophical organisation membership
- **Health or sex life data**
- **Genetic or biometric data**

---

## Data Subject Rights (Art. 18)

| Right | Description | Response Period |
|---|---|---|
| **I — Confirmação** | Confirm existence of processing | 15 days |
| **II — Acesso** | Access the data | 15 days |
| **III — Correção** | Correct incomplete, inaccurate or outdated data | 15 days |
| **IV — Anonimização / bloqueio / eliminação** | Anonymise, block or delete unnecessary/excessive/non-compliant data | 15 days |
| **V — Portabilidade** | Data portability to another service/product provider | As regulated by ANPD |
| **VI — Eliminação** | Delete data processed with consent | 15 days |
| **VII — Informação sobre compartilhamento** | Information about entities with whom data is shared | 15 days |
| **VIII — Informação sobre recusa de consentimento** | Information about the possibility of not providing consent and consequences | 15 days |
| **IX — Revogação do consentimento** | Revoke consent at any time | 15 days |

**Art. 18, § 5°:** The controller must respond within 15 days from the date of the data subject's request.

---

## Controller Obligations

| Obligation | Article |
|---|---|
| Maintain records of processing activities | 37 |
| Designate an Encarregado (DPO) | 41 |
| Conduct RIPD (DPIA) when required | 38 |
| Implement privacy by design | 46, § 2° |
| Report security incidents to ANPD and data subjects | 48 |
| Execute contracts with operators | 39 |
| Adopt security, technical and administrative measures | 46 |

---

## Encarregado (DPO) Requirements (Art. 41)

Unlike GDPR, LGPD requires **all controllers** to designate an Encarregado. The identity and contact must be made public (generally on the website).

**Responsibilities:**
- Receive complaints from data subjects
- Receive communications from ANPD
- Provide guidance to employees and contractors
- Carry out other tasks set by the controller or in supplementary rules

---

## Breach Notification (Art. 48)

Controllers must notify the ANPD and affected data subjects of security incidents that may create risk or harm to data subjects.

**Notice must include:**
- Nature of the affected data
- Information about affected data subjects
- Technical and security measures adopted
- Risks related to the incident
- Reasons for delayed notification (if applicable)
- Measures adopted or to be adopted

**Timing:** ANPD guidance = within 2 working days for initial notice; full report within 30 days.

---

## International Data Transfers (Art. 33)

Permitted only when:
- **I** — Destination country provides adequate protection level (determined by ANPD)
- **II** — Controller provides adequate guarantees (contracts, BCRs, seals/certifications)
- **III** — Specific derogations (consent, legal obligation, research, contract, exercise of rights, protection of life, health, credit, fraud prevention)

**ANPD** is responsible for issuing a list of countries with adequate protection.

---

## RIPD (Relatório de Impacto) — Art. 38

The ANPD may require controllers to produce a RIPD for personal data processing operations likely to generate risks to civil liberties and fundamental rights.

Unlike GDPR (which specifies triggers), LGPD gives the ANPD discretion to define when a RIPD is mandatory.

---

## Key Differences from GDPR

| Aspect | GDPR | LGPD |
|---|---|---|
| DPO requirement | Only some organisations | **All controllers** |
| Response time for DSARs | 1 month | 15 days |
| Breach notification | 72 hours (SA) + without undue delay (DS) | Reasonable timeframe (≈ 2 days initial, 30 days full) |
| Legal bases | 6 bases | 10 bases (more detailed) |
| Enforcement authority | National DPAs in 27 EU member states | Single ANPD |
| Fines | Up to 4% global turnover or €20M | Up to 2% Brazil revenue or R$50M per violation |
| DPIA triggers | Specified criteria | ANPD-determined |

---

## Key Resources

- Full text (Portuguese): https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm
- ANPD: https://www.gov.br/anpd
- ANPD guidelines and resolutions: https://www.gov.br/anpd/pt-br/documentos-e-publicacoes
