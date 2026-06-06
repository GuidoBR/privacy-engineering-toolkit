# GDPR — General Data Protection Regulation
*EU 2016/679 — Effective 25 May 2018*

> **Last verified:** June 2026
>
> **Known pending changes and active risks:**
> - **EU-US Data Privacy Framework (DPF):** Adequacy decision adopted July 2023. noyb (Max Schrems) filed a challenge before the CJEU in August 2023; a ruling is expected 2025–2026. Companies relying solely on DPF for US transfers carry transfer invalidation risk. Consider SCCs as a parallel safeguard.
> - **ePrivacy Regulation:** Long-delayed replacement for the ePrivacy Directive (Cookie Law) remains in trilogue as of 2026. Current rules still derive from the 2002/2009 Directive.
> - **AI Act (EU 2024/1689):** Effective August 2024, with phased obligations. High-risk AI systems that process personal data have additional transparency and documentation requirements that intersect with GDPR Art. 22 (automated decision-making).
> - **Fines landscape:** GDPR enforcement has accelerated significantly since 2022. Notable: Meta €1.2B (2023, data transfers), TikTok €345M (2023, children's data), LinkedIn €310M (2024, lawful basis for profiling).

## Overview

The GDPR is the primary privacy law for the European Union and European Economic Area. It applies to any organisation that processes personal data of EU/EEA residents, regardless of where the organisation is located.

**Enforcement:** National Data Protection Authorities (DPAs) in each EU member state. Cross-border cases handled by a Lead Supervisory Authority (LSA).

**Penalties:** Up to €20 million or 4% of global annual turnover (whichever is higher) for serious violations. Up to €10 million or 2% for administrative breaches.

---

## Scope (Art. 3)

Applies when:
- An organisation is **established in the EU/EEA**, or
- It **offers goods/services** to EU/EEA residents (regardless of payment), or
- It **monitors behaviour** of EU/EEA residents (e.g., tracking via cookies)

---

## Key Definitions (Art. 4)

| Term | Definition |
|---|---|
| **Personal data** | Any information relating to an identified or identifiable natural person |
| **Processing** | Any operation on personal data (collection, storage, use, disclosure, erasure…) |
| **Controller** | The entity that determines the purposes and means of processing |
| **Processor** | An entity that processes data on behalf of the controller |
| **Data subject** | The natural person whose data is processed |
| **Consent** | Freely given, specific, informed, and unambiguous indication of wishes |
| **Pseudonymisation** | Processing such that data can no longer be attributed to a specific person without additional information |

---

## Principles (Art. 5)

| Principle | Requirement |
|---|---|
| **Lawfulness, fairness, transparency** | Processing must have a legal basis; data subjects must be informed |
| **Purpose limitation** | Data collected for specified, explicit purposes; not further processed incompatibly |
| **Data minimisation** | Limited to what is necessary for the purpose |
| **Accuracy** | Kept accurate and up to date |
| **Storage limitation** | Not kept longer than necessary |
| **Integrity and confidentiality** | Appropriate security measures |
| **Accountability** | Controller must demonstrate compliance |

---

## Lawful Bases for Processing (Art. 6)

| Basis | When It Applies |
|---|---|
| **(a) Consent** | Data subject has given clear, specific consent |
| **(b) Contract** | Necessary for a contract with the data subject |
| **(c) Legal obligation** | Required by EU or member state law |
| **(d) Vital interests** | To protect someone's life |
| **(e) Public task** | Official authority vested by law |
| **(f) Legitimate interests** | Necessary for legitimate interests, not overridden by data subject's rights |

> **Note:** Legitimate interests (f) requires a three-part test: purpose test, necessity test, balancing test.

---

## Special Category Data (Art. 9)

Processing **prohibited** unless an Art. 9(2) exception applies:

- Racial or ethnic origin
- Political opinions
- Religious or philosophical beliefs
- Trade union membership
- **Genetic data**
- **Biometric data** for unique identification
- **Health data**
- Sex life or sexual orientation

**Art. 9(2) exceptions include:** explicit consent, employment law obligations, vital interests, legitimate activities of non-profits, data made public by the data subject, legal claims, substantial public interest, medical purposes, public health, archiving/research.

---

## Data Subject Rights

| Right | Article | Key Points |
|---|---|---|
| **Information** | 13/14 | Must inform at collection or within 1 month (indirect collection) |
| **Access** | 15 | Confirm processing exists; provide copy; respond in 1 month |
| **Rectification** | 16 | Correct inaccurate data without undue delay |
| **Erasure ("right to be forgotten")** | 17 | Delete when no longer necessary, consent withdrawn, unlawful processing, legal obligation |
| **Restriction** | 18 | Restrict processing while accuracy or legal basis is contested |
| **Portability** | 20 | Provide data in machine-readable format; transmit to another controller |
| **Object** | 21 | Object to processing based on legitimate interests or public task; absolute right to object to direct marketing |
| **Not to be subject to automated decisions** | 22 | Right not to be subject to solely automated decisions with significant effects |

**Response time:** 1 month; extendable by 2 months for complexity.

---

## Controller Obligations

| Obligation | Article |
|---|---|
| Maintain Records of Processing Activities (RoPA) | 30 |
| Appoint DPO (when required) | 37 |
| Conduct DPIA for high-risk processing | 35 |
| Consult supervisory authority if DPIA shows high residual risk | 36 |
| Implement data protection by design and by default | 25 |
| Use only processors providing sufficient guarantees | 28 |
| Report breaches to supervisory authority within 72 hours | 33 |
| Notify data subjects of high-risk breaches without undue delay | 34 |

---

## Processor Requirements (Art. 28)

Processors must:
- Process only on controller's documented instructions
- Ensure confidentiality
- Implement appropriate security (Art. 32)
- Not engage sub-processors without controller authorisation
- Assist with data subject rights and breach obligations
- Delete or return data at end of service
- Provide audit rights

**Mandatory contract (DPA)** required for every controller-processor relationship.

---

## International Data Transfers (Chapter V)

Transfers outside EEA require one of:
- **Adequacy decision** (Art. 45) — currently: UK, Switzerland, Japan, South Korea, Canada (commercial), New Zealand, Israel, Uruguay, USA (Data Privacy Framework)
- **Standard Contractual Clauses** (SCCs) (Art. 46) — EDPB-approved template agreements
- **Binding Corporate Rules** (BCRs) (Art. 47) — for intra-group transfers
- **Specific derogations** (Art. 49) — explicit consent, contract performance, legal claims, vital interests, public register

---

## DPO Appointment (Art. 37)

Required when the controller or processor:
- Is a public authority
- Carries out **large-scale, systematic monitoring** of data subjects
- Processes **special category data or criminal records** on a large scale

DPO tasks: inform/advise, monitor compliance, advise on DPIAs, cooperate with supervisory authority.

---

## DPIA Triggers (Art. 35)

A DPIA is mandatory for processing likely to result in high risk. Mandatory cases (Art. 35(3)):
1. Systematic and extensive profiling with legal/significant effects
2. Large-scale processing of special category data
3. Systematic monitoring of publicly accessible areas

The EDPB lists 9 criteria; two or more = DPIA required (WP248):
1. Evaluation/scoring
2. Automated decision-making with legal effects
3. Systematic monitoring
4. Sensitive data
5. Large-scale processing
6. Datasets combined/matched
7. Data concerning vulnerable subjects
8. Innovative technology
9. Processing that prevents exercising rights

---

## Enforcement Highlights

| Fine | Controller | Violation |
|---|---|---|
| €1.2 billion | Meta (Ireland) | Unlawful data transfers to US |
| €746 million | Amazon (Luxembourg) | Consent and transparency violations |
| €405 million | Instagram (Meta) | Children's data exposure |
| €225 million | WhatsApp | Transparency failures |
| €50 million | Google France | Consent in Android setup |

---

## Key Resources

- Full text: https://eur-lex.europa.eu/eli/reg/2016/679/oj
- EDPB guidelines: https://edpb.europa.eu/our-work-tools/general-guidance_en
- Lead Supervisory Authority map: https://edpb.europa.eu/about-edpb/about-edpb/members_en
