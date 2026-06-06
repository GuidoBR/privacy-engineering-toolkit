# Data Protection Impact Assessment (DPIA)
*GDPR Article 35 — Template*

---

## 1. Overview

| Field | Value |
|---|---|
| **Project / Feature Name** | |
| **Data Controller** | |
| **Data Protection Officer (DPO)** | |
| **Assessment Date** | |
| **Version** | 1.0 |
| **Review Date** | |
| **Status** | Draft / Under Review / Approved |

---

## 2. Necessity Check — Is a DPIA Required?

A DPIA is mandatory (GDPR Art. 35(3)) when processing is likely to result in high risk. Check all that apply:

- [ ] Systematic and extensive profiling with significant effects
- [ ] Large-scale processing of **special category data** (Art. 9) or criminal data (Art. 10)
- [ ] Systematic monitoring of publicly accessible areas (e.g., CCTV)
- [ ] Processing of **biometric data** for unique identification
- [ ] Processing of **genetic data**
- [ ] Innovative use of new technology with unknown risks
- [ ] Processing that **prevents data subjects from exercising rights**
- [ ] Large-scale processing of **children's data**
- [ ] Automated decision-making with **legal or similarly significant effects**
- [ ] Matching or combining datasets from different sources

**Conclusion:** [ ] DPIA required  [ ] DPIA not required (document justification below)

Justification if not required:
> _________________

---

## 3. Description of Processing

### 3.1 Nature of Processing

Describe what is being done with personal data (collection, recording, organisation, storage, adaptation, retrieval, use, disclosure, erasure, etc.):

> _________________

### 3.2 Scope of Processing

| Dimension | Details |
|---|---|
| **Categories of data subjects** | (e.g., customers, employees, children) |
| **Categories of personal data** | (e.g., name, email, location, health) |
| **Special category data (Art. 9)?** | Yes / No — if yes, specify |
| **Volume of data subjects** | (approximate number) |
| **Geographical scope** | (countries/regions) |
| **Retention period** | |
| **Frequency of processing** | (continuous / periodic / one-off) |

### 3.3 Purpose of Processing

| Purpose | Lawful Basis (Art. 6) | Legal Obligation / Legitimate Interest |
|---|---|---|
| | | |
| | | |

### 3.4 Data Flows

Describe how data moves through the system:

```
[Data Source] → [Collection point] → [Processing system] → [Storage] → [Recipients]
```

| Step | System / Actor | Country | Safeguards |
|---|---|---|---|
| Collection | | | |
| Processing | | | |
| Storage | | | |
| Third-party sharing | | | |

**International transfers:**
- [ ] No transfers outside EEA
- [ ] Transfers to adequate countries (list: _______)
- [ ] Transfers under SCCs (Standard Contractual Clauses)
- [ ] Transfers under BCRs (Binding Corporate Rules)
- [ ] Other mechanism: _______

---

## 4. Necessity and Proportionality Assessment

### 4.1 Lawfulness

For each purpose above, confirm the lawful basis (Art. 6(1)) is documented and valid:

| Purpose | Basis | Documented? | Notes |
|---|---|---|---|
| | Art. 6(1)(a) Consent / (b) Contract / (c) Legal / (d) Vital / (e) Public / (f) LI | | |

### 4.2 Data Minimisation (Art. 5(1)(c))

Is the data collected limited to what is strictly necessary?

| Data Element | Necessary? | Could Less Data Achieve the Same Goal? |
|---|---|---|
| | Yes / No | |

### 4.3 Storage Limitation (Art. 5(1)(e))

| Data Category | Retention Period | Deletion Mechanism | Justified By |
|---|---|---|---|
| | | | |

### 4.4 Transparency (Art. 13/14)

- [ ] Privacy notice updated to cover this processing
- [ ] Data subjects informed of: purposes, retention, rights, controller contact
- [ ] Consent records maintained (if applicable)

---

## 5. Risk Identification and Assessment

### 5.1 Identify Risks

For each risk, assess likelihood (1–3) and impact (1–3). Score = likelihood × impact.

**Likelihood scale:**
| Value | Meaning |
|---|---|
| 1 — Unlikely | Controls in place; breach of this type has not occurred in this context |
| 2 — Possible | Could occur despite controls; has occurred in similar contexts |
| 3 — Likely | Expected to occur without additional measures; known vulnerability exists |

**Impact scale:**
| Value | Meaning |
|---|---|
| 1 — Minor | Temporary inconvenience; no lasting harm; no special category data affected |
| 2 — Significant | Financial loss, reputational damage, or distress; some special category data |
| 3 — Severe | Discrimination, identity theft, physical harm, or large-scale special category exposure |

| Risk | Description | Likelihood (1–3) | Impact (1–3) | Score | Level |
|---|---|---|---|---|---|
| Unauthorised access / data breach | | 1/2/3 | 1/2/3 | | Low/Medium/High |
| Accidental loss or destruction | | | | | |
| Inaccuracy / outdated data | | | | | |
| Excessive collection / scope creep | | | | | |
| Unlawful third-party sharing | | | | | |
| Rights not honoured (access, erasure) | | | | | |
| Discrimination / profiling harm | | | | | |
| Retention beyond permitted period | | | | | |
| Special category data mishandled | | | | | |
| Cross-border transfer without safeguard | | | | | |

**Risk levels and required actions:**

| Score | Level | Required action |
|---|---|---|
| 1–2 | **Low** | Document; no additional measures required |
| 3–4 | **Medium** | Define mitigation measure; DPO review required |
| 6–9 | **High** | Mitigation mandatory; if residual risk remains High after mitigation → **Art. 36 prior consultation required** (see §6) |

> **Note on score 5:** A 1–3 × 1–3 matrix produces possible scores of 1, 2, 3, 4, 6, and 9. Score 5 cannot occur. If a score of 5 appears, recheck the calculation.

### 5.2 Existing Controls

| Control | Description | Risk(s) Mitigated |
|---|---|---|
| | | |

---

## 6. Risk Mitigation Measures

For each High or Medium risk, define a mitigation measure and owner:

| Risk | Measure | Owner | Target Date | Residual Score | Residual Level |
|---|---|---|---|---|---|
| | | | | | Low/Medium/High |

### 6.1 Escalation Decision Gate

> **GDPR Art. 36 and EDPB Guidelines WP248 rev.01** state that if the controller cannot find sufficient measures to reduce risks to an acceptable level (i.e., any residual risk remains **High — score ≥ 6**), it must consult the competent supervisory authority **before starting the processing**.
>
> Processing must not commence until either:
> (a) all residual risks are reduced to Low (1–2) or Medium (3–4), **or**
> (b) the supervisory authority has been consulted and has responded (Art. 36 gives the authority 8 weeks to respond, extendable to 14 weeks).

**Step 1 — Check residual scores from the table above:**

- [ ] **All residual risks are Low (1–2)** → Proceed. No Art. 36 consultation needed.
- [ ] **One or more residual risks are Medium (3–4)** → Proceed, with DPO sign-off and documented acceptance of residual risk.
- [ ] **One or more residual risks are High (≥ 6)** → **STOP. Art. 36 prior consultation is mandatory before processing begins.**

**Step 2 — If Art. 36 consultation is required:**

| Field | Value |
|---|---|
| Supervisory authority to consult | (Lead SA — determined by main establishment) |
| Date consultation submitted | |
| Reference / case number | |
| SA response deadline | (8 weeks from receipt; up to 14 weeks if extended) |
| SA response received | |
| SA decision | Approved / Approved with conditions / Objected |
| Conditions / restrictions imposed | |
| Processing start date (after SA response) | |

- [ ] Art. 36 consultation completed; SA has responded; conditions documented above
- [ ] Residual risk is acceptable; processing may commence

---

## 7. Data Subject Rights Compliance

| Right | Art. | Mechanism in Place | Contact Point |
|---|---|---|---|
| Right of access | 15 | | |
| Right to rectification | 16 | | |
| Right to erasure | 17 | | |
| Right to restriction | 18 | | |
| Right to data portability | 20 | | |
| Right to object | 21 | | |
| Rights re. automated decisions | 22 | | |

---

## 8. Processor and Third-Party Assessment

| Processor / Recipient | Data Shared | DPA in Place? | Location | Adequacy / Mechanism |
|---|---|---|---|---|
| | | Yes / No | | |

---

## 9. DPO Consultation

- [ ] DPO consulted
- [ ] DPO name: _______
- [ ] DPO advice date: _______
- [ ] DPO advice summary:

> _________________

- [ ] DPO opinion: Approved / Approved with conditions / Objected
- [ ] Conditions / objections: _______

---

## 10. Approval

| Role | Name | Signature | Date |
|---|---|---|---|
| Project Owner | | | |
| Data Protection Officer | | | |
| Legal / Compliance | | | |
| CISO / Security | | | |

---

## 11. Review History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | | | Initial draft |

---

*Template based on GDPR Art. 35 requirements and WP29 Guidelines on DPIA (WP248 rev.01).*
