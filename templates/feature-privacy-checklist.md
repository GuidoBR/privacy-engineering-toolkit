# Feature Privacy Checklist

Complete this checklist for every feature or change that involves personal data.
Attach to your pull request description.

> **When is this required?**
> Any feature that: collects new personal data, changes how data is used/shared, adds a new third-party integration, modifies retention, changes access controls, or introduces new logging.

---

## Feature / PR Details

| Field | Value |
|---|---|
| **Feature Name** | |
| **PR / Ticket** | |
| **Author** | |
| **Date** | |
| **Reviewer (Privacy)** | |

---

## Section 1 — Data Collection

- [ ] **1.1** Does this feature collect any new personal data?
  - If yes, list fields: _______
- [ ] **1.2** Is each field strictly necessary for the stated purpose (data minimisation)?
- [ ] **1.3** Is there a lawful basis for collecting this data?
  - Basis: [ ] Consent  [ ] Contract  [ ] Legal obligation  [ ] Legitimate interests
- [ ] **1.4** If based on legitimate interests, has a balancing test been documented?
- [ ] **1.5** If consent is the basis, is the consent mechanism: freely given, specific, informed, and unambiguous?
- [ ] **1.6** Are children under 16 (or lower local age) likely to use this feature?
  - If yes: parental consent mechanism required.

---

## Section 2 — Special / Sensitive Categories

- [ ] **2.1** Does the feature process any special category data?
  - [ ] Health / medical data
  - [ ] Biometric data (fingerprints, face recognition, voice patterns, handwritten signatures)
  - [ ] Genetic data
  - [ ] Racial or ethnic origin
  - [ ] Political opinions / religious beliefs
  - [ ] Sexual orientation / gender identity
  - [ ] Criminal records / offences
  - [ ] None of the above
- [ ] **2.2** If yes, is explicit consent or another Art. 9(2) / LGPD Art. 11(2) exception documented?
- [ ] **2.3** If yes, has a DPIA been initiated? (GDPR Art. 35; LGPD Art. 38)

---

## Section 3 — Data Storage and Retention

- [ ] **3.1** Where will the data be stored? (database, S3, cache, logs, etc.)
  - Location(s): _______
- [ ] **3.2** Is data encrypted at rest?
- [ ] **3.3** Is data encrypted in transit?
- [ ] **3.4** Has a retention period been defined?
  - Period: _______ | Justified by: _______
- [ ] **3.5** Is there an automated deletion / archival process for when retention expires?
- [ ] **3.6** Does the feature store personal data in logs?
  - If yes: is logging justified and minimal? Are emails/tokens/SSNs excluded?

---

## Section 4 — Third-Party Sharing

- [ ] **4.1** Does this feature share data with any third party or external service?
  - If yes, list parties: _______
- [ ] **4.2** Is a Data Processing Agreement (DPA) in place with each party?
- [ ] **4.3** Has each party's privacy posture been assessed (see processor-assessment.md)?
- [ ] **4.4** Is data transferred internationally?
  - If yes, transfer mechanism: [ ] SCCs  [ ] Adequacy  [ ] BCRs  [ ] Other: _______

---

## Section 5 — Access Controls

- [ ] **5.1** Is access to the new data limited to roles that need it (least privilege)?
- [ ] **5.2** Are access controls enforced at the API and database level?
- [ ] **5.3** Are changes to this data logged in an audit trail?
- [ ] **5.4** Can internal staff access this data in plaintext? If yes, is that necessary?

---

## Section 6 — Data Subject Rights

- [ ] **6.1** Can a data subject's data created by this feature be exported (portability)?
- [ ] **6.2** Can this data be deleted in response to an erasure request (Art. 17 / LGPD Art. 18, VI)?
- [ ] **6.3** Can this data be corrected in response to a rectification request?
- [ ] **6.4** Is there a dependency that would prevent deletion (e.g., FK constraint, audit log)?
  - If yes, document exception and legal basis for retention: _______

---

## Section 7 — Transparency

- [ ] **7.1** Does the privacy notice / policy need to be updated to reflect this feature?
- [ ] **7.2** Will users be informed of the new data collection before it begins?
- [ ] **7.3** If using cookies or local storage: is the cookie banner / consent manager updated?
- [ ] **7.4** Is there any profiling or automated decision-making in this feature?
  - If yes: is the logic documented? Can data subjects opt out or request human review?

---

## Section 8 — Security

- [ ] **8.1** Has the feature been reviewed for OWASP Top 10 vulnerabilities?
- [ ] **8.2** Is user input validated and sanitised (injection, XSS prevention)?
- [ ] **8.3** Are secrets / credentials stored in a secrets manager (not hardcoded)?
- [ ] **8.4** Are error messages and logs free of PII?
- [ ] **8.5** For APIs: is authentication and authorisation enforced on all endpoints?

---

## Section 9 — Privacy by Design (GDPR Art. 25)

- [ ] **9.1** Was privacy considered at the design stage (not bolted on)?
- [ ] **9.2** Are privacy-protective defaults used (e.g., opt-in rather than opt-out)?
- [ ] **9.3** Could the same functionality be achieved with less data or anonymised data?
- [ ] **9.4** Has the DPIA checklist been reviewed for necessity? (See templates/dpia-gdpr.md)

---

## Sign-off

| Role | Name | Date | Decision |
|---|---|---|---|
| **Author** | | | — |
| **Privacy Reviewer** | | | Approved / Approved with conditions / Rejected |
| **DPO (if DPIA required)** | | | Approved / Rejected |

**Conditions / Notes:**
> _________________

---

## Attaching to Your PR

Include in your PR description:

```markdown
## Privacy Checklist

- [x] Feature Privacy Checklist completed
- [x] No new personal data collected (or: lawful basis documented)
- [x] DPIA not required (or: DPIA in progress — link)
- [x] Privacy notice updated
- [x] No PII in logs
```
