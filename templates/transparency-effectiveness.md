# Transparency Effectiveness Assessment

*LGPD Art. 6(VI) — Princípio da Transparência / GDPR Art. 12 — Transparent information*

Use this template to document objective evidence that your privacy notices and transparency mechanisms are **effective** — that data subjects can locate, access, and understand privacy information without technical expertise.

**When to complete this assessment:**
- Before launching any new processing activity involving large-scale, systematic, or high-risk data processing
- When the ANPD or another supervisory authority requests accountability documentation
- Annually for existing high-risk processing activities
- When a material change is made to a privacy notice or data collection flow

> **Regulatory context:** In a 2026 enforcement action, the ANPD required a data bureau to provide usability studies, accessibility assessments, legibility analysis, UX research, and informational comprehension tests demonstrating that data subjects can locate and understand privacy information without technical expertise. This aligns with WP29 Guidelines on Transparency (WP260 rev.01) where user testing with participants representing the average data subject is the "gold standard" for verifying intelligibility under GDPR Art. 12.

---

## 1. Assessment Context

| Field | Value |
|---|---|
| **Organisation / Controller** | |
| **Processing Activity Assessed** | (e.g., user registration, marketing analytics, KYC verification) |
| **Risk Level of Processing** | Low / Medium / High (from DPIA or RIPD) |
| **Assessment Date** | |
| **Assessor** | |
| **Next Review Date** | |
| **Version** | 1.0 |

**Why this assessment is required for this processing activity:**

> _________________

---

## 2. Privacy Notice Inventory

List every privacy notice, transparency statement, and information disclosure point associated with this processing activity.

| Notice | Location / URL | Audience | Language(s) | Last Updated | Type |
|---|---|---|---|---|---|
| Full privacy policy | | All users | | | Full |
| Short notice at registration | | New users | | | Layered (short) |
| Cookie banner | | All visitors | | | Consent |
| _(add rows as needed)_ | | | | | |

---

## 3. Findability Assessment

> **Standard:** A first-time user with no prior knowledge of the product should be able to locate the privacy notice without assistance.

### 3.1 Click depth from homepage

| Starting point | Steps to reach full privacy policy | Result |
|---|---|---|
| Homepage (unauthenticated) | Click 1: ___ → Click 2: ___ | ≤ 2 clicks: Pass / > 2 clicks: Fail |
| Homepage (authenticated) | | |
| Data collection form | | |
| Mobile homepage | | |

**Target:** Reachable in ≤ 2 clicks from any page. Footer link on every page is the baseline.

### 3.2 Footer presence

- [ ] Privacy policy linked from the footer on every page (including authenticated views)
- [ ] Cookie policy / consent preferences linked from footer
- [ ] DPO / privacy contact linked or discoverable from footer

### 3.3 Short notice at point of collection

For each data collection form or flow, confirm a short layered notice is present:

| Collection point | Short notice present? | Text (first 100 chars) | Links to full policy? |
|---|---|---|---|
| Registration form | Yes / No | | Yes / No |
| Checkout / payment | Yes / No | | Yes / No |
| Contact form | Yes / No | | Yes / No |
| _(add rows)_ | | | |

**Minimum short notice content:** name of controller, purpose of collection, identity of any recipient, right to access/delete, link to full policy.

---

## 4. Legibility Assessment

> **Standard (LGPD Art. 6, VI / GDPR Art. 12(1)):** Information must be provided "in a concise, transparent, intelligible and easily accessible form, using clear and plain language." WP29 WP260 rev.01 states the standard is intelligibility "by an average member of the public" — not a lawyer or privacy professional.

### 4.1 Reading level

Measure the full privacy policy and any short notices.

| Document | Tool used | Score | Equivalent grade | Pass (≥ 60 / ≤ 8th grade)? |
|---|---|---|---|---|
| Full privacy policy | Flesch-Kincaid / Hemingway / readable.io | | | |
| Short notice at registration | | | | |
| Cookie banner text | | | | |

**How to measure:**
```bash
# Python — requires textstat: pip install textstat
python3 -c "
import textstat, sys
text = open(sys.argv[1]).read()
print('Flesch Reading Ease:', textstat.flesch_reading_ease(text))
print('Flesch-Kincaid Grade:', textstat.flesch_kincaid_grade(text))
print('Gunning Fog Index:', textstat.gunning_fog(text))
print('Reading Time (min):', round(len(text.split()) / 200, 1))
" privacy-policy.txt
```

| Flesch Reading Ease | Difficulty | Typical audience |
|---|---|---|
| 90–100 | Very easy | Age 11 / 5th grade |
| 70–90 | Easy | Age 13 / 7th grade — **target for consumer-facing notices** |
| 60–70 | Standard | Age 15 / 9th grade — **minimum acceptable** |
| 50–60 | Fairly difficult | College student |
| 0–50 | Difficult | Professional / academic — **flag as finding** |

### 4.2 Language and accessibility

- [ ] Privacy notice available in **Portuguese** (mandatory for LGPD when processing data of Brazilian residents)
- [ ] Privacy notice available in other languages matching the product's supported locales
- [ ] Font size ≥ 16px for body text
- [ ] Contrast ratio ≥ 4.5:1 (WCAG 2.1 AA) — check with browser DevTools or https://webaim.org/resources/contrastchecker/
- [ ] Privacy notice is responsive and readable on mobile devices
- [ ] Privacy notice is compatible with screen readers (test with VoiceOver / NVDA)

---

## 5. Comprehension Assessment

> **Standard:** Data subjects should be able to answer the five core questions below after reading the privacy notice, without assistance.

### 5.1 Core comprehension questions

After reading the privacy notice, a user should be able to answer:

| Question | Correct answer location in notice | Verified in user testing? |
|---|---|---|
| What personal data does this company collect about me? | | |
| Why does this company collect this data? | | |
| Who else receives my personal data? | | |
| How long is my data kept? | | |
| How do I request deletion of my data? | | |
| How do I contact the DPO / privacy team? | | |

### 5.2 User testing methodology

> WP29 WP260 rev.01 states that the "gold standard" for verifying intelligibility is user testing with participants representing the average data subject. For high-risk processing, the ANPD has adopted this position in enforcement.

| Field | Value |
|---|---|
| **Testing date** | |
| **Number of participants** | (WP29 guidance: minimum representative sample) |
| **Participant profile** | (age range, technical background, language) |
| **Methodology** | Moderated usability test / unmoderated / survey / A/B test |
| **Tasks given to participants** | 1. Find the privacy policy. 2. Identify who receives your data. 3. Find out how to delete your account. |
| **Success criteria** | e.g., task completed without assistance in < 2 minutes |

### 5.3 User testing results

| Task | Success rate | Average time | Observations |
|---|---|---|---|
| Find the privacy policy from the homepage | % | seconds | |
| Identify the purpose of data collection | % | — | |
| Find out how to exercise deletion right | % | seconds | |
| Identify third-party recipients | % | — | |
| Overall comprehension score | % | — | |

**Interpretation:**
- ≥ 80% success rate on all tasks: Strong evidence of effectiveness
- 60–79%: Adequate; document remediation plan for failing tasks
- < 60%: Inadequate; revise notice before this assessment is filed as evidence

---

## 6. Accessibility Audit

| Check | Result | Notes |
|---|---|---|
| WCAG 2.1 AA automated scan (axe, Lighthouse, WAVE) | Pass / Fail / Partial | |
| Keyboard navigation (tab through all links) | Pass / Fail | |
| Screen reader test (VoiceOver / NVDA) — headings, links announced correctly | Pass / Fail | |
| Colour contrast — all text meets 4.5:1 ratio | Pass / Fail | |
| Mobile responsiveness — no horizontal scroll, text not truncated | Pass / Fail | |
| Print / export — notice can be saved or printed in readable format | Pass / Fail | |

---

## 7. Remediation Log

| Finding | Severity | Action taken | Owner | Date resolved | Re-test date |
|---|---|---|---|---|---|
| | | | | | |

---

## 8. Evidence Registry

Documents available for ANPD or supervisory authority review:

| Evidence type | Document name / location | Date | Produced by |
|---|---|---|---|
| Reading level report | | | |
| Usability test session recordings | | | |
| Usability test summary report | | | |
| Accessibility audit report | | | |
| User comprehension survey results | | | |
| Privacy notice version history | | | |
| Previous assessments (for comparison) | | | |

---

## 9. Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Privacy Engineer / DPO | | | |
| Product Owner | | | |
| Legal / Compliance | | | |

**Assessment conclusion:**

- [ ] Transparency mechanisms are effective — evidence documented above supports this conclusion
- [ ] Transparency mechanisms have gaps — remediation plan in §7; re-assessment required by: ________
- [ ] Transparency mechanisms are inadequate — processing should not begin / continue until remediated

---

*Template aligned with: LGPD Art. 6(VI) (transparência), Art. 9 (requisitos de consentimento), Art. 18 (direitos dos titulares); GDPR Art. 12 (transparent communication), Art. 13/14 (information to data subjects); WP29 Guidelines on Transparency WP260 rev.01; ANPD enforcement posture (2026).*
