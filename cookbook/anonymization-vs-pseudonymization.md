# Cookbook: Anonymisation vs. Pseudonymisation

Understanding the difference is critical — only **true anonymisation** removes data from GDPR scope. Pseudonymous data is still personal data.

---

## The Distinction

| | Anonymisation | Pseudonymisation |
|---|---|---|
| **Definition** | Irreversibly removes all identifying information | Replaces identifiers with a reference; re-identification possible with additional data |
| **GDPR applies?** | **No** — no longer personal data (Recital 26) | **Yes** — still personal data (Art. 4(5)) |
| **LGPD applies?** | **No** — Art. 12 | **Yes** |
| **Use case** | Analytics, research, ML training | Internal logging, analytics while retaining linkability |
| **Reversible?** | No — by definition | Yes — with a key or mapping table |
| **Risk** | May fail (re-identification attacks) | Lower risk than identifiable data, but not zero |

---

## Anonymisation Techniques

### 1. Data Masking

Replace fields with fictional but structurally similar values:

```python
import random
import string

def mask_email(email: str) -> str:
    """Replace with synthetic email — same domain structure, random local part."""
    domain = email.split("@")[1] if "@" in email else "example.com"
    local = "".join(random.choices(string.ascii_lowercase, k=8))
    return f"{local}@{domain}"

def mask_name(name: str) -> str:
    names = ["Alice", "Bob", "Carol", "Dave", "Eve", "Frank"]
    return random.choice(names)
```

### 2. Data Generalisation

Replace specific values with ranges or categories:

```python
def generalise_age(age: int) -> str:
    if age < 18: return "under_18"
    if age < 30: return "18-29"
    if age < 40: return "30-39"
    if age < 50: return "40-49"
    return "50_plus"

def generalise_postcode(postcode: str) -> str:
    """Keep only first 3 characters — reduces geo precision."""
    return postcode[:3] + "XX"
```

### 3. Data Suppression

Remove fields entirely when not needed for the analytic purpose:

```python
FIELDS_TO_SUPPRESS = {"email", "phone", "address", "name", "ip_address", "user_agent"}

def suppress_pii(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in FIELDS_TO_SUPPRESS}
```

### 4. K-Anonymity

Ensure every record is indistinguishable from at least k−1 others on quasi-identifiers (age range, postcode prefix, gender):

```python
import pandas as pd

def apply_k_anonymity(df: pd.DataFrame, quasi_identifiers: list[str], k: int = 5) -> pd.DataFrame:
    """Suppress rows where a quasi-identifier combination has fewer than k records."""
    group_counts = df.groupby(quasi_identifiers).transform("count").iloc[:, 0]
    return df[group_counts >= k]
```

> **Limitation:** k-anonymity alone is vulnerable to homogeneity attacks and background knowledge attacks. Combine with l-diversity and t-closeness for stronger guarantees.

### 5. Differential Privacy

Add calibrated statistical noise to query results, preventing individual re-identification:

```python
# Using Google's dp-accounting library (pip install dp-accounting)
import numpy as np

def dp_count(true_count: int, epsilon: float = 1.0) -> int:
    """Return a differentially private count with Laplace noise."""
    sensitivity = 1  # counting query
    noise = np.random.laplace(loc=0, scale=sensitivity / epsilon)
    return max(0, int(true_count + noise))

def dp_mean(values: list[float], epsilon: float = 1.0, clip_min: float = 0, clip_max: float = 100) -> float:
    """Differentially private mean with clipping."""
    clipped = [max(clip_min, min(clip_max, v)) for v in values]
    true_mean = sum(clipped) / len(clipped)
    sensitivity = (clip_max - clip_min) / len(clipped)
    noise = np.random.laplace(loc=0, scale=sensitivity / epsilon)
    return true_mean + noise
```

---

## Pseudonymisation Techniques

### 1. Deterministic Hashing (SHA-256)

Replace an identifier with a one-way hash. Consistent across systems; not reversible without the original value.

```python
import hashlib

def pseudonymise(value: str, salt: str = "") -> str:
    """One-way pseudonymisation with optional salt."""
    return hashlib.sha256(f"{salt}{value}".encode()).hexdigest()

# Usage in logging:
user_ref = pseudonymise(user_id, salt=SECRET_SALT)
logger.info(f"User {user_ref} completed checkout")
```

> **Without a salt,** SHA-256 of common emails can be reversed by rainbow tables. Always use a secret salt stored in a secrets manager.

### 2. Token Mapping (Tokenisation)

Replace identifier with a random opaque token; store the mapping in a secure vault:

```python
import secrets
from redis import Redis

redis = Redis()
TOKEN_TTL = 60 * 60 * 24 * 365  # 1 year

def tokenise(user_id: str) -> str:
    token = secrets.token_urlsafe(16)
    redis.setex(f"token:{token}", TOKEN_TTL, user_id)
    redis.setex(f"user:{user_id}:token", TOKEN_TTL, token)
    return token

def detokenise(token: str) -> str | None:
    return redis.get(f"token:{token}")
```

### 3. Format-Preserving Encryption (FPE)

Encrypts a value while preserving its format (e.g., a 16-digit card number stays 16 digits):

```python
# Using pyffx (pip install pyffx) — AES-FFX
import pyffx

def fpe_encrypt(value: str, key: bytes) -> str:
    e = pyffx.String(key, alphabet=string.digits, length=len(value))
    return e.encrypt(value)

def fpe_decrypt(ciphertext: str, key: bytes) -> str:
    e = pyffx.String(key, alphabet=string.digits, length=len(ciphertext))
    return e.decrypt(ciphertext)
```

---

## Choosing the Right Technique

| Scenario | Recommended Technique | Why |
|---|---|---|
| Analytics / reporting (no individual lookup needed) | Generalisation + aggregation | True anonymisation; lowest risk |
| ML model training dataset | Suppression + k-anonymity | Remove direct identifiers; limit re-identification |
| Log correlation across services | Deterministic hash (salted) | Same user → same hash; not reversible externally |
| Fraud investigation (need to reverse later) | Tokenisation | Reversible by authorized service only |
| Database export to staging/dev | Data masking | Realistic structure, no real PII |
| Payment card numbers | Format-preserving encryption | PCI-DSS compliance; format preserved |
| Right to erasure | Hard delete + deletion registry | Full removal; registry prevents backup re-introduction |

---

## Anonymising a Database for Staging

```python
#!/usr/bin/env python3
"""Anonymise a production database dump for use in staging/dev."""

import psycopg2
import hashlib
import secrets

SALT = "staging-2026"  # rotate annually; store in secrets manager

def anonymise_users(conn):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users")
    users = cur.fetchall()
    for user_id, email in users:
        anon_email = f"user_{hashlib.sha256((SALT+email).encode()).hexdigest()[:8]}@example.invalid"
        cur.execute(
            "UPDATE users SET email=%s, first_name='Test', last_name='User', phone=NULL, address=NULL WHERE id=%s",
            (anon_email, user_id)
        )
    conn.commit()

def anonymise_orders(conn):
    cur = conn.cursor()
    cur.execute(
        "UPDATE orders SET shipping_name='Test User', shipping_address='123 Test St', shipping_phone=NULL"
    )
    conn.commit()

if __name__ == "__main__":
    conn = psycopg2.connect(DATABASE_URL)
    anonymise_users(conn)
    anonymise_orders(conn)
    print("Anonymisation complete")
    conn.close()
```

---

## Re-identification Risk Assessment

Even "anonymised" data can be re-identified. Before releasing a dataset, check:

1. **Uniqueness:** What percentage of records are unique on quasi-identifiers (age + postcode + gender)? > 20% unique = high re-identification risk.
2. **Linkability:** Can this dataset be joined with a public dataset (voter roll, LinkedIn) to re-identify individuals?
3. **Inference:** Can sensitive attributes (health condition, income) be inferred from the remaining data?

```python
def estimate_uniqueness(df: pd.DataFrame, quasi_identifiers: list[str]) -> float:
    """Returns fraction of records that are unique on quasi-identifiers."""
    return (df.groupby(quasi_identifiers).size() == 1).sum() / len(df)
```

A uniqueness rate below 5% on quasi-identifiers is generally considered acceptable for anonymised datasets.

---

## GDPR / LGPD Compliance Notes

- **GDPR Recital 26**: "The principles of data protection should … not apply to anonymous information, namely information which does not relate to an identified or identifiable natural person or to personal data rendered anonymous in such a manner that the data subject is not or no longer identifiable."
- **LGPD Art. 12**: Anonymised data is not considered personal data — unless the anonymisation process can be reversed using reasonable technical means.
- **The burden of proof** rests with the controller to demonstrate that data is truly anonymous. If there is any realistic possibility of re-identification, it is still personal data.
