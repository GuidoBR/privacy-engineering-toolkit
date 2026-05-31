# Cookbook: Implementing the Right to Erasure

The right to erasure ("right to be forgotten") under GDPR Art. 17, LGPD Art. 18(VI), and CCPA §1798.105 requires you to delete a user's personal data when they request it and there is no overriding legal basis to retain it.

This cookbook covers: what to delete, what to keep, common database patterns, cascade deletion, and verification.

---

## Step 1 — Inventory What You Hold

Before writing any deletion code, map every location where a user's data exists:

| Location | Data | Deletable? | Constraint |
|---|---|---|---|
| `users` table | name, email, phone | Yes | FK parent — delete last |
| `orders` table | user_id FK, address | Partial — anonymise | Financial records (7 yr) |
| `audit_logs` | user_id, action, IP | Anonymise | Legal obligation to retain log |
| `sessions` / Redis cache | JWT, user_id | Yes | TTL or explicit delete |
| S3 — profile photos | photo.jpg | Yes | No legal hold |
| S3 — invoices | invoice PDF with name | No | Tax/financial (7 yr) |
| CloudWatch logs | email in messages | Anonymise via export | Legal obligation — retain logs |
| Email service | bounce list | Yes | Contact CMP/ESP |
| Analytics | user_id events | Yes | Contact Mixpanel/Segment/etc. |
| Backups | full DB snapshot | Separate process | Time-limited; document |

---

## Step 2 — Define Your Retention Exceptions

These are the standard legal bases to **retain** data despite an erasure request:

| Basis | Examples | Max Retention |
|---|---|---|
| Tax / accounting law | Invoice amount, payer name | 5–7 years (varies by country) |
| Financial regulation | Payment records | 5–7 years |
| Contract performance | Delivery address (active order) | Until order complete |
| Legal claims | Dispute-related records | Until limitation period expires |
| Legal obligation | KYC/AML records | Per regulation |
| Public interest | Fraud signals | As needed, anonymised |

**Document each exception in your privacy notice and deletion procedure.**

---

## Step 3 — Choose a Deletion Strategy

### Hard Delete

Physically remove the row. Simple, complete. Breaks foreign keys if not cascaded.

```sql
-- PostgreSQL: delete user and cascade to FK children
DELETE FROM users WHERE id = $1;
-- Requires: ON DELETE CASCADE on children, or manual ordering
```

### Anonymisation (Pseudonymous Tombstone)

Replace PII with a deterministic placeholder. Preserves referential integrity and statistical data.

```sql
UPDATE users SET
  email      = 'deleted+' || id || '@redacted.invalid',
  first_name = 'Deleted',
  last_name  = 'User',
  phone      = NULL,
  address    = NULL,
  deleted_at = NOW()
WHERE id = $1;
```

> **GDPR note:** Truly anonymised data (irreversible) is no longer "personal data" and falls outside the GDPR. Pseudonymised data (reversible with a key) is still personal data. If you keep a mapping table, it's pseudonymous.

### Soft Delete + Scheduled Purge

Mark as deleted immediately; schedule hard delete after a retention window:

```sql
UPDATE users SET
  deletion_requested_at = NOW(),
  deletion_scheduled_for = NOW() + INTERVAL '30 days'
WHERE id = $1;
```

A background job then hard-deletes after the window:

```sql
DELETE FROM users WHERE deletion_scheduled_for < NOW();
```

---

## Step 4 — Implementation Patterns

### Python (SQLAlchemy + FastAPI)

```python
import hashlib
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

def request_deletion(db: Session, user_id: str) -> dict:
    """Initiates DSAR erasure — anonymises PII, schedules purge."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError("User not found")

    # 1. Anonymise PII in user record
    user.email        = f"deleted+{user_id[:8]}@redacted.invalid"
    user.first_name   = "Deleted"
    user.last_name    = "User"
    user.phone        = None
    user.address      = None
    user.deleted_at   = datetime.utcnow()
    user.is_active    = False

    # 2. Anonymise orders (keep amounts for accounting)
    db.query(Order).filter(Order.user_id == user_id).update({
        "shipping_name":    "Deleted User",
        "shipping_address": None,
        "shipping_phone":   None,
    })

    # 3. Revoke all active sessions
    db.query(Session).filter(Session.user_id == user_id).delete()

    # 4. Log the deletion event (use hashed user_id, not email)
    user_ref = hashlib.sha256(user_id.encode()).hexdigest()[:12]
    audit_log(db, action="user_deletion_requested", subject_ref=user_ref)

    db.commit()

    # 5. Trigger async cleanup of external services
    trigger_external_cleanup.delay(user_id=user_id)

    return {"status": "deletion_initiated", "scheduled_purge": "30_days"}
```

### Node.js (Prisma)

```typescript
import { prisma } from "./db";
import crypto from "crypto";

async function deleteUser(userId: string): Promise<void> {
  const userRef = crypto.createHash("sha256").update(userId).digest("hex").slice(0, 12);

  await prisma.$transaction([
    // Anonymise user
    prisma.user.update({
      where: { id: userId },
      data: {
        email:     `deleted+${userId.slice(0, 8)}@redacted.invalid`,
        firstName: "Deleted",
        lastName:  "User",
        phone:     null,
        address:   null,
        deletedAt: new Date(),
        isActive:  false,
      },
    }),
    // Anonymise orders
    prisma.order.updateMany({
      where: { userId },
      data: { shippingName: "Deleted User", shippingAddress: null },
    }),
    // Delete sessions
    prisma.session.deleteMany({ where: { userId } }),
    // Audit log
    prisma.auditLog.create({
      data: { action: "user_deletion", subjectRef: userRef },
    }),
  ]);
}
```

---

## Step 5 — External Services

You must instruct processors to delete user data too (GDPR Art. 17(2)):

| Service | Deletion Mechanism |
|---|---|
| **Mixpanel** | `mixpanel.people.delete_user(distinct_id)` or API |
| **Segment** | `DELETE /v1/regulations` (Segment Privacy Portal API) |
| **Intercom** | `DELETE /contacts/{id}` |
| **SendGrid / SES** | Remove from suppression lists; delete contact |
| **Stripe** | `POST /v1/customers/{id}/delete` (if allowed by financial regulations) |
| **HubSpot** | `DELETE /crm/v3/objects/contacts/{id}` |
| **Amplitude** | `POST /api/2/deletions/users` |
| **Datadog** | Sensitive data scanner + log archive deletion |

```python
# Async Celery task for external cleanup
@celery.task(bind=True, max_retries=3)
def trigger_external_cleanup(self, user_id: str, email: str):
    try:
        mixpanel.people.delete_user(user_id)
        segment_client.delete_user(user_id)
        intercom.contacts.delete(user_id)
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))
```

---

## Step 6 — Backups

Backups complicate erasure. GDPR Recital 65 acknowledges that re-erasure from backups is not required immediately:

> *"where the personal data have been made public ... appropriate measures including technical measures should be taken to inform controllers ... taking into account available technology and the cost of implementation."*

**Practical approach:**
1. Keep a **deletion log** (user_id hash + deletion date) that is checked before restoring any backup.
2. Set backup **retention to the minimum** required (don't keep 10 years of daily backups if 30 days suffices).
3. On backup restore, run the deletion log through a reconciliation job that re-anonymises any records that should have been deleted.

```sql
-- Deletion registry (kept separately from the main DB)
CREATE TABLE deletion_registry (
  user_id_hash TEXT NOT NULL,   -- SHA-256 of user_id
  deleted_at   TIMESTAMPTZ NOT NULL,
  reason       TEXT
);
```

---

## Step 7 — DSAR API Endpoint

```python
# FastAPI endpoint
from fastapi import APIRouter, Depends, HTTPException, status

router = APIRouter(prefix="/v1/privacy", tags=["privacy"])

@router.delete("/me", status_code=status.HTTP_202_ACCEPTED)
async def request_erasure(
    current_user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Data subject erasure request — GDPR Art. 17 / LGPD Art. 18(VI)."""
    result = request_deletion(db, current_user_id)
    return {
        "message": "Your deletion request has been received and is being processed.",
        "expected_completion": "30 days",
        "reference": result.get("reference"),
    }
```

---

## Step 8 — Verification Checklist

After implementing deletion:

- [ ] PII fields are nulled or anonymised in the primary database
- [ ] Session tokens are revoked
- [ ] Cache entries (Redis, Memcached) are cleared
- [ ] External processors are notified and confirmed deletion
- [ ] Audit log records the deletion event (using opaque reference, not email)
- [ ] Deletion registry updated for backup reconciliation
- [ ] Integration test covers the full deletion flow end-to-end
- [ ] DSAR endpoint returns 202 and queues async cleanup
- [ ] 30-day completion window is monitored and alerted if exceeded

---

## Common Pitfalls

**1. Deleting the parent before the children**

```sql
-- WRONG: violates FK constraint
DELETE FROM users WHERE id = $1;
-- ERROR: update or delete on table "users" violates foreign key on table "orders"

-- CORRECT: delete/anonymise children first, then parent
UPDATE orders SET user_id = NULL WHERE user_id = $1;
DELETE FROM users WHERE id = $1;
```

**2. Forgetting search indices**

Elasticsearch, Algolia, Typesense — they may have their own copies of user data. Delete from the index separately.

**3. Email marketing lists**

Even if you delete from your DB, the ESP (Mailchimp, SendGrid) may still have the user on a suppression or marketing list. Call the ESP API explicitly.

**4. "Deleted" user in audit logs**

Audit logs must retain the event (for legal/security reasons) but must not retain the identifying information. Use a one-way hash or opaque reference instead of the email.
