# Cookbook: DSAR API Endpoints

Implementing Data Subject Access Request (DSAR) endpoints — covering access, export, erasure, and correction — for GDPR Art. 15–20, LGPD Art. 18, and CCPA §1798.100–.125.

---

## Overview

A minimal compliant DSAR implementation requires four endpoints:

| Endpoint | Right | Law | Deadline |
|---|---|---|---|
| `GET /v1/privacy/me/export` | Access + portability | GDPR 15/20, LGPD 18(II/V), CCPA §1798.100 | 30 days (GDPR/LGPD), 45 days (CCPA) |
| `DELETE /v1/privacy/me` | Erasure | GDPR 17, LGPD 18(VI), CCPA §1798.105 | 30 days |
| `PATCH /v1/privacy/me/correct` | Rectification | GDPR 16, LGPD 18(III) | 30 days |
| `POST /v1/privacy/me/restrict` | Restriction | GDPR 18 | 30 days |

---

## FastAPI Implementation

### Setup

```python
# src/api/v1/privacy.py
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from datetime import datetime
import hashlib

from src.auth import get_current_user_id
from src.database import get_db
from src.privacy.services import (
    build_data_export,
    initiate_deletion,
    apply_correction,
    apply_restriction,
)

router = APIRouter(prefix="/v1/privacy", tags=["privacy"])
```

### 1. Data Export (Access + Portability)

```python
from fastapi.responses import JSONResponse

@router.get("/me/export")
async def export_my_data(
    background_tasks: BackgroundTasks,
    current_user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Returns all personal data held about the authenticated user.
    GDPR Art. 15 (access) + Art. 20 (portability).
    Response is machine-readable JSON; add PDF generation for human-readable copy.
    """
    export = build_data_export(db, current_user_id)

    # Audit the access request
    background_tasks.add_task(
        log_dsar_event,
        user_ref=_hash(current_user_id),
        action="data_export_requested",
    )

    return JSONResponse(
        content=export,
        headers={
            "Content-Disposition": "attachment; filename=my-data.json",
            "Content-Type": "application/json",
        },
    )


def build_data_export(db: Session, user_id: str) -> dict:
    """Assembles a complete data export for the user."""
    user = db.query(User).filter(User.id == user_id).first()
    orders = db.query(Order).filter(Order.user_id == user_id).all()
    consents = db.query(ConsentRecord).filter(ConsentRecord.user_id == user_id).all()

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "data_controller": "Acme Corp — privacy@acme.example",
        "profile": {
            "id":         user.id,
            "email":      user.email,
            "first_name": user.first_name,
            "last_name":  user.last_name,
            "phone":      user.phone,
            "created_at": user.created_at.isoformat(),
        },
        "orders": [
            {
                "id":         o.id,
                "amount":     o.amount,
                "status":     o.status,
                "created_at": o.created_at.isoformat(),
            }
            for o in orders
        ],
        "consent_history": [
            {
                "category":   c.category,
                "granted":    c.granted,
                "timestamp":  c.timestamp.isoformat(),
            }
            for c in consents
        ],
    }
```

### 2. Erasure Request

```python
from pydantic import BaseModel

class ErasureRequest(BaseModel):
    reason: str | None = None  # optional; useful for metrics

@router.delete("/me", status_code=status.HTTP_202_ACCEPTED)
async def request_erasure(
    body: ErasureRequest,
    background_tasks: BackgroundTasks,
    current_user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Initiates erasure of all personal data.
    GDPR Art. 17 / LGPD Art. 18(VI) / CCPA §1798.105.
    Returns 202 Accepted — actual deletion is async (30-day window).
    """
    # Check for retention holds (e.g., open orders, financial records)
    holds = check_retention_holds(db, current_user_id)
    if holds:
        return {
            "status": "partial",
            "message": "Deletion request received. Some data cannot be immediately deleted.",
            "holds": holds,
            "expected_completion_days": 30,
        }

    reference = initiate_deletion(db, current_user_id)
    background_tasks.add_task(
        log_dsar_event,
        user_ref=_hash(current_user_id),
        action="erasure_requested",
    )

    return {
        "status": "accepted",
        "reference": reference,
        "message": "Your deletion request has been received and will be processed within 30 days.",
        "expected_completion_days": 30,
    }


def check_retention_holds(db: Session, user_id: str) -> list[dict]:
    """Returns legal holds that prevent immediate full deletion."""
    holds = []
    # Financial records
    if db.query(Invoice).filter(Invoice.user_id == user_id, Invoice.year >= datetime.utcnow().year - 7).count():
        holds.append({
            "type": "financial_records",
            "reason": "Tax law requires retention of financial records for 7 years.",
            "release_date": f"{datetime.utcnow().year + 7}-01-01",
        })
    # Active contracts
    if db.query(Contract).filter(Contract.user_id == user_id, Contract.status == "active").count():
        holds.append({
            "type": "active_contract",
            "reason": "An active contract requires data retention until completion.",
        })
    return holds
```

### 3. Correction

```python
class CorrectionRequest(BaseModel):
    first_name: str | None = None
    last_name:  str | None = None
    phone:      str | None = None
    address:    str | None = None

@router.patch("/me/correct", status_code=status.HTTP_200_OK)
async def correct_my_data(
    body: CorrectionRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Corrects inaccurate personal data.
    GDPR Art. 16 / LGPD Art. 18(III).
    """
    updates = body.dict(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to correct.")

    user = db.query(User).filter(User.id == current_user_id).first()
    for field, value in updates.items():
        setattr(user, field, value)
    db.commit()

    return {"status": "corrected", "fields_updated": list(updates.keys())}
```

### 4. Restriction

```python
class RestrictionRequest(BaseModel):
    reason: str  # "accuracy_contested" | "unlawful_processing" | "legal_claims" | "objection_pending"

@router.post("/me/restrict", status_code=status.HTTP_200_OK)
async def restrict_processing(
    body: RestrictionRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Restricts processing of personal data.
    GDPR Art. 18 / LGPD Art. 18(IV).
    The user's data is stored but not actively processed.
    """
    user = db.query(User).filter(User.id == current_user_id).first()
    user.processing_restricted = True
    user.restriction_reason    = body.reason
    user.restriction_date      = datetime.utcnow()
    db.commit()

    return {
        "status": "restricted",
        "reason": body.reason,
        "message": "Processing of your data has been restricted. You will be notified before the restriction is lifted.",
    }
```

---

## Express.js / TypeScript Implementation

```typescript
import { Router, Request, Response } from "express";
import { authenticate } from "../middleware/auth";
import { buildDataExport, initiateErasure } from "../privacy/service";

const router = Router();

// Data export
router.get("/me/export", authenticate, async (req: Request, res: Response) => {
  const userId = req.user!.id;
  const exportData = await buildDataExport(userId);
  res
    .header("Content-Disposition", "attachment; filename=my-data.json")
    .json(exportData);
});

// Erasure
router.delete("/me", authenticate, async (req: Request, res: Response) => {
  const userId = req.user!.id;
  const reference = await initiateErasure(userId);
  res.status(202).json({
    status: "accepted",
    reference,
    message: "Deletion request received. Processing within 30 days.",
  });
});

export default router;
```

---

## Identity Verification

Before responding to any DSAR, verify the requester's identity:

```python
def verify_identity(claimed_user_id: str, current_user_id: str) -> bool:
    """For authenticated users, identity is already verified by the JWT."""
    return claimed_user_id == current_user_id

# For unauthenticated requests (e.g., CCPA "submit by email"):
# Require at least two pieces of identifying information:
# - email address + last 4 digits of a recent order, OR
# - email + account creation date
# Log verification attempt and outcome.
```

---

## CCPA "Do Not Sell" Endpoint

```python
@router.post("/me/opt-out-of-sale", status_code=status.HTTP_200_OK)
async def opt_out_of_sale(
    current_user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Opt out of sale/sharing of personal information.
    CCPA §1798.120 / CPRA.
    Must be honoured immediately.
    """
    user = db.query(User).filter(User.id == current_user_id).first()
    user.opted_out_of_sale   = True
    user.opt_out_date        = datetime.utcnow()
    db.commit()

    # Propagate to downstream processors immediately
    revoke_third_party_sharing.delay(user_id=current_user_id)

    return {"status": "opted_out", "effective": "immediately"}
```

---

## DSAR Request Tracking

Track all requests to demonstrate compliance:

```python
class DSARRequest(Base):
    __tablename__ = "dsar_requests"

    id              = Column(UUID, primary_key=True, default=uuid4)
    user_id_hash    = Column(String, nullable=False)  # SHA-256 — not plaintext
    request_type    = Column(String)   # export | erasure | correction | restriction | opt_out
    received_at     = Column(DateTime, default=datetime.utcnow)
    deadline        = Column(DateTime)
    completed_at    = Column(DateTime, nullable=True)
    status          = Column(String, default="pending")  # pending | in_progress | completed | denied
    denial_reason   = Column(String, nullable=True)
```

---

## Testing

```python
import pytest
from fastapi.testclient import TestClient

def test_export_returns_user_data(client, auth_headers, test_user):
    response = client.get("/v1/privacy/me/export", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["profile"]["email"] == test_user.email
    assert "orders" in data

def test_erasure_returns_202(client, auth_headers):
    response = client.delete("/v1/privacy/me", headers=auth_headers, json={})
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"

def test_erasure_anonymises_user(client, auth_headers, db, test_user):
    client.delete("/v1/privacy/me", headers=auth_headers, json={})
    db.refresh(test_user)
    assert "@redacted.invalid" in test_user.email
    assert test_user.phone is None

def test_unauthenticated_cannot_export(client):
    response = client.get("/v1/privacy/me/export")
    assert response.status_code == 401
```

---

## Response Time Monitoring

Add a Celery beat task (or cron) to alert on SLA breaches:

```python
from celery.schedules import crontab

@celery.task
def check_dsar_sla():
    """Alert if any DSAR is approaching its deadline without completion."""
    approaching = DSARRequest.query.filter(
        DSARRequest.status == "pending",
        DSARRequest.deadline <= datetime.utcnow() + timedelta(days=5),
    ).all()
    for req in approaching:
        send_alert(f"DSAR {req.id} approaching deadline: {req.deadline}")
```
