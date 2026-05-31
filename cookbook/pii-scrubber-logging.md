# Cookbook: PII Scrubber for Logging

A defence-in-depth scrubber that redacts personally identifiable information from log messages before they are written to any sink (console, file, CloudWatch, Datadog, etc.).

> **Use this alongside — not instead of — fixing individual log statements.** The scrubber catches regressions and third-party library leaks; fixing individual statements makes the code self-documenting and keeps test coverage honest.

---

## Python — loguru

```python
import re
import sys
from loguru import logger

# ── PII patterns ──────────────────────────────────────────────────────────────
_EMAIL_RE    = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_RE    = re.compile(r"\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b")
_SSN_RE      = re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b")
_CPF_RE      = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")        # Brazilian CPF
_CREDIT_RE   = re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")
_TOKEN_RE    = re.compile(r"(?i)(token|password|secret|api_?key)[=:\s\"']+([A-Za-z0-9\-_.~+/]{8,})")

def _scrub_pii(record: dict) -> bool:
    """loguru filter — redacts PII before the message is formatted."""
    msg = record["message"]
    msg = _EMAIL_RE.sub("[REDACTED_EMAIL]", msg)
    msg = _PHONE_RE.sub("[REDACTED_PHONE]", msg)
    msg = _SSN_RE.sub("[REDACTED_SSN]", msg)
    msg = _CPF_RE.sub("[REDACTED_CPF]", msg)
    msg = _CREDIT_RE.sub("[REDACTED_CARD]", msg)
    msg = _TOKEN_RE.sub(r"\1=[REDACTED]", msg)
    record["message"] = msg
    return True

# ── Logger configuration ──────────────────────────────────────────────────────
logger.remove()                            # remove default handler
logger.add(sys.stderr, filter=_scrub_pii) # add scrubbed handler
# Additional sinks:
# logger.add("app.log", filter=_scrub_pii, rotation="100 MB")
# logger.add(cloudwatch_sink, filter=_scrub_pii)
```

### Applying to structured log fields (extra dict)

```python
def _scrub_pii(record: dict) -> bool:
    msg = record["message"]
    # ... apply regexes to msg ...
    record["message"] = msg

    # also scrub extra fields (structured logging)
    for key in list(record.get("extra", {}).keys()):
        val = str(record["extra"][key])
        val = _EMAIL_RE.sub("[REDACTED_EMAIL]", val)
        record["extra"][key] = val

    return True
```

---

## Python — stdlib logging

```python
import logging
import re

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

class PIIScrubberFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _EMAIL_RE.sub("[REDACTED_EMAIL]", str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: _EMAIL_RE.sub("[REDACTED_EMAIL]", str(v))
                    for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    _EMAIL_RE.sub("[REDACTED_EMAIL]", str(a)) for a in record.args
                )
        return True

# Attach to root logger (affects all loggers in the process)
logging.getLogger().addFilter(PIIScrubberFilter())

# Or attach to a specific logger:
logging.getLogger("myapp").addFilter(PIIScrubberFilter())
```

---

## Node.js / TypeScript — pino

```typescript
import pino from "pino";

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const TOKEN_RE = /(token|password|secret|apiKey)[=:\s"']+([A-Za-z0-9\-_.~+/]{8,})/gi;

function scrubPii(value: string): string {
  return value
    .replace(EMAIL_RE, "[REDACTED_EMAIL]")
    .replace(TOKEN_RE, "$1=[REDACTED]");
}

const logger = pino({
  serializers: {
    // Scrub the message and any string fields in the log object
    msg: scrubPii,
    err: (err: Error) => ({
      ...pino.stdSerializers.err(err),
      message: scrubPii(err.message),
    }),
  },
  // Redact specific known-PII fields at the pino level:
  redact: {
    paths: ["email", "user.email", "body.email", "*.email", "password", "token"],
    censor: "[REDACTED]",
  },
});

export default logger;
```

### pino redact paths (simple approach)

```typescript
const logger = pino({
  redact: ["email", "user.email", "req.body.password", "headers.authorization"],
});
```

---

## Node.js / TypeScript — winston

```typescript
import winston from "winston";

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

const piiScrubber = winston.format((info) => {
  if (typeof info.message === "string") {
    info.message = info.message.replace(EMAIL_RE, "[REDACTED_EMAIL]");
  }
  // Scrub known fields
  if (info.email) info.email = "[REDACTED_EMAIL]";
  if (info.password) info.password = "[REDACTED]";
  if (info.token) info.token = "[REDACTED]";
  return info;
});

const logger = winston.createLogger({
  format: winston.format.combine(
    piiScrubber(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});
```

---

## Go — slog (stdlib, Go 1.21+)

```go
package logging

import (
    "log/slog"
    "regexp"
    "strings"
)

var emailRE = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

type PIIScrubHandler struct {
    inner slog.Handler
}

func (h *PIIScrubHandler) Handle(ctx context.Context, r slog.Record) error {
    r.Message = emailRE.ReplaceAllString(r.Message, "[REDACTED_EMAIL]")
    return h.inner.Handle(ctx, r)
}

func (h *PIIScrubHandler) Enabled(ctx context.Context, level slog.Level) bool {
    return h.inner.Enabled(ctx, level)
}

func (h *PIIScrubHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
    return &PIIScrubHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *PIIScrubHandler) WithGroup(name string) slog.Handler {
    return &PIIScrubHandler{inner: h.inner.WithGroup(name)}
}

// Usage:
// baseHandler := slog.NewJSONHandler(os.Stderr, nil)
// logger := slog.New(&PIIScrubHandler{inner: baseHandler})
// slog.SetDefault(logger)
```

---

## Testing the Scrubber

Always write tests to verify the scrubber works:

```python
# Python / pytest
from loguru import logger
import re

def test_email_scrubbed(caplog):
    with caplog.at_level("INFO"):
        logger.info("Sent email to user@example.com successfully")
    assert "user@example.com" not in caplog.text
    assert "[REDACTED_EMAIL]" in caplog.text

def test_non_pii_preserved(caplog):
    with caplog.at_level("INFO"):
        logger.info("Order 12345 processed successfully")
    assert "Order 12345" in caplog.text
```

```typescript
// Jest / Node.js
import { scrubPii } from "./logger";

test("redacts email addresses", () => {
  expect(scrubPii("Sent to user@example.com")).toBe("Sent to [REDACTED_EMAIL]");
});

test("preserves non-PII content", () => {
  expect(scrubPii("Order 12345 processed")).toBe("Order 12345 processed");
});
```

---

## Common Gotchas

**1. Scrubber doesn't catch interpolated exceptions**

```python
# PROBLEM: exception message may contain PII
logger.exception(f"Error for {email}")  # exception obj also logged

# FIX: log exception separately or scrub the exc_info too
```

**2. Structured fields bypass string scrubber**

If your logging library logs structured key-value pairs (pino, structlog), scrubbing the message string is not enough — you must also redact individual fields.

**3. Third-party library logging**

Libraries like boto3, httpx, requests can log full HTTP requests including Authorization headers and response bodies. Attach the scrubber to the root logger or suppress noisy library loggers:

```python
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
```

**4. Performance at high log volume**

Multiple regex `sub()` calls on every log message adds overhead. Profile under load. Consider:
- Combining patterns into one regex with alternation
- Applying only to WARNING+ in high-throughput paths
- Using pino's `redact` (compile-time field path, faster than regex)
