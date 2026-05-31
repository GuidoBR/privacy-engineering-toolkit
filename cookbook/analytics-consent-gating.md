# Cookbook: Analytics & Tracker Consent Gating

Loading analytics, advertising, or tracking scripts before the user has given consent violates GDPR Art. 6(1)(a), the ePrivacy Directive, LGPD Art. 7(I), and similar laws. This cookbook shows how to gate each major tracker correctly.

> **Key principle:** Non-essential cookies and trackers must not load until consent is given. Session replay, ad pixels, and behavioural analytics are always non-essential.

---

## The Pattern

Every tracker integration follows the same three-step pattern:

1. **Block the script** from loading on page load
2. **Listen for consent** from your consent management platform (CMP)
3. **Initialize the tracker** only after consent

---

## React — Generic Consent Hook

```tsx
// hooks/useConsent.ts
import { useState, useEffect } from "react";

export type ConsentCategory = "analytics" | "advertising" | "functional";

interface ConsentState {
  analytics: boolean;
  advertising: boolean;
  functional: boolean;
}

export function useConsent(): ConsentState {
  const [consent, setConsent] = useState<ConsentState>({
    analytics: false,
    advertising: false,
    functional: false,
  });

  useEffect(() => {
    // Read from your CMP. Examples for popular CMPs below.
    const stored = localStorage.getItem("cookieConsent");
    if (stored) {
      setConsent(JSON.parse(stored));
    }

    // Listen for consent changes
    const handler = (e: CustomEvent<ConsentState>) => setConsent(e.detail);
    window.addEventListener("cookieConsentUpdated", handler as EventListener);
    return () => window.removeEventListener("cookieConsentUpdated", handler as EventListener);
  }, []);

  return consent;
}
```

```tsx
// App.tsx — only mount analytics after consent
import { useConsent } from "./hooks/useConsent";
import { useEffect } from "react";

export function App() {
  const consent = useConsent();

  useEffect(() => {
    if (consent.analytics) {
      initGoogleAnalytics();
      initMixpanel();
    }
  }, [consent.analytics]);

  useEffect(() => {
    if (consent.advertising) {
      initFacebookPixel();
    }
  }, [consent.advertising]);

  return <>{/* ... */}</>;
}
```

---

## Google Analytics 4 (gtag.js)

```html
<!-- DO NOT use the standard Google snippet — it loads GA immediately -->
<!-- Instead: load conditionally -->

<script>
  window.dataLayer = window.dataLayer || [];
  function gtag() { dataLayer.push(arguments); }

  // Set default consent state — deny all until user chooses
  gtag('consent', 'default', {
    'analytics_storage': 'denied',
    'ad_storage': 'denied',
    'ad_user_data': 'denied',
    'ad_personalization': 'denied',
    'wait_for_update': 2000   // wait 2s for CMP to update
  });
</script>

<!-- Load gtag.js script here (it respects the consent mode above) -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>

<script>
  // After user accepts analytics consent:
  function onAnalyticsConsent() {
    gtag('consent', 'update', { 'analytics_storage': 'granted' });
  }

  // After user accepts advertising consent:
  function onAdvertisingConsent() {
    gtag('consent', 'update', {
      'ad_storage': 'granted',
      'ad_user_data': 'granted',
      'ad_personalization': 'granted'
    });
  }
</script>
```

---

## Google Tag Manager

```html
<!-- Step 1: configure consent before GTM loads -->
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag() { dataLayer.push(arguments); }
  gtag('consent', 'default', {
    'analytics_storage': 'denied',
    'ad_storage': 'denied',
    'wait_for_update': 2000
  });
</script>

<!-- Step 2: load GTM (it will wait for consent updates) -->
<!-- GTM snippet here -->

<!-- Step 3: in your CMP callback, push consent update -->
<script>
  function updateGtmConsent(analyticsGranted, adGranted) {
    window.dataLayer.push({
      event: 'consent_update',
      analytics_storage: analyticsGranted ? 'granted' : 'denied',
      ad_storage: adGranted ? 'granted' : 'denied',
    });
  }
</script>
```

---

## Mixpanel

```typescript
// DO NOT call mixpanel.init() at module load
// Instead, initialize only after consent

let mixpanelInitialized = false;

export function initMixpanel(token: string) {
  if (mixpanelInitialized) return;
  import("mixpanel-browser").then((mixpanel) => {
    mixpanel.default.init(token, {
      opt_out_tracking_by_default: false, // we checked consent before calling this
      persistence: "localStorage",
    });
    mixpanelInitialized = true;
  });
}

// In your consent handler:
// if (consent.analytics) initMixpanel(MIXPANEL_TOKEN);
```

---

## Segment

```typescript
// analytics.ts
let analyticsLoaded = false;

export function loadSegment(writeKey: string) {
  if (analyticsLoaded) return;
  // Segment's analytics.js has a built-in queue — safe to call identify/track
  // before the script loads, but we still gate the load itself.
  const script = document.createElement("script");
  script.src = "https://cdn.segment.com/analytics.js/v1/" + writeKey + "/analytics.min.js";
  script.async = true;
  document.head.appendChild(script);
  analyticsLoaded = true;
}

// Usage:
// onConsentGranted("analytics", () => loadSegment(WRITE_KEY));
```

---

## Facebook Pixel

```typescript
// DO NOT include the standard fbq snippet in your HTML — it fires PageView immediately

export function initFacebookPixel(pixelId: string) {
  if (window.fbq) return; // already initialized

  // Minimal fbq stub + script injection
  const f = window as any;
  f.fbq = function() { (f.fbq.q = f.fbq.q || []).push(arguments); };
  f._fbq = f.fbq;
  f.fbq.loaded = true;
  f.fbq.version = "2.0";
  f.fbq.q = [];

  const script = document.createElement("script");
  script.async = true;
  script.src = "https://connect.facebook.net/en_US/fbevents.js";
  document.head.appendChild(script);

  f.fbq("init", pixelId);
  f.fbq("track", "PageView");
}

// Call only after advertising consent:
// if (consent.advertising) initFacebookPixel(FB_PIXEL_ID);
```

---

## Sentry (Error Tracking)

Sentry is technically necessary for product reliability, but it can capture PII in stack traces and breadcrumbs. You have two options:

**Option A — Load without consent but scrub PII:**
```typescript
import * as Sentry from "@sentry/react";

Sentry.init({
  dsn: SENTRY_DSN,
  beforeSend(event) {
    // Scrub email from exception messages
    if (event.exception?.values) {
      event.exception.values.forEach((ex) => {
        if (ex.value) {
          ex.value = ex.value.replace(
            /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
            "[REDACTED_EMAIL]"
          );
        }
      });
    }
    // Remove user identity
    delete event.user;
    return event;
  },
  beforeBreadcrumb(breadcrumb) {
    // Remove sensitive URL params from breadcrumbs
    if (breadcrumb.data?.url) {
      breadcrumb.data.url = breadcrumb.data.url.replace(/email=[^&]+/, "email=[REDACTED]");
    }
    return breadcrumb;
  },
});
```

**Option B — Gate behind functional/analytics consent:**
```typescript
if (consent.functional) {
  Sentry.init({ dsn: SENTRY_DSN });
}
```

---

## CMP Integration Examples

### Cookiebot

```typescript
window.addEventListener("CookiebotOnAccept", () => {
  if (window.Cookiebot?.consent?.statistics) {
    initGoogleAnalytics();
    initMixpanel();
  }
  if (window.Cookiebot?.consent?.marketing) {
    initFacebookPixel();
  }
});
```

### OneTrust

```typescript
window.OneTrust?.OnConsentChanged((categories: string[]) => {
  if (categories.includes("C0002")) initGoogleAnalytics(); // Performance cookies
  if (categories.includes("C0004")) initFacebookPixel();   // Targeting cookies
});
```

### Custom CMP

```typescript
// Dispatch this event from your consent banner on accept
window.dispatchEvent(new CustomEvent("cookieConsentUpdated", {
  detail: { analytics: true, advertising: false }
}));
```

---

## Server-Side: Honour Opt-Out

Consent isn't only a frontend concern. Your backend must also respect opt-outs:

```python
# Python — check consent before sending data to third-party analytics
def track_event(user_id: str, event: str, properties: dict) -> None:
    user = get_user(user_id)
    if not user.analytics_consent:
        return  # do not send to Mixpanel / Segment / etc.
    mixpanel.track(user_id, event, properties)
```

---

## Testing Consent Gating

```typescript
// Jest — verify tracker not called before consent
test("does not initialize GA before consent", () => {
  const gtagSpy = jest.spyOn(window, "gtag");
  render(<App />);
  expect(gtagSpy).not.toHaveBeenCalledWith("config", expect.anything());
});

test("initializes GA after analytics consent is granted", () => {
  const gtagSpy = jest.spyOn(window, "gtag");
  render(<App />);
  window.dispatchEvent(new CustomEvent("cookieConsentUpdated", {
    detail: { analytics: true }
  }));
  expect(gtagSpy).toHaveBeenCalledWith("config", GA_MEASUREMENT_ID);
});
```

---

## Audit with scan-trackers.sh

Use the provided script to check all tracked files:

```bash
./scripts/scan-trackers.sh src/
```

Any `[UNGATED]` findings mean a tracker loads unconditionally — fix before deploying.
