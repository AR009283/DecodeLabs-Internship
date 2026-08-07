# Phishing Triage Decision Tree

This mirrors the triage flow from the DecodeLabs Project 3 brief: every
incoming suspicious message must end in one definitive action.

```
                     Incoming Suspicious Email
                               |
                 ------------------------------
                 |             |              |
              SAFE        SUSPICIOUS       MALICIOUS
           (score = 0)   (score 1-3)      (score >= 4)
                 |             |              |
              Close       Warn User    Block Domain & Escalate
```

## How the score is built

`src/analyzer.py` walks the message and adds points for every red flag it
finds. Severity determines weight:

| Severity | Weight | Example red flags |
|---|---|---|
| High   | 3 | Lookalike/typosquatted domain, brand/domain mismatch, credential or wire-transfer request, bypass/secrecy request, dangerous attachment, subdomain trap |
| Medium | 2 | Urgency language, fear/greed language, non-HTTPS link, shortened URL |
| Low    | 1 | Authority-figure language on its own |

## Header & URL checks (manual SOP, for anyone without the tool)

1. **Expand the full headers.** Compare the `From:` display name against the
   actual `From:` address and the `Return-Path`. A mismatch is a strong signal.
2. **Read the URL right to left.** The *true* root domain is the two labels
   directly before the top-level domain — e.g. in
   `www.decodelabs.tech.login-update.com`, the true root is `login-update.com`,
   not `decodelabs.tech`.
3. **Check the protocol.** `http://` (no "s") on a login page is a red flag.
4. **Check for IP-address links.** A destination like `http://192.168.x.x/login`
   should never appear in a legitimate corporate email.
5. **Check the attachment extension**, not just the icon or filename — icons
   can be faked, extensions like `.iso`, `.js`, `.scr` cannot be trusted.

## Outcome definitions

- **Close** — No indicators found. Treat as legitimate; no user action needed.
- **Warn User** — Some indicators present but not conclusive (e.g. urgency
  language alone). Send a caution note, ask the user not to click, and
  monitor.
- **Block Domain & Escalate** — Strong indicators of malicious intent
  (spoofed domain, credential harvesting, wire-transfer bypass request).
  Block the sending domain at the mail gateway, notify the security team, and
  search other inboxes for the same message (see `2026 Simulation Toolkit`
  in the source deck for real-world attack patterns this maps to).
