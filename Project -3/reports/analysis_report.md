# Phishing Triage Report

| File | Sender | Verdict | Score | Action |
|---|---|---|---|---|
| legitimate_email.txt | newsletter@google.com | SAFE | 0 | Close |
| phishing_email_1.txt | support@paypa1.com | MALICIOUS | 13 | Block Domain & Escalate |
| phishing_email_2.txt | rewards@amaz0n-gifts.com | MALICIOUS | 15 | Block Domain & Escalate |
| phishing_email_3.txt | admin@micr0soft-support.com | MALICIOUS | 15 | Block Domain & Escalate |
| phishing_email_4_bec.txt | ceo.urgent@executive-update.com | MALICIOUS | 9 | Block Domain & Escalate |
| phishing_email_5_quishing.txt | no-reply@accounts-google-secure.com | MALICIOUS | 11 | Block Domain & Escalate |

## legitimate_email.txt
- **From:** newsletter@google.com
- **Subject:** Monthly Security Update
- **URLs:** https://www.google.com/
- **Verdict:** SAFE (score 0) → **Close**
- **Red flags:** None detected.

## phishing_email_1.txt
- **From:** support@paypa1.com
- **Subject:** Urgent Action Required
- **URLs:** http://paypa1-security-login.com
- **Verdict:** MALICIOUS (score 13) → **Block Domain & Escalate**
- **Red flags:**
  - `[high]` **BRAND_DOMAIN_MISMATCH** — Message references brand 'paypal' but sender domain 'paypa1.com' does not match any official domain (paypal.com).
  - `[high]` **LOOKALIKE_DOMAIN** — Sender domain 'paypa1.com' looks like a disguised version of 'paypal.com' (character substitution / typosquat).
  - `[medium]` **NON_HTTPS_URL** — Link 'http://paypa1-security-login.com' uses unencrypted HTTP instead of HTTPS.
  - `[medium]` **URGENCY_LANGUAGE** — Artificial time-pressure language detected: 24 hours, act within, immediately, suspend, suspended, termination, urgent.
  - `[high]` **CREDENTIAL_OR_PAYMENT_REQUEST** — Message requests credentials, MFA codes, or payment/banking details: verify your account.

## phishing_email_2.txt
- **From:** rewards@amaz0n-gifts.com
- **Subject:** Congratulations! You have won a prize.
- **URLs:** http://amazon-reward-center.com
- **Verdict:** MALICIOUS (score 15) → **Block Domain & Escalate**
- **Red flags:**
  - `[high]` **BRAND_DOMAIN_MISMATCH** — Message references brand 'amazon' but sender domain 'amaz0n-gifts.com' does not match any official domain (amazon.com).
  - `[high]` **LOOKALIKE_DOMAIN** — Sender domain 'amaz0n-gifts.com' looks like a disguised version of 'amazon.com' (character substitution / typosquat).
  - `[medium]` **NON_HTTPS_URL** — Link 'http://amazon-reward-center.com' uses unencrypted HTTP instead of HTTPS.
  - `[medium]` **URGENCY_LANGUAGE** — Artificial time-pressure language detected: 12 hours, expire, expires.
  - `[medium]` **FEAR_OR_GREED_LANGUAGE** — Fear/greed trigger words detected: claim, congratulations, free, gift, prize, reward, selected, won.
  - `[high]` **CREDENTIAL_OR_PAYMENT_REQUEST** — Message requests credentials, MFA codes, or payment/banking details: provide your personal details.

## phishing_email_3.txt
- **From:** admin@micr0soft-support.com
- **Subject:** Your Office 365 account will be disabled
- **URLs:** http://office365-verification.net
- **Verdict:** MALICIOUS (score 15) → **Block Domain & Escalate**
- **Red flags:**
  - `[high]` **BRAND_DOMAIN_MISMATCH** — Message references brand 'microsoft' but sender domain 'micr0soft-support.com' does not match any official domain (microsoft.com, office.com, office365.com, live.com).
  - `[high]` **LOOKALIKE_DOMAIN** — Sender domain 'micr0soft-support.com' looks like a disguised version of 'microsoft.com' (character substitution / typosquat).
  - `[medium]` **NON_HTTPS_URL** — Link 'http://office365-verification.net' uses unencrypted HTTP instead of HTTPS.
  - `[medium]` **URGENCY_LANGUAGE** — Artificial time-pressure language detected: disable, disabled, suspend, suspended.
  - `[medium]` **FEAR_OR_GREED_LANGUAGE** — Fear/greed trigger words detected: unusual activity.
  - `[high]` **CREDENTIAL_OR_PAYMENT_REQUEST** — Message requests credentials, MFA codes, or payment/banking details: confirm your information, verify your account.

## phishing_email_4_bec.txt
- **From:** CEO Name <ceo.urgent@executive-update.com>
- **Subject:** IMMEDIATE ACTION REQUIRED: Transfer Authorization
- **URLs:** None
- **Verdict:** MALICIOUS (score 9) → **Block Domain & Escalate**
- **Red flags:**
  - `[medium]` **URGENCY_LANGUAGE** — Artificial time-pressure language detected: immediate action, immediately, urgent.
  - `[low]` **AUTHORITY_IMPERSONATION** — Message invokes authority/executive figures: ceo, confidential, executive, strictly confidential.
  - `[high]` **BYPASS_OR_SECRECY_REQUEST** — Message asks the recipient to bypass process or keep the request secret: bypass, do not discuss, just this once.
  - `[high]` **CREDENTIAL_OR_PAYMENT_REQUEST** — Message requests credentials, MFA codes, or payment/banking details: wire transfer.

## phishing_email_5_quishing.txt
- **From:** Google Account Recovery <no-reply@accounts-google-secure.com>
- **Subject:** Action Required: Prevent Account Lockout
- **URLs:** None
- **Verdict:** MALICIOUS (score 11) → **Block Domain & Escalate**
- **Red flags:**
  - `[high]` **BRAND_DOMAIN_MISMATCH** — Message references brand 'google' but sender domain 'accounts-google-secure.com' does not match any official domain (google.com, gmail.com, accounts.google.com).
  - `[high]` **LOOKALIKE_DOMAIN** — Sender domain 'accounts-google-secure.com' looks like a disguised version of 'google.com' (character substitution / typosquat).
  - `[high]` **COMBOSQUAT_DOMAIN** — Sender domain 'accounts-google-secure.com' pads a legitimate brand name with security-related words to appear trustworthy.
  - `[medium]` **URGENCY_LANGUAGE** — Artificial time-pressure language detected: 30 minutes, locked, lockout.
