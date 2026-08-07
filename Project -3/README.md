# Project 3 — Phishing Awareness Analysis

**DecodeLabs Industrial Training Kit — Cyber Security Track, Batch 2026**

A hands-on triage tool that analyzes raw emails, flags social-engineering /
phishing red flags with plain-English explanations, and classifies each
message as **SAFE**, **SUSPICIOUS**, or **MALICIOUS** with a definitive
next action — exactly the deliverable described in the project brief:

> Build a non-expert triage checklist and clear decision trees for incoming
> threats. Every triage event must end in a definitive action — Safe → Close,
> Suspicious → Warn User, or Malicious → Block Domain & Escalate.

## What this project does

1. **Analyzes sample emails/messages** (`src/analyzer.py`) to identify:
   - Suspicious or lookalike links and domains (typosquatting, leetspeak
     substitution, combosquatting, "subdomain trap" nesting)
   - Sender/brand domain mismatches and display-name spoofing
   - Cognitive-trigger keywords: urgency, fear/greed, authority, secrecy/bypass
   - Requests for credentials, MFA codes, or payment/banking details
   - Dangerous attachment extensions
2. **Lists red flags found**, each with a plain-English reason.
3. **Explains why the message is unsafe** via a weighted risk score and a
   final verdict + recommended action.
4. Ships a **non-expert checklist** (`docs/red-flag-checklist.md`) and a
   **decision tree** (`docs/decision-tree.md`) so the logic works even without
   running any code.

## Project structure

```
phishing-awareness-analysis/
├── README.md
├── requirements.txt
├── .gitignore
├── data/
│   └── emails/                     # sample messages to analyze
│       ├── legitimate_email.txt
│       ├── phishing_email_1.txt    # PayPal lookalike domain
│       ├── phishing_email_2.txt    # Amazon "you won a prize" scam
│       ├── phishing_email_3.txt    # Fake Microsoft/Office 365 alert
│       ├── phishing_email_4_bec.txt        # CEO wire-transfer / BEC scam
│       └── phishing_email_5_quishing.txt   # QR-code / quishing scam
├── src/
│   └── analyzer.py                 # the detection engine + CLI
├── docs/
│   ├── red-flag-checklist.md       # deliverable: non-expert checklist
│   └── decision-tree.md            # deliverable: triage decision tree
├── reports/                        # generated output lands here
└── tests/
    └── test_analyzer.py            # automated checks (pytest)
```

## Getting started in VS Code

1. Open this folder in VS Code (`File → Open Folder…`).
2. (Optional but recommended) create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate      # Windows: .venv\Scripts\activate
   ```
3. Install the (optional) test dependency:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the analyzer against the sample emails:
   ```bash
   python3 src/analyzer.py
   ```
   This prints a full report to the console and writes
   `reports/analysis_report.md`.

   To also get a machine-readable JSON report:
   ```bash
   python3 src/analyzer.py --json reports/analysis_report.json
   ```

   To analyze your **own** email samples, drop `.txt` files into a folder and
   point the tool at it:
   ```bash
   python3 src/analyzer.py --data-dir path/to/your/emails
   ```

5. Run the test suite:
   ```bash
   python3 -m pytest tests/ -v
   ```

## Sample email format

Each `.txt` file is a plain-text email with headers, e.g.:

```
From: support@paypa1.com
Subject: Urgent Action Required

Dear Customer,

Your account has been suspended. Click the link below immediately to
verify your account.

http://paypa1-security-login.com

Failure to act within 24 hours will result in account termination.

Thank you,
Support Team
```

## Sample findings (from `data/emails/`)

| File | Verdict | Key red flags |
|---|---|---|
| `legitimate_email.txt` | ✅ SAFE | None — sender domain matches the brand it claims to be, HTTPS link, no urgency/credential-harvesting language |
| `phishing_email_1.txt` | 🚨 MALICIOUS | Lookalike domain `paypa1.com`, brand/domain mismatch, HTTP link, urgency language, credential request |
| `phishing_email_2.txt` | 🚨 MALICIOUS | Lookalike domain `amaz0n-gifts.com`, fear/greed bait ("you won a prize"), urgency, request for personal details |
| `phishing_email_3.txt` | 🚨 MALICIOUS | Lookalike domain `micr0soft-support.com`, fake "unusual activity" alert, credential request |
| `phishing_email_4_bec.txt` | 🚨 MALICIOUS | Executive impersonation, request to bypass approval + keep it secret, wire-transfer request |
| `phishing_email_5_quishing.txt` | 🚨 MALICIOUS | Combosquatted domain (`accounts-google-secure.com`), account-lockout urgency, QR-code delivery vector |

Full explanations for every red flag are generated at
`reports/analysis_report.md` after running the tool.

## Why rule-based, not a black box?

The engine is intentionally transparent: every verdict is backed by a list of
named, explainable red flags (see `RedFlag` in `src/analyzer.py`) rather than
an opaque ML score. That mirrors the project's actual goal — **training a
human analyst to recognize the indicators themselves**, not just trusting a
tool's output blindly.

## Extending the project

Ideas from the source training deck worth trying next:
- Add detection for URL shorteners hiding malicious domains behind analytics
  (`bit.ly`, `tinyurl.com`, etc. — partially implemented in `SHORTENER_DOMAINS`).
- Add an SPF/DKIM/DMARC header parser for real `.eml` files.
- Build a small web UI (Flask/FastAPI) around `analyze_email()` so non-technical
  staff can paste a suspicious email and get an instant verdict.
- Expand `KNOWN_BRANDS` with your own organization's most-impersonated brands.

---
*Powered by DecodeLabs · Batch 2026 · Cyber Security Industrial Training Kit*
