"""
Phishing Awareness Analysis Engine
-----------------------------------
DecodeLabs | Cyber Security Project 3

A rule-based (non-ML) triage engine that inspects a raw email (From, Subject,
Body) and flags common social-engineering / phishing indicators:

  - Sender / display-name domain mismatches
  - Lookalike domains (typosquatting, leetspeak / homoglyph-style substitution,
    combosquatting, nested "subdomain trap" abuse)
  - Suspicious links (raw IPs, non-HTTPS, shortened URLs, domain != brand claimed)
  - Cognitive-trigger language: urgency, authority, fear/greed, curiosity
  - Requests to bypass process, keep secrets, or hand over credentials/MFA/payment info
  - Dangerous attachment extensions

Each email is scored and classified into one of three triage buckets that
mirror the deck's decision tree:

    SAFE        -> Close
    SUSPICIOUS  -> Warn User
    MALICIOUS   -> Block Domain & Escalate

This is intentionally a transparent, explainable rule engine (not a black-box
classifier) so it doubles as a *training tool*: every flag raised includes a
human-readable reason, which is exactly what a junior SOC analyst needs to
learn to spot on their own.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #

# Well-known brands frequently impersonated, mapped to their legitimate root
# domain(s). Used to catch typosquatting / combosquatting / leetspeak lookalikes.
KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com"],
    "google": ["google.com", "gmail.com", "accounts.google.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "office365": ["office.com", "microsoft.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "bankofamerica": ["bankofamerica.com"],
}

# Leetspeak / homoglyph-style character substitutions attackers use to
# disguise a brand name while still looking legible to the human eye.
LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})

URGENCY_WORDS = [
    "urgent", "immediately", "immediate action", "act now", "act within",
    "expires", "expire", "24 hours", "12 hours", "30 minutes", "final notice",
    "last chance", "right away", "as soon as possible", "asap", "deadline",
    "suspend", "suspended", "terminate", "termination", "locked", "lockout",
    "lock in", "disabled", "disable",
]

FEAR_GREED_WORDS = [
    "won", "winner", "congratulations", "free", "prize", "reward", "claim",
    "gift", "selected", "unauthorized", "unusual activity", "compromised",
    "penalty", "legal action", "fraud alert",
]

AUTHORITY_WORDS = [
    "ceo", "cfo", "director", "hr department", "human resources", "it security",
    "it support", "law enforcement", "government", "compliance team",
    "executive", "confidential", "strictly confidential",
]

BYPASS_SECRECY_WORDS = [
    "do not discuss", "keep this confidential", "bypass", "do not tell",
    "don't tell anyone", "just this once", "skip the approval",
    "without informing", "no one else needs to know",
]

CREDENTIAL_REQUEST_WORDS = [
    "verify your account", "confirm your password", "enter your password",
    "provide your personal details", "confirm your information",
    "mfa code", "authentication code", "one-time code", "billing information",
    "update your payment", "wire transfer", "bank details", "account number",
    "social security", "ssn", "routing number",
]

DANGEROUS_EXTENSIONS = [".exe", ".scr", ".js", ".iso", ".vbs", ".bat", ".cmd", ".hta", ".jar"]

URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\")\]]+", re.IGNORECASE)
IP_URL_REGEX = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
FROM_HEADER_REGEX = re.compile(r"^From:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
SUBJECT_HEADER_REGEX = re.compile(r"^Subject:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
DISPLAY_NAME_EMAIL_REGEX = re.compile(r"^(?P<display>[^<]*)<(?P<email>[^>]+)>\s*$")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class RedFlag:
    code: str
    severity: str  # "low" | "medium" | "high"
    message: str


@dataclass
class AnalysisResult:
    filename: str
    sender_display_name: str
    sender_email: str
    subject: str
    urls: List[str] = field(default_factory=list)
    red_flags: List[RedFlag] = field(default_factory=list)
    score: int = 0
    verdict: str = "SAFE"
    action: str = "Close"

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "sender_display_name": self.sender_display_name,
            "sender_email": self.sender_email,
            "subject": self.subject,
            "urls": self.urls,
            "red_flags": [rf.__dict__ for rf in self.red_flags],
            "score": self.score,
            "verdict": self.verdict,
            "action": self.action,
        }


SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #

def _extract_domain(email_or_url: str) -> str:
    if "@" in email_or_url:
        return email_or_url.strip().split("@")[-1].strip().lower()
    parsed = urlparse(email_or_url if "//" in email_or_url else f"//{email_or_url}")
    return (parsed.hostname or "").lower()


def _normalize_leet(text: str) -> str:
    return text.lower().translate(LEET_MAP)


def _root_domain_from_nested(hostname: str) -> str:
    """
    Reads a hostname 'right to left' the way the deck instructs, to expose a
    'subdomain trap' such as www.decodelabs.tech.login-update.com, whose true
    root domain is login-update.com, not decodelabs.tech.
    """
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname
    return ".".join(labels[-2:])


def _find_brand_mentions(text: str) -> List[str]:
    normalized = _normalize_leet(text)
    hits = []
    for brand in KNOWN_BRANDS:
        if brand in normalized:
            hits.append(brand)
    return hits


# --------------------------------------------------------------------------- #
# Core analysis
# --------------------------------------------------------------------------- #

def analyze_email(raw_text: str, filename: str = "email.txt") -> AnalysisResult:
    from_match = FROM_HEADER_REGEX.search(raw_text)
    subject_match = SUBJECT_HEADER_REGEX.search(raw_text)

    from_header = from_match.group(1).strip() if from_match else ""
    subject = subject_match.group(1).strip() if subject_match else ""

    display_name, sender_email = "", ""
    dn_match = DISPLAY_NAME_EMAIL_REGEX.match(from_header)
    if dn_match:
        display_name = dn_match.group("display").strip()
        sender_email = dn_match.group("email").strip().lower()
    elif "@" in from_header:
        sender_email = from_header.strip().lower()
    else:
        sender_email = from_header.strip().lower()

    sender_domain = _extract_domain(sender_email) if sender_email else ""

    body = raw_text
    urls = URL_REGEX.findall(raw_text)

    result = AnalysisResult(
        filename=filename,
        sender_display_name=display_name,
        sender_email=sender_email,
        subject=subject,
        urls=urls,
    )

    body_lower = body.lower()
    subject_lower = subject.lower()
    full_text_lower = f"{subject_lower} {body_lower} {display_name.lower()}"

    # -- 1. Brand impersonation vs. sender domain -------------------------- #
    brand_mentions = set(_find_brand_mentions(full_text_lower))
    for brand in brand_mentions:
        legit_domains = KNOWN_BRANDS[brand]
        if sender_domain and not any(
            sender_domain == d or sender_domain.endswith("." + d) for d in legit_domains
        ):
            result.red_flags.append(RedFlag(
                code="BRAND_DOMAIN_MISMATCH",
                severity="high",
                message=(
                    f"Message references brand '{brand}' but sender domain "
                    f"'{sender_domain}' does not match any official domain "
                    f"({', '.join(legit_domains)})."
                ),
            ))

    # -- 2. Lookalike / typosquatted sender domain -------------------------- #
    if sender_domain:
        normalized_sender = _normalize_leet(sender_domain)
        for brand, legit_domains in KNOWN_BRANDS.items():
            for legit in legit_domains:
                legit_root = legit.split(".")[0]
                if brand in normalized_sender and sender_domain not in legit_domains:
                    # e.g. paypa1.com -> normalizes to paypal.com-ish but isn't paypal.com
                    if legit_root in normalized_sender and sender_domain != legit:
                        result.red_flags.append(RedFlag(
                            code="LOOKALIKE_DOMAIN",
                            severity="high",
                            message=(
                                f"Sender domain '{sender_domain}' looks like a disguised "
                                f"version of '{legit}' (character substitution / typosquat)."
                            ),
                        ))
                        break

    # -- 3. Combosquatting: brand + security-ish words in the sender domain - #
    combosquat_words = ["secure", "login", "verify", "update", "support", "account", "security", "reward", "gifts"]
    if sender_domain:
        for brand in KNOWN_BRANDS:
            if brand in sender_domain.replace("-", "") and any(w in sender_domain for w in combosquat_words):
                if sender_domain not in KNOWN_BRANDS[brand]:
                    result.red_flags.append(RedFlag(
                        code="COMBOSQUAT_DOMAIN",
                        severity="high",
                        message=(
                            f"Sender domain '{sender_domain}' pads a legitimate brand name "
                            "with security-related words to appear trustworthy."
                        ),
                    ))

    # -- 4. Nested subdomain trap in any links ------------------------------ #
    for url in urls:
        hostname = _extract_domain(url)
        labels = hostname.split(".")
        if len(labels) > 2:
            root = _root_domain_from_nested(hostname)
            for brand, legit_domains in KNOWN_BRANDS.items():
                if brand in hostname and root not in legit_domains:
                    result.red_flags.append(RedFlag(
                        code="SUBDOMAIN_TRAP",
                        severity="high",
                        message=(
                            f"URL '{url}' buries brand '{brand}' in a subdomain, but the "
                            f"true root domain is '{root}', which is not an official domain."
                        ),
                    ))

    # -- 5. Risky URL structure --------------------------------------------- #
    for url in urls:
        hostname = _extract_domain(url)
        if IP_URL_REGEX.match(url):
            result.red_flags.append(RedFlag(
                code="RAW_IP_URL",
                severity="high",
                message=f"Link '{url}' points to a raw IP address instead of a domain name.",
            ))
        if url.lower().startswith("http://"):
            result.red_flags.append(RedFlag(
                code="NON_HTTPS_URL",
                severity="medium",
                message=f"Link '{url}' uses unencrypted HTTP instead of HTTPS.",
            ))
        if hostname in SHORTENER_DOMAINS:
            result.red_flags.append(RedFlag(
                code="SHORTENED_URL",
                severity="medium",
                message=f"Link '{url}' uses a URL shortener, which can hide the true destination.",
            ))

    # -- 6. Cognitive triggers ----------------------------------------------- #
    def _find_hits(word_list):
        return [w for w in word_list if w in full_text_lower]

    urgency_hits = _find_hits(URGENCY_WORDS)
    if urgency_hits:
        result.red_flags.append(RedFlag(
            code="URGENCY_LANGUAGE",
            severity="medium",
            message=f"Artificial time-pressure language detected: {', '.join(sorted(set(urgency_hits)))}.",
        ))

    fear_greed_hits = _find_hits(FEAR_GREED_WORDS)
    if fear_greed_hits:
        result.red_flags.append(RedFlag(
            code="FEAR_OR_GREED_LANGUAGE",
            severity="medium",
            message=f"Fear/greed trigger words detected: {', '.join(sorted(set(fear_greed_hits)))}.",
        ))

    authority_hits = _find_hits(AUTHORITY_WORDS)
    if authority_hits:
        result.red_flags.append(RedFlag(
            code="AUTHORITY_IMPERSONATION",
            severity="low",
            message=f"Message invokes authority/executive figures: {', '.join(sorted(set(authority_hits)))}.",
        ))

    bypass_hits = _find_hits(BYPASS_SECRECY_WORDS)
    if bypass_hits:
        result.red_flags.append(RedFlag(
            code="BYPASS_OR_SECRECY_REQUEST",
            severity="high",
            message=f"Message asks the recipient to bypass process or keep the request secret: {', '.join(sorted(set(bypass_hits)))}.",
        ))

    cred_hits = _find_hits(CREDENTIAL_REQUEST_WORDS)
    if cred_hits:
        result.red_flags.append(RedFlag(
            code="CREDENTIAL_OR_PAYMENT_REQUEST",
            severity="high",
            message=f"Message requests credentials, MFA codes, or payment/banking details: {', '.join(sorted(set(cred_hits)))}.",
        ))

    # -- 7. Dangerous attachment extensions mentioned in text ---------------- #
    for ext in DANGEROUS_EXTENSIONS:
        if ext in body_lower:
            result.red_flags.append(RedFlag(
                code="DANGEROUS_ATTACHMENT",
                severity="high",
                message=f"Message references an attachment with a high-risk extension '{ext}'.",
            ))

    # -- 8. Generic display-name mismatch (any CEO/staff name vs public mail) #
    if display_name and sender_email:
        free_mail_providers = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}
        if sender_domain in free_mail_providers and any(
            title in display_name.lower() for title in ["ceo", "cfo", "director", "support", "security", "it "]
        ):
            result.red_flags.append(RedFlag(
                code="DISPLAY_NAME_SPOOF",
                severity="high",
                message=(
                    f"Display name '{display_name}' implies a corporate role, but the "
                    f"underlying address uses a free public mail provider ({sender_domain})."
                ),
            ))

    # -- Scoring & verdict ---------------------------------------------------- #
    result.score = sum(SEVERITY_WEIGHT[rf.severity] for rf in result.red_flags)

    if result.score == 0:
        result.verdict = "SAFE"
        result.action = "Close"
    elif result.score <= 3:
        result.verdict = "SUSPICIOUS"
        result.action = "Warn User"
    else:
        result.verdict = "MALICIOUS"
        result.action = "Block Domain & Escalate"

    return result


def analyze_file(path: Path) -> AnalysisResult:
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    return analyze_email(raw_text, filename=path.name)


def analyze_directory(directory: Path) -> List[AnalysisResult]:
    results = []
    for path in sorted(directory.glob("*.txt")):
        results.append(analyze_file(path))
    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _print_console_report(results: List[AnalysisResult]) -> None:
    verdict_icon = {"SAFE": "✅", "SUSPICIOUS": "⚠️ ", "MALICIOUS": "🚨"}
    for r in results:
        print("=" * 78)
        print(f"FILE: {r.filename}")
        print(f"From: {r.sender_display_name} <{r.sender_email}>" if r.sender_display_name else f"From: {r.sender_email}")
        print(f"Subject: {r.subject}")
        print(f"URLs found: {r.urls if r.urls else 'None'}")
        print(f"Risk score: {r.score}")
        print(f"Verdict: {verdict_icon.get(r.verdict, '')} {r.verdict}  ->  Action: {r.action}")
        if r.red_flags:
            print("Red flags:")
            for rf in r.red_flags:
                print(f"  - [{rf.severity.upper():6}] {rf.code}: {rf.message}")
        else:
            print("Red flags: None detected.")
    print("=" * 78)


def _write_markdown_report(results: List[AnalysisResult], out_path: Path) -> None:
    lines = ["# Phishing Triage Report", ""]
    lines.append("| File | Sender | Verdict | Score | Action |")
    lines.append("|---|---|---|---|---|")
    for r in results:
        lines.append(f"| {r.filename} | {r.sender_email} | {r.verdict} | {r.score} | {r.action} |")
    lines.append("")

    for r in results:
        lines.append(f"## {r.filename}")
        lines.append(f"- **From:** {r.sender_display_name} <{r.sender_email}>" if r.sender_display_name else f"- **From:** {r.sender_email}")
        lines.append(f"- **Subject:** {r.subject}")
        lines.append(f"- **URLs:** {', '.join(r.urls) if r.urls else 'None'}")
        lines.append(f"- **Verdict:** {r.verdict} (score {r.score}) → **{r.action}**")
        if r.red_flags:
            lines.append("- **Red flags:**")
            for rf in r.red_flags:
                lines.append(f"  - `[{rf.severity}]` **{rf.code}** — {rf.message}")
        else:
            lines.append("- **Red flags:** None detected.")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Phishing Awareness Analysis Engine")
    parser.add_argument(
        "--data-dir", type=Path, default=Path(__file__).resolve().parent.parent / "data" / "emails",
        help="Directory containing .txt email samples (default: data/emails)",
    )
    parser.add_argument(
        "--report", type=Path, default=Path(__file__).resolve().parent.parent / "reports" / "analysis_report.md",
        help="Path to write the Markdown report",
    )
    parser.add_argument(
        "--json", type=Path, default=None,
        help="Optional path to also write a JSON report",
    )
    args = parser.parse_args()

    results = analyze_directory(args.data_dir)
    if not results:
        print(f"No .txt email files found in {args.data_dir}")
        return

    _print_console_report(results)

    args.report.parent.mkdir(parents=True, exist_ok=True)
    _write_markdown_report(results, args.report)
    print(f"\nMarkdown report written to: {args.report}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps([r.to_dict() for r in results], indent=2), encoding="utf-8"
        )
        print(f"JSON report written to: {args.json}")


if __name__ == "__main__":
    main()
