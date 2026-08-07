import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from analyzer import analyze_email, analyze_file  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "emails"


def test_legitimate_email_is_safe():
    result = analyze_file(DATA_DIR / "legitimate_email.txt")
    assert result.verdict == "SAFE"
    assert result.action == "Close"
    assert result.score == 0


def test_paypal_lookalike_is_malicious():
    result = analyze_file(DATA_DIR / "phishing_email_1.txt")
    assert result.verdict == "MALICIOUS"
    flag_codes = {rf.code for rf in result.red_flags}
    assert "LOOKALIKE_DOMAIN" in flag_codes
    assert "BRAND_DOMAIN_MISMATCH" in flag_codes
    assert "URGENCY_LANGUAGE" in flag_codes


def test_amazon_prize_scam_is_malicious():
    result = analyze_file(DATA_DIR / "phishing_email_2.txt")
    assert result.verdict == "MALICIOUS"
    flag_codes = {rf.code for rf in result.red_flags}
    assert "FEAR_OR_GREED_LANGUAGE" in flag_codes


def test_microsoft_support_scam_is_malicious():
    result = analyze_file(DATA_DIR / "phishing_email_3.txt")
    assert result.verdict == "MALICIOUS"
    flag_codes = {rf.code for rf in result.red_flags}
    assert "CREDENTIAL_OR_PAYMENT_REQUEST" in flag_codes


def test_bec_wire_transfer_flags_bypass_and_secrecy():
    result = analyze_file(DATA_DIR / "phishing_email_4_bec.txt")
    flag_codes = {rf.code for rf in result.red_flags}
    assert "BYPASS_OR_SECRECY_REQUEST" in flag_codes
    assert result.verdict in ("SUSPICIOUS", "MALICIOUS")


def test_quishing_email_flags_combosquat_domain():
    result = analyze_file(DATA_DIR / "phishing_email_5_quishing.txt")
    flag_codes = {rf.code for rf in result.red_flags}
    assert "COMBOSQUAT_DOMAIN" in flag_codes


def test_display_name_spoof_detected():
    raw = (
        "From: IT Security <it.help@gmail.com>\n"
        "Subject: Password expires in 24 hrs\n\n"
        "Please verify your account immediately."
    )
    result = analyze_email(raw, filename="synthetic.txt")
    flag_codes = {rf.code for rf in result.red_flags}
    assert "DISPLAY_NAME_SPOOF" in flag_codes


def test_raw_ip_url_flagged():
    raw = (
        "From: alerts@example.com\n"
        "Subject: Security check\n\n"
        "Click here: http://192.168.1.5/login"
    )
    result = analyze_email(raw, filename="synthetic_ip.txt")
    flag_codes = {rf.code for rf in result.red_flags}
    assert "RAW_IP_URL" in flag_codes
