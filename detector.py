import re
import whois
import tldextract
from datetime import datetime, timezone
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "password", "confirm", "urgent", "payment", "suspended",
    "reset", "signin", "security", "wallet", "invoice"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
]

def is_url(text):
    parsed = urlparse(text)
    return bool(parsed.scheme and parsed.netloc)

def extract_registered_domain(url):
    # Use /tmp cache dir so it works on Vercel's read-only file system
    ext = tldextract.TLDExtract(cache_dir='/tmp/tldextract')
    extracted = ext(url)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return None

def get_domain_age_info(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return None, "WHOIS did not return a creation date."

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        return age_days, None

    except Exception as e:
        return None, f"WHOIS lookup failed: {str(e)}"

def analyze_input(user_input):
    text = user_input.strip()
    lowered = text.lower()

    score = 0
    reasons = []
    domain_info = None

    if is_url(text):
        parsed = urlparse(text)
        domain = parsed.netloc.lower()

        registered_domain = extract_registered_domain(text)
        domain_info = registered_domain

        if any(shortener in domain for shortener in SHORTENERS):
            score += 25
            reasons.append("Uses a shortened URL service, which can hide the real destination.")

        if "@" in text:
            score += 20
            reasons.append("Contains '@' in the URL, which can obscure the actual target.")

        if len(text) > 75:
            score += 15
            reasons.append("URL is unusually long, which is a common phishing trait.")

        if text.count("//") > 1:
            score += 15
            reasons.append("Contains extra '//' patterns that may indicate redirection tricks.")

        if "-" in domain:
            score += 10
            reasons.append("Domain contains hyphens, sometimes used in spoofed domains.")

        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
        if matched_keywords:
            score += min(len(matched_keywords) * 8, 24)
            reasons.append(f"Suspicious keywords detected: {', '.join(matched_keywords)}.")

        if re.search(r"\d{2,}", domain):
            score += 10
            reasons.append("Domain contains multiple digits, which can be suspicious.")

        if registered_domain:
            age_days, whois_error = get_domain_age_info(registered_domain)

            if age_days is not None:
                if age_days < 30:
                    score += 30
                    reasons.append(f"Domain is very new ({age_days} days old), which is a strong phishing signal.")
                elif age_days < 180:
                    score += 20
                    reasons.append(f"Domain is relatively new ({age_days} days old).")
                elif age_days < 365:
                    score += 10
                    reasons.append(f"Domain is less than a year old ({age_days} days old).")
                else:
                    reasons.append(f"Domain age looks more established ({age_days} days old).")
            else:
                reasons.append(f"Could not verify domain age. {whois_error}")

    else:
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
        if matched_keywords:
            score += min(len(matched_keywords) * 8, 32)
            reasons.append(f"Suspicious keywords found in message content: {', '.join(matched_keywords)}.")

        if re.search(r"http[s]?://", lowered):
            score += 10
            reasons.append("Message contains a link, so it should be inspected carefully.")

        if "urgent" in lowered or "immediately" in lowered:
            score += 10
            reasons.append("Urgency language detected, which is common in phishing emails.")

        if "click here" in lowered:
            score += 10
            reasons.append("Contains 'click here', a common phishing call-to-action.")

    score = min(score, 100)

    if score >= 70:
        verdict = "High Risk"
    elif score >= 40:
        verdict = "Medium Risk"
    else:
        verdict = "Low Risk"

    if not reasons:
        reasons.append("No major phishing indicators were detected by the current rule set.")

    return {
        "input": user_input,
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "domain_info": domain_info
    }