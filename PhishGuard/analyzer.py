import ipaddress
import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@([^@\s]+)$")

KEYWORD_GROUPS = {
    "Urgency or pressure": {
        "weight": 12,
        "words": ["urgent", "immediately", "act now", "within 24 hours", "final warning", "expires today", "as soon as possible"],
        "explanation": "Urgency can pressure a recipient into acting before checking the message.",
    },
    "Account or credential request": {
        "weight": 18,
        "words": ["verify your account", "confirm your password", "login now", "sign in now", "update your credentials", "account suspended", "account locked"],
        "explanation": "Phishing messages often attempt to steal login credentials through a false verification request.",
    },
    "Money or payment request": {
        "weight": 16,
        "words": ["bank transfer", "wire transfer", "payment required", "unpaid invoice", "refund pending", "gift card", "crypto payment"],
        "explanation": "Unexpected financial instructions may be an attempt to steal money or payment information.",
    },
    "Reward or fear tactic": {
        "weight": 12,
        "words": ["you have won", "claim your prize", "lottery winner", "legal action", "security alert", "unusual activity", "unauthorized access"],
        "explanation": "Attackers commonly use fear or rewards to trigger an emotional response.",
    },
    "Sensitive information request": {
        "weight": 20,
        "words": ["credit card number", "one-time password", "otp", "security code", "social security", "bank details", "date of birth"],
        "explanation": "Legitimate organizations rarely request sensitive secrets through an unsolicited message.",
    },
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
RISKY_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "support", "country", "gq", "tk"}
BRAND_LOOKALIKES = ("paypa1", "micros0ft", "g00gle", "arnazon", "netf1ix", "faceb00k")


def add_flag(flags, category, evidence, explanation, weight):
    flags.append({
        "category": category,
        "evidence": evidence,
        "explanation": explanation,
        "weight": weight,
    })


def inspect_url(raw_url, flags):
    cleaned = raw_url.rstrip(".,);!?]")
    parsed = urlparse(cleaned if "://" in cleaned else f"http://{cleaned}")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return

    if parsed.scheme == "http":
        add_flag(flags, "Unencrypted link", cleaned, "The link uses HTTP instead of encrypted HTTPS.", 8)

    try:
        ipaddress.ip_address(hostname)
        add_flag(flags, "IP address used as website", hostname, "Legitimate services normally use a recognizable domain name, not a raw IP address.", 18)
    except ValueError:
        pass

    if hostname in SHORTENERS:
        add_flag(flags, "Shortened URL", cleaned, "A shortened link hides the final destination from the recipient.", 15)
    if "@" in parsed.netloc:
        add_flag(flags, "Misleading @ symbol in URL", cleaned, "Text before @ can mislead users while the browser visits the host after it.", 20)
    if hostname.startswith("xn--") or ".xn--" in hostname:
        add_flag(flags, "Punycode domain", hostname, "Punycode can be used for domains that visually imitate trusted names.", 18)
    if hostname.split(".")[-1] in RISKY_TLDS:
        add_flag(flags, "Higher-risk top-level domain", hostname, "This domain ending is commonly abused and deserves additional verification.", 8)
    if hostname.count(".") >= 3:
        add_flag(flags, "Excessive subdomains", hostname, "Many subdomains can make an attacker-controlled domain look legitimate.", 8)
    if hostname.count("-") >= 2:
        add_flag(flags, "Hyphen-heavy domain", hostname, "Multiple hyphens can be used to imitate an official service domain.", 7)
    if any(lookalike in hostname for lookalike in BRAND_LOOKALIKES):
        add_flag(flags, "Possible brand impersonation", hostname, "The domain contains a misspelled form of a well-known brand.", 22)


def analyze_message(sender, subject, message):
    sender = str(sender).strip()
    subject = str(subject).strip()
    message = str(message).strip()
    if not message:
        raise ValueError("Please paste an email or message to analyze.")
    if len(message) > 15000:
        raise ValueError("The message must contain 15,000 characters or fewer.")

    flags = []
    combined = f"{subject}\n{message}".lower()

    for category, rule in KEYWORD_GROUPS.items():
        matches = [word for word in rule["words"] if word in combined]
        if matches:
            add_flag(flags, category, ", ".join(matches[:4]), rule["explanation"], rule["weight"])

    urls = URL_PATTERN.findall(message)
    for url in urls[:20]:
        inspect_url(url, flags)
    if len(urls) > 3:
        add_flag(flags, "Many links", f"{len(urls)} links detected", "An unusually high number of links can increase the chance of a malicious destination.", 8)

    if re.search(r"(?i)\b(dear (customer|user|member)|valued customer|hello user)\b", combined):
        add_flag(flags, "Generic greeting", "Generic recipient name", "A generic greeting may indicate a message sent broadly rather than by an organization that knows you.", 6)
    if re.search(r"(?i)\b(enable content|enable macros|download attachment|open the attached|install this app)\b", combined):
        add_flag(flags, "Risky attachment instruction", "Attachment or software instruction", "Unexpected files, macros, or software can deliver malware.", 18)
    if combined.count("!") >= 3 or re.search(r"\b[A-Z]{8,}\b", f"{subject} {message}"):
        add_flag(flags, "Aggressive formatting", "Repeated exclamation marks or long capitalized words", "Aggressive formatting is often used to create pressure or fear.", 5)

    email_match = EMAIL_PATTERN.match(sender)
    if sender and not email_match:
        add_flag(flags, "Unusual sender format", sender, "The sender is not written as a normal email address.", 7)
    elif email_match:
        domain = email_match.group(1).lower()
        if domain.startswith("xn--") or any(word in domain for word in BRAND_LOOKALIKES):
            add_flag(flags, "Suspicious sender domain", domain, "The sender domain may be attempting to imitate a trusted organization.", 20)

    score = min(100, sum(flag["weight"] for flag in flags))
    if score >= 60:
        level, verdict = "High", "Likely phishing - do not click links, reply, download files, or provide information."
    elif score >= 30:
        level, verdict = "Medium", "Suspicious - verify the request through an official website or trusted contact method."
    else:
        level, verdict = "Low", "Few obvious indicators found, but this does not prove the message is safe."

    return {
        "score": score,
        "level": level,
        "verdict": verdict,
        "flags": flags,
        "links": [url.rstrip(".,);!?]") for url in urls[:20]],
        "safe_actions": [
            "Do not click links or open unexpected attachments.",
            "Visit the organization using a saved bookmark or type its official address yourself.",
            "Contact the sender using a trusted phone number or separate communication channel.",
            "Report suspicious messages to your organization or email provider.",
        ],
    }
