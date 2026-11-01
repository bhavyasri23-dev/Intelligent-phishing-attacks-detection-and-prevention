# url_analyzer.py
"""Lexical / structural analysis of a URL. No network access needed."""
import ipaddress
import re
from urllib.parse import urlparse, unquote

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "support", "rest", "icu"}
KEYWORDS = {"login", "signin", "verify", "update", "secure", "account", "banking", "confirm",
            "password", "wallet", "suspend", "unlock", "billing", "invoice", "recover"}
# brand -> legitimate registered domains
BRANDS = {
    "paypal": {"paypal.com"}, "google": {"google.com"}, "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"}, "amazon": {"amazon.com", "amazon.in"},
    "facebook": {"facebook.com"}, "instagram": {"instagram.com"}, "netflix": {"netflix.com"},
    "sbi": {"sbi.co.in", "onlinesbi.com"}, "hdfcbank": {"hdfcbank.com"}, "icici": {"icicibank.com"},
    "paytm": {"paytm.com"}, "phonepe": {"phonepe.com"}, "dropbox": {"dropbox.com"}, "linkedin": {"linkedin.com"},
}
_TWO_PART_TLDS = {"co.in", "co.uk", "com.au", "co.jp", "com.br", "org.in", "net.in", "gov.in", "ac.in"}


def split_host(host):
    """Return (subdomain, registered_domain). Heuristic, avoids extra deps."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return "", ".".join(parts)
    n = 3 if ".".join(parts[-2:]) in _TWO_PART_TLDS else 2
    return ".".join(parts[:-n]), ".".join(parts[-n:])


def _edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalize_leet(s):
    return s.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s").replace("rn", "m").replace("vv", "w")


def analyze_url(url):
    """Return {'score': int, 'reasons': [str]}."""
    score, reasons = 0, []

    def hit(points, why):
        nonlocal score
        score += points
        reasons.append(why)

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    full = unquote(url)

    if not host:
        return {"score": 50, "reasons": ["URL has no valid hostname"]}

    if len(url) > 75:
        hit(10, "Unusually long URL")
    if "@" in p.netloc:
        hit(25, "Contains '@' in the authority (hides the real destination)")
    if p.scheme != "https":
        hit(10, "Not using HTTPS")
    if p.port and p.port not in (80, 443):
        hit(10, f"Non-standard port {p.port}")

    try:
        ipaddress.ip_address(host)
        hit(30, "Host is a raw IP address")
        return {"score": min(score, 100), "reasons": reasons}
    except ValueError:
        pass

    sub, reg = split_host(host)
    tld = reg.rsplit(".", 1)[-1]

    if host in SHORTENERS or reg in SHORTENERS:
        hit(20, "URL shortener hides the final destination")
    if "xn--" in host:
        hit(25, "Punycode (possible homograph/lookalike characters)")
    if tld in SUSPICIOUS_TLDS:
        hit(15, f"Suspicious TLD .{tld}")
    if reg.count("-") >= 2 or (reg.count("-") == 1 and any(k in reg for k in KEYWORDS)):
        hit(10, "Hyphens in the registered domain")
    depth = len(sub.split(".")) if sub else 0
    if depth >= 3:
        hit(15, f"Deep subdomain nesting ({depth} levels)")
    if sum(c.isdigit() for c in reg) >= 4:
        hit(10, "Many digits in domain name")

    found = [k for k in KEYWORDS if k in full.lower()]
    if len(found) >= 2:
        hit(15, "Multiple phishing-style keywords: " + ", ".join(sorted(found)[:4]))
    elif found:
        hit(5, f"Phishing-style keyword: {found[0]}")

    # Brand impersonation
    label = reg.split(".")[0]
    for brand, legit in BRANDS.items():
        if reg in legit:
            break
        if brand in host.replace("-", ""):
            hit(30, f"Mentions '{brand}' but registered domain is {reg}")
            break
        norm = _normalize_leet(label)
        if label != brand and (_edit_distance(norm, brand) <= 1 and len(brand) >= 5 or brand in norm):
            hit(30, f"Domain '{reg}' looks like a lookalike of '{brand}'")
            break

    if re.search(r"(https?://|//)", p.path + "?" + p.query):
        hit(10, "Another URL embedded in path/query (redirect trick)")
    if "%" in p.path and len(re.findall(r"%[0-9a-fA-F]{2}", p.path)) > 5:
        hit(10, "Heavy percent-encoding in path")

    return {"score": min(score, 100), "reasons": reasons}
