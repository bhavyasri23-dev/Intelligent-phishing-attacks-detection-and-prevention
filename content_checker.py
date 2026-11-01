# content_checker.py
"""Fetch the page and look for phishing traits in its HTML."""
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from url_analyzer import BRANDS, split_host

URGENCY = ["urgent", "immediately", "suspended", "verify your account", "unusual activity",
           "confirm your identity", "limited time", "account will be closed", "security alert",
           "within 24 hours", "unauthorized"]


def _is_public(host):
    """SSRF guard: refuse to fetch private/loopback/link-local targets."""
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except (socket.gaierror, ValueError):
        return False


def check_content(url, timeout=6):
    """Return {'score': int, 'reasons': [str]}."""
    score, reasons = 0, []

    def hit(points, why):
        nonlocal score
        score += points
        reasons.append(why)

    if not re.match(r"^https?://", url):
        url = "http://" + url
    host = urlparse(url).hostname or ""
    if not _is_public(host):
        return {"score": 10, "reasons": ["Host did not resolve to a public address; page not fetched"]}

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, stream=True,
                            headers={"User-Agent": "PhishGuard/1.0 (security scanner)"})
        html = resp.raw.read(1_000_000, decode_content=True).decode(resp.encoding or "utf-8", "ignore")
    except requests.RequestException:
        return {"score": 10, "reasons": ["Page could not be fetched"]}

    if len(resp.history) >= 3:
        hit(10, f"Redirect chain of {len(resp.history)} hops")
    final_host = urlparse(resp.url).hostname or host
    if split_host(final_host)[1] != split_host(host)[1]:
        hit(15, f"Redirects to a different domain: {final_host}")

    soup = BeautifulSoup(html, "html.parser")
    page_reg = split_host(final_host)[1]
    text = soup.get_text(" ", strip=True).lower()

    pw = soup.find_all("input", {"type": "password"})
    if pw:
        hit(10, "Page asks for a password")
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            target = urlparse(urljoin(resp.url, action))
            if target.hostname and split_host(target.hostname)[1] != page_reg:
                hit(30, f"Form submits to a different domain ({target.hostname})")
                break
            if pw and target.scheme == "http":
                hit(20, "Credential form posts over plain HTTP")
                break
        elif pw and not action:
            pass

    title = (soup.title.string or "").lower() if soup.title and soup.title.string else ""
    for brand, legit in BRANDS.items():
        if page_reg not in legit and (brand in title or text.count(brand) >= 3):
            hit(25, f"Page presents itself as '{brand}' but is hosted on {page_reg}")
            break

    urgent = [u for u in URGENCY if u in text]
    if urgent:
        hit(min(5 * len(urgent), 15), "Urgency/pressure language: " + ", ".join(urgent[:3]))

    if soup.find("iframe", style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)) or \
            soup.find("iframe", attrs={"width": "0"}):
        hit(15, "Hidden iframe")
    if re.search(r"oncontextmenu\s*=\s*[\"']?return false|event\.button\s*==\s*2", html, re.I):
        hit(10, "Right-click disabled (hides page source)")
    # atob()/fromCharCode alone are common in legitimate sites; require stronger evidence.
    if re.search(r"eval\(\s*unescape|eval\(\s*atob|document\.write\(\s*unescape|(?:\\x[0-9a-f]{2}){20,}", html, re.I):
        hit(10, "Obfuscated JavaScript")
    ext = [a for a in soup.find_all("a", href=True)
           if urlparse(a["href"]).hostname and split_host(urlparse(a["href"]).hostname)[1] != page_reg]
    links = soup.find_all("a", href=True)
    if links and len(ext) / len(links) > 0.8 and len(links) > 5:
        hit(5, "Almost all links point to other domains")
    if links and sum(1 for a in links if a["href"] in ("#", "", "javascript:void(0)")) / len(links) > 0.5:
        hit(5, "Most links are dead ('#') placeholders")

    return {"score": min(score, 100), "reasons": reasons}
