# risk_engine.py
"""Combine individual checker results into one verdict."""
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, wait
from urllib.parse import urlparse

from url_analyzer import analyze_url
from domain_checker import check_domain
from ssl_checker import check_ssl
from content_checker import check_content

# Relative importance of each signal (sum to 1.0).
WEIGHTS = {"url": 0.30, "domain": 0.25, "ssl": 0.15, "content": 0.30}
SAFE_BELOW, DANGEROUS_FROM = 30, 60
DEADLINE = 8        # seconds to wait for all network checks together
CACHE_TTL = 3600    # reuse domain/SSL results for a host for 1 hour

_cache = {}


def _host(url):
    if "://" not in url:
        url = "http://" + url
    return urlparse(url).hostname or ""


def _is_local(host):
    """True for localhost and private/loopback IPs, which can't be assessed."""
    if host == "localhost" or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _run(fn, *args):
    try:
        return fn(*args)
    except Exception as e:  # one failing checker must never break a scan
        return {"score": 0, "reasons": [f"{fn.__name__} error: {type(e).__name__}"], "error": True}


def _cached(name, fn, key, *args):
    hit = _cache.get((name, key))
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    res = _run(fn, *args)
    if not res.get("error"):
        _cache[(name, key)] = (time.time(), res)
    return res


def assess(url, deep=True):
    """Run all checkers. deep=False skips network-based checks (fast, offline)."""
    host = _host(url)

    if host and _is_local(host):
        return {"url": url, "host": host, "score": 0, "verdict": "UNKNOWN",
                "reasons": ["Local/private address: not assessed (these cannot be checked from the internet)"],
                "breakdown": {}}

    results = {"url": _run(analyze_url, url)}

    if deep and host:
        # Network checks are independent, so run them at the same time.
        pool = ThreadPoolExecutor(max_workers=3)
        futures = {
            "domain": pool.submit(_cached, "domain", check_domain, host, host),
            "ssl": pool.submit(_cached, "ssl", check_ssl, host, host),
            "content": pool.submit(_run, check_content, url),
        }
        wait(futures.values(), timeout=DEADLINE)
        for name, fut in futures.items():
            if fut.done():
                results[name] = fut.result()
            else:
                results[name] = {"score": 0, "reasons": [f"{name} check timed out"], "error": True}
        pool.shutdown(wait=False, cancel_futures=True)  # don't block on slow lookups

    used = {k: WEIGHTS[k] for k in results if not results[k].get("error")}
    total_w = sum(used.values()) or 1
    score = sum(results[k]["score"] * w for k, w in used.items()) / total_w

    # A single very strong signal should not be diluted by clean ones.
    strongest = max((r["score"] for r in results.values()), default=0)
    if strongest >= 80:
        score = max(score, 0.8 * strongest)

    score = int(round(min(score, 100)))
    verdict = "SAFE" if score < SAFE_BELOW else "DANGEROUS" if score >= DANGEROUS_FROM else "SUSPICIOUS"
    reasons = [f"[{k}] {r}" for k, res in results.items() for r in res["reasons"]]
    return {
        "url": url, "host": host, "score": score, "verdict": verdict,
        "reasons": reasons,
        "breakdown": {k: v["score"] for k, v in results.items()},
    }
