# domain_checker.py
"""Domain age / registration checks via RDAP (WHOIS as backup)."""
from datetime import date, datetime, timezone

import requests
import whois

from url_analyzer import split_host


def _to_dt(value):
    """Coerce a WHOIS/RDAP date (datetime, date, or string) to a naive UTC datetime, or None."""
    if isinstance(value, str):
        value = value.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d"):
            try:
                value = datetime.strptime(value[:len(datetime.now().strftime(fmt))], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    return None


def _pick(value, earliest=True):
    """Lookups often return a list of dates; normalise and pick one."""
    items = value if isinstance(value, (list, tuple)) else [value]
    dts = [d for d in (_to_dt(v) for v in items) if d]
    if not dts:
        return None
    return min(dts) if earliest else max(dts)


def _rdap(reg):
    """Modern JSON replacement for WHOIS. Fast and needs no parsing library."""
    r = requests.get(f"https://rdap.org/domain/{reg}", timeout=5,
                     headers={"Accept": "application/rdap+json"})
    r.raise_for_status()
    j = r.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    has_registrar = any("registrar" in e.get("roles", []) for e in j.get("entities", []))
    return events.get("registration"), events.get("expiration"), has_registrar


def _lookup(reg):
    """Try RDAP first, fall back to WHOIS. Returns (created, expires, has_registrar)."""
    try:
        created, expires, reg_ok = _rdap(reg)
        if created:
            return created, expires, reg_ok
    except Exception:
        pass
    data = whois.whois(reg)  # may raise; caller handles it
    return data.creation_date, data.expiration_date, bool(data.registrar)


def check_domain(domain):
    """Return {'score': int, 'reasons': [str]}. Accepts a hostname."""
    score, reasons = 0, []
    _, reg = split_host(domain)

    try:
        created_raw, expires_raw, has_registrar = _lookup(reg)
    except Exception as e:  # network error, rate limit, unsupported TLD
        return {"score": 10, "reasons": [f"Domain age lookup failed ({type(e).__name__})"]}

    created = _pick(created_raw, earliest=True)
    expires = _pick(expires_raw, earliest=False)

    if not created:
        score += 15
        reasons.append("No domain creation date available")
    else:
        age = (datetime.utcnow() - created).days
        if age < 30:
            score += 40
            reasons.append(f"Domain registered only {age} days ago")
        elif age < 90:
            score += 25
            reasons.append(f"Domain is young ({age} days old)")
        elif age < 365:
            score += 10
            reasons.append(f"Domain is less than a year old ({age} days)")

    if expires and (expires - datetime.utcnow()).days < 90 and created and (expires - created).days <= 400:
        score += 10
        reasons.append("Domain registered for only ~1 year (common for throwaway domains)")

    if not has_registrar:
        score += 5
        reasons.append("No registrar information")

    return {"score": min(score, 100), "reasons": reasons}