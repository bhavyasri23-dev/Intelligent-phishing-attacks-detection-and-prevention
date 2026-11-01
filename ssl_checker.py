# ssl_checker.py
"""TLS certificate checks."""
import socket
import ssl
from datetime import datetime


def check_ssl(hostname, port=443, timeout=5):
    """Return {'score': int, 'reasons': [str]}."""
    score, reasons = 0, []
    ctx = ssl.create_default_context()  # verifies chain + hostname

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"score": 40, "reasons": [f"Certificate failed verification: {e.verify_message}"]}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"score": 15, "reasons": ["No HTTPS/TLS service reachable on port 443"]}

    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    age = (datetime.utcnow() - not_before).days
    if age < 7:
        score += 15
        reasons.append(f"Certificate issued only {age} days ago")

    if (not_after - not_before).days <= 100 and age < 30:
        score += 5
        reasons.append("Short-lived, freshly issued certificate (typical of free DV certs)")

    issuer = dict(x[0] for x in cert.get("issuer", ()))
    subject = dict(x[0] for x in cert.get("subject", ()))
    # No organization in the cert is normal (most sites use domain-validated certs), so it is not scored.
    if issuer.get("organizationName") in (None, ""):
        score += 5
        reasons.append("Unknown certificate issuer")

    return {"score": min(score, 100), "reasons": reasons}
