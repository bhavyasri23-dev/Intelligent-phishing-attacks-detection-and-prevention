Intelligent phishing attack detection and prevention

A Flask web app that checks a URL for signs of phishing and returns a risk score (0-100) with a SAFE / SUSPICIOUS / DANGEROUS verdict and the reasons behind it.

Tech stack: Python, Flask, BeautifulSoup, Requests, RDAP/WHOIS, SQLite

How it works

Each scan runs four independent checks and combines them with a weighted score.

Check	File	What it looks at
URL analysis	url_analyzer.py	Lookalike domains (e.g. paypa1), brand names on the wrong domain, punycode, @ tricks, raw IP hosts, URL shorteners, suspicious TLDs, phishing keywords
Domain age	domain_checker.py	Registration date via RDAP (WHOIS as fallback); newly registered domains score higher
SSL certificate	ssl_checker.py	Certificate validity, hostname match, very new certificates
Page content	content_checker.py	Password forms that submit to another domain, pages claiming to be a known brand, urgency wording, hidden iframes, obfuscated scripts

risk_engine.py runs the network checks in parallel with an 8-second limit, caches domain and SSL results for an hour, and produces the final verdict. Scores below 30 are SAFE, 30-59 SUSPICIOUS, and 60 or more DANGEROUS.

Other features:

Allow-list and block-list per host (stored in SQLite); a blocked host is always reported DANGEROUS.
Scan history saved to SQLite (GET /api/history).
SSRF guard: the page-content check refuses to fetch private or local addresses.
Local/private addresses return UNKNOWN instead of a misleading verdict.
Project structure
app.py               Flask app and API routes
risk_engine.py       Combines the checks into one verdict
url_analyzer.py      URL structure checks (no network needed)
domain_checker.py    Domain age lookup
ssl_checker.py       TLS certificate checks
content_checker.py   Page content checks
database.py          SQLite storage (scan history, allow/block lists)
templates/index.html Web page
requirements.txt     Python dependencies
Setup
bash
pip install -r requirements.txt
python app.py

Open http://127.0.0.1:5000 and paste a URL.

API
Method	Route	Purpose
POST	/api/scan	Body {"url": "..."}. Add ?deep=0 for a fast URL-only scan
GET	/api/history	Recent scans
POST	/api/list	Body {"host": "...", "kind": "allow" or "block"}
Limitations
Detection is rule-based with hand-chosen weights. It has not been measured against a labelled dataset, so no accuracy figure is claimed.
It can miss well-made phishing pages on old or hacked legitimate domains, or on trusted hosting platforms, and it can flag some legitimate sites.
It reports a verdict only. It does not block browsing or send alerts.
Domain, SSL and page checks need internet access.
Possible next steps
Train a classifier on a labelled dataset (e.g. PhishTank) and report accuracy.
Add a history page and exportable reports.
Build a browser extension that warns before a page loads.
