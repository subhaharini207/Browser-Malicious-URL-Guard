
import sqlite3
import math
import difflib
import os
import base64
import requests

from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_NAME = "threat_logs.db"

# VirusTotal API key must be stored as an environment variable
VT_API_KEY = os.getenv("VT_API_KEY")

# Local Threat Intelligence Blacklist
KNOWN_MALICIOUS_DOMAINS = {
    "evil-phish-login.xyz",
    "secure-bank-kyc-update.com",
    "free-crypto-airdrop-claim.net",
    "malware-payload-drop.org"
}

PROTECTED_BRANDS = [
    "google.com",
    "paypal.com",
    "amazon.in",
    "hdfcbank.com",
    "microsoft.com",
    "instagram.com"
]


# -----------------------------------------
# DATABASE INITIALIZATION
# -----------------------------------------

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS url_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            url TEXT,
            domain TEXT,
            risk_score INTEGER,
            verdict TEXT,
            reasons TEXT
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------------------
# ENTROPY CALCULATION
# -----------------------------------------

def calculate_entropy(text):
    if not text:
        return 0

    probs = [
        text.count(ch) / len(text)
        for ch in set(text)
    ]

    return -sum(
        p * math.log2(p)
        for p in probs
    )


# -----------------------------------------
# VIRUSTOTAL API INTEGRATION
# -----------------------------------------

def query_virustotal(raw_url):

    if not VT_API_KEY:
        return 0, "VirusTotal: API key not configured"

    try:
        url_id = base64.urlsafe_b64encode(
            raw_url.encode("utf-8")
        ).decode("ascii").rstrip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={
                "x-apikey": VT_API_KEY
            },
            timeout=15
        )

        if response.status_code == 200:

            result = response.json()

            stats = result.get(
                "data", {}
            ).get(
                "attributes", {}
            ).get(
                "last_analysis_stats", {}
            )

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                return 85, (
                    f"VirusTotal Alert: Flagged malicious by "
                    f"{malicious} security vendors"
                )

            if suspicious > 0:
                return 35, (
                    f"VirusTotal Warning: Flagged suspicious by "
                    f"{suspicious} security vendors"
                )

            return 0, (
                "VirusTotal: No malicious or suspicious detections "
                "in the available report"
            )

        elif response.status_code == 404:
            return 0, (
                "VirusTotal: URL report not found; threat status unknown"
            )

        elif response.status_code == 401:
            return 0, "VirusTotal Error: Invalid API key"

        elif response.status_code == 403:
            return 0, "VirusTotal Error: API access forbidden"

        elif response.status_code == 429:
            return 0, "VirusTotal Error: API rate limit exceeded"

        else:
            return 0, (
                f"VirusTotal API Error: HTTP {response.status_code}"
            )

    except requests.RequestException:
        return 0, "VirusTotal connection error"

    except (ValueError, KeyError, TypeError):
        return 0, "VirusTotal response could not be processed"


# -----------------------------------------
# URL THREAT ANALYSIS ENGINE
# -----------------------------------------

def analyze_url(raw_url):

    parsed = urlparse(raw_url)

    domain = (parsed.hostname or "").lower()

    if domain.startswith("www."):
        domain = domain[4:]

    score = 0
    reasons = []

    # 1. Known malicious domain check
    if domain in KNOWN_MALICIOUS_DOMAINS:

        score += 90

        reasons.append(
            "Matched Known Malicious Threat Intelligence Feed"
        )

    # 2. Raw IP address check
    try:
        import ipaddress
        ipaddress.ip_address(domain)

        score += 65

        reasons.append(
            "Raw IP address used instead of registered domain"
        )

    except ValueError:
        pass

    # 3. @ redirection trick
    if "@" in raw_url:

        score += 60

        reasons.append(
            "URL contains '@' credential/redirect obfuscation"
        )

    # 4. Typosquatting / Brand impersonation
    for brand in PROTECTED_BRANDS:

        if domain == brand:
            continue

        ratio = difflib.SequenceMatcher(
            None,
            domain,
            brand
        ).ratio()

        if 0.75 <= ratio < 1.0:

            score += 55

            reasons.append(
                f"Possible Typosquatting impersonating "
                f"'{brand}' ({int(ratio * 100)}% match)"
            )

            break

    # 5. Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "update",
        "kyc",
        "wallet",
        "free",
        "secure",
        "account"
    ]

    matched_words = [
        word for word in suspicious_words
        if word in raw_url.lower()
        and domain not in PROTECTED_BRANDS
    ]

    if matched_words:

        score += 25

        reasons.append(
            "Phishing lure keywords in URL: "
            + ", ".join(matched_words)
        )

    # 6. High entropy domain check
    main_domain = domain.split(".")[0]

    if calculate_entropy(main_domain) > 3.8:

        score += 20

        reasons.append(
            "High domain randomness (DGA/botnet pattern)"
        )

    # 7. VirusTotal detection
    vt_score, vt_reason = query_virustotal(raw_url)

    score += vt_score

    if vt_reason:
        reasons.append(vt_reason)

    # Final score
    score = min(score, 100)

    # Final verdict
    if score >= 60:

        verdict = "Malicious"

    elif score >= 25:

        verdict = "Suspicious"

    else:

        verdict = "Safe"

        if not reasons:
            reasons.append(
                "No local threat indicators detected"
            )

    return domain, score, verdict, "; ".join(reasons)


# -----------------------------------------
# URL SCAN API
# -----------------------------------------

@app.route("/api/scan", methods=["POST"])
def scan():

    data = request.get_json(silent=True) or {}

    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "error": "URL is required"
        }), 400

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return jsonify({
            "error": "A valid HTTP or HTTPS URL is required"
        }), 400

    domain, score, verdict, reasons = analyze_url(url)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute(
        """
        INSERT INTO url_logs
        (timestamp, url, domain, risk_score, verdict, reasons)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            domain,
            score,
            verdict,
            reasons
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "url": url,
        "domain": domain,
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    })


# -----------------------------------------
# SOC DASHBOARD
# -----------------------------------------

@app.route("/")
def dashboard():

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
        SELECT timestamp, domain, risk_score, verdict, reasons
        FROM url_logs
        ORDER BY id DESC
        LIMIT 50
    """)

    rows = c.fetchall()

    conn.close()

    total = len(rows)

    mal = sum(
        1 for r in rows
        if r[3] == "Malicious"
    )

    sus = sum(
        1 for r in rows
        if r[3] == "Suspicious"
    )

    safe = sum(
        1 for r in rows
        if r[3] == "Safe"
    )

    html = """
    <!DOCTYPE html>
    <html>

    <head>
        <title>Browser Threat Intelligence SOC Dashboard</title>

        <meta http-equiv="refresh" content="5">

        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
        rel="stylesheet">
    </head>

    <body class="bg-dark text-light p-4">

        <div class="container-fluid">

            <h2 class="mb-4">
                Browser Web Security & Threat Intelligence Dashboard
            </h2>

            <div class="row mb-4 text-center">

                <div class="col-md-3 mb-2">
                    <div class="card bg-secondary p-3">
                        <h5>Total Scanned</h5>
                        <h2>{{ total }}</h2>
                    </div>
                </div>

                <div class="col-md-3 mb-2">
                    <div class="card bg-success p-3">
                        <h5>Safe</h5>
                        <h2>{{ safe }}</h2>
                    </div>
                </div>

                <div class="col-md-3 mb-2">
                    <div class="card bg-warning text-dark p-3">
                        <h5>Suspicious</h5>
                        <h2>{{ sus }}</h2>
                    </div>
                </div>

                <div class="col-md-3 mb-2">
                    <div class="card bg-danger p-3">
                        <h5>Malicious Blocked</h5>
                        <h2>{{ mal }}</h2>
                    </div>
                </div>

            </div>

            <div class="table-responsive">

                <table class="table table-dark table-striped table-bordered">

                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Domain</th>
                            <th>Risk Score</th>
                            <th>Verdict</th>
                            <th>Threat Indicators</th>
                        </tr>
                    </thead>

                    <tbody>

                        {% for r in rows %}

                        <tr>
                            <td>{{ r[0] }}</td>
                            <td>{{ r[1] }}</td>
                            <td><strong>{{ r[2] }}/100</strong></td>

                            <td>
                                <span class="badge bg-{{
                                    'danger' if r[3]=='Malicious'
                                    else ('warning text-dark'
                                    if r[3]=='Suspicious'
                                    else 'success')
                                }}">
                                    {{ r[3] }}
                                </span>
                            </td>

                            <td>{{ r[4] }}</td>
                        </tr>

                        {% endfor %}

                    </tbody>

                </table>

            </div>

        </div>

    </body>
    </html>
    """

    return render_template_string(
        html,
        rows=rows,
        total=total,
        safe=safe,
        sus=sus,
        mal=mal
    )


# -----------------------------------------
# START FLASK SERVER
# -----------------------------------------

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
