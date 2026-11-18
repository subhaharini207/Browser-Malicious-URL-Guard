import sqlite3
import math
import difflib
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_NAME = "threat_logs.db"

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


def calculate_entropy(text):
    if not text:
        return 0

    probs = [text.count(ch) / len(text) for ch in set(text)]

    return -sum(p * math.log2(p) for p in probs)


def analyze_url(raw_url):

    parsed = urlparse(raw_url)

    domain = parsed.netloc.lower().split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    score = 0
    reasons = []
    
    

    # 1. Threat Intelligence Exact Match
    if domain in KNOWN_MALICIOUS_DOMAINS:
        score += 90
        reasons.append(
            "Matched Known Malicious Threat Intelligence Feed"
        )

    # 2. Raw IP Address Host Check
    if domain.replace(".", "").isdigit():
        score += 65
        reasons.append(
            "Raw IP address used instead of registered domain"
        )

    # 3. '@' Redirection Trick
    if "@" in raw_url:
        score += 60
        reasons.append(
            "URL contains '@' credential/redirect obfuscation"
        )

    # 4. Typosquatting / Brand Impersonation Check
    for brand in PROTECTED_BRANDS:

        ratio = difflib.SequenceMatcher(
            None, domain, brand
        ).ratio()

        if 0.75 <= ratio < 1.0:
            score += 55

            reasons.append(
                f"Possible Typosquatting impersonating '{brand}' "
                f"({int(ratio * 100)}% match)"
            )

            break

    # 5. Suspicious Keywords & High Entropy
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
        w for w in suspicious_words
        if w in raw_url.lower()
        and domain not in PROTECTED_BRANDS
    ]

    if matched_words:
        score += 25

        reasons.append(
            f"Phishing lure keywords in URL: "
            f"{', '.join(matched_words)}"
        )

    if calculate_entropy(domain.split(".")[0]) > 3.8:
        score += 20

        reasons.append(
            "High domain randomness (DGA/botnet pattern)"
        )

    score = min(score, 100)

    if score >= 60:
        verdict = "Malicious"

    elif score >= 25:
        verdict = "Suspicious"

    else:
        verdict = "Safe"
        reasons.append("No threat indicators detected")

    return domain, score, verdict, "; ".join(reasons)


@app.route("/api/scan", methods=["POST"])
def scan():

    data = request.get_json()

    url = data.get("url", "")

    if not url.startswith("http"):
        return jsonify({
            "verdict": "Safe",
            "score": 0
        })

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

    mal = sum(1 for r in rows if r[3] == "Malicious")

    sus = sum(1 for r in rows if r[3] == "Suspicious")

    safe = sum(1 for r in rows if r[3] == "Safe")

    html = """
    <!DOCTYPE html>
    <html>

    <head>
        <title>Browser Threat Intelligence SOC Dashboard</title>

        <meta http-equiv="refresh" content="5">

        <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
        rel="stylesheet">
    </head>

    <body class="bg-dark text-light p-4">

        <div class="container">

            <h2 class="mb-4">
                Browser Web Security & Threat Intelligence Dashboard
            </h2>

            <div class="row mb-4 text-center">

                <div class="col">
                    <div class="card bg-secondary p-3">
                        <h5>Total Scanned</h5>
                        <h2>{{total}}</h2>
                    </div>
                </div>

                <div class="col">
                    <div class="card bg-success p-3">
                        <h5>Safe</h5>
                        <h2>{{safe}}</h2>
                    </div>
                </div>

                <div class="col">
                    <div class="card bg-warning text-dark p-3">
                        <h5>Suspicious</h5>
                        <h2>{{sus}}</h2>
                    </div>
                </div>

                <div class="col">
                    <div class="card bg-danger p-3">
                        <h5>Malicious Blocked</h5>
                        <h2>{{mal}}</h2>
                    </div>
                </div>

            </div>

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
                        <td>{{r[0]}}</td>
                        <td>{{r[1]}}</td>
                        <td><strong>{{r[2]}}/100</strong></td>

                        <td>
                            <span class="badge bg-{{
                                'danger' if r[3]=='Malicious'
                                else ('warning text-dark'
                                if r[3]=='Suspicious'
                                else 'success')
                            }}">
                                {{r[3]}}
                            </span>
                        </td>

                        <td>{{r[4]}}</td>
                    </tr>

                    {% endfor %}

                </tbody>

            </table>

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


if __name__ == "__main__":

    init_db()

    app.run(port=5000, debug=True)