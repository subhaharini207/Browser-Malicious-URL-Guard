# 🛡️ Browser Malicious URL Guard
### CyberShield – Browser-Based URL Threat Detection & Protection System

A browser security project designed to identify potentially malicious and phishing URLs using a Chrome Extension, Python Flask backend, local threat analysis techniques, and VirusTotal threat intelligence.

---

## 📌 Project Overview

**Browser Malicious URL Guard** is a cybersecurity project that helps identify potentially unsafe websites while browsing the internet.

The system monitors website navigation through a Chrome Extension and sends URLs to a Python Flask backend for security analysis.

The backend evaluates URLs using multiple detection techniques, assigns a risk score, and classifies them into three categories:

- 🟢 **Safe** – No threat indicators detected by the implemented checks.
- 🟡 **Suspicious** – One or more suspicious URL characteristics detected.
- 🔴 **Malicious** – High-risk indicators detected.

The scanning results are stored in an SQLite database and displayed through a web-based Security Operations Center (SOC) dashboard.

## ✨ Key Features

- **Browser URL Monitoring:** Monitors website navigation using a Chrome Extension.
- **Malicious Domain Detection:** Checks URLs against a predefined malicious domain list.
- **IP Address Detection:** Identifies URLs that use raw IP addresses as hosts.
- **Typosquatting Detection:** Detects potential brand impersonation attempts.
- **Suspicious Keyword Analysis:** Identifies phishing-related keywords such as login, verify, update, and account.
- **Domain Entropy Analysis:** Checks domain randomness for potentially suspicious patterns.
- **VirusTotal API Integration:** Retrieves existing URL analysis reports from VirusTotal.
- **Risk Score Calculation:** Assigns a risk score between 0 and 100.
- **URL Classification:** Categorizes URLs as Safe, Suspicious, or Malicious.
- **SOC Dashboard:** Displays scan history, risk scores, verdicts, and threat indicators.
- **SQLite Database:** Stores URL scanning records for later review.

## 🏗️ System Architecture

```text
          USER BROWSING
                |
                v
       CHROME EXTENSION
                |
                v
        URL CAPTURE
                |
                v
        PYTHON FLASK API
                |
                v
       URL THREAT ANALYSIS
                |
       +--------+---------+
       |        |         |
       v        v         v
    Local   URL Pattern  VirusTotal
   Blacklist  Analysis      API
       |        |         |
       +--------+---------+
                |
                v
        RISK SCORE ENGINE
                |
                v
        URL CLASSIFICATION
                |
        +-------+-------+
        |       |       |
       SAFE  SUSPICIOUS MALICIOUS
                |
                v
         SQLITE DATABASE
                |
                v
          SOC DASHBOARD
```

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | REST API and web dashboard |
| JavaScript | Chrome Extension functionality |
| Chrome Extension Manifest V3 | Browser integration |
| HTML | Block page and dashboard structure |
| Bootstrap | Dashboard styling |
| SQLite | Scan history storage |
| VirusTotal API | External URL threat intelligence |
| Requests | HTTP API communication |

## 📂 Project Structure

```text
Browser-Malicious-URL-Guard/
│
├── backend/
│   ├── server.py
│   ├── sample.py
│   ├── test.py
│   └── requirements.txt
│
├── extension/
│   ├── manifest.json
│   ├── background.js
│   └── blocked.html
│
├── screenshots/
│   └── dashboard.png
│
├── README.md
└── .gitignore
```

## ⚙️ Installation & Setup

### Prerequisites

- Python 3.x
- Google Chrome
- Git (optional)
- VirusTotal API key

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR-GITHUB-USERNAME/Browser-Malicious-URL-Guard.git
```

```bash
cd Browser-Malicious-URL-Guard
```

### Step 2: Install Dependencies

```bash
python -m pip install -r backend/requirements.txt
```

### Step 3: Configure VirusTotal API Key

Set your API key as an environment variable.

**Windows PowerShell:**

```powershell
$env:VT_API_KEY="YOUR_VIRUSTOTAL_API
