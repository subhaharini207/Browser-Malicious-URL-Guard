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
git clone https://github.com/subaharini207/Browser-Malicious-URL-Guard.git
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
$env:VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
```

Never hardcode or publicly share your API key.

### Step 4: Start the Flask Backend

```powershell
cd backend
python server.py
```

The backend will run at:

`http://127.0.0.1:5000`

### Step 5: Install the Chrome Extension

1. Open Google Chrome.
2. Navigate to `chrome://extensions`.
3. Enable **Developer Mode**.
4. Click **Load unpacked**.
5. Select the project's `extension` folder.
6. Ensure the extension is enabled.

### Step 6: Open the SOC Dashboard

Visit:

`http://127.0.0.1:5000`

The dashboard displays URL scanning history and threat analysis results.

## 📊 Risk Classification

| Risk Score | Classification |
|---|---|
| 0–24 | Safe |
| 25–59 | Suspicious |
| 60–100 | Malicious |

Risk scores are calculated using the project's local detection rules and available VirusTotal report information.

## 🔍 Detection Techniques

1. **Threat Intelligence Matching:** Compares domains against a predefined malicious domain list.
2. **IP-Based URL Detection:** Identifies raw IP address hosts.
3. **URL Obfuscation Detection:** Checks for the `@` character in URLs.
4. **Typosquatting Analysis:** Uses string similarity to identify possible brand impersonation.
5. **Keyword Analysis:** Searches for suspicious words commonly associated with phishing.
6. **Entropy Analysis:** Evaluates domain randomness.
7. **External Threat Intelligence:** Checks existing VirusTotal URL reports.

## 📈 SOC Dashboard

The dashboard provides an overview of:

- Total URLs scanned
- Safe URLs
- Suspicious URLs
- Malicious URLs
- Risk scores
- Detection reasons
- Scan timestamps

## 🔐 Security Considerations

- API keys should be stored in environment variables.
- Secret files and local databases should not be committed to public repositories.
- VirusTotal API availability and usage limits may affect external analysis.
- An unavailable VirusTotal report does not mean a URL is safe.

## ⚠️ Limitations

- The local detection engine uses predefined rules and heuristic analysis.
- VirusTotal integration checks existing URL reports; it does not automatically submit unknown URLs for a new scan.
- A Safe classification does not guarantee that a website is completely safe.
- Detection results depend on the available threat intelligence and implemented rules.

This project is intended for educational and cybersecurity research purposes. It should not be considered a replacement for professional antivirus or enterprise web security solutions.

## 🚀 Future Enhancements

- Machine learning-based phishing URL detection.
- Automatic submission of unknown URLs for external analysis.
- Improved threat intelligence feeds.
- Advanced phishing detection techniques.
- Enhanced security analytics and dashboard visualizations.
- Configurable allowlists and blocklists.

## 👨‍💻 Author

**V. SUBHAHARINI**

Project: Browser Malicious URL Guard  
Category: Cybersecurity | Web Security | Phishing Detection

---

⭐ If you find this project useful, consider giving the repository a star!

**Contributions and suggestions are welcome.**
