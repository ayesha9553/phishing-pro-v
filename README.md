# 🛡️ PhishingPro

**Multi-layered email phishing detector** — Analyze emails for phishing threats using header analysis, URL scanning, NLP content analysis, email authentication verification, and optional AI/ML classification.

---

## ✨ Features

- **📎 File Upload Analysis** — Drop `.eml` or `.msg` email files for instant analysis
- **📝 Paste & Scan** — Paste raw email content (including headers) directly
- **📋 Header Analyzer** — Detect sender spoofing, display name mismatches, reply-to anomalies, suspicious X-Mailer headers, recently registered domains
- **🔗 URL Analyzer** — Detect IP-based URLs, URL shorteners, suspicious TLDs, brand impersonation, homograph attacks, excessive subdomains, encoded target data
- **📝 Content Analyzer** — NLP pattern matching for urgency language, credential requests, authority impersonation, dangerous attachments, HTML tricks (hidden content, embedded forms, iframes, scripts)
- **🔐 Auth Checker** — Parse SPF, DKIM, and DMARC authentication results
- **🤖 AI/ML Detection** (Optional) — Transformer-based sequence classification using the `ealvaradob/phishing-email-detection` model
- **📊 Dashboard** — Real-time statistics, risk distribution donut chart, 7-day trend graph
- **📜 Scan History** — Paginated history with filters by risk level and source
- **📥 Export Reports** — Download JSON analysis reports for any scan
- **🔗 VirusTotal Integration** (Optional) — Real-time URL reputation scanning via VirusTotal API
- **🌙 Dark Mode UI** — Premium glassmorphism design with animated backgrounds

---

## 🏗️ Architecture

```
phishing-pro/
├── backend/
│   ├── main.py                 # FastAPI app entry point
│   ├── config.py               # Environment configuration
│   ├── database.py             # Async SQLite with aiosqlite
│   ├── api/
│   │   ├── routes_scan.py      # Scan & export endpoints
│   │   ├── routes_history.py   # History & dashboard stats
│   │   └── routes_settings.py  # App settings
│   ├── engine/
│   │   ├── header_analyzer.py  # Email header analysis
│   │   ├── url_analyzer.py     # URL extraction & analysis
│   │   ├── content_analyzer.py # NLP body content analysis
│   │   ├── auth_checker.py     # SPF/DKIM/DMARC checks
│   │   ├── ml_analyzer.py      # Transformer ML model
│   │   └── risk_scorer.py      # Weighted risk aggregation
│   ├── models/
│   │   └── schemas.py          # Pydantic models
│   └── services/
│       ├── scanner_service.py  # Analysis pipeline orchestrator
│       ├── email_parser.py     # .eml/.msg file parsing
│       └── virustotal_service.py # VirusTotal API integration
├── frontend/
│   ├── index.html              # SPA shell
│   ├── css/styles.css          # Complete design system
│   └── js/
│       ├── api.js              # API client
│       ├── app.js              # Router & bootstrap
│       ├── dashboard.js        # Dashboard page
│       ├── scanner.js          # Scan page
│       ├── history.js          # History page
│       └── settings.js         # Settings page
├── data/                       # SQLite database (auto-created)
├── tests/
│   ├── test_api.py             # API test script
│   ├── sample_phishing.eml     # Test phishing email
│   └── sample_clean.eml        # Test clean email
├── pyproject.toml              # Project configuration
└── .env                        # Environment variables
```

---

## 🌐 Live Demo & Deployment

This project has been deployed!

- **Frontend (Live UI):** [https://ayesha9553.github.io/phishing-pro-v/](https://ayesha9553.github.io/phishing-pro-v/)
- **Backend API:** https://phishing-pro-backend.onrender.com

**How it is hosted:**
- The **Frontend** is served as static files via **GitHub Pages**. (Note: A .nojekyll file and relative /css/ /js/ paths are required for the UI to correctly locate its style assets on GitHub pages). 
- The **Backend** is deployed to **Render** as a free Web Service. It automatically spins up when you use the app. *(Note: The very first scan may take ~30-50 seconds as the free server wakes up from sleep).*

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+**
- **[uv](https://docs.astral.sh/uv/)** (recommended) or pip

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd phishing-pro

# Install dependencies with uv
uv sync

# (Optional) Install ML dependencies for AI detection
uv sync --extra ml
```

### Configuration

Copy the example environment file (or use the provided `.env`):

```bash
cp .env.example .env
```

Edit `.env` to add optional API keys:

```env
# Optional: VirusTotal API key for URL reputation
VIRUSTOTAL_API_KEY=your_key_here
```

### Run the Server

```bash
uv run uvicorn backend.main:app --reload
```

Open **http://127.0.0.1:8000** in your browser.

---

## 📡 API Reference

### Scan Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/upload` | Upload `.eml`/`.msg` file for analysis |
| `POST` | `/api/scan/text` | Analyze raw email text |
| `GET` | `/api/scan/{id}` | Get scan result by ID |
| `GET` | `/api/scan/{id}/export` | Download JSON report |

### History Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/history` | Paginated scan history (query: `limit`, `offset`, `risk_level`, `source`) |
| `GET` | `/api/history/stats` | Dashboard statistics |
| `GET` | `/api/history/{id}` | Scan detail |
| `DELETE` | `/api/history/{id}` | Delete a scan |
| `DELETE` | `/api/history` | Clear all history |

### Settings Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/settings` | Get current settings |
| `PUT` | `/api/settings` | Update settings |

---

## 🔬 Detection Layers

### 1. Header Analysis
- Sender display name vs. actual email mismatch
- Company impersonation (PayPal, Apple, Microsoft, etc.)
- Reply-To address mismatch
- Received header chain anomalies
- Known phishing toolkit detection (GoPhish, King Phisher, etc.)
- Missing standard headers (Message-ID, Date)
- IP-based sender domains
- Recently registered domain detection (via WHOIS)

### 2. URL Analysis
- IP address URLs
- URL shortener detection (20+ services)
- Suspicious TLD detection (30+ TLDs)
- Domain entropy analysis (algorithmically generated domains)
- Brand impersonation with homograph detection
- Excessive subdomain depth
- Suspicious path keywords (login, verify, password, etc.)
- Base64-encoded target data in URLs
- Mismatched anchor text vs. href
- Dangerous URI schemes (data:, javascript:)

### 3. Content Analysis
- Urgency/pressure language patterns (16 patterns)
- Threat/fear language (10 patterns)
- Credential request detection (10 patterns)
- Suspicious action requests (9 patterns)
- Authority impersonation (7 patterns)
- Excessive capitalization
- Generic greeting detection
- Dangerous attachment extensions (30+)
- Double extension attack detection
- HTML tricks (hidden content, embedded forms, iframes, scripts)

### 4. Authentication Verification
- SPF (Sender Policy Framework) result parsing
- DKIM (DomainKeys Identified Mail) signature verification
- DMARC (Domain-based Message Authentication) compliance

### 5. AI/ML Analysis (Optional)
- Transformer-based text classification
- Model: `ealvaradob/phishing-email-detection`
- Confidence-weighted severity mapping

### Risk Scoring
All findings are aggregated using a weighted scoring algorithm:
- Each analyzer category is scored independently (capped at 100)
- Category weights: Header 20%, URL 30%, Content 30%, Auth 20%
- Final score mapped to risk levels: Safe (0-25), Low (25-45), Medium (45-65), High (65-85), Critical (85-100)

---

## 🧪 Testing

```bash
# Start the server first
uv run uvicorn backend.main:app --reload

# Run the test script
python tests/test_api.py
```

---

## 📄 License

MIT
