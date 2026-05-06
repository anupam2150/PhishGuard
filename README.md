# 🛡️ PhishGuard

A **Phishing Detection & Threat Intelligence Web Application** built with Python and Django.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Django](https://img.shields.io/badge/Django-5.x-green?logo=django)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple?logo=bootstrap)
![License](https://img.shields.io/badge/License-MIT-yellow)

🔗 **Live Demo:** [https://phishgaurd-wo7n.onrender.com](https://phishgaurd-wo7n.onrender.com)

---

## 📌 Features

### 🔗 URL / Domain Phishing Scanner
- Scans URLs against **VirusTotal** (90+ AV engines)
- Checks **Google Safe Browsing** threat database
- Performs **WHOIS lookup** for domain age and registrar
- Computes risk level: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- Shows flagged engine badges and animated detection progress bar
- Recent scan history with risk badges

### 📧 Email Header Analyzer
- Parses raw email headers using Python's `email` stdlib
- Detects **SPF**, **DKIM**, **DMARC** pass/fail results
- Counts relay hops and detects suspicious flags:
  - SPF fail, DKIM missing, DMARC fail
  - Reply-To mismatch, Lookalike domain, Excessive hops, Unknown mailer
- Auto-expanding textarea for header input

### 🔍 Threat Intelligence Lookup
- Auto-detects indicator type: **IP / Domain / URL / Hash**
- Queries **VirusTotal API v3** for all indicator types
- Queries **AbuseIPDB** for IP abuse confidence score
- Displays flagged engines, abuse reports, ISP, country

### 🕸️ Phishing Campaign Correlator *(New)*
- Accepts 2–100 URLs and groups them into coordinated attack campaigns
- Uses **Union-Find algorithm** with weighted signals:
  - Shared IP address (+3), Shared /24 subnet (+2)
  - Shared hosting provider (+1), Domain fingerprint similarity (+2)
  - Shared suspicious keywords (+1)
- **Shannon entropy** scoring per domain
- **Confidence scoring** (HIGH / MEDIUM / LOW CONFIDENCE)
- **D3.js force-directed network graph** showing domain → IP → hosting relationships
- Export results as JSON
- Campaign detail view with per-URL suspicion scores and signals
- One-click "Scan in PhishGuard" button linking back to URL scanner

### 📊 Dashboard
- Live stats: total scans, high/critical today, high/critical all time
- Campaign correlator stats: total campaign scans, high confidence campaigns
- Clickable stat cards linking to filtered result lists
- Risk distribution **doughnut chart** (Chart.js)
- Recent activity tables for all modules
- **Quick Scan** bar — auto-detects indicator type and redirects
  - Detects multi-line input and redirects to Campaign Correlator
- **Global search** across all scan history

### 📰 Cyber News Panel
- Fixed right-side panel with latest cybersecurity news
- Powered by **NewsAPI** — filters out non-security articles
- Keywords: `cybersecurity OR phishing OR malware OR ransomware OR CVE OR data breach`
- Cached in `localStorage` for 10 minutes, auto-refreshes
- Shows "Last updated X minutes ago" timestamp
- Manual refresh button
- Responsive: collapses to icon on mobile, overlay on click

---

## 🖥️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, Django 5.x |
| Frontend | Django Templates, Bootstrap 5, Chart.js, D3.js v7 |
| Database | SQLite (development) |
| HTTP Client | requests |
| Environment | python-dotenv |
| Extra | dnspython, python-whois, tldextract, networkx, whitenoise, gunicorn |

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/anupam2150/PhishGuard.git
cd PhishGuard
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure environment variables
```bash
copy .env.example .env
```

Edit `.env` and fill in your API keys:
```env
DJANGO_SECRET_KEY=your-secret-key-here
DEBUG=True
VT_API_KEY=your-virustotal-api-key
ABUSEIPDB_KEY=your-abuseipdb-api-key
GSB_API_KEY=your-google-safe-browsing-api-key
NEWS_API_KEY=your-newsapi-key
```

### 4. Run migrations
```bash
python manage.py migrate
```

### 5. (Optional) Seed test correlation data
```bash
python manage.py seed_correlation
```

### 6. Create a superuser (optional)
```bash
python manage.py createsuperuser
```

### 7. Start the server
```bash
python manage.py runserver
```

Visit `http://127.0.0.1:8000`

---

## 🔑 API Keys

| Service | Where to get | Free tier |
|---|---|---|
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/join-us) | 4 req/min, 500/day |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/register) | 1,000 req/day |
| Google Safe Browsing | [console.cloud.google.com](https://console.cloud.google.com) | Free |
| NewsAPI | [newsapi.org/register](https://newsapi.org/register) | 100 req/day |

---

## 📁 Project Structure

```
phishguard/
├── phishguard/               # Django project config
│   ├── settings.py
│   ├── urls.py
│   └── context_processors.py
├── scanner/                  # URL/domain phishing scanner
├── emailparser/              # Email header analyzer
├── intel/                    # Threat intelligence lookup
├── correlation/              # Phishing campaign correlator
│   ├── models.py             # CampaignScan, URLRecord, Campaign
│   ├── views.py
│   ├── services/
│   │   ├── url_parser.py     # Feature extraction + entropy
│   │   ├── ip_resolver.py    # DNS resolution + subnet
│   │   ├── hosting.py        # Hosting provider lookup (cached)
│   │   ├── correlator.py     # Union-Find clustering
│   │   └── confidence.py     # Weighted confidence scoring
│   └── management/commands/
│       └── seed_correlation.py
├── dashboard/                # Overview, search, filtered lists
├── services/                 # Shared external API clients
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── safebrowsing.py
│   └── news.py
├── templates/                # Shared base template (dark theme)
├── static/css/               # Custom dark theme CSS
├── .env.example
├── requirements.txt
└── Procfile                  # For Render/Heroku deployment
```

---

## 📸 Pages

| Page | URL |
|---|---|
| Dashboard | `/` |
| URL Scanner | `/scanner/` |
| Email Analyzer | `/email/` |
| Threat Intel | `/intel/` |
| Campaign Correlator | `/correlation/` |
| Correlation Results | `/correlation/results/<id>/` |
| Campaign Detail | `/correlation/results/<id>/campaign/<n>/` |
| Correlation History | `/correlation/history/` |
| Global Search | `/search/?q=...` |
| Admin Panel | `/admin/` |

---

## 🧪 Test the Correlator

Run the seed command to instantly load 15 test URLs across 3 fake campaigns:

```bash
python manage.py seed_correlation
```

This creates:
- **Campaign A** — PayPal-themed domains with shared keywords
- **Campaign B** — Banking login patterns
- **Campaign C** — Crypto wallet themes
- **2 unrelated URLs** that should not cluster

---

## ⚠️ Disclaimer

This tool is intended for **educational and defensive security purposes only**.
Do not use it to scan systems or URLs without proper authorization.

---

## 📄 License

MIT License — feel free to use, modify, and distribute.
