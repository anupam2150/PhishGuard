# 🛡️ PhishGuard

A **Phishing Detection & Threat Intelligence Web Application** built with Python and Django.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Django](https://img.shields.io/badge/Django-5.x-green?logo=django)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple?logo=bootstrap)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📌 Features

### 🔗 URL / Domain Phishing Scanner
- Scans URLs against **VirusTotal** (90+ AV engines)
- Checks **Google Safe Browsing** threat database
- Performs **WHOIS lookup** for domain age and registrar
- Computes risk level: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- Shows flagged engine badges and animated detection progress bar

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

### 📊 Dashboard
- Live stats: total scans, high/critical today, high/critical all time
- Clickable stat cards linking to filtered result lists
- Risk distribution **doughnut chart** (Chart.js)
- Recent activity tables for all three modules
- **Quick Scan** bar — auto-detects indicator type and redirects
- **Global search** across all scan history

### 📰 Cyber News Panel
- Fixed right-side panel with latest cybersecurity news
- Powered by **NewsAPI** — filters out non-security articles
- Cached in `localStorage` for 10 minutes, auto-refreshes
- Shows "Last updated X minutes ago" timestamp
- Responsive: collapses to icon on mobile, overlay on click

---

## 🖥️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, Django 5.x |
| Frontend | Django Templates, Bootstrap 5, Chart.js |
| Database | SQLite (development) |
| HTTP Client | requests |
| Environment | python-dotenv |
| Extra | dnspython, python-whois |

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/anupam2150/PhishGaurd.git
cd PhishGaurd
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

### 5. Create a superuser (optional)
```bash
python manage.py createsuperuser
```

### 6. Start the server
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
├── phishguard/          # Django project config
├── scanner/             # URL/domain phishing scanner
├── emailparser/         # Email header analyzer
├── intel/               # Threat intelligence lookup
├── dashboard/           # Overview, search, filtered lists
├── services/            # External API clients
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── safebrowsing.py
│   └── news.py
├── templates/           # Shared base template
├── static/css/          # Custom dark theme CSS
├── .env.example         # Environment variable template
└── requirements.txt
```

---

## 📸 Pages

| Page | URL |
|---|---|
| Dashboard | `/` |
| URL Scanner | `/scanner/` |
| Email Analyzer | `/email/` |
| Threat Intel | `/intel/` |
| Global Search | `/search/?q=...` |
| Admin Panel | `/admin/` |

---

## ⚠️ Disclaimer

This tool is intended for **educational and defensive security purposes only**.
Do not use it to scan systems or URLs without proper authorization.

---

## 📄 License

MIT License — feel free to use, modify, and distribute.
