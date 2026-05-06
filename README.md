# 🛡️ PhishGuard

A **full-stack Phishing Detection & Threat Intelligence Platform** built with Python and Django.

![Python](https://img.shields.io/badge/Python-3.14+-blue?logo=python)
![Django](https://img.shields.io/badge/Django-5.x-green?logo=django)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple?logo=bootstrap)
![DRF](https://img.shields.io/badge/DRF-3.15-red?logo=django)
![Celery](https://img.shields.io/badge/Celery-5.x-brightgreen?logo=celery)
![License](https://img.shields.io/badge/License-MIT-yellow)

🔗 **Live Demo:** [https://phishguard-tool.onrender.com](https://phishguard-tool.onrender.com)

---

## 📌 Features

### 🔗 URL / Domain Phishing Scanner
- Scans URLs against **VirusTotal** (90+ AV engines) with 1-hour response caching
- Checks **Google Safe Browsing** threat database (30-min cache)
- Checks **PhishTank** — live API or free offline daily DB (no per-request quota)
- Performs **WHOIS lookup** for domain age and registrar
- **SSL/TLS certificate analysis** — issuer, validity, SANs, self-signed detection, risk flags
- Computes risk level: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- **PDF report export** (WeasyPrint) — professional A4 report with all scan data
- **Screenshot capture** (APIFlash + html2image fallback) for HIGH/CRITICAL results
- ⚡ Cached badge shown when results served from Redis cache
- Copy-to-clipboard and shareable permalink on every result

### 📧 Email Header Analyzer
- Parses raw email headers using Python's `email` stdlib
- Detects **SPF**, **DKIM**, **DMARC** pass/fail results
- Counts relay hops and detects suspicious flags

### 🔍 Threat Intelligence Lookup
- Auto-detects indicator type: **IP / Domain / URL / Hash**
- Queries **VirusTotal API v3** for all indicator types (1-hour cache)
- Queries **AbuseIPDB** for IP abuse confidence score (2-hour cache)
- Queries **URLhaus** (abuse.ch) — free, no key needed (2-hour cache)
- Queries **Shodan** for open ports, CVEs, service banners (24-hour cache)

### 🕸️ Phishing Campaign Correlator
- Accepts 2–100 URLs and groups them into coordinated attack campaigns
- Uses **Union-Find algorithm** with weighted signals
- **D3.js force-directed network graph** showing domain → IP → hosting relationships
- Export results as JSON

### 📦 Bulk URL Scanner
- Upload `.txt` or `.csv` files with up to 500 URLs
- Background processing via **Celery** workers (Upstash Redis broker)
- Live progress bar polling every 3 seconds
- Risk filter tabs, CSV report download
- Rate-limited: 5 uploads/hour

### 👁️ Watchlist & Monitoring
- Add domains, IPs, or URLs to a personal watchlist
- **APScheduler** re-scans every 6 hours (runs inside the web process)
- Creates `WatchlistAlert` on risk level change
- Sends **email alerts** via Django's `send_mail()`
- Unacknowledged alert count shown in sidebar badge

### 📊 Dashboard
- Live stats scoped to the current user
- Risk distribution **doughnut chart** (Chart.js)
- **14-day scan activity line chart** — per risk level, colour-coded
- **Top 10 threat domains bar chart** — last 30 days
- **Threat Map** (Leaflet.js + CARTO Dark Matter tiles) — geolocated HIGH/CRITICAL IPs
- Quick Scan bar with auto-type detection
- Global search across all scan history

### 🔌 REST API
- Full DRF API at `/api/` with **JWT authentication** (SimpleJWT)
- `POST /api/scan/` — run full scanner pipeline
- `POST /api/intel/` — run threat intel lookup
- `POST /api/correlate/` — run correlation pipeline
- `GET /api/stats/` — user scan statistics
- Paginated list/detail endpoints for all resources
- Rate-limited: 100 req/day (authenticated), 10 req/day (anonymous)

### 🔐 User Authentication & API Key Management
- Django auth — register, login, logout
- `UserProfile` with encrypted per-user API keys (Fernet AES)
- Users with their own keys get independent rate limits
- Personal API key (UUID) for programmatic access

### ✨ Quality of Life
- Permanent dark theme
- Custom 404, 500, 429 error pages
- PWA manifest + favicon
- Copy-to-clipboard buttons on all IOCs
- Shareable permalinks on every scan result

---

## 🖥️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.14+, Django 5.x |
| Task Queue | Celery 5.x + Upstash Redis |
| Scheduling | APScheduler + django-apscheduler |
| Frontend | Bootstrap 5.3, Chart.js, D3.js v7, Leaflet.js |
| Database | SQLite (dev) / PostgreSQL (production via dj-database-url) |
| Cache | Upstash Redis (production) / LocMemCache (dev) |
| API | Django REST Framework + SimpleJWT |
| PDF | WeasyPrint |
| Error Tracking | Sentry SDK |
| Deployment | Render (web + worker services) |

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
copy .env.example .env   # Windows
cp .env.example .env     # macOS/Linux
```

Edit `.env` — minimum required for local dev:
```env
DJANGO_SECRET_KEY=your-secret-key-here
DEBUG=True
FIELD_ENCRYPTION_KEY=<generate below>
VT_API_KEY=your-virustotal-api-key
```

Generate keys:
```bash
# Django secret key
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Fernet encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 4. Run migrations
```bash
python manage.py migrate
```

### 5. Collect static files
```bash
python manage.py collectstatic --noinput
```

### 6. Start the development server
```bash
python manage.py runserver
```

### 7. (Optional) Start Celery worker for bulk scanning
```bash
celery -A phishguard worker --loglevel=info --concurrency=2
```

Visit `http://127.0.0.1:8000`

---

## 🔑 API Keys

| Service | Where to get | Free tier | Used for |
|---|---|---|---|
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/join-us) | 4 req/min, 500/day | Scanner, Intel, Bulk |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/register) | 1,000 req/day | Intel (IP) |
| Google Safe Browsing | [console.cloud.google.com](https://console.cloud.google.com) | Free | Scanner |
| NewsAPI | [newsapi.org/register](https://newsapi.org/register) | 100 req/day | News panel |
| PhishTank | [phishtank.com](https://www.phishtank.com/api_register.php) | Optional | Scanner (offline DB works without key) |
| Shodan | [shodan.io](https://account.shodan.io/register) | Limited free | Intel (IP) |
| APIFlash | [apiflash.com](https://apiflash.com) | 500/month | Screenshots |
| Upstash Redis | [console.upstash.com](https://console.upstash.com) | Free tier | Cache + Celery broker |
| Sentry | [sentry.io](https://sentry.io) | Free tier | Error tracking |

---

## 🚢 Deploying to Render

### Web Service
- **Build command:** `./build.sh`
- **Start command:** `gunicorn phishguard.wsgi --workers 2 --timeout 120`
- The `Procfile` release command runs `migrate` and `collectstatic` automatically on every deploy

### Worker Service (for Bulk Scanner)
- **Build command:** `pip install -r requirements.txt`
- **Start command:** `celery -A phishguard worker --loglevel=info --concurrency=2 --max-tasks-per-child=50`
- Same environment variables as the web service

### Database
- Add a **Render PostgreSQL** instance
- Copy the **Internal Database URL** as `DATABASE_URL` in both services

### Redis
- Create a free **Upstash Redis** database at [console.upstash.com](https://console.upstash.com)
- Copy the `rediss://` TLS URL as `REDIS_URL`

### Required environment variables on Render
```
DEBUG=False
ALLOWED_HOSTS=your-app.onrender.com
SITE_URL=https://your-app.onrender.com
DATABASE_URL=postgresql://...
REDIS_URL=rediss://...
DJANGO_SECRET_KEY=<strong random key>
FIELD_ENCRYPTION_KEY=<fernet key>
VT_API_KEY=<your key>
ABUSEIPDB_KEY=<your key>
GSB_API_KEY=<your key>
SHODAN_API_KEY=<your key>
NEWS_API_KEY=<your key>
```

---

## 📁 Project Structure

```
PhishGuard/
├── phishguard/               # Django project config
│   ├── settings.py           # All settings (DB, cache, Celery, DRF, Sentry)
│   ├── urls.py               # Root URL config + handler404/500
│   ├── views.py              # Custom 404, 500, 429 handlers
│   ├── celery.py             # Celery app
│   └── context_processors.py
├── accounts/                 # Auth + encrypted API key management
├── scanner/                  # URL/domain phishing scanner
├── emailparser/              # Email header analyzer
├── intel/                    # Threat intelligence lookup
├── correlation/              # Phishing campaign correlator
├── bulk_scanner/             # Bulk URL scanner (Celery tasks)
├── watchlist/                # Watchlist + APScheduler monitoring
├── dashboard/                # Overview, charts, threat map, search
├── api/                      # DRF REST API
├── services/                 # Shared external API clients (all cached)
│   ├── virustotal.py         # VirusTotal (1h cache)
│   ├── abuseipdb.py          # AbuseIPDB (2h cache)
│   ├── safebrowsing.py       # Google Safe Browsing (30m cache)
│   ├── urlhaus.py            # URLhaus / abuse.ch (2h cache)
│   ├── phishtank.py          # PhishTank live + offline DB
│   ├── shodan_service.py     # Shodan host intel (24h cache)
│   ├── ssl_analyzer.py       # SSL/TLS certificate analysis
│   ├── screenshot.py         # APIFlash + html2image screenshots
│   ├── pdf_reporter.py       # WeasyPrint PDF generation
│   └── api_key_resolver.py   # Per-user API key resolution
├── templates/                # Shared templates (base, 404, 500, 429)
│   └── reports/              # PDF report template
├── static/
│   ├── css/custom.css        # Dark theme
│   ├── favicon.ico
│   └── manifest.json         # PWA manifest
├── build.sh                  # Render build script
├── .env.example
├── requirements.txt
└── Procfile                  # Render deployment (web + worker + release)
```

---

## 📸 Pages

| Page | URL |
|---|---|
| Dashboard | `/` |
| Threat Map | `/threat-map/` |
| URL Scanner | `/scanner/` |
| Email Analyzer | `/email/` |
| Threat Intel | `/intel/` |
| Campaign Correlator | `/correlation/` |
| Bulk Scanner | `/bulk/` |
| Watchlist | `/watchlist/` |
| Watchlist Alerts | `/watchlist/alerts/` |
| REST API Root | `/api/` |
| Profile / API Keys | `/accounts/profile/` |
| Admin Panel | `/admin/` |

---

## 🔌 REST API Quick Reference

```bash
# Obtain JWT token
curl -X POST /api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "you", "password": "pass"}'

# Scan a URL
curl -X POST /api/scan/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious.example.com"}'

# Threat intel lookup
curl -X POST /api/intel/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "1.2.3.4"}'

# Correlate URLs
curl -X POST /api/correlate/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://a.com", "https://b.com"], "label": "test"}'

# Get scan history (filter by risk)
curl "/api/scans/?risk=HIGH" \
  -H "Authorization: Bearer <access_token>"

# Get user stats
curl /api/stats/ \
  -H "Authorization: Bearer <access_token>"
```

---

## ⚠️ Disclaimer

This tool is intended for **educational and defensive security purposes only**.
Do not use it to scan systems or URLs without proper authorization.

---

## 📄 License

MIT License — feel free to use, modify, and distribute.
