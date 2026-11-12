# Ecosystem Early Warning Agent
### Web of Trust — Supply Chain Threat Scanner
**Public-source edition — runs anywhere, for any developer, with zero setup.**

Upload a dependency file. Get a personalized AI risk report in ~15 seconds.
No account. No enterprise server. No pipeline. Just upload and scan.

> Powered entirely by **public** vulnerability data: [OSV.dev](https://osv.dev) (Google) and the [NVD API](https://nvd.nist.gov/developers). No Sonatype, no Databricks, no keys required to run.

---

## Features

- **RED / YELLOW / GREEN risk cards** — traffic-light verdict per package with a 0–100 risk score
- **AI narrative per flagged package** — Claude explains in 2–3 sentences exactly what the threat does and why it matters
- **Namespace cluster detection** — groups packages by prefix to surface coordinated attacks (e.g. `aone-kit`, `aone-kit-cli`, `aone-sandbox` → same threat actor)
- **Chat with your scan results** — ask "which package should I remove first?" against your specific report
- **OSV.dev vulnerability check** — every package cross-checked against OSV.dev (aggregates NVD, GHSA, RustSec, PyPA, Go) across PyPI, npm, Maven, Cargo, RubyGems, NuGet
- **NVD trust score** — a 0–100 composite per package from NVD CVE data (CVSS severity, CISA KEV / exploit references, recency)
- **Live ecosystem pulse** — new CVEs published today / this week / this month from NVD
- **Trends** — published-CVE volume over time from NVD
- **Local malware catalog** — a bundled sample catalog flags known-malicious packages offline
- **Lead capture** — email + company form after results → logs to `leads.log`
- **Social proof counter** — tracks scans and high-risk catches across sessions

**Supported file formats:** `package.json` · `pom.xml` · `requirements.txt` · `pyproject.toml` · `Cargo.toml`

---

## Setup

### Prerequisites

- Python 3.11+
- An Anthropic API key (for AI narratives and chat — optional; the scan works without it)

**That's it.** No Databricks, no Sonatype token, no enterprise access.

### 1. Clone and configure

```bash
git clone <repo-url>
cd ecosystem-early-warning-agent
```

### 2. Create a virtual environment

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cd ..
```

> `start.sh` does this automatically — only needed if you want to run commands manually.

### 3. Create `.env` (optional)

```bash
cp backend/.env.sample backend/.env
```

Edit `backend/.env`:

```env
# Anthropic / LiteLLM — enables AI narratives and chat (optional)
ANTHROPIC_API_KEY=<your-anthropic-token>
LITELLM_MODEL=claude-sonnet-4-6

# NVD — optional; raises the NVD rate limit from 5 to 50 requests / 30s
NVD_API_KEY=<your-nvd-api-key>
```

> Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key
> Without it the app still works — NVD calls are just rate-limited and capped per scan.

### 4. Start the server

```bash
./start.sh
```

This will:
- Create a Python virtualenv if one doesn't exist
- Install all dependencies
- Kill any stale process on port 8000
- Load `.env` if present
- Start FastAPI on `http://localhost:8000`

Open `http://localhost:8000` in your browser.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | No | API key for Claude AI narratives/chat. Without it, narratives fall back to template text. |
| `ANTHROPIC_BASE_URL` | No | Override LiteLLM base URL |
| `LITELLM_MODEL` | No | Model name (default: `claude-sonnet-4-6`) |
| `NVD_API_KEY` | No | NVD API key — raises NVD rate limit 5 → 50 req/30s |
| `NVD_MAX_PER_SCAN` | No | Max NVD calls per scan (default `10`) — extra packages resolve via OSV only |

All public sources are keyless-usable. With no env at all, the app runs on OSV.dev plus the bundled sample malware catalog.

---

## Data Sources

| Source | Used for |
|---|---|
| **OSV.dev** (`api.osv.dev`) | Per-package CVE lookup across npm, PyPI, Maven, Cargo, RubyGems, NuGet |
| **NVD API 2.0** (`services.nvd.nist.gov`) | New-CVE pulse, trends, per-package trust score (CVSS, CISA KEV, exploit refs) |
| **Local catalog** (`data/*.csv`) | Bundled sample malware catalog for offline/demo flagging |

### Trust score (0–100)

Computed per package from its NVD CVEs:
- start at 100
- −12 per critical (CVSS ≥ 9), −7 per high (≥ 7), −3 per medium (≥ 4)
- −15 if any CVE is in CISA KEV or has an exploit reference
- +5 if no CVE published in the last 12 months

Omitted entirely when NVD has no data for the package — never a fake `0` or `100`.

### Bounded state

Every in-memory holder is hard-capped (see `docs/SPEC-public-intel-sources.md`):
- NVD per-package cache: 500 keys, 24h TTL
- Pulse cache: single dict, 1h TTL
- NVD calls per scan: capped (default 10); OSV batch: one `querybatch` POST per scan
- NVD rate limiter: rolling 30s window (5 keyless / 50 keyed)

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Frontend UI |
| `/analyze` | POST | Upload dependency file, returns full risk report |
| `/chat` | POST | Ask a question about your scan results |
| `/stats` | GET | Differentiator stats (local catalog + NVD) |
| `/pulse` | GET | New CVEs published (`?days=7`) |
| `/trends` | GET | Published-CVE volume over time (`?days=30`) |
| `/health` | GET | Health check + catalog row count |
| `/api/lead` | POST | Capture email + company to `leads.log` |

---

## Demo Files

| File | What it demonstrates |
|---|---|
| `data/demo-package.json` | 8 RED npm packages including `aone-*` namespace cluster attack |
| `data/demo-pom.xml` | 127 third-party Maven dependency names — larger scan |
| `data/demo-requirements.txt` | Python ecosystem coverage |
| `data/demo-pyproject.toml` | TOML format + OSV.dev badges |

---

## Project Structure

```
ecosystem-early-warning-agent/
├── backend/
│   ├── main.py            # FastAPI server — all endpoints
│   ├── scanner.py         # Parses package.json / pom.xml / requirements.txt / *.toml
│   ├── intelligence.py    # Risk scoring, RED/YELLOW/GREEN, namespace cluster detection
│   ├── data_loader.py     # NVD client + local catalog — pulse, trends, stats
│   ├── synthesizer.py     # LiteLLM/Claude — AI narratives + chat, with narrative caching
│   ├── oss_index.py       # OSV.dev batch lookup + NVD trust scores
│   ├── requirements.txt
│   └── .env.sample        # Copy to .env and fill in credentials
├── frontend/
│   └── index.html         # Single-page UI — no build step, no dependencies
├── data/
│   ├── demo-package.json      # 8 RED npm packages + aone-* namespace cluster
│   ├── demo-pom.xml           # 127 third-party Maven dependency names
│   ├── demo-requirements.txt
│   └── demo-pyproject.toml
├── docs/
│   ├── SPEC-public-intel-sources.md  # Design notes: sources, caps and trust score
│   └── WHY-WE-ARE-DIFFERENT.md
├── pom.xml                # Sample project with outdated dependencies, used to test dependency-update pull requests
├── README.md
└── start.sh               # One-command startup (creates venv, loads .env, starts gunicorn)
```

---

## Sharing Publicly (ngrok)

To share with remote judges or demo over a call:

```bash
# Install ngrok (once)
brew install ngrok
ngrok config add-authtoken <your-ngrok-token>

# Run in a separate terminal while start.sh is running
ngrok http 8000
```

Copy the `https://*.ngrok-free.app` URL and share it. The app runs locally — ngrok just tunnels traffic to it.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "Address already in use" on port 8000 | `lsof -ti:8000 \| xargs kill -9` then `./start.sh` |
| AI narratives not generating | Check `ANTHROPIC_API_KEY` in `.env` — scan still works, narratives fall back to template text |
| NVD calls rate-limited | Add `NVD_API_KEY` to `.env` (free at nvd.nist.gov) or lower `NVD_MAX_PER_SCAN` |
| OSV/NVD unreachable (offline) | App still runs on the bundled local catalog; live fields are omitted |
| ngrok URL expired between sessions | Re-run `ngrok http 8000` — new URL each time, share the updated link |
| Server logs full of pyarrow warnings | Already suppressed via `PYTHONWARNINGS=ignore` in `start.sh` |
