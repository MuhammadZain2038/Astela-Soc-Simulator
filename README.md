# 🛡️ ASTELA: AI-Augmented SOC & IDS Pipeline

An AI-augmented Security Operations Center pipeline that detects, scores, and
triages threats from log data using signature-based detection (YARA, ClamAV,
threat intel), behavioral detection (attack-pattern sequences mapped to
MITRE ATT&CK), and an LLM for severity scoring and remediation advice —
all visualized on a live Streamlit dashboard.

<img width="2816" height="1536" alt="Gemini_Generated_Image_apyf66apyf66apyf" src="https://github.com/user-attachments/assets/1318b4e8-0acd-4689-836b-9ff8b25fc8d4" />


## 🧠 How the Pipeline Works

ASTELA reads log entries and runs them through a two-tier detection
pipeline before every alert is scored by an LLM and pushed to a live
dashboard:

- **Tier 1 — Signature Detection.** Checks file hashes against a local
  Redis cache of known malware (seeded from MalwareBazaar's full dataset
  and kept in sync hourly), falls back to the MalwareBazaar API on a
  cache miss, and also runs YARA rules and a ClamAV scan against the raw
  log text.
- **Tier 2 — Behavioral Detection.** Tracks sequences of actions per IP
  and per user over a rolling time window. When a sequence matches a
  known attack pattern (phishing → execution, Defender tampering,
  log-clearing after a breach, brute force followed by login, etc.) it
  fires a MITRE ATT&CK-mapped alert.
- **AI Scoring.** Every alert is sent to an LLM (via OpenRouter) for a
  0–10 severity score, a one-sentence explanation, and a two-sentence
  remediation plan. Known-malware and MITRE-tagged detections have a
  hard-coded minimum score, so a bad or unavailable LLM response can
  never make a confirmed threat look harmless.
- **Repeat-Offender Tracking.** If the same IP triggers the same threat
  again inside a rolling window, the cached scoring is reused instead of
  calling the LLM again, and the alert escalates automatically.
- **Live Dashboard.** A Streamlit app reads alerts from OpenSearch and
  shows a live triage feed, severity charts, IP activity timelines, and
  filtering by tier, family, and score.

## ⚙️ Prerequisites

You need these installed before running ASTELA:

- **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** —
  running before you launch the app. Redis, ClamAV, and OpenSearch all
  run as containers.
- **Python 3.13** (or close to it) — [python.org](https://www.python.org/downloads/)
- **Git**, if you're cloning this repo — [git-scm.com](https://git-scm.com/download/win)

Nothing else needs to be installed manually — YARA, ClamAV, OpenSearch,
and Redis all come from Docker images the launcher pulls automatically
on first run.

## 🚀 Quick Start

```bash
git clone <your-repo-url>
cd WorkingAI

python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

copy .env.example .env
REM Now open .env and fill in MALWARE_BAZAAR_KEY and OPENROUTER_API_KEY
```

Then just **double-click `logparser\Launch_astela.bat`**.

On first run it will:
1. Ask permission before pulling the Redis and ClamAV Docker images
   (confirm both — ClamAV's is a large download, roughly 1–1.5 GB)
2. Ask whether to download MalwareBazaar's full hash dataset (~500 MB,
   optional — the pipeline still works without it, just with a smaller
   threat-intel cache until the hourly sync catches up)
3. Open the dashboard in your browser and start the detection pipeline

## 🔑 Getting API Keys

- **MalwareBazaar** (free): register at
  [bazaar.abuse.ch](https://bazaar.abuse.ch/) to get an API key.
- **OpenRouter** (LLM scoring): create a key at
  [openrouter.ai](https://openrouter.ai/) and add a small amount of
  credit (a few dollars). Free-tier keys share a heavily-throttled pool
  and will hit frequent rate limits; a small paid balance gives a much
  higher rate-limit tier.

## 🛠️ Configuration

All settings live in `.env` (copy `.env.example` to get started). Only
the two API keys are required — everything else has a working default.

| Variable | Default | Purpose |
|---|---|---|
| `MALWARE_BAZAAR_KEY` | *(required)* | Threat intel sync and Tier 1 API fallback |
| `OPENROUTER_API_KEY` | *(required)* | LLM severity scoring |
| `REDIS_DOCKER_PORT` | `6379` | Redis port, used everywhere it's read |
| `CLAMD_DOCKER_PORT` | `3310` | ClamAV daemon port |
| `OPEN_SEARCH_PATH` | *(auto-detected)* | Path to `docker-compose.yml` for OpenSearch |
| `VENV_PYTHON` | *(auto-detected)* | Override if your venv lives somewhere nonstandard |
| `SYNC_INTERVAL_SECONDS` | `3600` | How often threat intel re-syncs in the background |
| `REPEAT_TTL_SECONDS` | `3600` | Repeat-offender tracking window |

## 📂 Project Structure

```
project/
├── SecurityAI/
│   └── docker-compose.yml      # OpenSearch + Dashboards
└── WorkingAI/
    ├── .env                    # your local config (not committed)
    ├── requirements.txt
    ├── csp_rules/
    │   └── csp_rules.json      # Tier 2 behavioral rule definitions
    ├── yara_rules/
    │   └── malicious_rules.yar
    └── logparser/
        ├── Launch_astela.py    # main entrypoint
        ├── Launch_astela.bat   # double-click launcher (Windows)
        ├── dev checks/
        │   └── sync_threat_intel.py
        ├── pipeline/
        │   ├── astela_pipeline.py
        │   ├── tier1_bouncer.py
        │   ├── tier2_csp.py
        │   └── ai_scoring.py
        ├── frontend/
        │   └── app.py          # Streamlit dashboard
        ├── tests/
        │   └── sample_logs.txt
        └── threat_data/
            └── full.csv        # downloaded on first run, not committed
```

## ⚠️ Known Limitations

- **Log format is custom.** The pipeline expects lines in the form
  `DATE TIME EVENT_TYPE key=value key=value ...`. This is not a
  standard format like Syslog or Windows Event Log — connecting a real
  log source would need a small parser that translates that source's
  native format into this same shape first.
- **Not internet-facing.** Redis and ClamAV run without authentication
  and are bound to `127.0.0.1` for that reason. OpenSearch runs with
  its security plugin disabled. This is fine for local use; none of
  this should be exposed beyond your own machine.
- **LLM scoring depends on a third-party provider.** OpenRouter's free
  tier is shared and can rate-limit under load — the pipeline retries
  automatically, but a small paid balance is more reliable for a live
  demo.

## 🚑 Troubleshooting

**"Could not resolve host" errors during threat-intel sync** — usually
a temporary DNS blip, often right after Docker Desktop starts. Retry
the sync; if it keeps happening, check your network's DNS settings.

**LLM scoring shows "Scoring Error"** — check the console for the
actual error. A `429` means OpenRouter (or the upstream model
provider) is temporarily rate-limited; the pipeline retries a few
times automatically before falling back.

**`ModuleNotFoundError` even though packages are installed** — you're
likely running the wrong Python interpreter. Always run scripts using
the venv's own interpreter (`.venv\Scripts\python.exe`), not whatever
`python` resolves to on your system PATH.

**Redis shows a "DBSIZE mismatch" after sync** — usually one leftover
hash from an older run. Harmless, and doesn't affect detection.

## 🤝 Data Sources & Credits

- Threat intelligence: [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch)
- LLM scoring: [DeepSeek](https://www.deepseek.com/) via [OpenRouter](https://openrouter.ai/)
- Static analysis: [YARA](https://virustotal.github.io/yara/), [ClamAV](https://www.clamav.net/)
- Storage & dashboard: [Redis](https://redis.io/), [OpenSearch](https://opensearch.org/), [Streamlit](https://streamlit.io/)
