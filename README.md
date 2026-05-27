# ReconAI 🔍

> Automated OSINT reconnaissance agent powered by AI — built for security professionals and pentest engagements.

ReconAI automates the passive reconnaissance phase of a security assessment. Given a target domain, it enumerates subdomains, resolves IPs, scans for open ports, and delivers a professional AI-powered analysis report — directly to your Telegram.

---

## Features

- **Subdomain enumeration** — queries crt.sh with automatic fallback to HackerTarget
- **IP deduplication** — resolves and deduplicates IPs to avoid redundant queries
- **Port scanning** — multi-threaded socket scanner with service banner grabbing
- **Shodan integration** — ready for paid Shodan plans for deeper host intelligence
- **AI-powered analysis** — passes all findings to an LLM for professional report generation
- **Multi-provider AI** — supports Anthropic Claude, Google Gemini, Groq, and OpenAI
- **Automatic fallback** — if the primary data source is unavailable, switches to backup automatically
- **Telegram notifications** — receive scan summary and full AI analysis directly on Telegram
- **Organized output** — each scan creates a timestamped folder with JSON data and AI analysis

---

## How it works

```
python main.py target.com
         │
         ├── Step 1 — Subdomain enumeration (crt.sh → HackerTarget fallback)
         ├── Step 2 — IP resolution & deduplication
         ├── Step 3 — Multi-threaded port scan + banner grabbing
         ├── Step 4 — AI analysis (auto, provider from .env)
         └── Step 5 — Telegram notification
                           │
                           ├── Summary: subdomains, IPs, open ports
                           ├── Interesting subdomains highlighted
                           └── Button: download full AI analysis
```

---

## Quickstart

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/reconai.git
cd reconai
```

### 2. Install dependencies

```bash
pip install requests
```

### 3. Configure your API keys

```bash
cp .env.example .env
nano .env
```

Edit `.env` with your keys:

```env
# AI provider — choose one
AI_PROVIDER=gemini

# Free providers
GEMINI_API_KEY=your-key        # aistudio.google.com
GROQ_API_KEY=your-key          # console.groq.com

# Paid providers
ANTHROPIC_API_KEY=your-key     # console.anthropic.com
OPENAI_API_KEY=your-key        # platform.openai.com

# OSINT
SHODAN_API_KEY=your-key        # shodan.io

# Telegram notifications
TELEGRAM_BOT_TOKEN=your-token  # @BotFather on Telegram
TELEGRAM_CHAT_ID=your-chat-id  # @userinfobot on Telegram
```

### 4. Set up Telegram (optional)

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` and follow the instructions
3. Copy the token into `.env`
4. Search `@userinfobot` to get your Chat ID
5. Open a chat with your bot and send `/start`

### 5. Run a scan

```bash
# Full scan — subdomains + ports + AI analysis + Telegram
python main.py target.com

# Skip port scan (faster)
python main.py target.com --no-scan

# Skip Telegram notification
python main.py target.com --no-telegram

# Interactive mode (no arguments)
python main.py
```

### 6. Run AI analysis manually

```bash
# Auto-detects the latest report
python analyze.py

# Specify a report
python analyze.py report/target.com_20240527/report_completo.json
```

---

## Project structure

```
reconai/
├── main.py              # Orchestrator — runs the full pipeline
├── analyze.py           # AI analysis — multi-provider support
├── osint_step1.py       # Subdomain enumeration module
├── shodan_module.py     # Shodan integration + IP resolution
├── scanner_module.py    # Multi-threaded port scanner
├── telegram_module.py   # Telegram notifications
├── .env.example         # Configuration template
└── README.md
```

---

## Output example

```
==================================================
         ReconAI v0.1
==================================================
  Target    : tesla.com
  Avvio     : 2024-05-27 14:30:22
  Port scan : SI
  Telegram  : SI
==================================================

STEP 1 — Subdomain enumeration
[+] crt.sh OK — 51 results

STEP 2 — IP resolution
[+] 51 subdomains → 12 unique IPs

STEP 3 — Port scan
    [→] 1.2.3.4 (www.tesla.com)
        [+] 80/tcp   HTTP
        [+] 443/tcp  HTTPS

STEP 4 — AI analysis
[+] Analysis saved: report/tesla.com_xxx/analisi_gemini.txt

STEP 5 — Telegram notification
[+] Summary sent — waiting for your choice...
[+] Full analysis file sent
==================================================
```

---

## AI Providers

| Provider | Model | Cost | Notes |
|----------|-------|------|-------|
| Google Gemini | gemini-2.5-flash | Free | Recommended to start |
| Groq | llama-3.3-70b | Free | Fastest |
| Anthropic | claude-sonnet-4 | Paid | Best analysis quality |
| OpenAI | gpt-4o-mini | Paid | Good balance |

---

## Legal disclaimer

ReconAI is designed for **passive OSINT only**. All data is collected from public sources (certificate transparency logs, public APIs). No direct interaction with target infrastructure beyond DNS resolution and basic port probing.

**Only use ReconAI against targets you own or have explicit written authorization to test. Unauthorized scanning may be illegal in your jurisdiction.**

This tool is intended for:
- Security professionals conducting authorized assessments
- Students learning about reconnaissance techniques
- Bug bounty hunters within defined program scope

---

## Roadmap

- [ ] Web interface — submit a domain, receive a report
- [ ] PDF export — professional report for client delivery
- [ ] VirusTotal module — IP and domain reputation
- [ ] Email harvesting module
- [ ] Shodan paid plan integration
- [ ] Scheduled scans — monitor a target over time
- [ ] Diff reports — detect changes between scans

---

## Author

Built as a learning project while studying cybersecurity.
Contributions and feedback welcome.

---

## License

MIT License — see LICENSE file for details.
