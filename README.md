# ReconAI 🔍

> Automated OSINT reconnaissance agent powered by AI — built for security professionals and pentest engagements.

ReconAI automates the passive reconnaissance phase of a security assessment. Given a target domain, it enumerates subdomains, resolves IPs, scans for open ports, checks reputation on VirusTotal, digs into historical data via Wayback Machine, and delivers a professional AI-powered analysis report — directly to your Telegram.

---

## Features

- **Subdomain enumeration** — queries crt.sh with automatic fallback to HackerTarget
- **IP deduplication** — resolves and deduplicates IPs to avoid redundant queries
- **Port scanning** — multi-threaded socket scanner with service banner grabbing
- **Shodan integration** — ready for paid Shodan plans for deeper host intelligence
- **VirusTotal analysis** — checks IP and domain reputation across 90+ antivirus engines
- **Wayback Machine** — finds archived URLs, old endpoints, and historical technologies
- **AI-powered analysis** — passes all findings to an LLM for professional report generation
- **Multi-provider AI** — supports Anthropic Claude, Google Gemini, Groq, and OpenAI
- **Interactive provider selection** — choose your AI provider at runtime with automatic fallback
- **Automatic source fallback** — if crt.sh is unavailable, switches to HackerTarget automatically
- **Telegram notifications** — receive scan summary and full AI analysis directly on Telegram
- **Interactive mode** — prompts for each optional step at runtime, no flags to remember
- **Organized output** — each scan creates a timestamped folder with JSON data and AI analysis

---

## How it works

```
python main.py target.com
         │
         ├── Step 1 — Subdomain enumeration (crt.sh → HackerTarget fallback)
         ├── Step 2 — IP resolution & deduplication
         ├── Step 3 — Port scan + banner grabbing      [optional, asks at runtime]
         ├── Step 4 — VirusTotal reputation check      [optional, asks at runtime]
         ├── Step 5 — Wayback Machine analysis         [optional, asks at runtime]
         ├── Step 6 — AI analysis (provider chosen interactively)
         └── Step 7 — Telegram notification            [optional, asks at runtime]
                           │
                           ├── Summary: subdomains, IPs, open ports, risk levels
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

### 3. Configure API keys

```bash
cp .env.example .env
nano .env
```

### 4. Set up Telegram (optional)

1. Search `@BotFather` on Telegram → `/newbot` → copy the token
2. Search `@userinfobot` → copy your Chat ID
3. Open a chat with your bot and send `/start`
4. Add both values to `.env`

### 5. Run a scan

```bash
# Interactive mode — asks for domain and all options
python main.py

# Pass domain directly
python main.py target.com

# Skip specific steps without being asked
python main.py target.com --no-scan
python main.py target.com --no-virustotal
python main.py target.com --no-wayback
python main.py target.com --no-telegram
```

### 6. Run AI analysis on an existing report

```bash
# Auto-detects the latest report
python analyze.py

# Specify a report manually
python analyze.py report/target.com_20240527/report_completo.json
```

---

## Project structure

```
reconai/
├── main.py                # Orchestrator — runs the full pipeline
├── analyze.py             # AI analysis — interactive provider selection + fallback
├── osint_step1.py         # Subdomain enumeration with fallback
├── shodan_module.py       # Shodan integration + IP resolution
├── scanner_module.py      # Multi-threaded port scanner
├── virustotal_module.py   # VirusTotal reputation analysis
├── wayback_module.py      # Wayback Machine historical analysis
├── telegram_module.py     # Telegram notifications with inline buttons
├── .env.example           # Configuration template
└── README.md
```

---

## Output example

```
==================================================
         ReconAI v0.1
==================================================

  Target: tesla.com

[?] Vuoi eseguire il port scan? [y/n]: y
[?] Vuoi eseguire l'analisi VirusTotal? [y/n]: y
[?] Vuoi eseguire l'analisi Wayback Machine? [y/n]: y
[?] Vuoi ricevere la notifica Telegram? [y/n]: y

--------------------------------------------------
  Port scan        : SI
  VirusTotal       : SI
  Wayback Machine  : SI
  Telegram         : SI
--------------------------------------------------

STEP 1 — Subdomain enumeration
[+] crt.sh OK — 51 results

STEP 2 — IP resolution
[+] 51 subdomains → 12 unique IPs

STEP 3 — Port scan
    [→] 1.2.3.4 (www.tesla.com)
        [+] 80/tcp   HTTP    HTTP/1.0 400 Bad Request
        [+] 443/tcp  HTTPS

STEP 4 — VirusTotal
    [1/12] 1.2.3.4... rischio BASSO — 0 engine

STEP 5 — Wayback Machine
    Prima archiviazione: 2008-06-14
    URL interessanti trovati: 47

STEP 6 — AI analysis
[?] Scegli il provider AI:
    1. Google Gemini 2.5 Flash (gratuito)
    2. Groq LLaMA 3.3 (gratuito)
    Inserisci il numero [1-2]: 2
[+] Analisi completata con Groq LLaMA 3.3

STEP 7 — Telegram
[+] Riepilogo inviato — in attesa della tua scelta

==================================================
  SCAN COMPLETATO
  Sottodomini trovati  : 51
  IP unici             : 12
  IP con porte aperte  : 8
  Porte totali         : 17
  IP a rischio VT      : 0
  URL interessanti WB  : 47
==================================================
```

---

## AI Providers

| Provider | Model | Cost | Notes |
|----------|-------|------|-------|
| Google Gemini | gemini-2.5-flash | Free | Good quality |
| Groq | llama-3.3-70b | Free | Fastest |
| Anthropic | claude-sonnet-4 | Paid | Best analysis quality |
| OpenAI | gpt-4o-mini | Paid | Good balance |

If a provider fails (e.g. 503 overload), ReconAI asks if you want to retry with another one automatically.

---

## Legal disclaimer

ReconAI is designed for **passive OSINT only**. All data is collected from public sources — certificate transparency logs, public APIs, Wayback Machine archives. No direct exploitation or intrusive scanning.

**Only use ReconAI against targets you own or have explicit written authorization to test. Unauthorized scanning may be illegal in your jurisdiction.**

This tool is intended for:
- Security professionals conducting authorized assessments
- Students learning about reconnaissance techniques
- Bug bounty hunters within defined program scope

---

## Roadmap

- [ ] Web interface — submit a domain, receive a report
- [ ] PDF export — professional report for client delivery
- [ ] Email harvesting module
- [ ] Shodan paid plan full integration
- [ ] Scheduled scans — monitor a target over time
- [ ] Diff reports — detect changes between scans

---

## Author

Built as a learning project while studying cybersecurity.
Contributions and feedback welcome.

---

## License

MIT License — see LICENSE file for details.
