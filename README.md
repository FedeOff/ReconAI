# ReconAI 🔍

> Automated OSINT reconnaissance agent powered by AI — built for security professionals and pentest engagements.

ReconAI automates the passive reconnaissance phase of a security assessment. Given a target domain, it enumerates subdomains, resolves IPs, scans for open ports, and produces a professional analysis report powered by an AI model of your choice.

---

## Features

- **Subdomain enumeration** — queries crt.sh with automatic fallback to HackerTarget
- **IP deduplication** — resolves and deduplicates IPs to avoid redundant queries
- **Port scanning** — multi-threaded socket scanner with service banner grabbing
- **Shodan integration** — ready for paid Shodan plans for deeper host intelligence
- **AI-powered analysis** — passes all findings to an LLM for professional report generation
- **Multi-provider AI** — supports Anthropic Claude, Google Gemini, Groq, and OpenAI
- **Automatic fallback** — if the primary data source is unavailable, switches to backup automatically
- **Organized output** — each scan creates a timestamped folder with JSON data and AI analysis

---

## How it works

```
python main.py target.com
         │
         ├── Step 1 — Subdomain enumeration (crt.sh → HackerTarget fallback)
         ├── Step 2 — IP resolution & deduplication
         ├── Step 3 — Multi-threaded port scan + banner grabbing
         └── Output → report/target.com_TIMESTAMP/
                           ├── sottodomini.json
                           ├── ip_map.json
                           ├── port_scan.json
                           └── report_completo.json

python analyze.py
         │
         └── Reads latest report → sends to AI → analisi_gemini.txt
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
AI_PROVIDER=gemini          # anthropic | gemini | groq | openai

GEMINI_API_KEY=your-key     # free — aistudio.google.com
GROQ_API_KEY=your-key       # free — console.groq.com
ANTHROPIC_API_KEY=your-key  # console.anthropic.com
OPENAI_API_KEY=your-key     # platform.openai.com
SHODAN_API_KEY=your-key     # shodan.io (free plan supported)
```

### 4. Run a scan

```bash
# Basic scan
python main.py target.com

# Skip port scan (faster, subdomain enumeration only)
python main.py target.com --no-scan

# Custom output folder
python main.py target.com --output ./results
```

### 5. Analyze with AI

```bash
# Auto-detects the latest report
python analyze.py

# Or specify a report manually
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
├── .env.example         # Configuration template
└── README.md
```

---

## Output example

```
==================================================
         ReconAI v0.1
==================================================
  Target  : tesla.com
  Avvio   : 2024-05-27 14:30:22
  Port scan: SI
==================================================

[*] Provo crt.sh (timeout 20s)...
[+] crt.sh OK — 51 risultati

[*] Risoluzione IP dei sottodomini...
[+] 51 sottodomini → 12 IP unici

[*] Avvio port scan...
    [→] 1.2.3.4 (www.tesla.com, shop.tesla.com)
        [+] 80/tcp   HTTP    HTTP/1.0 400 Bad Request
        [+] 443/tcp  HTTPS

==================================================
  SCAN COMPLETATO
  Sottodomini trovati : 51
  IP unici            : 12
  IP con porte aperte : 8
  Porte totali        : 17
==================================================
```

---

## AI Providers

| Provider | Model | Cost | Speed |
|----------|-------|------|-------|
| Google Gemini | gemini-2.5-flash | Free | Fast |
| Groq | llama-3.3-70b | Free | Very fast |
| Anthropic | claude-sonnet-4 | Paid | Excellent quality |
| OpenAI | gpt-4o-mini | Paid | Good |

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
- [ ] Shodan paid plan integration
- [ ] Email harvesting module
- [ ] Slack / Telegram notifications

---

## Author

Built as a learning project while studying cybersecurity.
Contributions and feedback welcome.

---

## License

MIT License — see LICENSE file for details.
