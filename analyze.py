# ============================================================
# OSINT Agent - Analyze
# Analizza il report con il provider AI scelto nel .env
#
# Uso:
#   python analyze.py                        (ultimo report automatico)
#   python analyze.py report/tesla.com_xxx/report_completo.json
# ============================================================

import json
import os
import sys
import requests
from datetime import datetime


# ============================================================
# CARICA CONFIGURAZIONE DAL .env
# ============================================================

def carica_config():
    config = {}

    # Prima legge variabili d'ambiente
    for chiave in ["AI_PROVIDER", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
                   "GROQ_API_KEY", "OPENAI_API_KEY", "SHODAN_API_KEY"]:
        valore = os.environ.get(chiave)
        if valore:
            config[chiave] = valore

    # Poi sovrascrive con il file .env
    try:
        with open(".env", "r") as f:
            for riga in f:
                riga = riga.strip()
                # Salta commenti e righe vuote
                if not riga or riga.startswith("#"):
                    continue
                if "=" in riga:
                    chiave, valore = riga.split("=", 1)
                    config[chiave.strip()] = valore.strip()
    except FileNotFoundError:
        pass

    return config


# ============================================================
# TROVA ULTIMO REPORT AUTOMATICAMENTE
# ============================================================

def trova_ultimo_report():
    cartella_base = "report"

    if not os.path.exists(cartella_base):
        return None

    cartelle = sorted(
        [d for d in os.listdir(cartella_base)
         if os.path.isdir(os.path.join(cartella_base, d))],
        reverse=True
    )

    for cartella in cartelle:
        report_path = os.path.join(cartella_base, cartella, "report_completo.json")
        if os.path.exists(report_path):
            return report_path

    return None


# ============================================================
# PREPARA IL PROMPT
# ============================================================

def prepara_prompt(report):
    target = report.get("target", "sconosciuto")
    sottodomini = report.get("sottodomini", [])
    ip_map = report.get("ip_map", {})
    scan = report.get("scan", [])

    testo = f"""Sei un esperto di sicurezza informatica. Analizza i seguenti risultati OSINT su {target}.

============================================================
TARGET: {target}
SOTTODOMINI: {len(sottodomini)}
IP UNICI: {len(ip_map)}
============================================================

SOTTODOMINI:
{chr(10).join(f"  - {s}" for s in sottodomini)}

MAPPA IP → SOTTODOMINI:
"""
    for ip, subs in ip_map.items():
        testo += f"\n  {ip}:\n"
        for sub in subs:
            testo += f"    - {sub}\n"

    if scan:
        testo += "\nPORT SCAN:\n"
        for r in scan:
            testo += f"\n  IP: {r.get('ip')}\n"
            testo += f"  Sottodomini: {', '.join(r.get('sottodomini', [])[:3])}\n"
            porte = r.get("porte_aperte", [])
            if porte:
                for p in porte:
                    banner = p.get("banner", "")
                    testo += f"    - {p['porta']}/tcp {p['servizio']}"
                    if banner:
                        testo += f"  [{banner[:80]}]"
                    testo += "\n"
            else:
                testo += "    - nessuna porta aperta\n"

    testo += """
============================================================
Produci un report con queste sezioni:

1. PANORAMICA
   Superficie di attacco identificata.

2. SOTTODOMINI INTERESSANTI
   Quali meritano approfondimento e perché
   (staging, admin, api, dev, test, vpn, mail, ecc.)

3. ANALISI PORTE E SERVIZI
   Commenta porte aperte e configurazioni anomale.

4. TECNOLOGIE IDENTIFICATE
   Tecnologie riconosciute da banner e risposte HTTP.

5. PRIORITÀ DI APPROFONDIMENTO
   Lista ordinata di cosa investigare prima.

6. NOTE DI SICUREZZA
   Considerazioni generali sulla postura di sicurezza.

Sii preciso e tecnico. Contesto: pentest autorizzato.
============================================================"""

    return testo


# ============================================================
# CHIAMATE AI — un metodo per provider
# ============================================================

def chiama_anthropic(prompt, api_key):
    print("[*] Provider: Anthropic (Claude)")

    risposta = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        },
        json={
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        },
        timeout=60
    )
    risposta.raise_for_status()
    return risposta.json()["content"][0]["text"]


def chiama_gemini(prompt, api_key):
    print("[*] Provider: Google Gemini")

    risposta = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}",
        headers={"Content-Type": "application/json"},
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 4096}
        },
        timeout=60
    )
    risposta.raise_for_status()
    return risposta.json()["candidates"][0]["content"]["parts"][0]["text"]


def chiama_groq(prompt, api_key):
    print("[*] Provider: Groq (LLaMA 3.3)")

    risposta = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        json={
            "model": "llama-3.3-70b-versatile",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        },
        timeout=60
    )
    risposta.raise_for_status()
    return risposta.json()["choices"][0]["message"]["content"]


def chiama_openai(prompt, api_key):
    print("[*] Provider: OpenAI (GPT-4o-mini)")

    risposta = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        json={
            "model": "gpt-4o-mini",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        },
        timeout=60
    )
    risposta.raise_for_status()
    return risposta.json()["choices"][0]["message"]["content"]


# ============================================================
# ROUTER — sceglie il provider giusto
# ============================================================

def chiama_ai(prompt, config):
    provider = config.get("AI_PROVIDER", "gemini").lower()

    if provider == "anthropic":
        key = config.get("ANTHROPIC_API_KEY")
        if not key:
            raise Exception("ANTHROPIC_API_KEY non trovata nel .env")
        return chiama_anthropic(prompt, key)

    elif provider == "gemini":
        key = config.get("GEMINI_API_KEY")
        if not key:
            raise Exception("GEMINI_API_KEY non trovata nel .env")
        return chiama_gemini(prompt, key)

    elif provider == "groq":
        key = config.get("GROQ_API_KEY")
        if not key:
            raise Exception("GROQ_API_KEY non trovata nel .env")
        return chiama_groq(prompt, key)

    elif provider == "openai":
        key = config.get("OPENAI_API_KEY")
        if not key:
            raise Exception("OPENAI_API_KEY non trovata nel .env")
        return chiama_openai(prompt, key)

    else:
        raise Exception(f"Provider '{provider}' non riconosciuto. Usa: anthropic, gemini, groq, openai")


# ============================================================
# MAIN
# ============================================================

def main():

    # Trova il report
    if len(sys.argv) > 1:
        report_path = sys.argv[1]
    else:
        report_path = trova_ultimo_report()
        if not report_path:
            print("[!] Nessun report trovato.")
            print("    Lancia prima: python main.py <dominio>")
            sys.exit(1)
        print(f"[*] Report trovato: {report_path}")

    # Carica report
    try:
        with open(report_path, "r") as f:
            report = json.load(f)
    except FileNotFoundError:
        print(f"[!] File non trovato: {report_path}")
        sys.exit(1)

    # Carica config
    config = carica_config()
    provider = config.get("AI_PROVIDER", "gemini")

    print("\n" + "="*50)
    print("       OSINT Agent — Analisi AI")
    print("="*50)
    print(f"  Target  : {report.get('target')}")
    print(f"  Provider: {provider.upper()}")
    print(f"  Report  : {report_path}")
    print("="*50 + "\n")

    # Prepara prompt e chiama AI
    prompt = prepara_prompt(report)

    try:
        analisi = chiama_ai(prompt, config)
    except Exception as e:
        print(f"[!] Errore: {e}")
        sys.exit(1)

    # Stampa risultato
    print("\n" + "="*50)
    print(f"  ANALISI — {provider.upper()}")
    print("="*50 + "\n")
    print(analisi)

    # Salva nella cartella del report
    cartella = os.path.dirname(report_path)
    output_path = os.path.join(cartella, f"analisi_{provider}.txt")

    with open(output_path, "w") as f:
        f.write(f"ANALISI OSINT — {report.get('target')}\n")
        f.write(f"Provider  : {provider.upper()}\n")
        f.write(f"Generata  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        f.write(analisi)

    print(f"\n[+] Analisi salvata in: {output_path}\n")


if __name__ == "__main__":
    main()
