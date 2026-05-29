# ============================================================
# ReconAI - Analyze
# Analisi AI con selezione provider interattiva e fallback
#
# Uso:
#   python analyze.py
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

    try:
        with open(".env", "r") as f:
            for riga in f:
                riga = riga.strip()
                if not riga or riga.startswith("#"):
                    continue
                if "=" in riga:
                    chiave, valore = riga.split("=", 1)
                    config[chiave.strip()] = valore.strip()
    except FileNotFoundError:
        pass

    for chiave in ["AI_PROVIDER", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
                   "GROQ_API_KEY", "OPENAI_API_KEY"]:
        valore = os.environ.get(chiave)
        if valore:
            config[chiave] = valore

    return config


# ============================================================
# TROVA ULTIMO REPORT
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
# SELEZIONE PROVIDER INTERATTIVA
# Mostra solo i provider che hanno una key configurata
# ============================================================

PROVIDER_INFO = {
    "gemini":    {"nome": "Google Gemini 2.5 Flash", "key": "GEMINI_API_KEY",    "gratuito": True},
    "groq":      {"nome": "Groq LLaMA 3.3",          "key": "GROQ_API_KEY",      "gratuito": True},
    "anthropic": {"nome": "Anthropic Claude",         "key": "ANTHROPIC_API_KEY", "gratuito": False},
    "openai":    {"nome": "OpenAI GPT-4o-mini",       "key": "OPENAI_API_KEY",    "gratuito": False},
}

def scegli_provider(config, escludi=None):
    if escludi is None:
        escludi = []

    # Trova provider disponibili (hanno la key nel .env)
    disponibili = [
        (id_provider, info)
        for id_provider, info in PROVIDER_INFO.items()
        if config.get(info["key"]) and id_provider not in escludi
    ]

    if not disponibili:
        return None

    # Se c'è solo uno disponibile, usalo direttamente
    if len(disponibili) == 1:
        id_provider, info = disponibili[0]
        print(f"[*] Provider disponibile: {info['nome']}")
        return id_provider

    # Mostra menu di scelta
    print("\n[?] Scegli il provider AI:\n")
    for i, (id_provider, info) in enumerate(disponibili, 1):
        gratuito = "gratuito" if info["gratuito"] else "a pagamento"
        print(f"    {i}. {info['nome']} ({gratuito})")

    print()

    while True:
        scelta = input(f"    Inserisci il numero [1-{len(disponibili)}]: ").strip()
        try:
            indice = int(scelta) - 1
            if 0 <= indice < len(disponibili):
                id_provider, info = disponibili[indice]
                print(f"\n[+] Provider scelto: {info['nome']}\n")
                return id_provider
            else:
                print(f"    Inserisci un numero tra 1 e {len(disponibili)}")
        except ValueError:
            print("    Inserisci un numero valido")


# ============================================================
# PREPARA PROMPT
# ============================================================

def prepara_prompt(report):
    target = report.get("target", "sconosciuto")
    sottodomini = report.get("sottodomini", [])
    ip_map = report.get("ip_map", {})
    scan = report.get("scan", [])
    wayback = report.get("wayback", {})
    virustotal = report.get("virustotal", {})

    testo = f"""Sei un esperto di sicurezza informatica. Analizza i seguenti risultati OSINT su {target}.

============================================================
TARGET: {target}
SOTTODOMINI: {len(sottodomini)}
IP UNICI: {len(ip_map)}
============================================================

SOTTODOMINI:
{chr(10).join(f"  - {s}" for s in sottodomini)}

MAPPA IP:
"""
    for ip, subs in ip_map.items():
        testo += f"\n  {ip}:\n"
        for sub in subs:
            testo += f"    - {sub}\n"

    if scan:
        testo += "\nPORT SCAN:\n"
        for r in scan:
            testo += f"\n  IP: {r.get('ip')}\n"
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

    if virustotal:
        testo += "\nVIRUSTOTAL:\n"
        for ip_data in virustotal.get("ip", []):
            if ip_data.get("trovato"):
                testo += (f"  {ip_data['ip']} — rischio {ip_data.get('rischio')} "
                         f"({ip_data.get('malevolo', 0)} engine)\n")
        for dom_data in virustotal.get("domini", []):
            if dom_data.get("trovato") and dom_data.get("malevolo", 0) > 0:
                testo += (f"  {dom_data['dominio']} — rischio {dom_data.get('rischio')} "
                         f"({dom_data.get('malevolo', 0)} engine)\n")

    if wayback:
        testo += f"\nWAYBACK MACHINE:\n"
        testo += f"  Prima archiviazione: {wayback.get('prima_archiviazione', 'N/A')}\n"
        testo += f"  URL totali trovati: {wayback.get('totale_url_trovati', 0)}\n"
        url_int = wayback.get("url_interessanti", {})
        for categoria, url_list in url_int.items():
            testo += f"\n  {categoria.upper()}:\n"
            for entry in url_list[:5]:
                testo += f"    - {entry['url']} [{entry['timestamp']}]\n"

    testo += """
============================================================
Produci un report con queste sezioni:

1. PANORAMICA
2. SOTTODOMINI INTERESSANTI
3. ANALISI PORTE E SERVIZI
4. TECNOLOGIE IDENTIFICATE
5. FINDINGS VIRUSTOTAL (se presenti)
6. FINDINGS WAYBACK MACHINE (se presenti)
7. PRIORITA' DI APPROFONDIMENTO
8. NOTE DI SICUREZZA

Sii preciso e tecnico. Contesto: pentest autorizzato.
============================================================"""

    return testo


# ============================================================
# CHIAMATE AI — un metodo per provider
# ============================================================

def chiama_anthropic(prompt, api_key):
    risposta = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        },
        json={
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 16000,
            "messages": [{"role": "user", "content": prompt}]
        },
        timeout=60
    )
    risposta.raise_for_status()
    return risposta.json()["content"][0]["text"]


def chiama_gemini(prompt, api_key):
    risposta = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}",
        headers={"Content-Type": "application/json"},
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 8192}
        },
        timeout=60
    )
    risposta.raise_for_status()
    return risposta.json()["candidates"][0]["content"]["parts"][0]["text"]


def chiama_groq(prompt, api_key):
    risposta = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        json={
            "model": "llama-3.3-70b-versatile",
            "max_tokens": 8192,
            "messages": [{"role": "user", "content": prompt}]
        },
        timeout=60
    )
    risposta.raise_for_status()
    return risposta.json()["choices"][0]["message"]["content"]


def chiama_openai(prompt, api_key):
    risposta = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        json={
            "model": "gpt-4o-mini",
            "max_tokens": 16384,
            "messages": [{"role": "user", "content": prompt}]
        },
        timeout=60
    )
    risposta.raise_for_status()
    return risposta.json()["choices"][0]["message"]["content"]


# ============================================================
# ROUTER — chiama il provider giusto
# ============================================================

def chiama_ai(prompt, config, provider=None):
    if provider is None:
        provider = config.get("AI_PROVIDER", "gemini").lower()

    chiama = {
        "anthropic": (chiama_anthropic, "ANTHROPIC_API_KEY"),
        "gemini":    (chiama_gemini,    "GEMINI_API_KEY"),
        "groq":      (chiama_groq,      "GROQ_API_KEY"),
        "openai":    (chiama_openai,    "OPENAI_API_KEY"),
    }

    if provider not in chiama:
        raise Exception(f"Provider '{provider}' non riconosciuto")

    funzione, chiave_key = chiama[provider]
    api_key = config.get(chiave_key)

    if not api_key:
        raise Exception(f"Key {chiave_key} non trovata nel .env")

    return funzione(prompt, api_key)


# ============================================================
# ANALISI CON FALLBACK INTERATTIVO
# ============================================================

def esegui_analisi(prompt, config, provider):
    provider_usati = []

    while True:
        provider_usati.append(provider)
        nome = PROVIDER_INFO.get(provider, {}).get("nome", provider)

        print(f"[*] Analisi con {nome}...")

        try:
            risultato = chiama_ai(prompt, config, provider)
            print(f"[+] Analisi completata con {nome}")
            return risultato, provider

        except Exception as e:
            print(f"[!] Errore con {nome}: {e}")

            # Cerca altri provider disponibili non ancora provati
            altri = [
                p for p in PROVIDER_INFO
                if config.get(PROVIDER_INFO[p]["key"])
                and p not in provider_usati
            ]

            if not altri:
                print("[!] Nessun altro provider disponibile.")
                return None, provider

            print(f"\n[?] Vuoi provare con un altro provider?")
            risposta = input("    [y/n]: ").strip().lower()

            if risposta not in ["y", "yes", "s", "si"]:
                return None, provider

            # Scegli tra gli altri disponibili
            provider = scegli_provider(config, escludi=provider_usati)

            if not provider:
                print("[!] Nessun altro provider disponibile.")
                return None, provider


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

    print("\n" + "="*50)
    print("       ReconAI — Analisi AI")
    print("="*50)
    print(f"  Target  : {report.get('target')}")
    print(f"  Report  : {report_path}")
    print("="*50)

    # Scegli provider interattivamente
    provider = scegli_provider(config)

    if not provider:
        print("[!] Nessun provider configurato nel .env")
        print("    Aggiungi almeno una key (GEMINI_API_KEY, GROQ_API_KEY, ecc.)")
        sys.exit(1)

    # Prepara prompt
    prompt = prepara_prompt(report)

    # Esegui analisi con fallback
    analisi, provider_usato = esegui_analisi(prompt, config, provider)

    if not analisi:
        print("[!] Analisi fallita con tutti i provider disponibili.")
        sys.exit(1)

    # Stampa risultato
    print("\n" + "="*50)
    print(f"  ANALISI — {PROVIDER_INFO.get(provider_usato, {}).get('nome', provider_usato)}")
    print("="*50 + "\n")
    print(analisi)

    # Salva nella cartella del report
    cartella = os.path.dirname(report_path)
    output_path = os.path.join(cartella, f"analisi_{provider_usato}.txt")

    with open(output_path, "w") as f:
        f.write(f"ANALISI OSINT — {report.get('target')}\n")
        f.write(f"Provider  : {PROVIDER_INFO.get(provider_usato, {}).get('nome', provider_usato)}\n")
        f.write(f"Generata  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        f.write(analisi)

    print(f"\n[+] Analisi salvata in: {output_path}\n")


if __name__ == "__main__":
    main()
