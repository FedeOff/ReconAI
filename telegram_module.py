# ============================================================
# ReconAI - Modulo Telegram
# Invia riepilogo + bottone per scaricare analisi completa
# ============================================================

import requests
import os
import json
import time


# ============================================================
# CARICA CONFIGURAZIONE
# ============================================================

def carica_config_telegram():
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

    for chiave in ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"]:
        valore = os.environ.get(chiave)
        if valore:
            config[chiave] = valore

    return config


# ============================================================
# FUNZIONI BASE TELEGRAM API
# ============================================================

def invia_messaggio(token, chat_id, testo, reply_markup=None):
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": testo
    }

    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup)

    risposta = requests.post(url, json=payload, timeout=10)
    risposta.raise_for_status()
    return risposta.json()


def invia_file(token, chat_id, path_file, caption=""):
    url = f"https://api.telegram.org/bot{token}/sendDocument"

    with open(path_file, "rb") as f:
        risposta = requests.post(
            url,
            data={"chat_id": chat_id, "caption": caption},
            files={"document": f},
            timeout=30
        )
    risposta.raise_for_status()
    return risposta.json()


def get_updates(token, offset=None):
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    params = {"timeout": 10}
    if offset:
        params["offset"] = offset

    risposta = requests.get(url, params=params, timeout=15)
    risposta.raise_for_status()
    return risposta.json()


# ============================================================
# PREPARA RIEPILOGO TESTUALE
# ============================================================

def prepara_riepilogo(report, analisi_path=None):
    target = report.get("target", "sconosciuto")
    sottodomini = report.get("sottodomini", [])
    ip_map = report.get("ip_map", {})
    scan = report.get("scan", [])

    totale_porte = sum(r.get("totale_porte", 0) for r in scan)
    ip_con_porte = sum(1 for r in scan if r.get("totale_porte", 0) > 0)

    # Sottodomini interessanti
    parole_chiave = ["admin", "api", "dev", "staging", "test", "vpn",
                     "mail", "remote", "beta", "old", "backup", "panel",
                     "login", "dashboard", "internal", "private"]
    interessanti = [s for s in sottodomini
                    if any(k in s.lower() for k in parole_chiave)]

    # Porte aperte per IP
    porte_trovate = []
    for r in scan:
        if r.get("porte_aperte"):
            ip = r.get("ip")
            subs = r.get("sottodomini", [])[:2]
            for p in r["porte_aperte"]:
                porte_trovate.append(
                    f"{ip} [{', '.join(subs)}] — {p['porta']}/tcp {p['servizio']}"
                )

    testo = (
        f"ReconAI — Scan Completato\n"
        f"{'='*35}\n\n"
        f"Target: {target}\n\n"
        f"RIEPILOGO\n"
        f"• Sottodomini trovati: {len(sottodomini)}\n"
        f"• IP unici: {len(ip_map)}\n"
        f"• IP con porte aperte: {ip_con_porte}\n"
        f"• Porte totali trovate: {totale_porte}\n"
    )

    if interessanti:
        testo += f"\nSOTTODOMINI INTERESSANTI ({len(interessanti)})\n"
        for sub in interessanti[:10]:
            testo += f"• {sub}\n"
        if len(interessanti) > 10:
            testo += f"• ... e altri {len(interessanti) - 10}\n"

    if porte_trovate:
        testo += f"\nPORTE APERTE\n"
        for p in porte_trovate[:10]:
            testo += f"• {p}\n"
        if len(porte_trovate) > 10:
            testo += f"• ... e altre {len(porte_trovate) - 10}\n"

    if analisi_path and os.path.exists(analisi_path):
        testo += "\nAnalisi AI disponibile — clicca il bottone per scaricarla."

    return testo


# ============================================================
# ATTENDI LA SCELTA DELL'UTENTE
# ============================================================

def attendi_scelta(token, timeout=60):
    print("[*] Aspetto risposta su Telegram (60s)...")

    offset = None
    inizio = time.time()

    while time.time() - inizio < timeout:
        try:
            updates = get_updates(token, offset)

            for update in updates.get("result", []):
                offset = update["update_id"] + 1

                if "callback_query" in update:
                    callback = update["callback_query"]
                    scelta = callback["data"]
                    callback_id = callback["id"]

                    requests.post(
                        f"https://api.telegram.org/bot{token}/answerCallbackQuery",
                        json={"callback_query_id": callback_id},
                        timeout=5
                    )

                    return scelta

        except Exception as e:
            print(f"[!] Errore polling: {e}")

        time.sleep(2)

    return None


# ============================================================
# FUNZIONE PRINCIPALE
# ============================================================

def invia_report_telegram(report, analisi_path=None):

    config = carica_config_telegram()
    token = config.get("TELEGRAM_BOT_TOKEN")
    chat_id = config.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print("[!] TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID non trovati nel .env")
        return False

    print("\n[*] Invio notifica Telegram...")

    try:
        riepilogo = prepara_riepilogo(report, analisi_path)

        # Bottone unico per scaricare il file
        reply_markup = None
        if analisi_path and os.path.exists(analisi_path):
            reply_markup = {
                "inline_keyboard": [[
                    {"text": "Scarica analisi completa", "callback_data": "file"}
                ]]
            }

        invia_messaggio(token, chat_id, riepilogo, reply_markup)
        print("[+] Riepilogo inviato su Telegram")

        # Aspetta click solo se c'è il bottone
        if reply_markup:
            scelta = attendi_scelta(token, timeout=60)

            if scelta == "file":
                invia_file(
                    token, chat_id,
                    analisi_path,
                    caption=f"Analisi completa — {report.get('target')}"
                )
                print(f"[+] File analisi inviato")

            elif scelta is None:
                print("[!] Nessuna risposta in 60s — il file resta disponibile con analyze.py")

        return True

    except Exception as e:
        print(f"[!] Errore Telegram: {e}")
        return False


# ============================================================
# TEST STANDALONE
# ============================================================

if __name__ == "__main__":
    report_test = {
        "target": "test.com",
        "sottodomini": ["www.test.com", "admin.test.com", "api.test.com",
                        "staging.test.com", "mail.test.com", "dev.test.com"],
        "ip_map": {"1.2.3.4": ["www.test.com", "admin.test.com"]},
        "scan": [{
            "ip": "1.2.3.4",
            "sottodomini": ["www.test.com"],
            "totale_porte": 2,
            "porte_aperte": [
                {"porta": 80, "servizio": "HTTP", "banner": "nginx 1.18"},
                {"porta": 443, "servizio": "HTTPS", "banner": ""}
            ]
        }]
    }

    invia_report_telegram(report_test, None)
