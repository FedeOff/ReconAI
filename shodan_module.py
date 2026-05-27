# ============================================================
# OSINT Agent - Modulo Shodan
# Per ogni sottodominio: risolve l'IP e chiede a Shodan
# ============================================================

import requests
import json
import socket
import time
import os

# ============================================================
# CONFIGURAZIONE SICURA
# La key NON va scritta nel codice — si legge da una variabile
# d'ambiente oppure da un file .env
#
# Come impostare la key sul tuo PC:
#   Mac/Linux:  export SHODAN_API_KEY="la-tua-key"
#   Windows:    set SHODAN_API_KEY=la-tua-key
#
# Oppure crea un file .env nella stessa cartella con:
#   SHODAN_API_KEY=la-tua-key
# ============================================================

def carica_key():
    key = os.environ.get("SHODAN_API_KEY")
    if key:
        print(f"[] Key trovata da variabile ambiente: {key[:6]}...")
        return key

    try:
        with open(".env", "r") as f:
            for riga in f:
                if riga.startswith("SHODAN_API_KEY"):
                    key = riga.split("=", 1)[1].strip()
                    print(f"[] Key trovata da .env: {key[:6]}...")
                    return key
    except FileNotFoundError:
        print("[!] File .env non trovato nel path corrente:", os.getcwd())

    return None
    # Prima prova le variabili d'ambiente
    key = os.environ.get("SHODAN_API_KEY")
    if key:
        return key

    # Poi prova il file .env nella stessa cartella
    try:
        with open(".env", "r") as f:
            for riga in f:
                if riga.startswith("SHODAN_API_KEY"):
                    return riga.split("=", 1)[1].strip()
    except FileNotFoundError:
        pass

    return None


# ============================================================
# STEP A: Risolvi i sottodomini in IP
# Molti sottodomini possono puntare allo stesso IP —
# li deduplicchiamo per non sprecare query Shodan
# ============================================================

def risolvi_ip(sottodomini):
    print("\n[*] Risoluzione IP dei sottodomini...")

    # dizionario: { "ip": ["sub1.esempio.com", "sub2.esempio.com"] }
    ip_map = {}

    for sub in sottodomini:
        try:
            # socket.gethostbyname = risolve il DNS, come fa il browser
            ip = socket.gethostbyname(sub)

            if ip not in ip_map:
                ip_map[ip] = []
            ip_map[ip].append(sub)

        except socket.gaierror:
            # Il sottodominio non risolve (DNS non trovato) — saltiamo
            pass

    print(f"[+] {len(sottodomini)} sottodomini → {len(ip_map)} IP unici")
    return ip_map


# ============================================================
# STEP B: Interroga Shodan per ogni IP unico
# ============================================================

def shodan_lookup(ip_map, api_key):
    print("\n[*] Interrogo Shodan per ogni IP...")

    risultati = []

    # enumerate() = ciclo con contatore: (1, ip), (2, ip), ...
    for i, (ip, sottodomini_associati) in enumerate(ip_map.items(), 1):

        print(f"    [{i}/{len(ip_map)}] {ip} ({', '.join(sottodomini_associati[:2])}...)")

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            risposta = requests.get(url, timeout=10)

            # 404 = IP non trovato in Shodan (normale, non è un errore)
            if risposta.status_code == 404:
                print(f"           → non in Shodan")
                continue

            risposta.raise_for_status()
            dati = risposta.json()

            # Estraiamo solo le info utili
            porte = []
            servizi = []

            # "data" contiene un entry per ogni porta/servizio trovato
            for servizio in dati.get("data", []):
                porta = servizio.get("port")
                trasporto = servizio.get("transport", "tcp")
                banner = servizio.get("data", "")[:100]  # primi 100 caratteri
                prodotto = servizio.get("product", "")
                versione = servizio.get("version", "")

                porte.append(f"{porta}/{trasporto}")

                info_servizio = {
                    "porta": porta,
                    "trasporto": trasporto,
                    "prodotto": prodotto,
                    "versione": versione,
                    "banner": banner.strip()
                }
                servizi.append(info_servizio)

            risultato = {
                "ip": ip,
                "sottodomini": sottodomini_associati,
                "paese": dati.get("country_name", ""),
                "org": dati.get("org", ""),
                "porte": porte,
                "servizi": servizi,
                "os": dati.get("os", "")
            }

            risultati.append(risultato)

            # Shodan free plan: max 1 richiesta/secondo
            # time.sleep(1) = aspetta 1 secondo prima della prossima query
            time.sleep(1)

        except Exception as e:
            print(f"           → errore: {e}")
            continue

    print(f"\n[+] Shodan: {len(risultati)} IP con dati trovati")
    return risultati


# ============================================================
# FUNZIONE PRINCIPALE del modulo
# Questa è quella che verrà chiamata dallo script principale
# ============================================================

def analizza_con_shodan(sottodomini):

    # Carica la key in modo sicuro
    api_key = carica_key()

    if not api_key:
        print("[!] API key Shodan non trovata.")
        print("    Crea un file .env con: SHODAN_API_KEY=la-tua-key")
        return None

    # Step A: risolvi gli IP
    ip_map = risolvi_ip(sottodomini)

    if not ip_map:
        print("[!] Nessun IP risolto — controlla la connessione")
        return None

    # Step B: interroga Shodan
    risultati = shodan_lookup(ip_map, api_key)

    # Salva i risultati in JSON
    nome_file = "risultati_shodan.json"
    with open(nome_file, "w") as f:
        json.dump(risultati, f, indent=2)

    print(f"[+] Risultati Shodan salvati in: {nome_file}")
    return risultati


# ============================================================
# TEST STANDALONE
# Puoi lanciare questo file da solo per testarlo
# con una lista di sottodomini di esempio
# ============================================================

if __name__ == "__main__":
    # Sottodomini di test — in produzione arrivano da osint_step1.py
    test_sottodomini = [
        "www.tesla.com",
        "shop.tesla.com",
        "api.tesla.com"
    ]

    analizza_con_shodan(test_sottodomini)
