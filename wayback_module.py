# ============================================================
# ReconAI - Modulo Wayback Machine
# Cerca versioni archiviate del target e dei sottodomini
# Nessuna API key necessaria — completamente pubblico
# ============================================================

import requests
import json
import time
from datetime import datetime


# ============================================================
# FUNZIONE BASE — CDX API di Wayback Machine
# CDX = indice di tutti gli URL archiviati
# ============================================================

def cerca_url_archiviati(dominio, limit=500):
    print(f"    [→] {dominio}...")

    # CDX API — restituisce tutti gli URL archiviati per un dominio
    # fl = campi da restituire
    # collapse = elimina duplicati sullo stesso URL
    # output = formato json
    url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{dominio}/*",
        "output": "json",
        "fl": "original,statuscode,timestamp,mimetype",
        "collapse": "urlkey",
        "limit": limit,
        "filter": "statuscode:200"   # solo URL che rispondevano 200
    }

    try:
        risposta = requests.get(url, params=params, timeout=30)
        risposta.raise_for_status()

        dati = risposta.json()

        # Il primo elemento è l'header dei campi — lo saltiamo
        if not dati or len(dati) <= 1:
            return []

        risultati = []
        for riga in dati[1:]:  # salta header
            if len(riga) >= 4:
                risultati.append({
                    "url": riga[0],
                    "status": riga[1],
                    "timestamp": riga[2],
                    "mimetype": riga[3]
                })

        return risultati

    except Exception as e:
        print(f"        [!] Errore: {e}")
        return []


# ============================================================
# ANALIZZA GLI URL TROVATI
# Cerca pattern interessanti dal punto di vista security
# ============================================================

def analizza_url(url_list, dominio):

    # Pattern interessanti in un pentest
    pattern_interessanti = {
        "admin":      ["admin", "administrator", "cms", "cpanel", "dashboard",
                       "manage", "manager", "panel", "control"],
        "auth":       ["login", "logout", "signin", "signup", "register",
                       "auth", "oauth", "sso", "password", "reset"],
        "api":        ["api", "v1", "v2", "v3", "graphql", "rest",
                       "endpoint", "webhook", "swagger", "docs/api"],
        "file":       [".zip", ".tar", ".gz", ".bak", ".sql", ".db",
                       ".env", ".config", ".conf", ".xml", ".json"],
        "dev":        ["dev", "development", "staging", "test", "beta",
                       "debug", "demo", "sandbox", "qa", "uat"],
        "infra":      ["wp-admin", "wp-login", "phpmyadmin", "adminer",
                       "jenkins", "gitlab", "jira", "confluence", "kibana"],
    }

    trovati = {categoria: [] for categoria in pattern_interessanti}
    tutti_sottodomini = set()

    for entry in url_list:
        url = entry.get("url", "").lower()
        timestamp = entry.get("timestamp", "")

        # Estrai il sottodominio dall'URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            host = parsed.netloc
            if host and dominio in host:
                tutti_sottodomini.add(host)
        except Exception:
            pass

        # Controlla se l'URL matcha pattern interessanti
        for categoria, keywords in pattern_interessanti.items():
            if any(kw in url for kw in keywords):
                # Evita duplicati nella stessa categoria
                if url not in [u["url"] for u in trovati[categoria]]:
                    trovati[categoria].append({
                        "url": entry.get("url"),
                        "timestamp": formatta_timestamp(timestamp)
                    })

    # Rimuovi categorie vuote
    trovati = {k: v for k, v in trovati.items() if v}

    return trovati, list(tutti_sottodomini)


# ============================================================
# FORMATTA TIMESTAMP WAYBACK
# Il timestamp è in formato YYYYMMDDHHmmss
# ============================================================

def formatta_timestamp(ts):
    try:
        dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return ts


# ============================================================
# TROVA LA PRIMA E ULTIMA ARCHIVIAZIONE
# ============================================================

def prima_ultima_archiviazione(dominio):
    url = "http://web.archive.org/cdx/search/cdx"

    try:
        # Prima archiviazione
        params_prima = {
            "url": f"{dominio}",
            "output": "json",
            "fl": "timestamp",
            "limit": 1,
            "from": "19900101"
        }
        r = requests.get(url, params=params_prima, timeout=15)
        dati = r.json()
        prima = formatta_timestamp(dati[1][0]) if len(dati) > 1 else "N/A"

        # Ultima archiviazione
        params_ultima = {
            "url": f"{dominio}",
            "output": "json",
            "fl": "timestamp",
            "limit": 1,
            "to": "29991231"
        }
        r = requests.get(url, params=params_ultima, timeout=15)
        dati = r.json()

        # Prende l'ultima riga
        ultima = formatta_timestamp(dati[-1][0]) if len(dati) > 1 else "N/A"

        return prima, ultima

    except Exception:
        return "N/A", "N/A"


# ============================================================
# FUNZIONE PRINCIPALE
# ============================================================

def analizza_con_wayback(dominio, sottodomini):

    print("\n[*] Avvio analisi Wayback Machine...")
    print("[*] Nessuna API key richiesta — fonte pubblica\n")

    risultati = {
        "dominio": dominio,
        "prima_archiviazione": "",
        "ultima_archiviazione": "",
        "totale_url_trovati": 0,
        "sottodomini_storici": [],
        "url_interessanti": {}
    }

    # ============================================================
    # PRIMA E ULTIMA ARCHIVIAZIONE
    # ============================================================

    print(f"[*] Cerco storico archiviazioni per {dominio}...")
    prima, ultima = prima_ultima_archiviazione(dominio)
    risultati["prima_archiviazione"] = prima
    risultati["ultima_archiviazione"] = ultima
    print(f"[+] Prima archiviazione: {prima}")
    print(f"[+] Ultima archiviazione: {ultima}")

    # ============================================================
    # CERCA URL ARCHIVIATI
    # Lo fa sul dominio principale + sottodomini interessanti
    # ============================================================

    parole_chiave = ["admin", "api", "dev", "staging", "test", "vpn",
                     "mail", "remote", "beta", "old", "backup", "panel"]

    domini_da_cercare = [dominio]
    domini_da_cercare += [s for s in sottodomini
                          if any(k in s.lower() for k in parole_chiave)][:5]

    print(f"\n[*] Cerco URL archiviati per {len(domini_da_cercare)} domini...")

    tutti_url = []
    tutti_sottodomini_storici = set()

    for target in domini_da_cercare:
        url_trovati = cerca_url_archiviati(target, limit=300)
        print(f"        trovati {len(url_trovati)} URL")

        tutti_url.extend(url_trovati)
        time.sleep(2)  # rispettiamo i server di archive.org

    risultati["totale_url_trovati"] = len(tutti_url)

    # ============================================================
    # ANALISI DEI RISULTATI
    # ============================================================

    if tutti_url:
        url_interessanti, sottodomini_storici = analizza_url(tutti_url, dominio)

        risultati["url_interessanti"] = url_interessanti
        risultati["sottodomini_storici"] = list(sottodomini_storici)

        tutti_sottodomini_storici.update(sottodomini_storici)

    # ============================================================
    # RIEPILOGO
    # ============================================================

    print(f"\n[+] Analisi Wayback completata")
    print(f"    URL totali trovati    : {len(tutti_url)}")
    print(f"    Sottodomini storici   : {len(tutti_sottodomini_storici)}")

    for categoria, url_list in risultati["url_interessanti"].items():
        print(f"    {categoria.upper():12} : {len(url_list)} URL")

    # Salva risultati
    nome_file = "risultati_wayback.json"
    with open(nome_file, "w") as f:
        json.dump(risultati, f, indent=2)

    print(f"[+] Risultati salvati in: {nome_file}")
    return risultati


# ============================================================
# TEST STANDALONE
# ============================================================

if __name__ == "__main__":
    test_sottodomini = [
        "www.tesla.com",
        "api.tesla.com",
        "shop.tesla.com",
        "admin.tesla.com"
    ]

    analizza_con_wayback("tesla.com", test_sottodomini)
