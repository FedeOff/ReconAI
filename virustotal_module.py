# ============================================================
# ReconAI - Modulo VirusTotal
# Per ogni IP e dominio controlla reputazione, blacklist,
# malware associati e categorie
# ============================================================

import requests
import json
import os
import time


# ============================================================
# CARICA API KEY
# ============================================================

def carica_key_vt():
    key = os.environ.get("VIRUSTOTAL_API_KEY")
    if key:
        return key

    try:
        with open(".env", "r") as f:
            for riga in f:
                riga = riga.strip()
                if not riga or riga.startswith("#"):
                    continue
                if "=" in riga:
                    chiave, valore = riga.split("=", 1)
                    if chiave.strip() == "VIRUSTOTAL_API_KEY":
                        return valore.strip()
    except FileNotFoundError:
        pass

    return None


# ============================================================
# FUNZIONE BASE — chiama VirusTotal API v3
# ============================================================

def vt_get(endpoint, api_key):
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": api_key}

    risposta = requests.get(url, headers=headers, timeout=15)

    # 404 = non trovato in VT, normale
    if risposta.status_code == 404:
        return None

    risposta.raise_for_status()
    return risposta.json()


# ============================================================
# ANALIZZA UN SINGOLO IP
# ============================================================

def analizza_ip(ip, api_key):
    dati = vt_get(f"ip_addresses/{ip}", api_key)

    if not dati:
        return {"ip": ip, "trovato": False}

    attributi = dati.get("data", {}).get("attributes", {})

    # Statistiche analisi — quanti engine lo segnalano come malevolo
    stats = attributi.get("last_analysis_stats", {})
    malevolo = stats.get("malicious", 0)
    sospetto = stats.get("suspicious", 0)
    pulito = stats.get("undetected", 0) + stats.get("harmless", 0)
    totale = sum(stats.values()) if stats else 0

    # Reputazione — negativa = cattiva, positiva = buona
    reputazione = attributi.get("reputation", 0)

    # Paese e ASN
    paese = attributi.get("country", "")
    asn = attributi.get("asn", "")
    org = attributi.get("as_owner", "")

    # Categorie (CDN, hosting, ecc.)
    categorie = list(attributi.get("categories", {}).values())

    # Engine che lo segnalano come malevolo
    analisi = attributi.get("last_analysis_results", {})
    segnalazioni = [
        engine for engine, risultato in analisi.items()
        if risultato.get("category") in ["malicious", "suspicious"]
    ]

    return {
        "ip": ip,
        "trovato": True,
        "reputazione": reputazione,
        "malevolo": malevolo,
        "sospetto": sospetto,
        "pulito": pulito,
        "totale_engine": totale,
        "paese": paese,
        "asn": asn,
        "organizzazione": org,
        "categorie": categorie[:5],
        "segnalato_da": segnalazioni[:10],
        "rischio": calcola_rischio(malevolo, sospetto, reputazione)
    }


# ============================================================
# ANALIZZA UN SINGOLO DOMINIO
# ============================================================

def analizza_dominio(dominio, api_key):
    dati = vt_get(f"domains/{dominio}", api_key)

    if not dati:
        return {"dominio": dominio, "trovato": False}

    attributi = dati.get("data", {}).get("attributes", {})

    stats = attributi.get("last_analysis_stats", {})
    malevolo = stats.get("malicious", 0)
    sospetto = stats.get("suspicious", 0)
    totale = sum(stats.values()) if stats else 0

    reputazione = attributi.get("reputation", 0)
    categorie = list(attributi.get("categories", {}).values())

    # Registrar e date
    registrar = attributi.get("registrar", "")
    creazione = attributi.get("creation_date", "")
    scadenza = attributi.get("expiration_date", "")

    analisi = attributi.get("last_analysis_results", {})
    segnalazioni = [
        engine for engine, risultato in analisi.items()
        if risultato.get("category") in ["malicious", "suspicious"]
    ]

    return {
        "dominio": dominio,
        "trovato": True,
        "reputazione": reputazione,
        "malevolo": malevolo,
        "sospetto": sospetto,
        "totale_engine": totale,
        "categorie": categorie[:5],
        "registrar": registrar,
        "creazione": creazione,
        "scadenza": scadenza,
        "segnalato_da": segnalazioni[:10],
        "rischio": calcola_rischio(malevolo, sospetto, reputazione)
    }


# ============================================================
# CALCOLA LIVELLO DI RISCHIO
# ============================================================

def calcola_rischio(malevolo, sospetto, reputazione):
    if malevolo >= 5 or reputazione <= -50:
        return "ALTO"
    elif malevolo >= 1 or sospetto >= 3 or reputazione <= -10:
        return "MEDIO"
    else:
        return "BASSO"


# ============================================================
# FUNZIONE PRINCIPALE
# ============================================================

def analizza_con_virustotal(sottodomini, ip_map):

    api_key = carica_key_vt()

    if not api_key:
        print("[!] VIRUSTOTAL_API_KEY non trovata nel .env")
        return None

    print("\n[*] Avvio analisi VirusTotal...")
    print(f"[*] IP da analizzare: {len(ip_map)}")
    print(f"[*] Dominio principale + sottodomini interessanti")
    print("[*] Limite free: 500 req/giorno, 4 req/minuto\n")

    risultati = {
        "ip": [],
        "domini": []
    }

    # ============================================================
    # ANALISI IP
    # ============================================================

    print("--- Analisi IP ---")
    for i, (ip, subs) in enumerate(ip_map.items(), 1):
        print(f"  [{i}/{len(ip_map)}] {ip}...", end=" ", flush=True)

        risultato = analizza_ip(ip, api_key)
        risultato["sottodomini"] = subs
        risultati["ip"].append(risultato)

        if risultato["trovato"]:
            rischio = risultato["rischio"]
            malevolo = risultato["malevolo"]
            print(f"rischio {rischio} — {malevolo} engine lo segnalano")
        else:
            print("non trovato in VT")

        # Rate limit: max 4 richieste/minuto nel piano free
        time.sleep(15)

    # ============================================================
    # ANALISI DOMINI — solo quelli interessanti
    # ============================================================

    parole_chiave = ["admin", "api", "dev", "staging", "test", "vpn",
                     "mail", "remote", "beta", "old", "backup", "panel",
                     "login", "dashboard", "internal", "private"]

    domini_interessanti = [s for s in sottodomini
                           if any(k in s.lower() for k in parole_chiave)]

    # Aggiungi il dominio root (primo sottodominio senza prefisso)
    if sottodomini:
        root = ".".join(sottodomini[0].split(".")[-2:])
        if root not in domini_interessanti:
            domini_interessanti.insert(0, root)

    # Limita a 10 per non esaurire le query free
    domini_interessanti = domini_interessanti[:10]

    print(f"\n--- Analisi Domini ({len(domini_interessanti)}) ---")
    for i, dominio in enumerate(domini_interessanti, 1):
        print(f"  [{i}/{len(domini_interessanti)}] {dominio}...", end=" ", flush=True)

        risultato = analizza_dominio(dominio, api_key)
        risultati["domini"].append(risultato)

        if risultato["trovato"]:
            rischio = risultato["rischio"]
            malevolo = risultato["malevolo"]
            print(f"rischio {rischio} — {malevolo} engine lo segnalano")
        else:
            print("non trovato in VT")

        time.sleep(15)

    # ============================================================
    # RIEPILOGO
    # ============================================================

    ip_alto_rischio = [r for r in risultati["ip"]
                       if r.get("rischio") == "ALTO"]
    ip_medio_rischio = [r for r in risultati["ip"]
                        if r.get("rischio") == "MEDIO"]
    domini_alto_rischio = [r for r in risultati["domini"]
                           if r.get("rischio") == "ALTO"]

    print(f"\n[+] Analisi VirusTotal completata")
    print(f"    IP alto rischio  : {len(ip_alto_rischio)}")
    print(f"    IP medio rischio : {len(ip_medio_rischio)}")
    print(f"    Domini a rischio : {len(domini_alto_rischio)}")

    # Salva risultati
    nome_file = "risultati_virustotal.json"
    with open(nome_file, "w") as f:
        json.dump(risultati, f, indent=2)

    print(f"[+] Risultati salvati in: {nome_file}")
    return risultati


# ============================================================
# TEST STANDALONE
# ============================================================

if __name__ == "__main__":
    from shodan_module import risolvi_ip

    test_sottodomini = [
        "www.tesla.com",
        "api.tesla.com",
        "shop.tesla.com"
    ]

    ip_map = risolvi_ip(test_sottodomini)
    analizza_con_virustotal(test_sottodomini, ip_map)
