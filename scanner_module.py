# ============================================================
# OSINT Agent - Modulo Port Scanner
# Scansiona le porte più comuni su ogni IP
# Funziona senza API key, completamente gratuito
# ============================================================

import socket
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# CONFIGURAZIONE
# ============================================================

# Porte più comuni da controllare
# Puoi aggiungerne altre o togliere quelle che non ti interessano
PORTE_COMUNI = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    9200: "Elasticsearch",
    27017:"MongoDB"
}

# Timeout per ogni porta (secondi)
# Troppo basso = falsi negativi, troppo alto = lento
TIMEOUT = 1.5

# Quante porte scansionare in parallelo
# Con thread multipli è molto più veloce
MAX_THREADS = 50


# ============================================================
# FUNZIONE: testa una singola porta
# Restituisce True se aperta, False se chiusa
# ============================================================

def testa_porta(ip, porta, timeout=TIMEOUT):
    try:
        # socket.socket = crea una connessione di rete
        # AF_INET = IPv4, SOCK_STREAM = TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex = prova a connettersi
        # restituisce 0 se riesce, un numero di errore altrimenti
        risultato = sock.connect_ex((ip, porta))
        sock.close()

        return risultato == 0  # True = porta aperta

    except Exception:
        return False


# ============================================================
# FUNZIONE: leggi il banner di un servizio
# Il "banner" è il messaggio che un servizio manda
# quando ti connetti — spesso rivela versione e software
# ============================================================

def leggi_banner(ip, porta, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, porta))

        # Alcuni servizi mandano il banner subito (SSH, FTP, SMTP)
        # Altri lo mandano solo dopo una richiesta (HTTP)
        if porta in [80, 8080, 8443, 8888]:
            # Per HTTP mandiamo una richiesta HEAD minimale
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        # recv(256) = leggi fino a 256 byte di risposta
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:150]  # primi 150 caratteri

    except Exception:
        return ""


# ============================================================
# FUNZIONE: scansiona un singolo IP
# ============================================================

def scansiona_ip(ip, sottodomini_associati):

    print(f"    [→] {ip} ({', '.join(sottodomini_associati[:2])})")

    porte_aperte = []

    # Usiamo ThreadPoolExecutor per testare più porte in parallelo
    # Senza thread: 19 porte × 1.5s timeout = ~28 secondi per IP
    # Con 50 thread: tutte le porte in ~1.5 secondi per IP
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

        # Creiamo un "future" per ogni porta
        # Un future = un compito che verrà eseguito in parallelo
        futures = {
            executor.submit(testa_porta, ip, porta): (porta, nome)
            for porta, nome in PORTE_COMUNI.items()
        }

        # as_completed = aspetta che ogni future finisca
        for future in as_completed(futures):
            porta, nome_servizio = futures[future]

            try:
                aperta = future.result()

                if aperta:
                    # Porta aperta — proviamo a leggere il banner
                    banner = leggi_banner(ip, porta)

                    info = {
                        "porta": porta,
                        "servizio": nome_servizio,
                        "banner": banner
                    }
                    porte_aperte.append(info)
                    print(f"        [+] {porta}/tcp  {nome_servizio}  {banner[:50] if banner else ''}")

            except Exception:
                pass

    # Ordina per numero di porta
    porte_aperte.sort(key=lambda x: x["porta"])

    return {
        "ip": ip,
        "sottodomini": sottodomini_associati,
        "porte_aperte": porte_aperte,
        "totale_porte": len(porte_aperte)
    }


# ============================================================
# FUNZIONE PRINCIPALE del modulo
# Questa è quella chiamata dallo script principale
# ============================================================

def scansiona_tutti(ip_map):

    print("\n[*] Avvio port scan...")
    print(f"[*] Target: {len(ip_map)} IP unici")
    print(f"[*] Porte: {len(PORTE_COMUNI)} | Threads: {MAX_THREADS} | Timeout: {TIMEOUT}s\n")

    risultati = []
    inizio = time.time()

    for ip, sottodomini in ip_map.items():
        risultato = scansiona_ip(ip, sottodomini)
        risultati.append(risultato)

    durata = round(time.time() - inizio, 1)

    # ============================================================
    # RIEPILOGO
    # ============================================================

    print(f"\n[+] Scan completato in {durata}s")

    totale_porte = sum(r["totale_porte"] for r in risultati)
    ip_con_porte = [r for r in risultati if r["totale_porte"] > 0]

    print(f"[+] IP con porte aperte: {len(ip_con_porte)}/{len(risultati)}")
    print(f"[+] Totale porte trovate: {totale_porte}")

    # Salva i risultati
    nome_file = "risultati_scan.json"
    with open(nome_file, "w") as f:
        json.dump(risultati, f, indent=2)

    print(f"[+] Risultati salvati in: {nome_file}")
    return risultati


# ============================================================
# TEST STANDALONE
# ============================================================

if __name__ == "__main__":
    # Importiamo la funzione di risoluzione IP dal modulo Shodan
    # che abbiamo già scritto — non duplichiamo il codice
    from shodan_module import risolvi_ip

    test_sottodomini = [
        "www.tesla.com",
        "shop.tesla.com",
        "api.tesla.com"
    ]

    ip_map = risolvi_ip(test_sottodomini)
    scansiona_tutti(ip_map)
