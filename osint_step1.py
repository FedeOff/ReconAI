# ============================================================
# OSINT Agent - Step 1
# Trova sottodomini con fallback automatico crt.sh → HackerTarget
# ============================================================

import requests
import json

TARGET = "tesla.com"


def trova_sottodomini(dominio):

    print(f"\n[*] Target: {dominio}")

    sottodomini = set()

    # ============================================================
    # FONTE 1: crt.sh (timeout 20 secondi)
    # ============================================================

    print("[*] Provo crt.sh (timeout 20s)...")

    try:
        url_crt = f"https://crt.sh/?q=%.{dominio}&output=json"
        risposta = requests.get(url_crt, timeout=20)
        risposta.raise_for_status()

        if not risposta.text:
            raise Exception("Risposta vuota")

        dati = risposta.json()

        for certificato in dati:
            nome = certificato["name_value"].strip()
            for riga in nome.split("\n"):
                riga = riga.strip()
                if dominio in riga and not riga.startswith("*"):
                    sottodomini.add(riga)

        print(f"[+] crt.sh OK — {len(sottodomini)} risultati")

    except Exception as errore:

        # ============================================================
        # FALLBACK: HackerTarget
        # ============================================================

        print(f"[!] crt.sh non disponibile ({errore})")
        print("[*] Passo a HackerTarget...")

        try:
            url_ht = f"https://api.hackertarget.com/hostsearch/?q={dominio}"
            risposta = requests.get(url_ht, timeout=15)
            risposta.raise_for_status()

            righe = risposta.text.strip().split("\n")

            for riga in righe:
                if "," in riga:
                    nome = riga.split(",")[0].strip()
                    if dominio in nome and not nome.startswith("*"):
                        sottodomini.add(nome)

            print(f"[+] HackerTarget OK — {len(sottodomini)} risultati")

        except Exception as errore2:
            print(f"[!] Anche HackerTarget non disponibile: {errore2}")
            print("[!] Nessuna fonte raggiungibile. Riprova tra qualche minuto.")
            return []

    # Restituisce la lista ordinata — il salvataggio lo fa main.py
    return sorted(list(sottodomini))


# ============================================================
# TEST STANDALONE
# Quando lanci solo questo file stampa i risultati a schermo
# ============================================================

if __name__ == "__main__":
    risultato = trova_sottodomini(TARGET)
    print(f"\n[+] Trovati {len(risultato)} sottodomini:\n")
    for sub in risultato:
        print(f"    {sub}")
