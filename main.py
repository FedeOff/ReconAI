# ============================================================
# ReconAI - Main
# Orchestra scan + analisi AI + notifica Telegram
#
# Uso:
#   python main.py tesla.com
#   python main.py --target tesla.com
#   python main.py                          (tutto interattivo)
#   python main.py tesla.com --no-scan
#   python main.py tesla.com --no-virustotal
#   python main.py tesla.com --no-wayback
#   python main.py tesla.com --no-telegram
# ============================================================

import argparse
import json
import os
import sys
from datetime import datetime

from osint_step1 import trova_sottodomini
from shodan_module import risolvi_ip
from scanner_module import scansiona_tutti


# ============================================================
# HELPER — chiede y/n interattivamente
# ============================================================

def chiedi(domanda):
    while True:
        risposta = input(f"{domanda} [y/n]: ").strip().lower()
        if risposta in ["y", "yes", "s", "si"]:
            return True
        elif risposta in ["n", "no"]:
            return False
        else:
            print("    Digita 'y' per si o 'n' per no.")


# ============================================================
# ARGPARSE + PROMPT INTERATTIVI
# ============================================================

def leggi_argomenti():
    parser = argparse.ArgumentParser(
        description="ReconAI — OSINT reconnaissance agent",
        epilog="Esempio: python main.py tesla.com"
    )

    parser.add_argument("dominio", nargs="?", help="Dominio target")
    parser.add_argument("--target", "-t", help="Dominio target (alternativa)")
    parser.add_argument("--output", "-o", default="report",
                        help="Cartella output (default: ./report)")
    parser.add_argument("--no-scan", action="store_true",
                        help="Salta il port scan senza chiedere")
    parser.add_argument("--no-virustotal", action="store_true",
                        help="Salta VirusTotal senza chiedere")
    parser.add_argument("--no-wayback", action="store_true",
                        help="Salta Wayback Machine senza chiedere")
    parser.add_argument("--no-telegram", action="store_true",
                        help="Salta Telegram senza chiedere")

    args = parser.parse_args()
    target = args.target or args.dominio

    print("\n" + "="*50)
    print("         ReconAI v0.1")
    print("="*50)

    if not target:
        target = input("\n[?] Inserisci il dominio target: ").strip()
        if not target:
            print("[!] Nessun dominio inserito. Uscita.")
            sys.exit(1)

    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    print(f"\n  Target: {target}\n")

    salta_scan     = args.no_scan        or not chiedi("[?] Vuoi eseguire il port scan?")
    salta_vt       = args.no_virustotal  or not chiedi("[?] Vuoi eseguire l'analisi VirusTotal?")
    salta_wayback  = args.no_wayback     or not chiedi("[?] Vuoi eseguire l'analisi Wayback Machine?")
    salta_telegram = args.no_telegram    or not chiedi("[?] Vuoi ricevere la notifica Telegram?")

    return target, args.output, salta_scan, salta_vt, salta_wayback, salta_telegram


# ============================================================
# SETUP CARTELLA OUTPUT
# ============================================================

def crea_cartella_output(base, dominio):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cartella = os.path.join(base, f"{dominio}_{timestamp}")
    os.makedirs(cartella, exist_ok=True)
    return cartella


# ============================================================
# MAIN
# ============================================================

def main():

    target, output_base, salta_scan, salta_vt, salta_wayback, salta_telegram = leggi_argomenti()

    print("\n" + "-"*50)
    print(f"  Port scan        : {'NO' if salta_scan else 'SI'}")
    print(f"  VirusTotal       : {'NO' if salta_vt else 'SI'}")
    print(f"  Wayback Machine  : {'NO' if salta_wayback else 'SI'}")
    print(f"  Telegram         : {'NO' if salta_telegram else 'SI'}")
    print(f"  Avvio            : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*50)

    cartella = crea_cartella_output(output_base, target)
    print(f"\n[*] Output in: {cartella}\n")

    risultati_completi = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "sottodomini": [],
        "ip_map": {},
        "scan": [],
        "virustotal": {},
        "wayback": {}
    }

    # ============================================================
    # STEP 1: Sottodomini
    # ============================================================

    print("\n" + "-"*40)
    print("STEP 1 — Enumerazione sottodomini")
    print("-"*40)

    sottodomini = trova_sottodomini(target)

    if not sottodomini:
        print("[!] Nessun sottodominio trovato. Uscita.")
        sys.exit(1)

    risultati_completi["sottodomini"] = sottodomini

    with open(os.path.join(cartella, "sottodomini.json"), "w") as f:
        json.dump(sottodomini, f, indent=2)

    # ============================================================
    # STEP 2: Risoluzione IP
    # ============================================================

    print("\n" + "-"*40)
    print("STEP 2 — Risoluzione IP")
    print("-"*40)

    ip_map = risolvi_ip(sottodomini)

    if not ip_map:
        print("[!] Nessun IP risolto. Uscita.")
        sys.exit(1)

    ip_map_serializable = {ip: subs for ip, subs in ip_map.items()}
    risultati_completi["ip_map"] = ip_map_serializable

    with open(os.path.join(cartella, "ip_map.json"), "w") as f:
        json.dump(ip_map_serializable, f, indent=2)

    # ============================================================
    # STEP 3: Port scan
    # ============================================================

    if not salta_scan:
        print("\n" + "-"*40)
        print("STEP 3 — Port scan")
        print("-"*40)

        risultati_scan = scansiona_tutti(ip_map)
        risultati_completi["scan"] = risultati_scan

        with open(os.path.join(cartella, "port_scan.json"), "w") as f:
            json.dump(risultati_scan, f, indent=2)
    else:
        print("\n[*] Port scan saltato")

    # ============================================================
    # STEP 4: VirusTotal
    # ============================================================

    if not salta_vt:
        print("\n" + "-"*40)
        print("STEP 4 — VirusTotal")
        print("-"*40)

        try:
            from virustotal_module import analizza_con_virustotal

            vt_risultati = analizza_con_virustotal(sottodomini, ip_map)

            if vt_risultati:
                risultati_completi["virustotal"] = vt_risultati
                with open(os.path.join(cartella, "virustotal.json"), "w") as f:
                    json.dump(vt_risultati, f, indent=2)
                print(f"[+] VirusTotal salvato in: {cartella}/virustotal.json")
            else:
                print("[!] VirusTotal non disponibile — controlla la key nel .env")

        except Exception as e:
            print(f"[!] Errore VirusTotal: {e}")
    else:
        print("\n[*] VirusTotal saltato")

    # ============================================================
    # STEP 5: Wayback Machine
    # ============================================================

    if not salta_wayback:
        print("\n" + "-"*40)
        print("STEP 5 — Wayback Machine")
        print("-"*40)

        try:
            from wayback_module import analizza_con_wayback

            wb_risultati = analizza_con_wayback(target, sottodomini)

            if wb_risultati:
                risultati_completi["wayback"] = wb_risultati
                with open(os.path.join(cartella, "wayback.json"), "w") as f:
                    json.dump(wb_risultati, f, indent=2)
                print(f"[+] Wayback salvato in: {cartella}/wayback.json")

        except Exception as e:
            print(f"[!] Errore Wayback Machine: {e}")
    else:
        print("\n[*] Wayback Machine saltata")

    # Salva report completo
    report_path = os.path.join(cartella, "report_completo.json")
    with open(report_path, "w") as f:
        json.dump(risultati_completi, f, indent=2)

    # ============================================================
    # STEP 6: Analisi AI
    # ============================================================

    print("\n" + "-"*40)
    print("STEP 6 — Analisi AI")
    print("-"*40)

    analisi_path = None

    try:
        from analyze import prepara_prompt, chiama_ai, carica_config, scegli_provider, esegui_analisi, PROVIDER_INFO

        config = carica_config()

        # Scelta interattiva del provider
        provider = scegli_provider(config)

        if not provider:
            print("[!] Nessun provider configurato nel .env — analisi saltata")
        else:
            prompt = prepara_prompt(risultati_completi)
            analisi, provider_usato = esegui_analisi(prompt, config, provider)

            if analisi:
                analisi_path = os.path.join(cartella, f"analisi_{provider_usato}.txt")
                nome_provider = PROVIDER_INFO.get(provider_usato, {}).get("nome", provider_usato)
                with open(analisi_path, "w") as f:
                    f.write(f"ANALISI OSINT — {target}\n")
                    f.write(f"Provider  : {nome_provider}\n")
                    f.write(f"Generata  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*50 + "\n\n")
                    f.write(analisi)
                print(f"[+] Analisi salvata: {analisi_path}")
            else:
                print("[!] Analisi AI non riuscita")

    except Exception as e:
        print(f"[!] Errore analisi AI: {e}")
        print("[*] Puoi eseguirla manualmente con: python analyze.py")

    # ============================================================
    # RIEPILOGO FINALE
    # ============================================================

    print("\n" + "="*50)
    print("  SCAN COMPLETATO")
    print("="*50)
    print(f"  Sottodomini trovati  : {len(sottodomini)}")
    print(f"  IP unici             : {len(ip_map)}")

    if not salta_scan and risultati_completi["scan"]:
        totale_porte = sum(r["totale_porte"] for r in risultati_completi["scan"])
        ip_con_porte = sum(1 for r in risultati_completi["scan"] if r["totale_porte"] > 0)
        print(f"  IP con porte aperte  : {ip_con_porte}")
        print(f"  Porte totali         : {totale_porte}")

    if not salta_vt and risultati_completi.get("virustotal"):
        vt = risultati_completi["virustotal"]
        ip_rischio = [r for r in vt.get("ip", [])
                      if r.get("rischio") in ["ALTO", "MEDIO"]]
        print(f"  IP a rischio VT      : {len(ip_rischio)}")

    if not salta_wayback and risultati_completi.get("wayback"):
        wb = risultati_completi["wayback"]
        url_int = wb.get("url_interessanti", {})
        totale_int = sum(len(v) for v in url_int.values())
        print(f"  URL interessanti WB  : {totale_int}")
        print(f"  Prima archiviazione  : {wb.get('prima_archiviazione', 'N/A')}")

    print(f"\n  Report in            : {cartella}/")
    print("="*50 + "\n")

    # ============================================================
    # STEP 7: Telegram
    # ============================================================

    if not salta_telegram:
        print("-"*40)
        print("STEP 7 — Notifica Telegram")
        print("-"*40)

        try:
            from telegram_module import invia_report_telegram
            invia_report_telegram(risultati_completi, analisi_path)
        except Exception as e:
            print(f"[!] Errore Telegram: {e}")
    else:
        print("[*] Notifica Telegram saltata")


if __name__ == "__main__":
    main()
