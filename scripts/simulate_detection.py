#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simulate_detection.py — SOC Home Lab
Auteur : André Capito (@acapitow)

Moteur de détection HORS-LIGNE : rejoue une trace d'événements et applique la MÊME
logique de corrélation que les règles Wazuh (IDs 100100+) et Sigma de ce dépôt, puis
affiche les alertes déclenchées. Objectif : démontrer que les détections fonctionnent
SANS avoir à déployer les VM ni installer un SIEM — il suffit de Python 3.

Ce n'est PAS un vrai SIEM : c'est une simulation pédagogique de la logique de
corrélation (seuils, fenêtres, champs). Les sorties sont étiquetées « simulation ».

Usage :
  python3 scripts/simulate_detection.py                 # génère une trace et détecte
  python3 scripts/simulate_detection.py --out-dir results/alerts
  python3 scripts/simulate_detection.py --from events.ndjson   # sur des événements réels

Schéma d'un événement (JSON) attendu par --from (un objet par ligne en NDJSON) :
  {"ts": 1760389201.0, "type": "ssh_fail", "src": "10.20.0.50",
   "user": "labadmin", "dst": "10.20.0.30", "dport": 22}
Types reconnus : ssh_fail, ssh_success, win_fail_4625, sysmon_netconn
"""

import argparse
import json
import os
import sys
from collections import deque


# =============================================================================
# Corrélateurs génériques (miroir des sémantiques Wazuh frequency / different_field)
# =============================================================================
def correlate_count(events, etype, group_key, threshold, window_s):
    """Déclenche quand >= `threshold` événements `etype` partagent `group_key`
    dans une fenêtre glissante de `window_s` secondes. (≈ Wazuh same_field + frequency)
    Renvoie la liste des événements « déclencheurs » (celui qui atteint le seuil)."""
    buckets = {}
    triggers = []
    fired = set()
    for ev in sorted(events, key=lambda e: e["ts"]):
        if ev.get("type") != etype:
            continue
        key = ev.get(group_key)
        dq = buckets.setdefault(key, deque())
        dq.append(ev["ts"])
        while dq and ev["ts"] - dq[0] > window_s:
            dq.popleft()
        if len(dq) >= threshold and key not in fired:
            fired.add(key)
            triggers.append({**ev, "_count": len(dq)})
    return triggers


def correlate_distinct(events, etype, group_key, distinct_field, threshold, window_s):
    """Déclenche quand >= `threshold` valeurs DISTINCTES de `distinct_field`
    partagent `group_key` dans la fenêtre. (≈ Wazuh different_field / Sigma value_count)."""
    buckets = {}
    triggers = []
    fired = set()
    for ev in sorted(events, key=lambda e: e["ts"]):
        if ev.get("type") != etype:
            continue
        key = ev.get(group_key)
        dq = buckets.setdefault(key, deque())
        dq.append((ev["ts"], ev.get(distinct_field)))
        while dq and ev["ts"] - dq[0][0] > window_s:
            dq.popleft()
        distinct = {v for _, v in dq}
        if len(distinct) >= threshold and key not in fired:
            fired.add(key)
            triggers.append({**ev, "_distinct": sorted(map(str, distinct))})
    return triggers


def correlate_success_after(events, src_with_bruteforce, window_s=60):
    """100102 : un ssh_success depuis une source qui vient de subir un brute force."""
    triggers = []
    bf_times = {}
    for ev in sorted(events, key=lambda e: e["ts"]):
        if ev.get("type") == "ssh_fail" and ev.get("src") in src_with_bruteforce:
            bf_times[ev["src"]] = ev["ts"]
        elif ev.get("type") == "ssh_success":
            last = bf_times.get(ev.get("src"))
            if last is not None and 0 <= ev["ts"] - last <= window_s:
                triggers.append(ev)
    return triggers


# =============================================================================
# Définition des règles (identiques aux seuils de detection/wazuh/local_rules.xml)
# =============================================================================
def run_rules(events):
    """Applique les règles et renvoie une liste d'alertes (format proche Wazuh)."""
    alerts = []

    # --- 01 · SSH brute force (100101) : >= 8 ssh_fail / même src / 60 s ---
    bf = correlate_count(events, "ssh_fail", "src", threshold=8, window_s=60)
    bf_srcs = {t["src"] for t in bf}
    for t in bf:
        alerts.append(_alert("100101", 10, "T1110.001", "srv01",
            f"Brute force SSH détecté — {t['_count']} échecs/60s depuis {t['src']}",
            {"srcip": t["src"], "dstuser": t.get("user"), "echecs_fenetre": t["_count"]}))

    # --- 01 · Succès après brute force (100102) ---
    for t in correlate_success_after(events, bf_srcs):
        alerts.append(_alert("100102", 13, "T1110.001", "srv01",
            f"Connexion SSH réussie APRÈS brute force depuis {t['src']} — compromission probable de {t.get('user')}",
            {"srcip": t["src"], "dstuser": t.get("user")}))

    # --- 02 · Password spraying (100201) : >= 5 users distincts / même src / 120 s ---
    for t in correlate_distinct(events, "win_fail_4625", "src", "user", threshold=5, window_s=120):
        alerts.append(_alert("100201", 12, "T1110.003", "dc01",
            f"Password spraying AD — {len(t['_distinct'])}+ comptes visés depuis {t['src']}",
            {"ipAddress": t["src"], "comptes": t["_distinct"]}))

    # --- 03 · Scan Nmap (100301) : >= 20 ports distincts / même src / 60 s ---
    for t in correlate_distinct(events, "sysmon_netconn", "src", "dport", threshold=20, window_s=60):
        alerts.append(_alert("100301", 10, "T1046", "ws01",
            f"Scan réseau (Nmap) détecté — {len(t['_distinct'])}+ ports balayés depuis {t['src']}",
            {"sourceIp": t["src"], "ports_distincts": len(t["_distinct"])}))

    return alerts


def _alert(rule_id, level, mitre, agent, desc, data):
    return {
        "_note": "SIMULATION hors-ligne (simulate_detection.py) — pas un vrai SIEM",
        "rule": {"id": rule_id, "level": level,
                 "description": f"SOC-LAB: {desc}",
                 "mitre": {"id": [mitre]}},
        "agent": {"name": agent},
        "data": data,
    }


# =============================================================================
# Génération d'une trace d'attaque réaliste (quand on n'a pas de logs réels)
# =============================================================================
def generate_trace():
    """Reproduit les scénarios décrits dans scenarios/*/expected-logs.md."""
    base = 1760389200.0  # 2025-10-13 ~22:40 UTC (epoch d'exemple)
    ev = []

    # 01 · SSH brute force depuis 10.20.0.50 vers srv01, puis succès
    for i in range(12):
        ev.append({"ts": base + i * 0.4, "type": "ssh_fail",
                   "src": "10.20.0.50", "user": "labadmin", "dst": "10.20.0.30", "dport": 22})
    ev.append({"ts": base + 6.0, "type": "ssh_success",
               "src": "10.20.0.50", "user": "labadmin", "dst": "10.20.0.30", "dport": 22})

    # 02 · Password spraying depuis 10.20.0.50 vers dc01 (5 comptes)
    users = ["jdupont", "amartin", "pbernard", "svc_backup", "svc_sql"]
    for i, u in enumerate(users):
        ev.append({"ts": base + 1500 + i * 15, "type": "win_fail_4625",
                   "src": "10.20.0.50", "user": u, "dst": "10.20.0.10", "dport": 445})

    # 03 · Scan Nmap depuis ws01 (10.20.0.20) : 24 ports distincts
    ports = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 389, 443, 445, 464,
             636, 993, 995, 1433, 3268, 3389, 5985, 5986, 8080, 8443]
    for i, p in enumerate(ports):
        ev.append({"ts": base + 3000 + i * 1.2, "type": "sysmon_netconn",
                   "src": "10.20.0.20", "dst": "10.20.0.10", "dport": p})
    return ev


def load_events(path):
    """Charge des événements depuis un NDJSON (un objet/ligne) ou un tableau JSON."""
    txt = open(path, encoding="utf-8").read().strip()
    if txt.startswith("["):
        return json.loads(txt)
    out = []
    for line in txt.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# =============================================================================
def main(argv=None):
    p = argparse.ArgumentParser(description="Simulation hors-ligne des détections du SOC Home Lab.")
    p.add_argument("--from", dest="src_file", help="Fichier d'événements NDJSON/JSON (sinon trace générée)")
    p.add_argument("--out-dir", help="Dossier où écrire les alertes simulées (ex. results/alerts)")
    p.add_argument("--quiet", action="store_true", help="Moins de sortie")
    args = p.parse_args(argv)

    events = load_events(args.src_file) if args.src_file else generate_trace()
    source = args.src_file or "trace générée (synthétique)"
    alerts = run_rules(events)

    # Rapport console
    print("────────────────────────────────────────────────────────────")
    print(" SOC Home Lab — Simulation de détection (HORS-LIGNE, pas un vrai SIEM)")
    print(f" Source des événements : {source}")
    print(f" Événements traités : {len(events)}   Alertes déclenchées : {len(alerts)}")
    print("────────────────────────────────────────────────────────────")
    for a in alerts:
        r = a["rule"]
        print(f"  [règle {r['id']} · niv.{r['level']} · {r['mitre']['id'][0]}] {r['description']}")
    if not alerts:
        print("  (aucune alerte — vérifier la trace/les seuils)")

    # Écriture optionnelle
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        by_rule = {"ssh-bruteforce": ["100101", "100102"],
                   "password-spraying": ["100201"],
                   "nmap-scan": ["100301"]}
        for name, ids in by_rule.items():
            subset = [a for a in alerts if a["rule"]["id"] in ids]
            path = os.path.join(args.out_dir, f"simulated-{name}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(subset, fh, indent=2, ensure_ascii=False)
            if not args.quiet:
                print(f"  → écrit {path} ({len(subset)} alerte(s))")

    # Code de sortie : 0 si au moins une alerte par scénario attendu
    expected = {"100101", "100102", "100201", "100301"}
    got = {a["rule"]["id"] for a in alerts}
    missing = expected - got
    if missing:
        print(f"\n[!] Règles attendues non déclenchées : {sorted(missing)}", file=sys.stderr)
        return 1
    print("\n[+] Toutes les règles attendues se sont déclenchées.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
