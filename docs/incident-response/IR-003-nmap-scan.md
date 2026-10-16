# Rapport d'incident — IR-003 : Scan réseau (Nmap) du sous-réseau

> Structure SANS PICERL. Sections « Preuves à insérer » à compléter avec
> les preuves réelles après `./attack.sh --execute` (ou `ws01-portsweep.ps1 -Execute`).

---

## 1. Résumé exécutif

| Champ | Valeur |
|-------|--------|
| **Identifiant** | IR-003 |
| **Titre** | Balayage de ports du sous-réseau 10.20.0.0/24 |
| **Date de détection** | 2026-10-13 23:30 (exemple) |
| **Analyste** | André Capito (@acapitow) |
| **Sévérité** | Moyenne (niveau 10) |
| **Statut** | Clôturé (exercice de labo) |
| **Systèmes concernés** | Sous-réseau du labo ; source observée sur WS01 (Sysmon) |
| **Technique MITRE ATT&CK** | [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |

**Synthèse.** Une activité de découverte réseau a été détectée : une même source a établi
des connexions vers un grand nombre de ports distincts sur plusieurs hôtes en moins d'une
minute. Sysmon (EventID 3) a enregistré la rafale ; Wazuh a corrélé ≥ 20 ports distincts
depuis la même source (règle `100301`). Comportement typique d'une **reconnaissance**
préalable à une attaque.

## 2. Préparation

- **Sources de logs** : Sysmon (EID 3) sur WS01/DC01 ; PowerShell (4104) si sweep PS.
- **Config Sysmon** : journalisation réseau large (`detection/sysmon/sysmonconfig.xml`).
- **Détections** : Wazuh 100300/100301 ; Sigma `nmap_network_scan.yml`.

## 3. Identification

- **Alerte** : Wazuh `100301` — « Scan réseau (Nmap) détecté — 20+ ports balayés ».
- **Fenêtre** : 23:30:00 → 23:30:45 (exemple).
- **Source** : hôte lançant le scan (ex. WS01 `10.20.0.20`, outil `nmap.exe`/`powershell.exe`).
- **Cibles** : DC01, SRV01, SIEM01 (ports 22, 80, 88, 135, 389, 445, 3389, 5985…).

**Preuves à insérer** :
- Export : `results/alerts/nmap-scan.json` (`export_alerts.py --rule 100301`)
- Capture dashboard : `results/img/nmap-scan-alert.png`
- Résumé Sysmon EID 3 (voir `scenarios/03-nmap-scan/expected-logs.md`).

### Indicateurs de compromission (IOC)

| Type | Valeur | Remarque |
|------|--------|----------|
| Source | `10.20.0.20` (WS01) ou `10.20.0.50` (Kali) | Origine du scan |
| Processus | `nmap.exe` / `powershell.exe` | `Image` dans Sysmon EID 3 |
| Pattern | ≥ 20 `DestinationPort` distincts / même source / 60 s | Signature de scan |

## 4. Confinement

- [x] Identification de l'hôte source via `Image` et `SourceIp` (Sysmon).
- [ ] Si la source est un poste interne : isoler l'hôte (possible compromission/pivot).
- [ ] Blocage réseau de la source si externe.

## 5. Éradication

- [x] Analyse de l'hôte source : qui/quoi a lancé l'outil ? (corrélation EID 1 / 4104).
- [ ] Suppression de l'outil non autorisé le cas échéant.

## 6. Rétablissement

- [x] Vérifier qu'aucune exploitation n'a suivi la reconnaissance (connexions, logons).
- [x] Surveillance renforcée des hôtes scannés.

## 7. Leçons apprises

- **Détection** : lancer le scan depuis un hôte équipé de Sysmon le rend très visible.
  Pour les scans *entrants* de ports fermés, prévoir l'audit WFP (5156) ou un capteur
  réseau (Zeek/Suricata) — piste d'extension documentée.
- **Durcissement proposé** :
  - Segmentation réseau et restriction des flux est-ouest.
  - Alerte sur l'usage d'outils de scan sur les postes (EID 1 : `nmap.exe`).

## 8. Chronologie

| Heure | Événement |
|-------|-----------|
| 23:30:00 | Début de la rafale de connexions (Sysmon EID 3) |
| 23:30:40 | Seuil atteint → alerte Wazuh `100301` (niveau 10) |
| 23:33 | Prise en charge analyste, identification de l'hôte source |
| 23:40 | Vérification d'absence d'exploitation, clôture |
