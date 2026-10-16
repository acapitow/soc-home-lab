# Scénario 03 — Scan réseau Nmap

| | |
|---|---|
| **Technique MITRE** | [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |
| **Tactique** | TA0007 Discovery |
| **Cible** | Sous-réseau du labo `10.20.0.0/24` (isolé) |
| **Lancé depuis** | ATTACK01 (`nmap`) — ou WS01 (`ws01-portsweep.ps1`) en profil léger |
| **Réf. Atomic Red Team** | T1046 |

## Principe

Avant d'attaquer, l'adversaire cartographie les services exposés. `nmap` balaie les ports
des hôtes du sous-réseau pour trouver SSH, RDP, SMB, HTTP, LDAP, etc.

## Exécuter

```bash
./attack.sh                       # simulation (top 100 ports)
./attack.sh --execute             # scan réel du /24 du labo
SCAN_PROFILE=full ./attack.sh --execute   # scan complet -p-
```

Commande sous-jacente :

```bash
nmap -sS -T4 -Pn --top-ports 100 --open 10.20.0.0/24
```

### Profil léger — depuis WS01 (recommandé pour la visibilité Sysmon)

```powershell
powershell -ExecutionPolicy Bypass -File .\ws01-portsweep.ps1 -Execute
```

> Lancer le scan depuis **WS01** (équipé de Sysmon) rend le balayage très visible :
> le processus (`nmap.exe` ou `powershell.exe`) génère une rafale de **Sysmon EventID 3**
> vers de nombreux ports, ce que détecte la règle Wazuh `100301`.

## Journaux attendus

| Source | Événement | Détail |
|--------|-----------|--------|
| WS01/DC01 | **Sysmon EID 3** | Rafale de connexions réseau, même `SourceIp`, nombreux `DestinationPort` |
| WS01 | **PowerShell EID 4104** | Si lancé via `ws01-portsweep.ps1` (Script Block Logging) |
| SRV01 | auth.log / Nginx | Connexions sur 22/80 si ports ouverts sondés |

Voir [`expected-logs.md`](expected-logs.md).

## Détection

- **Wazuh** — [`detection/wazuh/local_rules.xml`](../../detection/wazuh/local_rules.xml)
  - `100300` (connexion Sysmon EID 3) → `100301` : **≥ 20 ports distincts / même source / 60 s**
- **Sigma** — [`detection/sigma/nmap_network_scan.yml`](../../detection/sigma/nmap_network_scan.yml)
  (corrélation `value_count` ≥ 20 `DestinationPort` distincts par `SourceIp`).

### Note de visibilité (honnêteté SOC)

Un scan SYN de **ports fermés** peut ne pas être journalisé côté cible (pas de processus
qui accepte). Pour une détection robuste du scan *entrant*, deux options documentées :
1. lancer le scan depuis un hôte **équipé de Sysmon** (WS01) → connexions sortantes visibles ;
2. activer l'audit **Windows Filtering Platform** (EventID 5156) — piste d'extension.

## Réponse à incident

Rapport : [`docs/incident-response/IR-003-nmap-scan.md`](../../docs/incident-response/IR-003-nmap-scan.md).
