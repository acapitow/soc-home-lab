# Scénarios d'attaque & de détection

> **Usage autorisé uniquement.** Ces scripts ne visent que les VM du
> **laboratoire isolé** (`10.20.0.0/24`). Le garde-fou `lib/lab_guard.sh` refuse
> toute autre cible, et tout tourne en **mode simulation (`--check`) par défaut**.
> N'exécutez jamais ceci contre un système sans autorisation écrite.

Chaque scénario fournit : un script d'attaque *bridé labo*, la technique **MITRE ATT&CK**,
les **journaux attendus**, la **règle Wazuh**, la **règle Sigma** et un **rapport d'incident**.

| # | Scénario | MITRE | Script | Détails |
|---|----------|-------|--------|---------|
| 01 | Brute force SSH sur SRV01 | T1110.001 | [`01-ssh-bruteforce/attack.sh`](01-ssh-bruteforce/attack.sh) | [README](01-ssh-bruteforce/README.md) |
| 02 | Password spraying AD | T1110.003 | [`02-password-spraying/attack.sh`](02-password-spraying/attack.sh) | [README](02-password-spraying/README.md) |
| 03 | Scan réseau Nmap | T1046 | [`03-nmap-scan/attack.sh`](03-nmap-scan/attack.sh) | [README](03-nmap-scan/README.md) |

## Comment lancer

```bash
cd scenarios

# Tout, en simulation (sûr, n'exécute rien de réel) :
./run_all_scenarios.sh

# Tout, pour de vrai (contre le labo isolé) :
./run_all_scenarios.sh --execute

# Détection HORS-LIGNE (Python seul, aucune VM) — idéal sous WSL / pour une démo :
./run_all_scenarios.sh --simulate

# Un seul scénario :
./01-ssh-bruteforce/attack.sh --execute
```

> **`--simulate`** appelle [`../scripts/simulate_detection.py`](../scripts/simulate_detection.py),
> qui rejoue une trace d'attaque et applique la même logique de corrélation que les règles
> Wazuh/Sigma, puis écrit les alertes dans `../results/alerts/simulated-*.json`. Aucune VM,
> aucun SIEM, aucun outil d'attaque requis — seulement Python 3.

## D'où lancer les attaques ?

| Scénario | Profil complet | Profil léger (sans Kali) |
|----------|----------------|---------------------------|
| 01 SSH brute force | ATTACK01 (`hydra`) | SIEM01 (`hydra`) |
| 02 Password spraying | ATTACK01 (`nxc`/`kerbrute`) | WS01 (PowerShell natif) |
| 03 Scan Nmap | ATTACK01 (`nmap`) | WS01 (`ws01-portsweep.ps1`) ou SIEM01 (`nmap`) |

## Le mode simulation (`--check`)

Par défaut, chaque script :
1. affiche la cible, la technique MITRE et la **commande exacte** qui serait lancée ;
2. vérifie la présence des outils ;
3. **n'exécute rien**.

C'est pratique pour relire la chaîne, faire une démo, ou tester les détections avec
`wazuh-logtest` sans générer de trafic réel. Ajoutez `--execute` pour passer à l'action.

## Après exécution

Les alertes remontent dans le dashboard Wazuh (**https://10.20.0.40**). Pour les exporter :

```bash
python3 ../scripts/export_alerts.py --since 15m --out ../results/alerts/mon-test.json
```

Voir [`../results/README.md`](../results/README.md) pour la mise en forme des résultats.
