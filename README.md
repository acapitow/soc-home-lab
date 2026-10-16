# SOC Home Lab

> Laboratoire SOC *Blue Team* entièrement déployable en **Infrastructure as Code**.
> Une seule commande crée les machines virtuelles, les configure, installe le SIEM
> et enrôle les agents. Le labo couvre : **Active Directory**, **collecte de journaux**,
> **règles de détection**, **simulation d'attaques mappées sur MITRE ATT&CK** et
> **réponse à incident**.

**Auteur : André Capito ([@acapitow](https://github.com/acapitow))** — projet réalisé dans le
cadre du MSc Cybersécurité (Epitech), en vue d'une alternance d'analyste SOC.

![IaC](https://img.shields.io/badge/IaC-Vagrant%20%2B%20Ansible-1563FF)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-005792)
![ATTACK](https://img.shields.io/badge/MITRE-ATT%26CK-C8102E)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Avertissement — usage autorisé uniquement

Ce dépôt est un **laboratoire pédagogique défensif**. Les scripts dits « d'attaque »
servent **exclusivement** à générer de la télémétrie pour tester les détections.

- Le réseau du labo est **isolé** (réseau interne VirtualBox, pas d'exposition Internet).
- Les scripts d'attaque sont **bridés** : un garde-fou (`scenarios/lib/lab_guard.sh`)
  **refuse toute cible hors du sous-réseau du labo** `10.20.0.0/24`.
- Les identifiants et mots de passe sont **fictifs** et créés par le labo lui-même.
- N'exécutez **jamais** ces scripts contre un système que vous ne possédez pas ou pour
  lequel vous n'avez pas d'autorisation écrite. Le brute force, le password spraying et
  le scan de ports sans autorisation sont **illégaux** (en France, art. 323-1 et suivants
  du Code pénal).

---

## Architecture

Réseau interne VirtualBox `soc-lab` — `10.20.0.0/24` — isolé d'Internet.

```
                        ┌───────────────────────────────────────────────┐
                        │        Réseau interne VirtualBox « soc-lab »    │
                        │                 10.20.0.0/24                    │
                        │                                                 │
   ┌───────────┐        │   ┌───────────┐      ┌───────────┐              │
   │ ATTACK01  │        │   │   DC01    │      │   WS01    │              │
   │   Kali    │────────┼──▶│ Win2022   │◀────▶│ Win10/11  │              │
   │.50        │  attaques  │ AD DS/DNS │ join │ Sysmon +  │              │
   └───────────┘        │   │ lab.local │      │ PS logging│              │
         │              │   │ .10       │      │ .20       │              │
         │              │   └─────┬─────┘      └─────┬─────┘              │
         │              │         │ logs             │ logs               │
         │ attaques     │         ▼                  ▼                    │
         │              │   ┌─────────────────────────────┐              │
         │              │   │          SIEM01             │   ┌─────────┐ │
         └──────────────┼──▶│  Wazuh manager + indexer    │◀──│  SRV01  │ │
          (nmap/hydra)  │   │        + dashboard          │   │ Ubuntu  │ │
                        │   │  .40  https://10.20.0.40    │   │ SSH+NGX │ │
                        │   └─────────────────────────────┘   │ .30     │ │
                        │                                      └─────────┘ │
                        └───────────────────────────────────────────────┘
```

| VM         | IP           | OS                     | Rôle                                                       | RAM (full/light) |
|------------|--------------|------------------------|------------------------------------------------------------|------------------|
| `DC01`     | 10.20.0.10   | Windows Server 2022    | Contrôleur de domaine AD DS + DNS (`lab.local`), audit avancé | 4096 / 2048 Mo |
| `WS01`     | 10.20.0.20   | Windows 10/11          | Poste joint au domaine, Sysmon, PowerShell Script Block Logging | 4096 / 2048 Mo |
| `SRV01`    | 10.20.0.30   | Ubuntu Server 22.04    | SSH + Nginx (cible Linux)                                  | 1024 / 1024 Mo |
| `SIEM01`   | 10.20.0.40   | Ubuntu Server 22.04    | Wazuh *all-in-one* (manager + indexer + dashboard)         | 6144 / 3072 Mo |
| `ATTACK01` | 10.20.0.50   | Kali Linux (rolling)   | Machine d'attaque (labo uniquement)                         | 2048 / — (désactivée) |

> Détails complets, choix techniques et plan d'adressage : [`docs/architecture.md`](docs/architecture.md)
> et [`docs/decisions.md`](docs/decisions.md).

---

## Prérequis (sur votre machine hôte)

Ces outils ne sont **pas** installés automatiquement — installez-les une fois sur l'hôte :

| Outil           | Rôle                                   | Lien |
|-----------------|----------------------------------------|------|
| VirtualBox ≥ 7.0 | Hyperviseur (provider Vagrant)        | https://www.virtualbox.org/ |
| Vagrant ≥ 2.4   | Création/orchestration des VM          | https://developer.hashicorp.com/vagrant |
| Ansible ≥ 2.15  | Configuration des VM                   | https://docs.ansible.com/ |
| Git + GitHub CLI (`gh`) | Versionnage et publication     | https://cli.github.com/ |
| Python 3.10+    | Script d'export des alertes            | https://www.python.org/ |

**Windows** : Ansible ne tourne pas nativement. Installez **WSL2 (Ubuntu)** et lancez
Vagrant/Ansible depuis WSL, *ou* utilisez le mode « Ansible local » (voir
[`docs/setup.md`](docs/setup.md)). VirtualBox s'installe côté Windows.

**Ressources recommandées** : profil *full* → hôte avec **32 Go** de RAM ;
profil *light* → hôte avec **16 Go** (voir plus bas).

---

## Démarrage rapide (une seule commande)

```bash
git clone https://github.com/acapitow/premier-projet-cyber.git
cd premier-projet-cyber        # (ou le dossier soc-home-lab selon votre organisation)

# (optionnel) récupérer les dépôts de référence cités ci-dessous
./scripts/fetch-references.sh

# Profil complet (hôte 32 Go) :
vagrant up

# OU profil léger (hôte 16 Go) :
LAB_PROFILE=light vagrant up        # sous Windows cmd : set LAB_PROFILE=light && vagrant up
```

`vagrant up` enchaîne : création des 5 VM → provisioning Ansible → promotion d'AD →
jonction au domaine → installation de Sysmon + journalisation PowerShell →
déploiement du manager Wazuh → enrôlement automatique des agents.

Puis ouvrez le dashboard Wazuh : **https://10.20.0.40** (identifiants dans la sortie
de provisioning et dans [`docs/setup.md`](docs/setup.md)).

Pour tout arrêter / détruire :

```bash
vagrant halt       # éteint
vagrant destroy -f # supprime tout
```

---

## Profil léger (PC à 16 Go)

Activé par `LAB_PROFILE=light`. Compromis assumés et documentés :

- **ATTACK01 (Kali) est désactivée.** Les scénarios Linux (SSH brute force, Nmap)
  se lancent depuis `SIEM01` ou l'hôte ; le password spraying AD se lance depuis `WS01`.
- RAM réduite par VM (voir le tableau d'architecture).
- Empreinte totale ≈ **8 Go** au lieu de ≈ **16 Go**.

Détails et autres leviers (désactiver WS01, réduire l'indexer Wazuh) :
[`docs/light-profile.md`](docs/light-profile.md).

---

## Détection & scénarios

Chaque scénario fournit : le script d'attaque *bridé labo*, la technique **MITRE ATT&CK**,
les **journaux attendus** (Event IDs Windows / Sysmon / `auth.log`), une **règle Wazuh**,
la **règle Sigma** équivalente et un **modèle de rapport d'incident**.

| # | Scénario | MITRE ATT&CK | Source de log | Règle Wazuh | Règle Sigma | Rapport |
|---|----------|--------------|---------------|-------------|-------------|---------|
| 1 | Brute force SSH sur SRV01 | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | `auth.log` (SRV01) | [`100100`+](detection/wazuh/local_rules.xml) | [`ssh_bruteforce.yml`](detection/sigma/ssh_bruteforce.yml) | [IR-001](docs/incident-response/IR-001-ssh-bruteforce.md) |
| 2 | Password spraying AD | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | EventID 4625/4768/4771 (DC01) | [`100200`+](detection/wazuh/local_rules.xml) | [`ad_password_spraying.yml`](detection/sigma/ad_password_spraying.yml) | [IR-002](docs/incident-response/IR-002-password-spraying.md) |
| 3 | Scan réseau Nmap | [T1046](https://attack.mitre.org/techniques/T1046/) | Sysmon EID 3 + firewall/`auth.log` | [`100300`+](detection/wazuh/local_rules.xml) | [`nmap_network_scan.yml`](detection/sigma/nmap_network_scan.yml) | [IR-003](docs/incident-response/IR-003-nmap-scan.md) |

Lancer **tous** les scénarios et collecter les alertes :

```bash
cd scenarios
./run_all_scenarios.sh            # mode --check par défaut (sûr, ne lance rien de réel)
./run_all_scenarios.sh --execute  # lance réellement les attaques (labo déployé uniquement)
./run_all_scenarios.sh --simulate # détection HORS-LIGNE : prouve que les règles se déclenchent, SANS VM
```

> **Sans infrastructure ?** `--simulate` (ou `python3 scripts/simulate_detection.py`)
> rejoue une trace d'attaque réaliste et applique **la même logique de corrélation** que
> les règles Wazuh/Sigma — avec **Python seul**, sans VirtualBox ni SIEM. Pratique sous
> WSL ou pour une démo rapide. Les alertes produites vont dans `results/alerts/simulated-*.json`.

Couverture MITRE complète : [`docs/mitre-attack-matrix.md`](docs/mitre-attack-matrix.md).

---

## Structure du dépôt

```
soc-home-lab/
├── Vagrantfile               # Définition des 5 VM + bascule full/light
├── ansible/                  # Rôles de configuration (AD, Sysmon, Nginx, Wazuh…)
├── detection/
│   ├── wazuh/                # Règles & décodeurs Wazuh personnalisés
│   ├── sigma/                # Règles Sigma (format officiel SigmaHQ)
│   └── sysmon/               # Config Sysmon (basée sur SwiftOnSecurity/Olaf Hartong)
├── scenarios/                # Scripts d'attaque bridés + run_all_scenarios.sh
├── scripts/                  # export_alerts.py, fetch-references.sh
├── results/                  # Alertes exportées & captures (sorties du labo)
├── docs/                     # Architecture, décisions, IR, matrice MITRE…
└── portfolio/                # CV, post LinkedIn, Q&R entretien SOC
```

---

## État de validation des résultats

> **Transparence.** Ce dépôt a été construit et versionné de façon reproductible.
> Le dossier [`results/`](results/) contient des **sorties de référence** (journaux et
> alertes *attendus*) clairement étiquetées comme telles — elles illustrent ce que vous
> **devez** observer après avoir lancé le labo sur un hôte disposant de VirtualBox et de
> suffisamment de RAM. Elles ne sont **pas** présentées comme la preuve d'une exécution
> réelle. Remplacez-les par vos propres captures après `vagrant up` : voir
> [`results/README.md`](results/README.md).

---

## Crédits & licences

Ce projet s'appuie sur des références reconnues de la communauté — merci à leurs auteurs.
Voir [`NOTICE.md`](NOTICE.md) pour le détail des licences.

- **SigmaHQ/sigma** — format standard des règles de détection — *Detection Rule License (DRL) 1.1 / GPL-3.0*
- **SwiftOnSecurity/sysmon-config** & **olafhartong/sysmon-modular** — configurations Sysmon de référence — *CC / MIT*
- **redcanaryco/atomic-red-team** — tests d'attaque mappés ATT&CK — *MIT*
- **wazuh/wazuh-ansible** — rôles Ansible officiels Wazuh — *GPL-2.0*
- **MITRE ATT&CK®** — base de connaissances des techniques adverses — © The MITRE Corporation

Récupération locale de ces dépôts (exclus du dépôt via `.gitignore`) :
`./scripts/fetch-references.sh`.

## Licence

Code de ce dépôt sous licence **MIT** — voir [`LICENSE`](LICENSE).
