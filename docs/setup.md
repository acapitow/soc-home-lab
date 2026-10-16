# Installation & mise en route

## 1. Prérequis hôte

Installez (une seule fois) : **VirtualBox ≥ 7.0**, **Vagrant ≥ 2.4**, **Ansible ≥ 2.15**,
**Git**, **GitHub CLI (`gh`)**, **Python 3.10+**.

### Windows

- Installez **VirtualBox** côté Windows.
- Installez **WSL2 + Ubuntu** (`wsl --install`) et, dans Ubuntu :
  ```bash
  sudo apt update && sudo apt install -y ansible git python3 python3-pip
  ```
- Installez Vagrant côté Windows **ou** dans WSL (dans WSL, pointez Vagrant vers
  VirtualBox Windows en exportant :
  `export VAGRANT_WSL_ENABLE_WINDOWS_ACCESS=1`).
- Alternative sans WSL : mode **Ansible local** (voir § 4).

### macOS / Linux

```bash
# macOS (Homebrew)
brew install --cask virtualbox vagrant
brew install ansible git gh python

# Debian/Ubuntu
sudo apt install -y virtualbox ansible git python3 python3-pip
# Vagrant : paquet HashiCorp (voir doc officielle)
```

### Plugins Vagrant utiles

```bash
vagrant plugin install vagrant-reload        # redémarrages pendant le provisioning Windows
vagrant plugin install winrm winrm-fs winrm-elevated   # communication WinRM (auto si besoin)
```

## 2. Récupérer les dépôts de référence (optionnel mais recommandé)

```bash
./scripts/fetch-references.sh
```

Clone (en *shallow*) SigmaHQ/sigma, SwiftOnSecurity/sysmon-config,
olafhartong/sysmon-modular, redcanaryco/atomic-red-team et wazuh/wazuh-ansible dans
`references/` (dossier **exclu** du dépôt).

## 3. Lancer le labo

```bash
vagrant up                      # profil complet (hôte 32 Go)
LAB_PROFILE=light vagrant up    # profil léger (hôte 16 Go)
```

Suivi de l'avancement :

```bash
vagrant status
vagrant provision dc01          # relancer le provisioning d'une VM
vagrant ssh srv01               # se connecter à une VM Linux
```

## 4. Mode « Ansible local » (sans contrôleur Ansible)

Si vous ne voulez pas installer Ansible sur l'hôte, le `Vagrantfile` peut utiliser le
provisioner `ansible_local` (Ansible est alors installé **dans** chaque VM Linux). Activez :

```bash
ANSIBLE_MODE=local vagrant up
```

Pour les VM Windows, la configuration passe par des scripts PowerShell de provisioning
(`ansible/roles/*/files/*.ps1`) invoqués par Vagrant — aucun Ansible requis côté hôte.

## 5. Accéder au SIEM

- Dashboard Wazuh : **https://10.20.0.40** (certificat auto-signé → accepter l'exception).
- Identifiants par défaut : utilisateur `admin`, mot de passe affiché en fin de
  provisioning de SIEM01 (également stocké sur la VM dans
  `/var/ossec/api/configuration/...` et le fichier `wazuh-passwords.txt`).
- Depuis l'hôte, ajoutez si besoin une redirection ou un accès host-only — voir les
  commentaires réseau du `Vagrantfile`.

## 6. Identifiants de test du domaine

Définis dans `ansible/group_vars/vault.yml.example` (à copier en `vault.yml`). Exemple :

| Compte            | Rôle               | Usage scénario            |
|-------------------|--------------------|---------------------------|
| `LAB\\jdupont`     | Utilisateur std    | Cible password spraying   |
| `LAB\\amartin`     | Utilisateur std    | Cible password spraying   |
| `LAB\\svc_backup`  | Compte de service  | Cible password spraying   |
| `labadmin`        | Admin local SRV01  | Cible SSH brute force     |

> Mots de passe **volontairement faibles** et **fictifs** : environnement jetable isolé.
> Ne réutilisez jamais ces identifiants ailleurs.

## 7. Dépannage rapide

| Symptôme | Piste |
|----------|-------|
| `vagrant up` Windows très lent | Normal au 1er boot (promotion AD, reboots). Patienter. |
| Agent Wazuh non enrôlé | Vérifier que SIEM01 est up avant DC01/WS01 ; `vagrant provision <vm>`. |
| Pas assez de RAM | Passer en `LAB_PROFILE=light`. |
| WinRM timeout | `vagrant plugin install winrm-elevated` ; relancer `vagrant provision`. |
| Dashboard inaccessible | Attendre ~2 min après provisioning (indexer JVM) ; vérifier `https://` et le port 443. |
