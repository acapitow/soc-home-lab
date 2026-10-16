# Rapport d'incident — IR-001 : Brute force SSH sur SRV01

> Structure SANS PICERL. Les sections « Preuves à insérer » sont à compléter avec les
> preuves réelles (export `results/alerts/…` + captures du dashboard) après
> `./attack.sh --execute`.

---

## 1. Résumé exécutif

| Champ | Valeur |
|-------|--------|
| **Identifiant** | IR-001 |
| **Titre** | Tentative de brute force SSH contre le compte `labadmin` sur SRV01 |
| **Date de détection** | 2026-10-13 22:40 (exemple) |
| **Analyste** | André Capito (@acapitow) |
| **Sévérité** | Élevée (niveau 10 ; critique 13 si connexion réussie) |
| **Statut** | Clôturé (exercice de labo) |
| **Systèmes concernés** | SRV01 (10.20.0.30) |
| **Technique MITRE ATT&CK** | [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |

**Synthèse.** Une rafale d'échecs d'authentification SSH a été détectée sur SRV01, toutes
en provenance de `10.20.0.50` et ciblant le compte `labadmin`. Wazuh a corrélé ≥ 8 échecs
en moins de 60 s (règle `100101`). Le scénario vérifie aussi l'escalade critique `100102`
(connexion réussie *après* la rafale), signe d'une compromission d'identifiant.

## 2. Préparation

- **Sources de logs** : `/var/log/auth.log` de SRV01, collecté par l'agent Wazuh.
- **Durcissement journalisation** : `LogLevel VERBOSE` activé (rôle `srv01-linux`).
- **Détections en place** : Wazuh 100100/100101/100102 ; Sigma `ssh_bruteforce.yml`.

## 3. Identification

- **Alerte** : Wazuh `100101` — « Brute force SSH détecté — 8+ échecs/60 s ».
- **Fenêtre** : 22:40:01 → 22:40:05 (exemple).
- **Source** : `10.20.0.50` (ATTACK01). **Cible** : `labadmin@SRV01`, SSH/22.
- **Outil présumé** : `hydra` (connexions parallèles rapides, nombreux ports source).

**Preuves à insérer** :
- Export : `results/alerts/ssh-bruteforce.json` (via `export_alerts.py --rule 100101,100102`)
- Capture dashboard : `results/img/ssh-bruteforce-alert.png`
- Extrait `auth.log` (voir `scenarios/01-ssh-bruteforce/expected-logs.md`).

### Indicateurs de compromission (IOC)

| Type | Valeur | Remarque |
|------|--------|----------|
| IP source | `10.20.0.50` | Origine des tentatives |
| Compte visé | `labadmin` | Compte local SRV01 |
| Pattern | ≥ 8 `Failed password` / 60 s, même IP | Signature brute force |
| Escalade | `Accepted password` après la rafale | Compromission (règle 100102) |

## 4. Confinement

- [x] Blocage de l'IP source `10.20.0.50` (règle pare-feu / active response Wazuh).
- [x] Verrouillage temporaire du compte `labadmin`.
- [ ] Déconnexion des sessions actives suspectes (`who`, `pkill -KILL -u labadmin`).

## 5. Éradication

- [x] Réinitialisation du mot de passe de `labadmin` (mot de passe fort).
- [x] Vérification d'absence de clé SSH ajoutée (`~/.ssh/authorized_keys`).

## 6. Rétablissement

- [x] Réactivation du compte avec mot de passe robuste.
- [x] Surveillance renforcée 24 h sur `100100/100101`.

## 7. Leçons apprises

- **Détection** : efficace (< 60 s), corrélation claire.
- **À améliorer** / durcissement proposé :
  - Désactiver l'authentification SSH par mot de passe (clés uniquement).
  - Déployer **fail2ban** ou l'**active response** Wazuh (blocage auto d'IP).
  - Restreindre SSH aux IP d'administration ; MFA si possible.

## 8. Chronologie

| Heure | Événement |
|-------|-----------|
| 22:40:01 | Premier `Failed password` depuis 10.20.0.50 |
| 22:40:04 | Seuil atteint → alerte Wazuh `100101` (niveau 10) |
| 22:40:05 | (Le cas échéant) `Accepted password` → alerte `100102` (niveau 13) |
| 22:42 | Prise en charge analyste, blocage IP + verrouillage compte |
| 22:55 | Réinitialisation identifiants, clôture |
