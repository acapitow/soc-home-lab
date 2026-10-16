# Rapport d'incident — IR-002 : Password spraying Active Directory

> Structure SANS PICERL. Sections « Preuves à insérer » à compléter avec
> les preuves réelles après `./attack.sh --execute`.

---

## 1. Résumé exécutif

| Champ | Valeur |
|-------|--------|
| **Identifiant** | IR-002 |
| **Titre** | Password spraying contre le domaine `lab.local` (DC01) |
| **Date de détection** | 2026-10-13 23:05 (exemple) |
| **Analyste** | André Capito (@acapitow) |
| **Sévérité** | Élevée (niveau 12) |
| **Statut** | Clôturé (exercice de labo) |
| **Systèmes concernés** | DC01 (10.20.0.10), comptes de domaine multiples |
| **Technique MITRE ATT&CK** | [T1110.003 — Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |

**Synthèse.** Depuis `10.20.0.50`, un même mot de passe a été testé successivement sur
plusieurs comptes du domaine (`jdupont`, `amartin`, `pbernard`, `svc_backup`, `svc_sql`).
Ce schéma « 1 mot de passe × N comptes » vise à **éviter les verrouillages**. Wazuh a
corrélé ≥ 5 comptes distincts en échec depuis la même IP en 120 s (règle `100201`).

## 2. Préparation

- **Sources de logs** : journal **Security** de DC01 (agent Wazuh, canal eventchannel).
- **Audit avancé** activé (rôle `dc01-domain-controller`) : Logon, Account Logon, Kerberos.
- **Détections** : Wazuh 100200/100201 (4625) et 100202/100203 (Kerberos 4771) ;
  Sigma `ad_password_spraying.yml`.

## 3. Identification

- **Alerte** : Wazuh `100201` — « Password spraying AD — 5+ comptes visés ».
- **Fenêtre** : 23:05:10 → 23:06:40 (exemple).
- **Source** : `10.20.0.50`. **Cibles** : 5 comptes de domaine.
- **Event IDs** : `4625` (SubStatus `0xC000006A`), éventuels `4771` (code `0x18`).
- **Absence de 4740** : cohérent avec un spraying (sous le seuil de verrouillage).

**Preuves à insérer** :
- Export : `results/alerts/password-spraying.json` (`export_alerts.py --rule 100201,100203`)
- Capture dashboard : `results/img/password-spraying-alert.png`
- Tableau des 4625 (voir `scenarios/02-password-spraying/expected-logs.md`).

### Indicateurs de compromission (IOC)

| Type | Valeur | Remarque |
|------|--------|----------|
| IP source | `10.20.0.50` | Même source pour tous les échecs |
| Comptes visés | `jdupont, amartin, pbernard, svc_backup, svc_sql` | 5 comptes distincts |
| Pattern | ≥ 5 `TargetUserName` distincts / même `IpAddress` / 120 s | Signature spraying |
| SubStatus | `0xC000006A` | Mauvais mot de passe (compte existant) |

## 4. Confinement

- [x] Blocage de l'IP source `10.20.0.50`.
- [x] Vérification des comptes : aucun `4624` (succès) associé → pas de compromission.
- [ ] Si un compte était tombé : réinitialisation immédiate + révocation des tickets Kerberos.

## 5. Éradication

- [x] Contrôle des comptes de service (`svc_*`) souvent ciblés (mots de passe faibles).
- [x] Renforcement de la politique de mots de passe du domaine.

## 6. Rétablissement

- [x] Surveillance renforcée des 4625/4771 multi-comptes.
- [x] Revue des comptes à privilèges.

## 7. Leçons apprises

- **Détection** : la corrélation « N comptes / 1 source » capte le spraying là où une
  règle par-compte échouerait (le but du spraying est justement d'éviter ce seuil).
- **Durcissement proposé** :
  - Politique de verrouillage **intelligente** + alerte sur 4625 multi-comptes.
  - **MFA** sur les accès sensibles ; mots de passe forts pour les comptes de service.
  - Surveillance Kerberos (4768/4771) et détection d'énumération (`0xC0000064`).

## 8. Chronologie

| Heure | Événement |
|-------|-----------|
| 23:05:10 | Premiers 4625 depuis 10.20.0.50 sur plusieurs comptes |
| 23:06:40 | Seuil atteint → alerte Wazuh `100201` (niveau 12) |
| 23:09 | Prise en charge analyste, blocage IP, vérification des comptes |
| 23:20 | Confirmation d'absence de compromission, clôture |
