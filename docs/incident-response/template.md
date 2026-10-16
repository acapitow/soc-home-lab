# Rapport d'incident — MODÈLE

> Modèle réutilisable (structure SANS PICERL). Copier ce fichier, le renommer
> `IR-XXX-<sujet>.md`, et remplir les champs entre crochets `[...]`.
> Les sections **Preuves** sont à compléter avec les **preuves réelles** après
> exécution du scénario (captures du dashboard, export `results/alerts/…`).

---

## 1. Résumé exécutif

| Champ | Valeur |
|-------|--------|
| **Identifiant** | IR-XXX |
| **Titre** | [Brève description de l'incident] |
| **Date de détection** | [AAAA-MM-JJ hh:mm] |
| **Analyste** | André Capito (@acapitow) |
| **Sévérité** | [Faible / Moyenne / Élevée / Critique] |
| **Statut** | [Ouvert / En cours / Clôturé] |
| **Systèmes concernés** | [DC01 / WS01 / SRV01 …] |
| **Technique MITRE ATT&CK** | [TXXXX — nom] |

**Synthèse (3-4 phrases)** : [Qui/quoi/quand/où/impact. Ce qui a été détecté, par
quel moyen, et la réponse apportée.]

## 2. Préparation (Preparation)

- Sources de journaux disponibles : [auth.log, Sysmon, Security Windows, …]
- Règles de détection en place : [Wazuh 100xxx, Sigma …]
- Périmètre et criticité des actifs : [description]

## 3. Identification (Identification)

- **Alerte déclenchée** : [règle Wazuh / Sigma, niveau]
- **Date/heure** : [première et dernière occurrence]
- **Source de l'attaque** : [IP, hôte, compte]
- **Cible** : [hôte, service, compte]
- **Preuves** :
  - Journaux : [extraits — Event IDs, lignes auth.log]
  - Export des alertes : [`results/alerts/…json`]
  - Capture du dashboard : [`results/…png`]

### Indicateurs de compromission (IOC)

| Type | Valeur | Remarque |
|------|--------|----------|
| IP source | [10.20.0.x] | |
| Compte visé | [...] | |
| Processus / outil | [...] | |

## 4. Confinement (Containment)

Mesures immédiates pour limiter l'impact :
- [ ] [Bloquer l'IP source au pare-feu]
- [ ] [Désactiver/verrouiller le(s) compte(s) concerné(s)]
- [ ] [Isoler l'hôte du réseau]

## 5. Éradication (Eradication)

- [ ] [Supprimer l'accès de l'attaquant / réinitialiser les identifiants]
- [ ] [Corriger la configuration à l'origine de l'exposition]

## 6. Rétablissement (Recovery)

- [ ] [Restaurer le service en condition normale et surveiller]
- [ ] [Vérifier l'absence de persistance]

## 7. Leçons apprises (Lessons Learned)

- Ce qui a bien fonctionné : [détection, délai…]
- À améliorer : [règle à affiner, seuil, source de log manquante…]
- Actions de durcissement proposées : [MFA, fail2ban, politique de verrouillage…]

## 8. Chronologie (Timeline)

| Heure | Événement |
|-------|-----------|
| [hh:mm] | [Début de l'activité malveillante] |
| [hh:mm] | [Alerte Wazuh déclenchée] |
| [hh:mm] | [Prise en charge analyste] |
| [hh:mm] | [Confinement] |
| [hh:mm] | [Clôture] |
