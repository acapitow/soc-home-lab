# Post LinkedIn de présentation

> À adapter/personnaliser avant publication. Ajoutez une capture du dashboard Wazuh
> (très efficace visuellement) et le lien vers le dépôt.

---

**J'ai construit mon propre SOC à la maison — et je l'ai attaqué pour mieux le défendre.**

En tant qu'étudiant en MSc Cybersécurité à Epitech, je voulais aller au-delà de la théorie
et comprendre concrètement le quotidien d'un analyste SOC. J'ai donc monté un laboratoire
de détection complet, **déployable en une seule commande** grâce à l'Infrastructure as Code.

**L'architecture (Vagrant + Ansible, réseau isolé) :**
• Un domaine **Active Directory** (Windows Server 2022) avec audit avancé
• Un poste Windows instrumenté avec **Sysmon** + journalisation PowerShell
• Un serveur Linux (SSH/Nginx)
• Un SIEM **Wazuh** (manager + indexer + dashboard), agents déployés automatiquement

**Côté détection, j'ai simulé 3 attaques réelles (mappées MITRE ATT&CK) et écrit les
règles pour les repérer :**
• Brute force SSH → `T1110.001`
• Password spraying sur Active Directory → `T1110.003`
• Scan réseau → `T1046`

Pour chacune : la télémétrie attendue (Event IDs Windows, Sysmon, auth.log), une **règle
Wazuh**, la **règle Sigma** équivalente, et un **rapport d'incident** (méthode PICERL).

**Ce que ce projet m'a appris :**
• La différence pratique entre brute force et password spraying — et pourquoi on détecte
  le second en corrélant « N comptes depuis 1 source » plutôt qu'en comptant les échecs
  par compte.
• L'importance de Sysmon : les journaux Windows natifs ne suffisent pas.
• Penser « détection » : une attaque ne vaut que par le signal qu'elle laisse.

Le projet est open source (avec un profil « léger » pour tourner sur 16 Go de RAM) :
https://github.com/acapitow/premier-projet-cyber

Je recherche une **alternance d'analyste SOC** — n'hésitez pas à me contacter ou à partager !
Vos retours de pros de la détection sont les bienvenus.

#Cybersécurité #SOC #BlueTeam #Wazuh #SIEM #MITREATTACK #Sigma #Sysmon #ActiveDirectory #DetectionEngineering #Alternance #InfrastructureAsCode
