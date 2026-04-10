# Solution hybride finale — InfraSentinel

## 1. Vue d'ensemble

InfraSentinel est un agent autonome de cyberdefense destine aux PME africaines. Son architecture est concue pour fonctionner dans deux contextes complementaires :

- **mode connecte** : le systeme opere localement tout en profitant de services externes d'enrichissement et de supervision ;
- **mode hors connexion** : le systeme continue de detecter, scorer, journaliser et bloquer localement sans dependre d'internet.

L'objectif est de garantir une protection continue meme lorsque la connectivite est instable, tout en permettant une intelligence augmentee des qu'une connexion redevient disponible.

---

## 2. Principe d'architecture

InfraSentinel suit une logique de couches :

1. **Collecte**
2. **Analyse IA**
3. **Decision**
4. **Reponse**
5. **Stockage**
6. **Visualisation**
7. **Synchronisation**

Flux principal :

```text
Capture reseau / logs / scan
        ->
Analyse IA locale
        ->
Scoring dynamique
        ->
Decision
        ->
Reponse automatique
        ->
Stockage local
        ->
Dashboard local / synchronisation optionnelle
```

---

## 3. Mode connecte (online intelligent)

En mode connecte, InfraSentinel conserve toute son autonomie locale mais active en plus des fonctions d'enrichissement et de communication.

### 3.1 Collecte

Le systeme collecte :

- le trafic reseau avec **Scapy**
- les ports et services exposes avec **Nmap**
- les journaux systeme quand ils sont accessibles

**Deja implemente dans le projet actuel** :

- capture reseau Scapy
- agregation par IP
- scan de ports conditionnel
- collecte de logs systeme selon la plateforme

### 3.2 Analyse IA

Le moteur IA est local et fonctionne meme en mode connecte sans dependre d'un cloud.

Il repose sur :

- un modele **Isolation Forest**
- l'extraction de features reseau
- un **scoring dynamique du risque**

Le systeme peut detecter :

- scan de ports
- brute force
- comportements anormaux
- activites proches d'un DoS
- profils d'exfiltration suspects

**Deja implemente dans le projet actuel** :

- modele local
- scoring composite
- classification de menaces

### 3.3 Reponse automatique

Selon le niveau de risque :

- **faible** : journalisation + surveillance
- **moyen** : alerte + suivi renforce
- **critique** : blocage automatique de l'IP si la politique l'autorise

Les mecanismes de reponse sont :

- alertes locales
- WebSocket vers le dashboard
- blocage firewall
- journalisation des incidents

**Deja implemente dans le projet actuel**.

### 3.4 Dashboard temps reel

En mode connecte, le dashboard local affiche :

- statistiques en temps reel
- incidents
- decisions
- IPs bloquees
- faux positifs
- whitelist
- logs
- carte 3D des menaces

Le dashboard s'appuie sur :

- **FastAPI**
- **WebSocket**
- graphiques frontend
- globe 3D pour la carte

**Deja implemente dans le projet actuel**.

### 3.5 Enrichissement externe

Quand internet est disponible, le systeme peut enrichir les incidents avec :

- geolocalisation IP
- notifications externes
- a terme, threat intelligence reputational

**Deja implemente** :

- geolocalisation IP externe
- support de webhooks dans le code

**A prevoir dans l'architecture cible** :

- flux de threat intelligence structuree
- reputation IP / IOC
- federation multi-sites

### 3.6 Synchronisation des donnees

La solution hybride cible prevoit une synchronisation des donnees vers une plateforme centrale ou un noeud de consolidation.

Cela permettrait :

- consolidation multi-agents
- remontes centralisees
- mutualisation des IOC
- supervision multi-sites

**Etat actuel** :

- pas encore implemente de bout en bout
- a prevoir dans l'architecture cible

---

## 4. Mode hors connexion (offline-first)

Le mode hors connexion est la garantie de continuite de defense.

### 4.1 Ce qui doit rester actif sans internet

Les fonctions critiques maintenues localement sont :

- capture reseau
- analyse IA locale
- scoring
- classification
- blocage automatique
- journalisation
- dashboard local

**Deja implemente dans le projet actuel** pour l'essentiel.

### 4.2 Analyse locale autonome

Le modele IA est charge depuis le disque local. L'absence d'internet n'interrompt donc pas :

- la prediction
- la classification
- la prise de decision

**Deja implemente**.

### 4.3 Stockage local

Le stockage hors connexion repose sur :

- **SQLite** pour la persistance principale
- **JSON/CSV** pour l'export

Cela permet de conserver :

- incidents
- blocages
- faux positifs
- whitelist
- historique de supervision

**Deja implemente**.

### 4.4 Dashboard local embarque

Le dashboard reste consultable localement sans internet.

L'administrateur peut encore :

- voir les incidents
- voir les IPs bloquees
- gerer la whitelist
- consulter les logs
- suivre les statistiques

**Deja implemente**.

### 4.5 Fonctions a desactiver intelligemment hors ligne

En mode hors connexion, les fonctions dependantes d'internet doivent se mettre en mode degrade sans provoquer de crash :

- geolocalisation IP externe
- threat intelligence externe
- webhooks distants
- chatbot externe
- chargements frontend depuis des CDN publics

**Etat actuel** :

- plusieurs integrations sont deja tolerees en mode degrade
- mais la gestion explicite d'un vrai mode offline reste a renforcer

### 4.6 Contraintes importantes du mode offline

Pour etre totalement robuste hors connexion, la solution cible doit prevoir :

- assets frontend servis localement sans CDN
- mecanisme clair de desactivation des enrichissements externes
- file locale d'evenements a resynchroniser plus tard
- messages d'etat clairs dans le dashboard

**A prevoir dans l'architecture cible**.

---

## 5. Transition hybride

La valeur de la solution vient aussi de sa capacite a basculer proprement entre les deux modes.

### 5.1 Detection de l'etat reseau

Le systeme doit identifier :

- perte de connexion
- retour de la connexion
- indisponibilite d'un service externe
- mode degrade partiel

**Etat actuel** :

- degradation partielle deja presente

**A completer** :

- etat online/offline explicite
- heartbeat ou verification reseau periodique

### 5.2 Synchronisation differee

Quand internet revient, les donnees accumulees localement doivent pouvoir etre synchronisees sans perte.

Objets a synchroniser :

- incidents
- alertes
- blocages
- faux positifs
- whitelist
- metadata de supervision

**A prevoir dans l'architecture cible**.

### 5.3 Gestion des conflits

Une architecture hybride serieuse doit gerer :

- doublons
- modifications concurrentes
- faux positifs marques localement
- listes blanches modifiees sur plusieurs noeuds

Mecanismes recommandes :

- identifiants uniques
- horodatage fiable
- versioning simple
- priorite aux etats les plus recents
- journal d'audit

**A prevoir dans l'architecture cible**.

### 5.4 Integrite des logs et incidents

Le passage online/offline ne doit jamais compromettre la valeur probante des incidents.

Chaque evenement critique doit conserver :

- son horodatage
- son contexte
- l'action appliquee
- son etat de synchronisation
- si possible une verification d'integrite

**Historisation locale deja implemente**.

**Integrite de synchronisation a renforcer**.

---

## 6. Securite, robustesse et bonnes pratiques

### 6.1 Protection des modeles IA

Les fichiers de modele `.pkl` doivent etre proteges contre :

- l'alteration
- le remplacement
- la suppression non autorisee

Bonnes pratiques :

- permissions restreintes
- verifications d'empreinte
- journalisation des reentrainements

**Stockage local deja present ; protection avancee a renforcer**.

### 6.2 Protection des logs

Les logs et incidents sont des preuves techniques.

Bonnes pratiques :

- rotation propre
- stockage local fiable
- export controle
- chiffrement ou signature selon le niveau de sensibilite

**Rotation et stockage deja presents ; chiffrement/signature a prevoir si besoin**.

### 6.3 Tolerance aux pannes

Une panne partielle ne doit pas arreter toute la solution.

Le systeme doit continuer a tourner si :

- Nmap est absent
- la geolocalisation echoue
- les logs systeme sont indisponibles
- les services externes sont injoignables

**Deja partiellement implemente via mode degrade**.

### 6.4 Gestion des erreurs sans crash

Le comportement attendu est :

- journaliser l'erreur
- isoler la panne au composant concerne
- poursuivre les fonctions critiques locales

**Deja partiellement implemente dans le projet actuel**.

### 6.5 Audit et tracabilite

Le systeme doit conserver :

- la date
- l'heure
- l'IP
- le score
- la menace
- l'action prise
- l'etat de blocage
- idealement, l'auteur des actions manuelles

**Tracabilite technique deja presente ; audit humain avance a prevoir**.

---

## 7. Resultat final attendu de la solution hybride

### 7.1 En mode connecte

InfraSentinel doit offrir :

- collecte locale complete
- IA locale active
- scoring dynamique
- detection de menaces
- reponse automatique
- dashboard temps reel
- geolocalisation IP
- enrichissement externe
- synchronisation vers une architecture cible centralisee

### 7.2 En mode hors connexion

InfraSentinel doit continuer a offrir :

- capture reseau
- analyse IA locale
- scoring
- blocage automatique
- stockage SQLite local
- consultation du dashboard local
- continute de supervision

Avec des fonctions intelligemment suspendues :

- geolocalisation externe
- threat intelligence externe
- services cloud
- integrations non critiques

### 7.3 Ce que cela prouve

Dans sa forme finale, la solution hybride InfraSentinel est :

- autonome
- intelligente
- resiliente
- adaptee aux environnements a faible connectivite

---

## 8. Ce qui est deja fait vs ce qui reste a faire

### Deja implemente

- capture reseau Scapy
- modele IA local Isolation Forest
- scoring du risque
- classification de menaces
- blocage IP local
- dashboard FastAPI + WebSocket
- SQLite
- carte 3D des menaces
- geolocalisation IP
- faux positifs
- whitelist
- gestionnaire hybride online/offline avec bascule automatique
- file de synchronisation differee locale (JSON)
- suspension intelligente des services externes
- chatbot IA hybride: local embarque + cloud optionnel avec fallback automatique

### A completer pour la cible hybride complete

- gestion des conflits
- assets frontend 100 % offline
- threat intelligence externe structuree
- audit complet des actions humaines
- protection renforcee des journaux et modeles

---

## 9. Conclusion

InfraSentinel est deja un socle solide de cyberdefense locale. La version actuelle couvre deja une grande partie du mode offline-first et plusieurs briques du mode connecte.

La solution hybride finale consiste a conserver ce noyau autonome tout en ajoutant proprement :

- l'enrichissement externe
- la synchronisation differee
- la gouvernance des donnees
- une gestion explicite des transitions reseau

Le resultat attendu est une plateforme de cyberdefense locale et resiliente, capable de proteger efficacement des PME meme en contexte de connectivite intermittente.
