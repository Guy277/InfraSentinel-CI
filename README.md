# InfraSentinel-CI

InfraSentinel-CI est un agent autonome de cyberdefense concu pour proteger des PME dans des environnements a connectivite faible, intermittente ou instable.

Le projet repose sur une architecture hybride :

- **offline-first** : les fonctions critiques continuent de fonctionner localement sans internet ;
- **online intelligent** : quand la connexion est disponible, le systeme enrichit son analyse et sa supervision.

Le detail de la solution hybride finale est documente dans [SOLUTION_HYBRIDE.md](SOLUTION_HYBRIDE.md).

## Etat actuel du projet

Le projet dispose deja d'un noyau technique fonctionnel :

- capture reseau en temps reel avec Scapy
- detection d'anomalies par IA avec Isolation Forest
- scoring dynamique du risque
- blocage automatique des IPs critiques
- dashboard local FastAPI avec WebSocket
- carte 3D des menaces geolocalisees
- gestion des faux positifs et de la whitelist
- stockage local SQLite
- chatbot IA hybride (assistant local embarque + cloud optionnel)

Les briques suivantes sont presentes partiellement ou a renforcer :

- scan de ports conditionnel selon l'environnement
- notifications externes
- reentrainement automatique
- synchronisation hybride online/offline

## Installation

### Windows

1. Installez Npcap :
   - https://npcap.com/dist/Npcap-1.79.exe
   - activez le mode "WinPcap API-compatible Mode"

2. Lancez l'installation automatique :

```cmd
python setup_hackathon.py
```

3. Demarrez le systeme :

```cmd
venv\Scripts\python.exe main.py
```

Ou double-cliquez sur `run_hackathon.bat`.

### Linux

```bash
sudo apt update
sudo apt install libpcap-dev iptables python3-venv
python3 setup_hackathon.py
sudo ./hackathon.sh start
```

## Configuration

Le fichier `.env` est cree automatiquement avec une configuration locale simple :

```env
DB_TYPE=sqlite
DB_SQLITE_PATH=data/ids.db
DASHBOARD_PORT=9090
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=admin
```

Pour activer le cloud chatbot avec Gemini :

```env
CHATBOT_PROVIDER=gemini
CHATBOT_MODEL=gemini-2.0-flash
GEMINI_API_KEY=votre_cle_api_gemini
```

## Acces dashboard

- URL : `http://localhost:9090`
- Login : `admin / admin`

## Commandes utiles

### Windows

- `run_hackathon.bat` : demarrage rapide
- `venv\Scripts\python.exe main.py` : lancement direct

### Linux

- `./hackathon.sh start` : demarrer
- `./hackathon.sh stop` : arreter
- `./hackathon.sh status` : verifier le statut
- `./hackathon.sh reset` : reinitialiser la base

## Architecture du code

```text
main.py            -> point d'entree
core/agent.py      -> orchestrateur principal
capture/           -> sniffer, scanner, logs, geolocalisation
ai_engine/         -> detection anomalie, scoring
ips/               -> blocage, alertes, journalisation
dashboard/         -> application web FastAPI
database/          -> modeles et acces SQLite/PostgreSQL
```

## Vision hybride

### Mode connecte

Quand internet est disponible, InfraSentinel-CI peut :

- enrichir les incidents avec la geolocalisation IP
- diffuser des alertes en temps reel
- activer l'enrichissement cloud du chatbot (avec fallback local automatique)
- exposer le dashboard avec une supervision plus riche
- preparer la synchronisation vers une architecture cible centralisee

### Mode hors connexion

Quand internet est indisponible, InfraSentinel-CI continue a assurer :

- la capture reseau
- l'analyse IA locale
- le scoring du risque
- le blocage automatique local
- le stockage local SQLite
- le dashboard local embarque

## Documentation complementaire

- [SOLUTION_HYBRIDE.md](SOLUTION_HYBRIDE.md) : description finale de la solution hybride en mode connecte et hors connexion
- [RAPPORT_SYSTEME.txt](RAPPORT_SYSTEME.txt) : rapport technique detaille
